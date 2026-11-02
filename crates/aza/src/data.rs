//! Private data, section 9: data secrets, app keys, envelopes and sync data.
use crate::Value;
use crate::certificate::Certificate;
use crate::crypto::{self, Hash, SigningKey, hkdf, hkdf_named};
use crate::error::{Error, Result};
use crate::identity::Identity;

pub fn secret_check(secret: &Hash) -> Hash {
    hkdf(secret, b"aza secret check v1")
}

pub fn app_key(secret: &Hash, app: &str) -> Hash {
    hkdf_named(secret, "aza app key v1", app)
}

pub fn contact_tag(contact_secret: &Hash, app: &str) -> Hash {
    hkdf_named(contact_secret, "aza contact tag v1", app)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    DataSecret,
    AppKey,
    ContactTag,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::DataSecret => "data-secret",
            Kind::AppKey => "app-key",
            Kind::ContactTag => "contact-tag",
        }
    }

    fn parse(s: &str) -> Option<Kind> {
        Some(match s {
            "data-secret" => Kind::DataSecret,
            "app-key" => Kind::AppKey,
            "contact-tag" => Kind::ContactTag,
            _ => return None,
        })
    }
}

/// A secret sealed to one holder's encryption key, signed by the device that made it.
#[derive(Clone, Debug)]
pub struct Envelope {
    raw: Value,
    pub identity: Hash,
    pub kind: Kind,
    /// The data secret's name, or for a contact tag the hash of its contact secret.
    pub secret: Hash,
    /// A device ID or client key fingerprint.
    pub holder: Hash,
    pub sealed: Vec<u8>,
    /// Contact tags only: raised by one with each new contact secret.
    pub generation: Option<u64>,
    pub by: Hash,
    pub sig: Vec<u8>,
}

impl Envelope {
    /// Seals `contents` (32 bytes) to the holder's encryption key and signs the envelope.
    #[allow(clippy::too_many_arguments)]
    pub fn make(
        identity: Hash,
        kind: Kind,
        secret: Hash,
        holder: Hash,
        holder_enc: &[u8],
        contents: &Hash,
        generation: Option<u64>,
        by: Hash,
        key: &SigningKey,
    ) -> Result<Envelope> {
        let sealed = crypto::seal(holder_enc, contents).ok_or(Error::Malformed("holder encryption key"))?;
        let mut m: Vec<(&str, Value)> = vec![
            ("identity", identity.into()),
            ("kind", kind.as_str().into()),
            ("secret", secret.into()),
            ("holder", holder.into()),
            ("sealed", sealed.into()),
            ("by", by.into()),
        ];
        if let Some(g) = generation {
            m.push(("generation", g.into()));
        }
        let unsigned = Value::map(m);
        let sig = key.sign(&unsigned.to_bytes());
        Envelope::from_value(unsigned.with("sig", sig.into()))
    }

    pub fn from_value(raw: Value) -> Result<Envelope> {
        let bad = || Error::Malformed("envelope");
        let h = |k: &str| raw.get(k).and_then(Value::as_hash).ok_or_else(bad);
        let kind = raw.get("kind").and_then(Value::as_text).and_then(Kind::parse).ok_or_else(bad)?;
        let generation = match raw.get("generation") {
            None => None,
            Some(g) => Some(g.as_u64().ok_or_else(bad)?),
        };
        if (kind == Kind::ContactTag) != generation.is_some() {
            return Err(bad());
        }
        Ok(Envelope {
            identity: h("identity")?,
            kind,
            secret: h("secret")?,
            holder: h("holder")?,
            sealed: raw.get("sealed").and_then(Value::as_bytes).ok_or_else(bad)?.to_vec(),
            generation,
            by: h("by")?,
            sig: raw.get("sig").and_then(Value::as_bytes).ok_or_else(bad)?.to_vec(),
            raw,
        })
    }

    pub fn to_value(&self) -> &Value {
        &self.raw
    }

    /// The signature is valid for device `by`'s key, whether or not the device is current.
    pub fn signature_valid(&self, identity: &Identity) -> bool {
        self.identity == identity.id
            && identity
                .device_key_any(&self.by)
                .is_some_and(|k| crypto::verify(k, &self.raw.without("sig").to_bytes(), &self.sig))
    }

    /// Signed by a device current at the end of the log.
    pub fn trusted(&self, identity: &Identity) -> bool {
        self.signature_valid(identity) && identity.is_current(&self.by)
    }

    pub fn open(&self, key: &crypto::EncKey) -> Option<Hash> {
        key.open(&self.sealed)?.try_into().ok()
    }
}

/// Picks the envelope a reader uses among those the node returned in storage order: signed by a
/// current device, of this kind and secret, the most recently stored.
pub fn choose<'a>(
    envelopes: &'a [Envelope],
    identity: &Identity,
    holder: &Hash,
    kind: Kind,
    secret: &Hash,
) -> Option<&'a Envelope> {
    envelopes.iter().rev().find(|e| e.holder == *holder && e.kind == kind && e.secret == *secret && e.trusted(identity))
}

/// Opens the data secret `name` from the holder's envelopes. Its `check` vouches for it, so an
/// envelope from any of the identity's devices will do, even one no longer current: the newest
/// whose secret matches.
pub fn open_data_secret(
    envelopes: &[Envelope],
    identity: &Identity,
    holder: &Hash,
    key: &crypto::EncKey,
    name: &Hash,
) -> Result<Hash> {
    let check = identity.secret_check(name).ok_or(Error::NotFound("that data secret isn't announced".into()))?;
    envelopes
        .iter()
        .rev()
        .filter(|e| {
            e.holder == *holder && e.kind == Kind::DataSecret && e.secret == *name && e.signature_valid(identity)
        })
        .filter_map(|e| e.open(key))
        .find(|s| secret_check(s) == check)
        .ok_or(Error::NotFound("data secret envelope".into()))
}

/// Opens an app key from a client's envelopes. App keys can't be checked against `check`, so
/// only the envelope's signer vouches for them.
pub fn open_app_key(
    envelopes: &[Envelope],
    identity: &Identity,
    holder: &Hash,
    key: &crypto::EncKey,
    name: &Hash,
) -> Result<Hash> {
    if identity.secret_check(name).is_none() {
        return Err(Error::NotFound("that data secret isn't announced".into()));
    }
    let env =
        choose(envelopes, identity, holder, Kind::AppKey, name).ok_or(Error::NotFound("app key envelope".into()))?;
    env.open(key).ok_or(Error::Malformed("app key envelope"))
}

/// The contact tags a client holds: (tag, generation), newest generation first.
pub fn open_contact_tags(
    envelopes: &[Envelope],
    identity: &Identity,
    holder: &Hash,
    key: &crypto::EncKey,
) -> Vec<(Hash, u64)> {
    let mut seen = std::collections::HashSet::new();
    let mut tags: Vec<(Hash, u64)> = envelopes
        .iter()
        .rev()
        .filter(|e| e.holder == *holder && e.kind == Kind::ContactTag && e.trusted(identity))
        .filter(|e| seen.insert(e.secret))
        .filter_map(|e| Some((e.open(key)?, e.generation?)))
        .collect();
    tags.sort_by_key(|t| std::cmp::Reverse(t.1));
    tags
}

/// One encrypted item of an app's sync data.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncItem {
    pub identity: Hash,
    pub app: String,
    pub name: String,
    pub version: u64,
    pub secret: Hash,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl SyncItem {
    fn header(identity: Hash, app: &str, name: &str, version: u64, secret: Hash) -> Value {
        Value::map([
            ("identity", identity.into()),
            ("app", app.into()),
            ("name", name.into()),
            ("version", version.into()),
            ("secret", secret.into()),
        ])
    }

    /// Encrypts `plaintext` with the app key of data secret `secret`.
    pub fn seal(
        identity: Hash,
        app: &str,
        name: &str,
        version: u64,
        secret: Hash,
        app_key: &Hash,
        plaintext: &[u8],
    ) -> SyncItem {
        let nonce = crypto::random::<12>();
        let aad = SyncItem::header(identity, app, name, version, secret).to_bytes();
        SyncItem {
            identity,
            app: app.into(),
            name: name.into(),
            version,
            secret,
            nonce: nonce.to_vec(),
            ciphertext: crypto::aes_encrypt(app_key, &nonce, plaintext, &aad),
        }
    }

    pub fn open(&self, app_key: &Hash) -> Result<Vec<u8>> {
        let aad = SyncItem::header(self.identity, &self.app, &self.name, self.version, self.secret).to_bytes();
        crypto::aes_decrypt(app_key, &self.nonce, &self.ciphertext, &aad)
            .ok_or(Error::Refused("sync item doesn't decrypt".into()))
    }

    pub fn to_value(&self) -> Value {
        SyncItem::header(self.identity, &self.app, &self.name, self.version, self.secret)
            .with("nonce", self.nonce.clone().into())
            .with("ciphertext", self.ciphertext.clone().into())
    }

    pub fn from_value(v: &Value) -> Result<SyncItem> {
        let bad = || Error::Malformed("sync item");
        Ok(SyncItem {
            identity: v.get("identity").and_then(Value::as_hash).ok_or_else(bad)?,
            app: v.get("app").and_then(Value::as_text).ok_or_else(bad)?.into(),
            name: v.get("name").and_then(Value::as_text).ok_or_else(bad)?.into(),
            version: v.get("version").and_then(Value::as_u64).filter(|&n| n >= 1).ok_or_else(bad)?,
            secret: v.get("secret").and_then(Value::as_hash).ok_or_else(bad)?,
            nonce: v.get("nonce").and_then(Value::as_bytes).filter(|n| n.len() == 12).ok_or_else(bad)?.to_vec(),
            ciphertext: v.get("ciphertext").and_then(Value::as_bytes).ok_or_else(bad)?.to_vec(),
        })
    }
}

/// The holder of an envelope a client can read: its certificate's client key fingerprint.
pub fn client_holder(cert: &Certificate) -> Hash {
    cert.client_fp()
}
