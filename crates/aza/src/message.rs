//! Messages, section 10: inbox items, contact requests, acceptances and key packages.
use crate::Value;
use crate::certificate::{Certificate, RECEIVE};
use crate::change::CLOCK_SKEW;
use crate::crypto::{self, Hash, SigningKey};
use crate::error::{Error, Result};
use crate::identity::Identity;

/// How long a contact request stays acceptable.
pub const REQUEST_LIFETIME: u64 = 24 * 60 * 60;

/// A sealed message for one device or `receive` client.
#[derive(Clone, Debug, PartialEq)]
pub struct InboxItem {
    pub to: Hash,
    pub sealed: Vec<u8>,
}

impl InboxItem {
    pub fn seal(to: Hash, enc: &[u8], plaintext: &[u8]) -> Result<InboxItem> {
        Ok(InboxItem { to, sealed: crypto::seal(enc, plaintext).ok_or(Error::Malformed("encryption key"))? })
    }

    pub fn to_value(&self) -> Value {
        Value::map([("to", self.to.into()), ("sealed", self.sealed.clone().into())])
    }

    pub fn from_value(v: &Value) -> Result<InboxItem> {
        let bad = || Error::Malformed("inbox item");
        Ok(InboxItem {
            to: v.get("to").and_then(Value::as_hash).ok_or_else(bad)?,
            sealed: v.get("sealed").and_then(Value::as_bytes).ok_or_else(bad)?.to_vec(),
        })
    }

    /// The hash of the stored item, which names it for deletion.
    pub fn hash(&self) -> Hash {
        crypto::sha256(&self.to_value().to_bytes())
    }
}

/// A contact request: someone without the contact secret asks to message an identity.
#[derive(Clone, Debug)]
pub struct ContactRequest {
    raw: Value,
    /// The sender's identity ID and home node URL.
    pub identity: Hash,
    pub node: String,
    pub app: String,
    /// The sender's client's certificate, which must have `receive`.
    pub certificate: Certificate,
    /// The sender's contact tag for the app, where the acceptance goes.
    pub tag: Hash,
    pub note: Option<String>,
    pub recipient: Hash,
    pub time: u64,
    pub sig: Vec<u8>,
}

impl ContactRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        certificate: &Certificate,
        node: &str,
        tag: Hash,
        note: Option<&str>,
        recipient: Hash,
        time: u64,
        client_key: &SigningKey,
    ) -> Result<ContactRequest> {
        let mut m: Vec<(&str, Value)> = vec![
            ("identity", certificate.identity.into()),
            ("node", node.into()),
            ("app", certificate.app.as_str().into()),
            ("certificate", certificate.to_value().clone()),
            ("tag", tag.into()),
            ("recipient", recipient.into()),
            ("time", time.into()),
        ];
        if let Some(n) = note {
            m.push(("note", n.into()));
        }
        let unsigned = Value::map(m);
        let sig = client_key.sign(&unsigned.to_bytes());
        ContactRequest::from_value(unsigned.with("sig", sig.into()))
    }

    pub fn from_value(raw: Value) -> Result<ContactRequest> {
        let bad = || Error::Malformed("contact request");
        Ok(ContactRequest {
            identity: raw.get("identity").and_then(Value::as_hash).ok_or_else(bad)?,
            node: raw.get("node").and_then(Value::as_text).ok_or_else(bad)?.into(),
            app: raw.get("app").and_then(Value::as_text).ok_or_else(bad)?.into(),
            certificate: Certificate::from_value(raw.get("certificate").ok_or_else(bad)?.clone())?,
            tag: raw.get("tag").and_then(Value::as_hash).ok_or_else(bad)?,
            note: match raw.get("note") {
                None => None,
                Some(n) => Some(n.as_text().ok_or_else(bad)?.to_string()),
            },
            recipient: raw.get("recipient").and_then(Value::as_hash).ok_or_else(bad)?,
            time: raw.get("time").and_then(Value::as_u64).ok_or_else(bad)?,
            sig: raw.get("sig").and_then(Value::as_bytes).ok_or_else(bad)?.to_vec(),
            raw,
        })
    }

    pub fn to_value(&self) -> &Value {
        &self.raw
    }

    /// The checks the aza app makes before showing a request, given the sender's change log.
    pub fn check(&self, sender: &Identity, recipient: &Hash, now: u64) -> Result<()> {
        let cert = &self.certificate;
        if cert.identity != self.identity || cert.app != self.app || !cert.has(RECEIVE) {
            return Err(Error::Refused("contact request certificate doesn't match".into()));
        }
        cert.check(sender)?;
        if !crypto::verify(&cert.client, &self.raw.without("sig").to_bytes(), &self.sig) {
            return Err(Error::BadSignature("contact request"));
        }
        if self.recipient != *recipient {
            return Err(Error::Refused("contact request is for someone else".into()));
        }
        if self.time > now + CLOCK_SKEW || now.saturating_sub(self.time) > REQUEST_LIFETIME + CLOCK_SKEW {
            return Err(Error::Refused("contact request is too old".into()));
        }
        Ok(())
    }
}

/// An acceptance of a contact request, sent to the requesting client.
#[derive(Clone, Debug)]
pub struct Acceptance {
    raw: Value,
    /// The recipient's identity ID.
    pub identity: Hash,
    pub app: String,
    /// The recipient's newest tag for the app.
    pub tag: Hash,
    pub generation: u64,
    /// The `time` of the request being accepted.
    pub time: u64,
    pub by: Hash,
    pub sig: Vec<u8>,
}

impl Acceptance {
    pub fn sign(
        identity: Hash,
        app: &str,
        tag: Hash,
        generation: u64,
        time: u64,
        by: Hash,
        key: &SigningKey,
    ) -> Result<Acceptance> {
        let unsigned = Value::map([
            ("identity", identity.into()),
            ("app", app.into()),
            ("tag", tag.into()),
            ("generation", generation.into()),
            ("time", time.into()),
            ("by", by.into()),
        ]);
        let sig = key.sign(&unsigned.to_bytes());
        Acceptance::from_value(unsigned.with("sig", sig.into()))
    }

    pub fn from_value(raw: Value) -> Result<Acceptance> {
        let bad = || Error::Malformed("acceptance");
        Ok(Acceptance {
            identity: raw.get("identity").and_then(Value::as_hash).ok_or_else(bad)?,
            app: raw.get("app").and_then(Value::as_text).ok_or_else(bad)?.into(),
            tag: raw.get("tag").and_then(Value::as_hash).ok_or_else(bad)?,
            generation: raw.get("generation").and_then(Value::as_u64).ok_or_else(bad)?,
            time: raw.get("time").and_then(Value::as_u64).ok_or_else(bad)?,
            by: raw.get("by").and_then(Value::as_hash).ok_or_else(bad)?,
            sig: raw.get("sig").and_then(Value::as_bytes).ok_or_else(bad)?.to_vec(),
            raw,
        })
    }

    pub fn to_value(&self) -> &Value {
        &self.raw
    }

    /// The client uses the tag only if `by` is current at the end of the recipient's log and the
    /// signature is valid for that device's key, and it matches a request the client sent.
    pub fn check(&self, recipient: &Identity, app: &str, request_time: u64) -> Result<()> {
        let device = recipient
            .device(&self.by)
            .filter(|d| d.current)
            .ok_or(Error::Refused("acceptance signer isn't current".into()))?;
        if !crypto::verify(&device.key, &self.raw.without("sig").to_bytes(), &self.sig) {
            return Err(Error::BadSignature("acceptance"));
        }
        if self.identity != recipient.id || self.app != app || self.time != request_time {
            return Err(Error::Refused("acceptance doesn't match a request".into()));
        }
        Ok(())
    }
}

/// The aza part of an MLS key package's credential: the client's certificate and its signature
/// binding the key package's MLS signature key to the client.
#[derive(Clone, Debug)]
pub struct Credential {
    pub certificate: Certificate,
    /// The MLS signature key of the key package.
    pub key: Vec<u8>,
    pub sig: Vec<u8>,
}

fn credential_message(identity: &Hash, app: &str, key: &[u8]) -> Vec<u8> {
    Value::Array(vec!["aza mls key v1".into(), (*identity).into(), app.into(), key.to_vec().into()]).to_bytes()
}

impl Credential {
    pub fn sign(certificate: &Certificate, mls_key: &[u8], client_key: &SigningKey) -> Credential {
        let sig = client_key.sign(&credential_message(&certificate.identity, &certificate.app, mls_key));
        Credential { certificate: certificate.clone(), key: mls_key.to_vec(), sig }
    }

    pub fn to_value(&self) -> Value {
        Value::map([
            ("certificate", self.certificate.to_value().clone()),
            ("key", self.key.clone().into()),
            ("sig", self.sig.clone().into()),
        ])
    }

    pub fn from_value(v: &Value) -> Result<Credential> {
        let bad = || Error::Malformed("key package credential");
        Ok(Credential {
            certificate: Certificate::from_value(v.get("certificate").ok_or_else(bad)?.clone())?,
            key: v.get("key").and_then(Value::as_bytes).ok_or_else(bad)?.to_vec(),
            sig: v.get("sig").and_then(Value::as_bytes).ok_or_else(bad)?.to_vec(),
        })
    }

    /// The checks anyone adding the client makes: the binding signature, that the certificate
    /// is the intended identity's and app's, has `receive`, and passes checks 1 to 3.
    pub fn check(&self, identity: &Identity, app: &str) -> Result<()> {
        let cert = &self.certificate;
        if !crypto::verify(&cert.client, &credential_message(&identity.id, app, &self.key), &self.sig) {
            return Err(Error::BadSignature("key package credential"));
        }
        if cert.identity != identity.id || cert.app != app || !cert.has(RECEIVE) {
            return Err(Error::Refused("key package is for another identity or app".into()));
        }
        cert.check(identity)
    }
}

/// A key package as a node stores it: the aza credential and the MLS key package bytes.
#[derive(Clone, Debug)]
pub struct KeyPackage {
    pub credential: Credential,
    pub package: Vec<u8>,
}

impl KeyPackage {
    pub fn to_value(&self) -> Value {
        Value::map([("credential", self.credential.to_value()), ("package", self.package.clone().into())])
    }

    pub fn from_value(v: &Value) -> Result<KeyPackage> {
        Ok(KeyPackage {
            credential: Credential::from_value(v.get("credential").ok_or(Error::Malformed("key package"))?)?,
            package: v.get("package").and_then(Value::as_bytes).ok_or(Error::Malformed("key package"))?.to_vec(),
        })
    }
}
