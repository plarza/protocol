//! Apps, clients and certificates, section 7.
use crate::Value;
use crate::crypto::{self, ENC_PUBLIC_KEY_LEN, Hash, PUBLIC_KEY_LEN, SigningKey, fingerprint};
use crate::error::{Error, Result};
use crate::identity::Identity;
use base64::Engine;

pub const SIGN_IN: &str = "sign-in";
pub const READ: &str = "read";
pub const WRITE: &str = "write";
pub const PUBLISH: &str = "publish";
pub const RECEIVE: &str = "receive";

/// The aza app's own app ID.
pub const AZA_APP: &str = "aza.network";

/// Whether `s` is a domain name usable as an app ID: lowercase labels of letters, digits and
/// hyphens, at least two of them.
pub fn is_app_id(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    s.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

pub(crate) fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

pub(crate) fn unb64(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).ok()
}

/// A certificate: a device's statement that a client may act for the identity in one app.
#[derive(Clone, Debug)]
pub struct Certificate {
    raw: Value,
    pub identity: Hash,
    pub node: String,
    pub app: String,
    pub client: Vec<u8>,
    pub enc: Option<Vec<u8>>,
    pub scopes: Vec<String>,
    pub time: u64,
    pub by: Hash,
    pub sig: Vec<u8>,
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

/// What a certificate grants, before a device signs it.
#[derive(Clone, Debug)]
pub struct Grant {
    pub identity: Hash,
    pub node: String,
    pub app: String,
    pub client: Vec<u8>,
    pub enc: Option<Vec<u8>>,
    pub scopes: Vec<String>,
}

fn scopes_ok(scopes: &[String], enc: &Option<Vec<u8>>) -> bool {
    let has = |s: &str| scopes.iter().any(|x| x == s);
    (!has(WRITE) || has(READ)) && (!(has(READ) || has(RECEIVE)) || enc.is_some())
}

impl Certificate {
    /// Signs a certificate with a device's key.
    pub fn sign(grant: Grant, time: u64, by: Hash, key: &SigningKey) -> Result<Certificate> {
        if !scopes_ok(&grant.scopes, &grant.enc) || !is_app_id(&grant.app) {
            return Err(Error::Refused("scopes don't fit the certificate rules".into()));
        }
        let mut m: Vec<(&str, Value)> = vec![
            ("identity", grant.identity.into()),
            ("node", grant.node.as_str().into()),
            ("app", grant.app.as_str().into()),
            ("client", grant.client.clone().into()),
            ("scopes", Value::Array(grant.scopes.iter().map(|s| s.as_str().into()).collect())),
            ("time", time.into()),
            ("by", by.into()),
        ];
        if let Some(enc) = &grant.enc {
            m.push(("enc", enc.clone().into()));
        }
        let unsigned = Value::map(m);
        let sig = key.sign(&unsigned.to_bytes());
        Certificate::from_value(unsigned.with("sig", sig.into()))
    }

    pub fn from_value(raw: Value) -> Result<Certificate> {
        let bad = || Error::Malformed("certificate");
        let text = |k: &str| raw.get(k).and_then(Value::as_text).map(str::to_string).ok_or_else(bad);
        let client =
            raw.get("client").and_then(Value::as_bytes).filter(|b| b.len() == PUBLIC_KEY_LEN).ok_or_else(bad)?.to_vec();
        let enc = match raw.get("enc") {
            None => None,
            Some(e) => Some(e.as_bytes().filter(|b| b.len() == ENC_PUBLIC_KEY_LEN).ok_or_else(bad)?.to_vec()),
        };
        let scopes = raw
            .get("scopes")
            .and_then(Value::as_array)
            .ok_or_else(bad)?
            .iter()
            .map(|s| s.as_text().map(str::to_string).ok_or_else(bad))
            .collect::<Result<Vec<_>>>()?;
        let cert = Certificate {
            identity: raw.get("identity").and_then(Value::as_hash).ok_or_else(bad)?,
            node: text("node")?,
            app: text("app")?,
            client,
            enc,
            scopes,
            time: raw.get("time").and_then(Value::as_u64).ok_or_else(bad)?,
            by: raw.get("by").and_then(Value::as_hash).ok_or_else(bad)?,
            sig: raw.get("sig").and_then(Value::as_bytes).ok_or_else(bad)?.to_vec(),
            raw,
        };
        if !scopes_ok(&cert.scopes, &cert.enc) || !is_app_id(&cert.app) {
            return Err(bad());
        }
        Ok(cert)
    }

    pub fn from_bytes(b: &[u8]) -> Result<Certificate> {
        Certificate::from_value(Value::from_bytes(b).ok_or(Error::Malformed("certificate encoding"))?)
    }

    pub fn to_value(&self) -> &Value {
        &self.raw
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.raw.to_bytes()
    }

    /// The fingerprint of the client key.
    pub fn client_fp(&self) -> Hash {
        fingerprint(&self.client)
    }

    pub fn has(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    fn signature_valid(&self, key: &[u8]) -> bool {
        crypto::verify(key, &self.raw.without("sig").to_bytes(), &self.sig)
    }

    /// Checks 1 to 3 of section 7: the signature is valid, device `by` is current at the end of
    /// the log, and the log has no revocation of the client key.
    pub fn check(&self, identity: &Identity) -> Result<()> {
        if self.identity != identity.id {
            return Err(Error::Refused("certificate is for another identity".into()));
        }
        let device = identity.device(&self.by).ok_or(Error::Refused("certificate signer isn't a device".into()))?;
        if !self.signature_valid(&device.key) {
            return Err(Error::BadSignature("certificate"));
        }
        if !device.current {
            return Err(Error::Refused("the device that signed the certificate isn't current".into()));
        }
        if identity.is_revoked(&self.client_fp()) {
            return Err(Error::Refused("client is revoked".into()));
        }
        Ok(())
    }

    /// The signature is valid for the key of device `by`, taking the key from the change that
    /// brought the device in even if that change is discarded (section 10, rule 1).
    pub fn signed_by_device_key(&self, identity: &Identity) -> bool {
        self.identity == identity.id && identity.device_key_any(&self.by).is_some_and(|k| self.signature_valid(k))
    }

    /// Checks 1 to 4 of section 7 for the app doing the checking.
    pub fn check_for(&self, identity: &Identity, app: &str, scope: &str) -> Result<()> {
        self.check(identity)?;
        if self.app != app || !self.has(scope) {
            return Err(Error::Refused(format!("certificate doesn't grant {scope} for {app}")));
        }
        Ok(())
    }

    /// Check 5: the client proves it holds the client key by signing a challenge.
    pub fn check_sign_in(&self, identity: &Identity, app: &str, challenge: &[u8; 32], proof: &[u8]) -> Result<()> {
        self.check_for(identity, app, SIGN_IN)?;
        if !crypto::verify(&self.client, &sign_in_message(app, &identity.id, challenge), proof) {
            return Err(Error::BadSignature("sign-in proof"));
        }
        Ok(())
    }
}

/// The CBOR array a client signs to prove it holds its key when signing in.
pub fn sign_in_message(app: &str, identity: &Hash, challenge: &[u8; 32]) -> Vec<u8> {
    Value::Array(vec!["aza sign-in v1".into(), app.into(), (*identity).into(), challenge.to_vec().into()]).to_bytes()
}

/// A client's request for a certificate.
#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub app: String,
    pub client: Vec<u8>,
    pub enc: Option<Vec<u8>>,
    pub scopes: Vec<String>,
    /// Where the aza app sends the certificate: an `https` URL whose host is exactly the app ID.
    pub return_url: String,
}

impl Request {
    pub fn to_value(&self) -> Value {
        let mut m: Vec<(&str, Value)> = vec![
            ("app", self.app.as_str().into()),
            ("client", self.client.clone().into()),
            ("scopes", Value::Array(self.scopes.iter().map(|s| s.as_str().into()).collect())),
            ("return", self.return_url.as_str().into()),
        ];
        if let Some(enc) = &self.enc {
            m.push(("enc", enc.clone().into()));
        }
        Value::map(m)
    }

    pub fn from_value(v: &Value) -> Result<Request> {
        let bad = || Error::Malformed("certificate request");
        let r = Request {
            app: v.get("app").and_then(Value::as_text).ok_or_else(bad)?.to_string(),
            client: v
                .get("client")
                .and_then(Value::as_bytes)
                .filter(|b| b.len() == PUBLIC_KEY_LEN)
                .ok_or_else(bad)?
                .to_vec(),
            enc: match v.get("enc") {
                None => None,
                Some(e) => Some(e.as_bytes().filter(|b| crypto::is_enc_public_key(b)).ok_or_else(bad)?.to_vec()),
            },
            scopes: v
                .get("scopes")
                .and_then(Value::as_array)
                .ok_or_else(bad)?
                .iter()
                .map(|s| s.as_text().map(str::to_string).ok_or_else(bad))
                .collect::<Result<_>>()?,
            return_url: v.get("return").and_then(Value::as_text).ok_or_else(bad)?.to_string(),
        };
        Ok(r)
    }

    /// The return URL must be `https` with a host of exactly the app ID, and the scopes must fit.
    pub fn validate(&self) -> Result<()> {
        if !is_app_id(&self.app) {
            return Err(Error::Refused("app ID isn't a domain".into()));
        }
        let url = url::Url::parse(&self.return_url).map_err(|_| Error::Refused("return URL isn't a URL".into()))?;
        if url.scheme() != "https"
            || url.host_str() != Some(self.app.as_str())
            || url.port().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::Refused(format!("return URL isn't on https://{}", self.app)));
        }
        if !scopes_ok(&self.scopes, &self.enc) || self.scopes.is_empty() {
            return Err(Error::Refused("scopes don't fit the certificate rules".into()));
        }
        Ok(())
    }

    /// `aza:approve#req=…`, opened on the same machine.
    pub fn approve_url(&self) -> String {
        format!("aza:approve#req={}", b64(&self.to_value().to_bytes()))
    }

    pub fn from_approve_url(url: &str) -> Result<Request> {
        let enc = url.strip_prefix("aza:approve#req=").ok_or(Error::Malformed("approve URL"))?;
        let bytes = unb64(enc).ok_or(Error::Malformed("approve URL"))?;
        Request::from_value(&Value::from_bytes(&bytes).ok_or(Error::Malformed("certificate request"))?)
    }

    pub fn hash(&self) -> Hash {
        crypto::sha256(&self.to_value().to_bytes())
    }

    /// Where an app's server stores a request for the other-machine path.
    pub fn well_known_url(app: &str, id: &str) -> String {
        format!("https://{app}/.well-known/aza/request/{id}")
    }
}

/// What the QR code holds for the other-machine path: the request's URL and hash.
pub fn qr_payload(request_url: &str, request_hash: &Hash) -> String {
    format!("{request_url}#{}", hex::encode(request_hash))
}

pub fn parse_qr_payload(s: &str) -> Result<(String, Hash)> {
    let (url, h) = s.rsplit_once('#').ok_or(Error::Malformed("QR code"))?;
    let h: Hash = hex::decode(h).ok().and_then(|b| b.try_into().ok()).ok_or(Error::Malformed("QR code"))?;
    Ok((url.to_string(), h))
}

/// The return URL with the certificate appended, for the same-machine path.
pub fn return_with_certificate(return_url: &str, cert: &Certificate) -> String {
    format!("{return_url}#aza={}", b64(&cert.to_bytes()))
}

pub fn certificate_from_return_url(url: &str) -> Result<Certificate> {
    let (_, enc) = url.split_once("#aza=").ok_or(Error::Malformed("return URL"))?;
    Certificate::from_bytes(&unb64(enc).ok_or(Error::Malformed("return URL"))?)
}
