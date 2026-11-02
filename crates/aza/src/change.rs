//! Changes, sections 5.1 to 5.3.
use crate::Value;
use crate::crypto::{self, Hash, PUBLIC_KEY_LEN, SigningKey, fingerprint, sha256};
use crate::error::{Error, Result};

/// The protocol version this software follows (section 13).
pub const VERSION: u64 = 1;

#[derive(Clone, Debug, PartialEq)]
pub enum Body {
    Genesis {
        key: Vec<u8>,
        enc: Vec<u8>,
        next: Hash,
        counter: u64,
        check: Hash,
    },
    AddDevice {
        key: Vec<u8>,
        enc: Vec<u8>,
        label: String,
    },
    SignOut {
        device: Hash,
        endorse: Option<Hash>,
    },
    RemoveDevice {
        device: Hash,
        keep: Option<Hash>,
        endorse: Option<Hash>,
    },
    SetMaster {
        reveal: Vec<u8>,
        key: Vec<u8>,
        enc: Vec<u8>,
        next: Hash,
        endorse: Option<Hash>,
    },
    SetHandle {
        handle: Option<String>,
    },
    SetHome {
        node: String,
    },
    RevokeClient {
        client: Hash,
    },
    NewSecret {
        check: Hash,
    },
    /// A supported version but an unknown type, or a body that breaks its type's form. Invalid
    /// and ignored (section 13).
    Invalid,
    /// A change from a higher protocol version.
    Future,
}

impl Body {
    pub fn type_name(&self) -> &'static str {
        match self {
            Body::Genesis { .. } => "genesis",
            Body::AddDevice { .. } => "add-device",
            Body::SignOut { .. } => "sign-out",
            Body::RemoveDevice { .. } => "remove-device",
            Body::SetMaster { .. } => "set-master",
            Body::SetHandle { .. } => "set-handle",
            Body::SetHome { .. } => "set-home",
            Body::RevokeClient { .. } => "revoke-client",
            Body::NewSecret { .. } => "new-secret",
            Body::Invalid => "invalid",
            Body::Future => "future",
        }
    }

    pub fn to_value(&self) -> Value {
        let mut m: Vec<(&str, Value)> = vec![("type", self.type_name().into())];
        let opt = |m: &mut Vec<(&str, Value)>, k, v: &Option<Hash>| {
            if let Some(v) = v {
                m.push((k, (*v).into()));
            }
        };
        match self {
            Body::Genesis { key, enc, next, counter, check } => {
                m.push(("key", key.clone().into()));
                m.push(("enc", enc.clone().into()));
                m.push(("next", (*next).into()));
                m.push(("counter", (*counter).into()));
                m.push(("check", (*check).into()));
            }
            Body::AddDevice { key, enc, label } => {
                m.push(("key", key.clone().into()));
                m.push(("enc", enc.clone().into()));
                m.push(("label", label.as_str().into()));
            }
            Body::SignOut { device, endorse } => {
                m.push(("device", (*device).into()));
                opt(&mut m, "endorse", endorse);
            }
            Body::RemoveDevice { device, keep, endorse } => {
                m.push(("device", (*device).into()));
                opt(&mut m, "keep", keep);
                opt(&mut m, "endorse", endorse);
            }
            Body::SetMaster { reveal, key, enc, next, endorse } => {
                m.push(("reveal", reveal.clone().into()));
                m.push(("key", key.clone().into()));
                m.push(("enc", enc.clone().into()));
                m.push(("next", (*next).into()));
                opt(&mut m, "endorse", endorse);
            }
            Body::SetHandle { handle } => {
                if let Some(h) = handle {
                    m.push(("handle", h.as_str().into()));
                }
            }
            Body::SetHome { node } => m.push(("node", node.as_str().into())),
            Body::RevokeClient { client } => m.push(("client", (*client).into())),
            Body::NewSecret { check } => m.push(("check", (*check).into())),
            Body::Invalid | Body::Future => {}
        }
        Value::map(m)
    }

    /// Parses a body of a supported version; anything that breaks its type's form is `Invalid`.
    fn parse(v: &Value) -> Body {
        Body::try_parse(v).unwrap_or(Body::Invalid)
    }

    fn try_parse(v: &Value) -> Option<Body> {
        let hash = |k: &str| v.get(k).and_then(Value::as_hash);
        let opt_hash = |k: &str| match v.get(k) {
            None => Some(None),
            Some(x) => x.as_hash().map(Some),
        };
        let key =
            |k: &str| v.get(k).and_then(Value::as_bytes).filter(|b| b.len() == PUBLIC_KEY_LEN).map(<[u8]>::to_vec);
        let enc =
            || v.get("enc").and_then(Value::as_bytes).filter(|b| crypto::is_enc_public_key(b)).map(<[u8]>::to_vec);
        Some(match v.get("type")?.as_text()? {
            "genesis" => Body::Genesis {
                key: key("key")?,
                enc: enc()?,
                next: hash("next")?,
                counter: v.get("counter")?.as_u64()?,
                check: hash("check")?,
            },
            "add-device" => {
                Body::AddDevice { key: key("key")?, enc: enc()?, label: v.get("label")?.as_text()?.to_string() }
            }
            "sign-out" => Body::SignOut { device: hash("device")?, endorse: opt_hash("endorse")? },
            "remove-device" => {
                Body::RemoveDevice { device: hash("device")?, keep: opt_hash("keep")?, endorse: opt_hash("endorse")? }
            }
            "set-master" => Body::SetMaster {
                reveal: key("reveal")?,
                key: key("key")?,
                enc: enc()?,
                next: hash("next")?,
                endorse: opt_hash("endorse")?,
            },
            "set-handle" => Body::SetHandle {
                handle: match v.get("handle") {
                    None => None,
                    Some(h) => Some(h.as_text().filter(|h| crate::handle::is_handle(h))?.to_string()),
                },
            },
            "set-home" => {
                Body::SetHome { node: v.get("node")?.as_text().filter(|u| crate::node::is_node_url(u))?.to_string() }
            }
            "revoke-client" => Body::RevokeClient { client: hash("client")? },
            "new-secret" => Body::NewSecret { check: hash("check")? },
            _ => return None,
        })
    }
}

/// A signed change.
#[derive(Clone, Debug)]
pub struct Change {
    raw: Value,
    hash: Hash,
    id: Hash,
    pub v: u64,
    pub identity: Option<Hash>,
    pub prev: Vec<Hash>,
    pub time: u64,
    pub by: Option<Hash>,
    pub body: Body,
    pub sig: Vec<u8>,
}

impl PartialEq for Change {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

/// A change before it is signed.
#[derive(Clone, Debug)]
pub struct Unsigned {
    pub identity: Option<Hash>,
    pub prev: Vec<Hash>,
    pub time: u64,
    pub by: Option<Hash>,
    pub body: Body,
}

impl Unsigned {
    pub fn to_value(&self) -> Value {
        let mut m: Vec<(&str, Value)> =
            vec![("v", VERSION.into()), ("time", self.time.into()), ("body", self.body.to_value())];
        if let Some(id) = self.identity {
            m.push(("identity", id.into()));
        }
        if self.identity.is_some() || !self.prev.is_empty() {
            m.push(("prev", Value::Array(self.prev.iter().map(|h| (*h).into()).collect())));
        }
        if let Some(by) = self.by {
            m.push(("by", by.into()));
        }
        Value::map(m)
    }

    /// The bytes a signature covers.
    pub fn signing_bytes(&self) -> Vec<u8> {
        self.to_value().to_bytes()
    }

    pub fn sign(self, key: &SigningKey) -> Change {
        let unsigned = self.to_value();
        let sig = key.sign(&unsigned.to_bytes());
        Change::from_value(unsigned.with("sig", sig.into())).expect("a change this software built parses")
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Change {
    pub fn from_bytes(b: &[u8]) -> Result<Change> {
        Change::from_value(Value::from_bytes(b).ok_or(Error::Malformed("change encoding"))?)
    }

    /// Parses a change. Fields every change has must be well formed; a body that breaks its
    /// type's form makes the change `Invalid` rather than unparseable, so that it still takes
    /// its place in the log.
    pub fn from_value(raw: Value) -> Result<Change> {
        let bad = Error::Malformed("change");
        if raw.as_map().is_none() {
            return Err(bad);
        }
        let v = raw.get("v").and_then(Value::as_u64).ok_or(Error::Malformed("change v"))?;
        if v == 0 {
            return Err(bad);
        }
        let time = raw.get("time").and_then(Value::as_u64).ok_or(Error::Malformed("change time"))?;
        let sig = raw.get("sig").and_then(Value::as_bytes).ok_or(Error::Malformed("change sig"))?.to_vec();
        let body_raw = raw.get("body").filter(|b| b.as_map().is_some()).ok_or(Error::Malformed("change body"))?;
        let identity = match raw.get("identity") {
            None => None,
            Some(x) => Some(x.as_hash().ok_or(Error::Malformed("change identity"))?),
        };
        let prev = match raw.get("prev") {
            None => Vec::new(),
            Some(p) => p
                .as_array()
                .ok_or(Error::Malformed("change prev"))?
                .iter()
                .map(|h| h.as_hash().ok_or(Error::Malformed("change prev")))
                .collect::<Result<Vec<_>>>()?,
        };
        let by = match raw.get("by") {
            None => None,
            Some(x) => Some(x.as_hash().ok_or(Error::Malformed("change by"))?),
        };
        let mut body = if v > VERSION { Body::Future } else { Body::parse(body_raw) };
        // Which envelope fields are present depends on the type.
        let fits = match &body {
            Body::Genesis { .. } => identity.is_none() && raw.get("prev").is_none() && by.is_none(),
            Body::SetMaster { .. } => identity.is_some() && by.is_none(),
            Body::Future => identity.is_some(),
            _ => identity.is_some() && by.is_some(),
        };
        if !fits {
            if identity.is_none() {
                return Err(bad);
            }
            body = Body::Invalid;
        }
        let hash = sha256(&raw.to_bytes());
        let id = match body {
            Body::SetMaster { .. } => sha256(&raw.without("sig").to_bytes()),
            _ => hash,
        };
        Ok(Change { raw, hash, id, v, identity, prev, time, by, body, sig })
    }

    pub fn to_value(&self) -> &Value {
        &self.raw
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.raw.to_bytes()
    }

    /// The hash of the whole encoded change.
    pub fn hash(&self) -> Hash {
        self.hash
    }

    /// The device ID this change would bring in (section 5.2).
    pub fn device_id(&self) -> Hash {
        self.id
    }

    /// The bytes the signature covers.
    pub fn signing_bytes(&self) -> Vec<u8> {
        self.raw.without("sig").to_bytes()
    }

    /// The signing public key this change brings in, if it brings in a device.
    pub fn device_key(&self) -> Option<&[u8]> {
        match &self.body {
            Body::Genesis { key, .. } | Body::AddDevice { key, .. } | Body::SetMaster { key, .. } => Some(key),
            _ => None,
        }
    }

    /// The encryption public key this change brings in, if it brings in a device.
    pub fn device_enc(&self) -> Option<&[u8]> {
        match &self.body {
            Body::Genesis { enc, .. } | Body::AddDevice { enc, .. } | Body::SetMaster { enc, .. } => Some(enc),
            _ => None,
        }
    }

    /// The key whose signature this change must carry, when it isn't the key of device `by`.
    pub fn own_signer(&self) -> Option<&[u8]> {
        match &self.body {
            Body::Genesis { key, .. } => Some(key),
            Body::SetMaster { reveal, .. } => Some(reveal),
            _ => None,
        }
    }

    pub fn verify_with(&self, key: &[u8]) -> bool {
        crypto::verify(key, &self.signing_bytes(), &self.sig)
    }

    pub fn key_fingerprint(&self) -> Option<Hash> {
        self.device_key().map(fingerprint)
    }
}
