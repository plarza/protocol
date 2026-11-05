//! Changes, sections 5.1 to 5.3.
use crate::Value;
use crate::crypto::{self, Hash, SigningKey, sha256};
use crate::error::{Error, Result};

use aza_core::parse;

/// The protocol version this software follows (section 13).
pub const VERSION: u64 = parse::VERSION;

const _: () = assert!(crate::crypto::PUBLIC_KEY_LEN == parse::PUBLIC_KEY_LEN);

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
    /// A body the verified parser read, once the checks outside the core pass: encryption keys
    /// pass FIPS 203's check, a handle is a registrable domain, and a home node is a node URL.
    /// `None` if one fails.
    fn from_parsed(b: &parse::Body) -> Option<Body> {
        let enc = |e: &[u8]| crypto::is_enc_public_key(e).then(|| e.to_vec());
        let text = |t: &[u8]| String::from_utf8(t.to_vec()).ok();
        Some(match b {
            parse::Body::Genesis { key, enc: e, next, counter, check } => {
                Body::Genesis { key: key.clone(), enc: enc(e)?, next: *next, counter: *counter, check: *check }
            }
            parse::Body::AddDevice { key, enc: e, label } => {
                Body::AddDevice { key: key.clone(), enc: enc(e)?, label: text(label)? }
            }
            parse::Body::SignOut { device, endorse } => Body::SignOut { device: *device, endorse: *endorse },
            parse::Body::RemoveDevice { device, keep, endorse } => {
                Body::RemoveDevice { device: *device, keep: *keep, endorse: *endorse }
            }
            parse::Body::SetMaster { reveal, key, enc: e, next, endorse } => Body::SetMaster {
                reveal: reveal.clone(),
                key: key.clone(),
                enc: enc(e)?,
                next: *next,
                endorse: *endorse,
            },
            parse::Body::SetHandle { handle } => Body::SetHandle {
                handle: match handle {
                    None => None,
                    Some(h) => Some(text(h).filter(|h| crate::handle::is_handle(h))?),
                },
            },
            parse::Body::SetHome { node } => {
                Body::SetHome { node: text(node).filter(|n| crate::node::is_node_url(n))? }
            }
            parse::Body::RevokeClient { client } => Body::RevokeClient { client: *client },
            parse::Body::NewSecret { check } => Body::NewSecret { check: *check },
            parse::Body::Invalid => Body::Invalid,
            parse::Body::Future => Body::Future,
        })
    }

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
}

/// A signed change.
#[derive(Clone, Debug)]
pub struct Change {
    raw: Value,
    hash: Hash,
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

/// How far a signer's clock may be from a checker's, in seconds (section 3).
pub const CLOCK_SKEW: u64 = 300;

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Change {
    pub fn from_bytes(b: &[u8]) -> Result<Change> {
        Change::from_value(Value::from_bytes(b).ok_or(Error::Malformed("change encoding"))?)
    }

    /// Parses a change exactly as the verified `aza_core::parse` says (sections 5.1, 5.3 and 13):
    /// fields every change has must be well formed; a body that breaks its type's form makes the
    /// change `Invalid` rather than unparseable, so that it still takes its place in the log. The
    /// checks the core leaves out run here: encryption keys, handles and node URLs.
    pub fn from_value(raw: Value) -> Result<Change> {
        let bad = || Error::Malformed("change");
        let mut parsed = parse::parse_change(&raw, true).ok_or_else(bad)?;
        let body = match Body::from_parsed(&parsed.body) {
            Some(body) => body,
            None => {
                parsed = parse::parse_change(&raw, false).ok_or_else(bad)?;
                Body::from_parsed(&parsed.body).expect("an invalid body needs no checks")
            }
        };
        let hash = sha256(&raw.without("sig").to_bytes());
        let parse::Change { v, identity, prev, time, by, sig, .. } = parsed;
        Ok(Change { raw, hash, v, identity, prev, time, by, body, sig })
    }

    pub fn to_value(&self) -> &Value {
        &self.raw
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.raw.to_bytes()
    }

    /// The change's name: the hash of its encoding without `sig`, so copies that differ only in
    /// their signature are the same change (section 5.1). It is also the device ID of the device
    /// the change brings in, if it brings one in (section 5.2).
    pub fn hash(&self) -> Hash {
        self.hash
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
}
