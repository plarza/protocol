//! Profile records, section 6.
use crate::Value;
use crate::crypto::{self, Hash, SigningKey};
use crate::error::{Error, Result};
use crate::identity::Identity;

/// The largest profile record.
pub const MAX_PROFILE: usize = 16 * 1024;
/// The largest profile picture.
pub const MAX_PICTURE: usize = 256 * 1024;
pub const PICTURE_TYPES: [&str; 4] = ["image/png", "image/jpeg", "image/webp", "image/avif"];

#[derive(Clone, Debug, PartialEq)]
pub struct Picture {
    pub hash: Hash,
    pub r#type: String,
    pub size: u64,
}

impl Picture {
    pub fn to_value(&self) -> Value {
        Value::map([("hash", self.hash.into()), ("type", self.r#type.as_str().into()), ("size", self.size.into())])
    }

    pub fn from_value(v: &Value) -> Option<Picture> {
        let p = Picture {
            hash: v.get("hash")?.as_hash()?,
            r#type: v.get("type")?.as_text()?.to_string(),
            size: v.get("size")?.as_u64()?,
        };
        (PICTURE_TYPES.contains(&p.r#type.as_str()) && p.size as usize <= MAX_PICTURE).then_some(p)
    }

    /// The image matches this picture's hash, size and type.
    pub fn matches(&self, image: &[u8], r#type: &str) -> bool {
        crypto::sha256(image) == self.hash && image.len() as u64 == self.size && r#type == self.r#type
    }
}

#[derive(Clone, Debug)]
pub struct Profile {
    raw: Value,
    pub identity: Hash,
    pub version: u64,
    pub fields: Value,
    pub by: Hash,
    pub sig: Vec<u8>,
}

impl Profile {
    pub fn sign(identity: Hash, version: u64, fields: Value, by: Hash, key: &SigningKey) -> Result<Profile> {
        let unsigned = Value::map([
            ("identity", identity.into()),
            ("version", version.into()),
            ("fields", fields.sorted()),
            ("by", by.into()),
        ]);
        let sig = key.sign(&unsigned.to_bytes());
        Profile::from_value(unsigned.with("sig", sig.into()))
    }

    pub fn from_value(raw: Value) -> Result<Profile> {
        let bad = || Error::Malformed("profile record");
        if raw.to_bytes().len() > MAX_PROFILE {
            return Err(Error::Refused("profile record is over 16 KiB".into()));
        }
        Ok(Profile {
            identity: raw.get("identity").and_then(Value::as_hash).ok_or_else(bad)?,
            version: raw.get("version").and_then(Value::as_u64).ok_or_else(bad)?,
            fields: raw.get("fields").filter(|f| f.as_map().is_some()).ok_or_else(bad)?.clone(),
            by: raw.get("by").and_then(Value::as_hash).ok_or_else(bad)?,
            sig: raw.get("sig").and_then(Value::as_bytes).ok_or_else(bad)?.to_vec(),
            raw,
        })
    }

    pub fn to_value(&self) -> &Value {
        &self.raw
    }

    pub fn signature_valid(&self, identity: &Identity) -> bool {
        self.identity == identity.id
            && identity
                .device_key_any(&self.by)
                .is_some_and(|k| crypto::verify(k, &self.raw.without("sig").to_bytes(), &self.sig))
    }

    /// The display name: text up to 64 characters.
    pub fn name(&self) -> Option<&str> {
        self.fields.get("name").and_then(Value::as_text).filter(|n| n.chars().count() <= 64)
    }

    pub fn picture(&self) -> Option<Picture> {
        self.fields.get("picture").and_then(Picture::from_value)
    }

    /// The published contact secret, if any.
    pub fn contact(&self) -> Option<Hash> {
        self.fields.get("contact").and_then(Value::as_hash)
    }

    pub fn field(&self, name: &str) -> Option<&Value> {
        self.fields.get(name)
    }
}

/// The profile record a reader uses: the highest version among those signed by a device current
/// at the end of the log.
pub fn choose<'a>(records: &'a [Profile], identity: &Identity) -> Option<&'a Profile> {
    records.iter().filter(|p| p.signature_valid(identity) && identity.is_current(&p.by)).max_by_key(|p| p.version)
}
