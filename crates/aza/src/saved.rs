//! What a client or the aza app keeps between launches. It holds private keys and secrets, so the
//! library only ever hands it out encrypted under a [`StorageKey`] the program keeps apart from it
//! (on a server, in its secret store), or, with the `keychain` feature, as-is for the operating
//! system's keychain, which keeps it where only that app can read it (section 7).
use crate::Value;
use crate::crypto::{Hash, aes_decrypt, aes_encrypt, random};
use crate::error::{Error, Result};

/// A 32-byte AES-256-GCM key that encrypts saved clients and aza apps. Keep it somewhere other
/// than what it encrypts.
#[derive(Clone)]
pub struct StorageKey(Hash);

impl StorageKey {
    pub fn generate() -> StorageKey {
        StorageKey(random())
    }

    pub fn from_bytes(b: &[u8]) -> Option<StorageKey> {
        Some(StorageKey(b.try_into().ok()?))
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for StorageKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StorageKey(…)")
    }
}

/// `{format: 1, nonce, ciphertext}`, with `label` as the associated data so a saved client can't
/// be opened as an aza app or the other way round.
pub(crate) fn seal(key: &StorageKey, label: &str, plaintext: &[u8]) -> Vec<u8> {
    let nonce: [u8; 12] = random();
    let ciphertext = aes_encrypt(&key.0, &nonce, plaintext, label.as_bytes());
    Value::map([("format", 1u64.into()), ("nonce", nonce.to_vec().into()), ("ciphertext", ciphertext.into())])
        .to_bytes()
}

pub(crate) fn open(key: &StorageKey, label: &'static str, sealed: &[u8]) -> Result<Vec<u8>> {
    let v = Value::from_bytes(sealed).ok_or(Error::Malformed(label))?;
    if v.get("format").and_then(Value::as_u64) != Some(1) {
        return Err(Error::Malformed(label));
    }
    let nonce = v.get("nonce").and_then(Value::as_bytes).ok_or(Error::Malformed(label))?;
    let ciphertext = v.get("ciphertext").and_then(Value::as_bytes).ok_or(Error::Malformed(label))?;
    aes_decrypt(&key.0, nonce, ciphertext, label.as_bytes()).ok_or(Error::Malformed(label))
}
