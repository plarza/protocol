//! Backup files, section 8.1.
use crate::Value;
use crate::crypto::{self, EncKey, Hash, SigningKey};
use crate::error::{Error, Result};

/// Argon2id settings for new backup files.
pub const MEMORY_KIB: u32 = 65536;
pub const ITERATIONS: u32 = 3;
pub const PARALLELISM: u32 = 1;

/// What a backup file holds: a device's private keys, or a master's next key alone.
#[derive(Clone, Debug)]
pub struct Contents {
    pub identity: Hash,
    pub key: SigningKey,
    /// `None` for a next key.
    pub enc: Option<EncKey>,
    pub node: String,
}

impl Contents {
    fn to_value(&self) -> Value {
        let mut m: Vec<(&str, Value)> = vec![
            ("identity", self.identity.into()),
            ("key", self.key.secret().to_vec().into()),
            ("node", self.node.as_str().into()),
        ];
        if let Some(enc) = &self.enc {
            m.push(("enc", enc.secret().to_vec().into()));
        }
        Value::map(m)
    }

    fn from_value(v: &Value) -> Option<Contents> {
        Some(Contents {
            identity: v.get("identity")?.as_hash()?,
            key: SigningKey::from_bytes(v.get("key")?.as_bytes()?)?,
            enc: match v.get("enc") {
                None => None,
                Some(e) => Some(EncKey::from_bytes(e.as_bytes()?)?),
            },
            node: v.get("node")?.as_text()?.to_string(),
        })
    }
}

/// Encrypts `contents` with a password into a backup file.
pub fn write(contents: &Contents, password: &str) -> Result<Vec<u8>> {
    write_with(contents, password, MEMORY_KIB, ITERATIONS, PARALLELISM)
}

pub fn write_with(
    contents: &Contents,
    password: &str,
    memory: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>> {
    if password.is_empty() {
        return Err(Error::Refused("a backup file needs a password".into()));
    }
    let salt = crypto::random::<16>();
    let nonce = crypto::random::<12>();
    let key = crypto::argon2id(password.as_bytes(), &salt, memory, iterations, parallelism)
        .ok_or(Error::Malformed("Argon2id settings"))?;
    let ciphertext = crypto::aes_encrypt(&key, &nonce, &contents.to_value().to_bytes(), b"");
    Ok(Value::map([
        ("format", 1u64.into()),
        (
            "argon2id",
            Value::map([
                ("salt", salt.to_vec().into()),
                ("memory", (memory as u64).into()),
                ("iterations", (iterations as u64).into()),
                ("parallelism", (parallelism as u64).into()),
            ]),
        ),
        ("nonce", nonce.to_vec().into()),
        ("ciphertext", ciphertext.into()),
    ])
    .to_bytes())
}

/// Opens a backup file with its password.
pub fn open(file: &[u8], password: &str) -> Result<Contents> {
    let bad = || Error::Malformed("backup file");
    let v = Value::from_bytes(file).ok_or_else(bad)?;
    if v.get("format").and_then(Value::as_u64) != Some(1) {
        return Err(bad());
    }
    let a = v.get("argon2id").ok_or_else(bad)?;
    let num = |k: &str| a.get(k).and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()).ok_or_else(bad);
    let salt = a.get("salt").and_then(Value::as_bytes).ok_or_else(bad)?;
    let key = crypto::argon2id(password.as_bytes(), salt, num("memory")?, num("iterations")?, num("parallelism")?)
        .ok_or_else(bad)?;
    let nonce = v.get("nonce").and_then(Value::as_bytes).ok_or_else(bad)?;
    let ciphertext = v.get("ciphertext").and_then(Value::as_bytes).ok_or_else(bad)?;
    let plain = crypto::aes_decrypt(&key, nonce, ciphertext, b"").ok_or(Error::BadPassword)?;
    Contents::from_value(&Value::from_bytes(&plain).ok_or_else(bad)?).ok_or_else(bad)
}
