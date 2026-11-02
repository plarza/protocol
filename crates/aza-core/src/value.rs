//! Conveniences for building and reading CBOR values. Not part of the verified core: everything
//! that decides whether bytes are acceptable goes through `cbor::decode`.
use crate::cbor::{self, Value};

impl Clone for Value {
    fn clone(&self) -> Self {
        match self {
            Value::Uint(n) => Value::Uint(*n),
            Value::Nint(n) => Value::Nint(*n),
            Value::Bytes(b) => Value::Bytes(b.clone()),
            Value::Text(t) => Value::Text(t.clone()),
            Value::Array(a) => Value::Array(a.clone()),
            Value::Map(m) => Value::Map(m.clone()),
            Value::Tag(t, b) => Value::Tag(*t, b.clone()),
            Value::Simple(s) => Value::Simple(*s),
            Value::Float16(x) => Value::Float16(*x),
            Value::Float32(x) => Value::Float32(*x),
            Value::Float64(x) => Value::Float64(*x),
        }
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Uint(a), Value::Uint(b)) | (Value::Nint(a), Value::Nint(b)) => a == b,
            (Value::Bytes(a), Value::Bytes(b)) | (Value::Text(a), Value::Text(b)) => a == b,
            (Value::Array(a), Value::Array(b)) => a == b,
            (Value::Map(a), Value::Map(b)) => a == b,
            (Value::Tag(t, a), Value::Tag(u, b)) => t == u && a == b,
            (Value::Simple(a), Value::Simple(b)) => a == b,
            (Value::Float16(a), Value::Float16(b)) => a == b,
            (Value::Float32(a), Value::Float32(b)) => a == b,
            (Value::Float64(a), Value::Float64(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for Value {}

impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Uint(n) => write!(f, "{n}"),
            Value::Nint(n) => write!(f, "-{}", *n as u128 + 1),
            Value::Bytes(b) if b.len() > 8 => write!(f, "h'{}…'", hex(&b[..8])),
            Value::Bytes(b) => write!(f, "h'{}'", hex(b)),
            Value::Text(t) => write!(f, "{:?}", String::from_utf8_lossy(t)),
            Value::Array(a) => f.debug_list().entries(a).finish(),
            Value::Map(m) => f.debug_map().entries(m.iter().map(|(k, v)| (k, v))).finish(),
            Value::Tag(t, b) => write!(f, "{t}({b:?})"),
            Value::Simple(20) => write!(f, "false"),
            Value::Simple(21) => write!(f, "true"),
            Value::Simple(22) => write!(f, "null"),
            Value::Simple(s) => write!(f, "simple({s})"),
            Value::Float16(x) => write!(f, "f16({x:#x})"),
            Value::Float32(x) => write!(f, "{}", f32::from_bits(*x)),
            Value::Float64(x) => write!(f, "{}", f64::from_bits(*x)),
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Text(s.as_bytes().to_vec())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Text(s.into_bytes())
    }
}

impl From<u64> for Value {
    fn from(n: u64) -> Self {
        Value::Uint(n)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Simple(if b { 21 } else { 20 })
    }
}

impl From<Vec<u8>> for Value {
    fn from(b: Vec<u8>) -> Self {
        Value::Bytes(b)
    }
}

impl From<&[u8]> for Value {
    fn from(b: &[u8]) -> Self {
        Value::Bytes(b.to_vec())
    }
}

impl From<[u8; 32]> for Value {
    fn from(b: [u8; 32]) -> Self {
        Value::Bytes(b.to_vec())
    }
}

impl From<Vec<Value>> for Value {
    fn from(a: Vec<Value>) -> Self {
        Value::Array(a)
    }
}

impl Value {
    /// A map with text keys, its entries put in deterministic order.
    pub fn map<K: AsRef<str>>(entries: impl IntoIterator<Item = (K, Value)>) -> Value {
        Value::Map(entries.into_iter().map(|(k, v)| (Value::from(k.as_ref()), v)).collect()).sorted()
    }

    /// Puts every map's entries in deterministic order, recursively.
    pub fn sorted(self) -> Value {
        match self {
            Value::Map(entries) => {
                let mut keyed: Vec<(Vec<u8>, Value, Value)> = entries
                    .into_iter()
                    .map(|(k, v)| {
                        let k = k.sorted();
                        (cbor::encode(&k), k, v.sorted())
                    })
                    .collect();
                keyed.sort_by(|a, b| a.0.cmp(&b.0));
                keyed.dedup_by(|a, b| a.0 == b.0);
                Value::Map(keyed.into_iter().map(|(_, k, v)| (k, v)).collect())
            }
            Value::Array(items) => Value::Array(items.into_iter().map(Value::sorted).collect()),
            Value::Tag(t, b) => Value::Tag(t, Box::new(b.sorted())),
            v => v,
        }
    }

    pub fn null() -> Value {
        Value::Simple(22)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        cbor::encode(self)
    }

    /// Decodes deterministic CBOR, rejecting any other form.
    pub fn from_bytes(b: &[u8]) -> Option<Value> {
        cbor::decode(b)
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries.iter().find_map(|(k, v)| match k {
                Value::Text(t) if t == key.as_bytes() => Some(v),
                _ => None,
            }),
            _ => None,
        }
    }

    /// This map without `key`.
    pub fn without(&self, key: &str) -> Value {
        self.without_all(&[key])
    }

    pub fn without_all(&self, keys: &[&str]) -> Value {
        match self {
            Value::Map(entries) => Value::Map(
                entries
                    .iter()
                    .filter(|(k, _)| !matches!(k, Value::Text(t) if keys.iter().any(|key| t == key.as_bytes())))
                    .cloned()
                    .collect(),
            ),
            v => v.clone(),
        }
    }

    /// This map with `key` set to `value`.
    pub fn with(&self, key: &str, value: Value) -> Value {
        let mut entries = match self.without(key) {
            Value::Map(entries) => entries,
            _ => Vec::new(),
        };
        entries.push((Value::from(key), value));
        Value::Map(entries).sorted_top()
    }

    fn sorted_top(self) -> Value {
        match self {
            Value::Map(entries) => {
                let mut keyed: Vec<(Vec<u8>, Value, Value)> =
                    entries.into_iter().map(|(k, v)| (cbor::encode(&k), k, v)).collect();
                keyed.sort_by(|a, b| a.0.cmp(&b.0));
                Value::Map(keyed.into_iter().map(|(_, k, v)| (k, v)).collect())
            }
            v => v,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_hash(&self) -> Option<[u8; 32]> {
        self.as_bytes().and_then(|b| b.try_into().ok())
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => std::str::from_utf8(t).ok(),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Uint(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Simple(20) => Some(false),
            Value::Simple(21) => Some(true),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Simple(22))
    }
}
