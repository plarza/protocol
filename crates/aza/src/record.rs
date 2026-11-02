//! Public records and endorsements, section 10.
use crate::Value;
use crate::certificate::{Certificate, PUBLISH};
use crate::crypto::{self, Hash, SigningKey, sha256};
use crate::error::{Error, Result};
use crate::identity::Identity;
use aza_core::merkle;

/// An inclusion proof that a record is endorsed by one endorsing change.
#[derive(Clone, Debug, PartialEq)]
pub struct InclusionProof {
    pub change: Hash,
    pub index: u64,
    pub size: u64,
    pub path: Vec<Hash>,
}

impl InclusionProof {
    pub fn to_value(&self) -> Value {
        Value::map([
            ("change", self.change.into()),
            ("index", self.index.into()),
            ("size", self.size.into()),
            ("path", Value::Array(self.path.iter().map(|h| (*h).into()).collect())),
        ])
    }

    pub fn from_value(v: &Value) -> Result<InclusionProof> {
        let bad = || Error::Malformed("inclusion proof");
        Ok(InclusionProof {
            change: v.get("change").and_then(Value::as_hash).ok_or_else(bad)?,
            index: v.get("index").and_then(Value::as_u64).ok_or_else(bad)?,
            size: v.get("size").and_then(Value::as_u64).ok_or_else(bad)?,
            path: v
                .get("path")
                .and_then(Value::as_array)
                .ok_or_else(bad)?
                .iter()
                .map(|h| h.as_hash().ok_or_else(bad))
                .collect::<Result<_>>()?,
        })
    }

    /// The proof rebuilds `root` from the record hash `leaf` (RFC 9162 section 2.1.3.2).
    pub fn verifies(&self, leaf: &Hash, root: &Hash) -> bool {
        let path: Vec<Vec<u8>> = self.path.iter().map(|h| h.to_vec()).collect();
        merkle::verify(leaf, self.index, self.size, &path, root)
    }
}

/// An endorsement tree over the hashes of the records a person still trusts.
pub struct Endorsement {
    leaves: Vec<Hash>,
}

impl Endorsement {
    /// Leaves are sorted, with duplicates removed.
    pub fn new(mut leaves: Vec<Hash>) -> Endorsement {
        leaves.sort();
        leaves.dedup();
        Endorsement { leaves }
    }

    fn data(&self) -> Vec<Vec<u8>> {
        self.leaves.iter().map(|h| h.to_vec()).collect()
    }

    pub fn root(&self) -> Hash {
        merkle::root(&self.data()).try_into().expect("SHA-256 is 32 bytes")
    }

    pub fn leaves(&self) -> &[Hash] {
        &self.leaves
    }

    /// The inclusion proof for a record hash, once the endorsing change is known.
    pub fn proof(&self, leaf: &Hash, change: Hash) -> Option<InclusionProof> {
        let index = self.leaves.binary_search(leaf).ok()?;
        let path = merkle::path(index, &self.data()).into_iter().map(|p| p.try_into().unwrap()).collect();
        Some(InclusionProof { change, index: index as u64, size: self.leaves.len() as u64, path })
    }
}

/// A public record: app data anyone can read, signed by a client key.
#[derive(Clone, Debug)]
pub struct Record {
    raw: Value,
    pub identity: Hash,
    pub app: String,
    pub name: String,
    pub version: u64,
    /// `None` for a tombstone.
    pub content: Option<Value>,
    pub certificate: Certificate,
    pub sig: Vec<u8>,
    pub endorsed: Vec<InclusionProof>,
}

impl Record {
    /// Signs a record (or a tombstone, with no content) with a client key.
    pub fn sign(
        cert: &Certificate,
        name: &str,
        version: u64,
        content: Option<Value>,
        key: &SigningKey,
    ) -> Result<Record> {
        let mut m: Vec<(&str, Value)> = vec![
            ("identity", cert.identity.into()),
            ("app", cert.app.as_str().into()),
            ("name", name.into()),
            ("version", version.into()),
            ("certificate", cert.to_value().clone()),
        ];
        if let Some(c) = content {
            m.push(("content", c));
        }
        let unsigned = Value::map(m);
        let sig = key.sign(&unsigned.to_bytes());
        Record::from_value(unsigned.with("sig", sig.into()))
    }

    pub fn from_value(raw: Value) -> Result<Record> {
        let bad = || Error::Malformed("public record");
        let endorsed = match raw.get("endorsed") {
            None => Vec::new(),
            Some(e) => e.as_array().ok_or_else(bad)?.iter().map(InclusionProof::from_value).collect::<Result<_>>()?,
        };
        Ok(Record {
            identity: raw.get("identity").and_then(Value::as_hash).ok_or_else(bad)?,
            app: raw.get("app").and_then(Value::as_text).ok_or_else(bad)?.into(),
            name: raw.get("name").and_then(Value::as_text).ok_or_else(bad)?.into(),
            version: raw.get("version").and_then(Value::as_u64).filter(|&v| v >= 1).ok_or_else(bad)?,
            content: raw.get("content").cloned(),
            certificate: Certificate::from_value(raw.get("certificate").ok_or_else(bad)?.clone())?,
            sig: raw.get("sig").and_then(Value::as_bytes).ok_or_else(bad)?.to_vec(),
            endorsed,
            raw,
        })
    }

    pub fn to_value(&self) -> &Value {
        &self.raw
    }

    /// The record's hash without its `endorsed` field: its leaf in an endorsement tree.
    pub fn leaf(&self) -> Hash {
        sha256(&self.raw.without("endorsed").to_bytes())
    }

    /// This record with an inclusion proof added, replacing any for the same endorsing change.
    pub fn with_proof(&self, proof: InclusionProof) -> Record {
        let mut proofs: Vec<InclusionProof> =
            self.endorsed.iter().filter(|p| p.change != proof.change).cloned().collect();
        proofs.push(proof);
        proofs.sort_by_key(|a| a.change);
        let raw = self.raw.with("endorsed", Value::Array(proofs.iter().map(InclusionProof::to_value).collect()));
        Record::from_value(raw).expect("adding a proof keeps a record well formed")
    }

    fn signature_valid(&self) -> bool {
        crypto::verify(&self.certificate.client, &self.raw.without_all(&["sig", "endorsed"]).to_bytes(), &self.sig)
    }

    /// Whether anyone accepts this record, checked against the identity's change log: normally
    /// while its certificate is valid, and afterwards through an endorsement.
    pub fn is_valid(&self, identity: &Identity) -> bool {
        let cert = &self.certificate;
        if self.identity != cert.identity || self.identity != identity.id || !self.signature_valid() {
            return false;
        }
        if cert.app != self.app || !cert.has(PUBLISH) || identity.is_revoked(&cert.client_fp()) {
            return false;
        }
        if cert.check(identity).is_ok() {
            return true;
        }
        self.endorsement_counts(identity)
    }

    fn endorsement_counts(&self, identity: &Identity) -> bool {
        if !self.certificate.signed_by_device_key(identity) {
            return false;
        }
        let leaf = self.leaf();
        identity.endorsement_holds(&self.certificate.by, |change, root| {
            self.endorsed.iter().any(|p| p.change == *change && p.verifies(&leaf, root))
        })
    }
}

/// From every version of every record, the one readers take for each name: the highest valid
/// version. Tombstones are returned too, so callers can tell a deleted name from a missing one.
pub fn current_versions<'a>(records: &'a [Record], identity: &Identity) -> Vec<&'a Record> {
    let mut best: std::collections::BTreeMap<&str, &Record> = std::collections::BTreeMap::new();
    for r in records {
        if !r.is_valid(identity) {
            continue;
        }
        match best.get(r.name.as_str()) {
            Some(b) if b.version >= r.version => {}
            _ => {
                best.insert(&r.name, r);
            }
        }
    }
    best.into_values().collect()
}
