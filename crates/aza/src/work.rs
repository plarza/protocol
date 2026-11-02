//! Proof of work, section 12.
use crate::crypto::{Hash, argon2id};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// The minimum work in version 1.
pub const MIN_WORK: u32 = 6;

/// The work of a genesis change, given its encoding without `sig`: how many zero bits the
/// Argon2id output starts with.
pub fn work(genesis_without_sig: &[u8]) -> u32 {
    let out = argon2id(genesis_without_sig, b"aza work v1", 65536, 1, 1).expect("fixed Argon2id parameters are valid");
    let mut bits = 0;
    for b in out {
        if b == 0 {
            bits += 8;
        } else {
            bits += b.leading_zeros();
            break;
        }
    }
    bits
}

/// The work of an identity's genesis change, computed once per process.
pub fn cached_work(identity: &Hash, genesis_without_sig: &[u8]) -> u32 {
    static CACHE: OnceLock<Mutex<HashMap<Hash, u32>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(w) = cache.lock().unwrap().get(identity) {
        return *w;
    }
    let w = work(genesis_without_sig);
    cache.lock().unwrap().insert(*identity, w);
    w
}
