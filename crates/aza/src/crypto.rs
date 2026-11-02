//! Cryptography, section 3.
//!
//! SHA-256, HKDF and Ed25519 are HACL*'s formally verified implementations; ML-DSA-65 and X-Wing
//! (ML-KEM-768 with HACL*'s X25519) are libcrux's (all through `libcrux`). Sealing is HPKE base
//! mode (RFC 9180) built here on those, checked to interoperate with the `hpke` crate. The encoding rules section 3 adds to Ed25519 are checked
//! by the Verus-verified `aza_core::ed25519`.
use aes_gcm::aead::{Aead, KeyInit, Payload};
use libcrux_ml_dsa::ml_dsa_65;
use libcrux_traits::kem::arrayref::Kem;

pub type Hash = [u8; 32];

pub const PUBLIC_KEY_LEN: usize = 32 + 1952;
pub const SIGNATURE_LEN: usize = 64 + 3309;
pub const ENC_PUBLIC_KEY_LEN: usize = 1216;
pub const ENCAPSULATED_LEN: usize = 1120;
const SEAL_INFO: &[u8] = b"aza seal v1";
const XWING_DK_LEN: usize = 2432;

pub fn sha256(data: &[u8]) -> Hash {
    libcrux_sha2::sha256(data)
}

/// The hash of a public key.
pub fn fingerprint(public_key: &[u8]) -> Hash {
    sha256(public_key)
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("the system has no random number generator");
    b
}

/// HKDF-SHA256 with an empty salt and a 32-byte output.
pub fn hkdf(secret: &[u8], info: &[u8]) -> Hash {
    let mut out = [0u8; 32];
    libcrux_hkdf::hkdf(libcrux_hkdf::Algorithm::Sha256, &mut out, &[], secret, info)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

/// HKDF with an `info` made of a label followed by a name, such as an app ID.
pub fn hkdf_named(secret: &[u8], label: &str, name: &str) -> Hash {
    let mut info = label.as_bytes().to_vec();
    info.extend_from_slice(name.as_bytes());
    hkdf(secret, &info)
}

pub fn aes_encrypt(key: &Hash, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = aes_gcm::Aes256Gcm::new(&(*key).into());
    cipher
        .encrypt(&(*nonce).into(), Payload { msg: plaintext, aad })
        .expect("AES-256-GCM encryption can't fail for in-range lengths")
}

pub fn aes_decrypt(key: &Hash, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let nonce: [u8; 12] = nonce.try_into().ok()?;
    let cipher = aes_gcm::Aes256Gcm::new(&(*key).into());
    cipher.decrypt(&nonce.into(), Payload { msg: ciphertext, aad }).ok()
}

/// Argon2id with a 32-byte output.
pub fn argon2id(password: &[u8], salt: &[u8], memory_kib: u32, iterations: u32, parallelism: u32) -> Option<Hash> {
    let params = argon2::Params::new(memory_kib, iterations, parallelism, Some(32)).ok()?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    argon.hash_password_into(password, salt, &mut out).ok()?;
    Some(out)
}

/// A hybrid signing key pair: Ed25519 and ML-DSA-65. The private key is the Ed25519 secret key
/// followed by the ML-DSA-65 key generation seed, 64 bytes.
#[derive(Clone)]
pub struct SigningKey {
    secret: [u8; 64],
    public: Vec<u8>,
}

fn ml_dsa_pair(seed: &[u8; 64]) -> ml_dsa_65::MLDSA65KeyPair {
    ml_dsa_65::generate_key_pair(seed[32..].try_into().unwrap())
}

impl SigningKey {
    pub fn generate() -> SigningKey {
        SigningKey::from_secret(&random::<64>())
    }

    pub fn from_secret(secret: &[u8; 64]) -> SigningKey {
        let mut ed_public = [0u8; 32];
        libcrux_ed25519::secret_to_public(&mut ed_public, secret[..32].try_into().unwrap());
        let mut public = ed_public.to_vec();
        public.extend_from_slice(ml_dsa_pair(secret).verification_key.as_ref());
        SigningKey { secret: *secret, public }
    }

    pub fn from_bytes(b: &[u8]) -> Option<SigningKey> {
        Some(SigningKey::from_secret(b.try_into().ok()?))
    }

    pub fn secret(&self) -> &[u8; 64] {
        &self.secret
    }

    pub fn public(&self) -> &[u8] {
        &self.public
    }

    pub fn fingerprint(&self) -> Hash {
        fingerprint(&self.public)
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut sig = libcrux_ed25519::sign(message, self.secret[..32].try_into().unwrap())
            .expect("Ed25519 signing can't fail")
            .to_vec();
        let ml = ml_dsa_65::sign(&ml_dsa_pair(&self.secret).signing_key, message, b"", random::<32>())
            .expect("an empty context is always allowed");
        sig.extend_from_slice(ml.as_ref());
        sig
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKey({})", hex::encode(&self.fingerprint()[..8]))
    }
}

/// Checks a hybrid signature exactly one way (section 3): both halves must be valid.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != PUBLIC_KEY_LEN || signature.len() != SIGNATURE_LEN {
        return false;
    }
    verify_ed25519(&public_key[..32], message, &signature[..64])
        && verify_ml_dsa(&public_key[32..], message, &signature[64..])
}

/// Ed25519 as in RFC 8032 section 5.1.7 with the cofactorless equation `[S]B = R + [k]A`
/// (HACL*), rejecting `S` >= L, non-canonical encodings of `R` and `A`, and small-order `A`
/// (`aza_core::ed25519`).
fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let a: [u8; 32] = public_key.try_into().unwrap();
    let r: [u8; 32] = signature[..32].try_into().unwrap();
    let s: [u8; 32] = signature[32..].try_into().unwrap();
    let sig: [u8; 64] = signature.try_into().unwrap();
    aza_core::ed25519::strict_encoding_ok(&a, &r, &s) && libcrux_ed25519::verify(message, &a, &sig).is_ok()
}

/// Pure ML-DSA-65 from FIPS 204 with an empty context string.
fn verify_ml_dsa(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(vk), Ok(sig)) = (<[u8; 1952]>::try_from(public_key), <[u8; 3309]>::try_from(signature)) else {
        return false;
    };
    let vk = ml_dsa_65::MLDSA65VerificationKey::new(vk);
    let sig = ml_dsa_65::MLDSA65Signature::new(sig);
    ml_dsa_65::verify(&vk, message, b"", &sig).is_ok()
}

/// An X-Wing encryption key pair. The private key is the 32-byte X-Wing decapsulation key (the
/// seed `expandDecapsulationKey` expands).
#[derive(Clone)]
pub struct EncKey {
    secret: [u8; 32],
    public: Vec<u8>,
}

fn xwing_keys(seed: &[u8; 32]) -> ([u8; ENC_PUBLIC_KEY_LEN], [u8; XWING_DK_LEN]) {
    let mut ek = [0u8; ENC_PUBLIC_KEY_LEN];
    let mut dk = [0u8; XWING_DK_LEN];
    libcrux_kem::XWing::keygen(&mut ek, &mut dk, seed).expect("X-Wing key generation can't fail");
    (ek, dk)
}

impl EncKey {
    pub fn generate() -> EncKey {
        EncKey::from_secret(&random::<32>())
    }

    pub fn from_secret(secret: &[u8; 32]) -> EncKey {
        EncKey { secret: *secret, public: xwing_keys(secret).0.to_vec() }
    }

    pub fn from_bytes(b: &[u8]) -> Option<EncKey> {
        Some(EncKey::from_secret(b.try_into().ok()?))
    }

    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    pub fn public(&self) -> &[u8] {
        &self.public
    }

    /// Opens a sealed box made for this key.
    pub fn open(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < ENCAPSULATED_LEN {
            return None;
        }
        let (_, dk) = xwing_keys(&self.secret);
        let mut ss = [0u8; 32];
        libcrux_kem::XWing::decaps(&mut ss, sealed[..ENCAPSULATED_LEN].try_into().ok()?, &dk).ok()?;
        let (key, nonce) = key_schedule(&ss, SEAL_INFO);
        aes_decrypt(&key, &nonce, &sealed[ENCAPSULATED_LEN..], b"")
    }
}

impl std::fmt::Debug for EncKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EncKey({})", hex::encode(&fingerprint(&self.public)[..8]))
    }
}

// HPKE base mode with X-Wing (0x647a), HKDF-SHA256 (0x0001) and AES-256-GCM (0x0002), RFC 9180.

fn suite_id() -> [u8; 10] {
    let mut s = [0u8; 10];
    s[..4].copy_from_slice(b"HPKE");
    s[4..6].copy_from_slice(&0x647au16.to_be_bytes());
    s[6..8].copy_from_slice(&0x0001u16.to_be_bytes());
    s[8..].copy_from_slice(&0x0002u16.to_be_bytes());
    s
}

fn labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8]) -> Hash {
    let input = [b"HPKE-v1".as_slice(), &suite_id(), label, ikm].concat();
    let mut prk = [0u8; 32];
    libcrux_hkdf::extract(libcrux_hkdf::Algorithm::Sha256, &mut prk, salt, &input).expect("HKDF-SHA256 extract");
    prk
}

fn labeled_expand(prk: &[u8], label: &[u8], info: &[u8], out: &mut [u8]) {
    let full = [(out.len() as u16).to_be_bytes().as_slice(), b"HPKE-v1", &suite_id(), label, info].concat();
    libcrux_hkdf::expand(libcrux_hkdf::Algorithm::Sha256, out, prk, &full).expect("HKDF-SHA256 expand");
}

/// KeySchedule for mode_base with the default PSK: the AEAD key and base nonce.
fn key_schedule(shared_secret: &[u8], info: &[u8]) -> (Hash, [u8; 12]) {
    let psk_id_hash = labeled_extract(b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(b"", b"info_hash", info);
    let context = [[0u8].as_slice(), &psk_id_hash, &info_hash].concat();
    let secret = labeled_extract(shared_secret, b"secret", b"");
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    labeled_expand(&secret, b"key", &context, &mut key);
    labeled_expand(&secret, b"base_nonce", &context, &mut nonce);
    (key, nonce)
}

/// Seals `plaintext` so only the holder of the encryption key `public_key` can read it: HPKE's
/// single-shot `Seal`, the 1120-byte encapsulated key followed by the ciphertext.
pub fn seal(public_key: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    if !is_enc_public_key(public_key) {
        return None;
    }
    let ek: [u8; ENC_PUBLIC_KEY_LEN] = public_key.try_into().ok()?;
    let mut ct = [0u8; ENCAPSULATED_LEN];
    let mut ss = [0u8; 32];
    libcrux_kem::XWing::encaps(&mut ct, &mut ss, &ek, &random::<64>()).ok()?;
    let (key, nonce) = key_schedule(&ss, SEAL_INFO);
    let mut out = ct.to_vec();
    out.extend_from_slice(&aes_encrypt(&key, &nonce, plaintext, b""));
    Some(out)
}

/// Whether `b` is an X-Wing public key: 1216 bytes whose ML-KEM-768 part passes the FIPS 203
/// encapsulation key check.
pub fn is_enc_public_key(b: &[u8]) -> bool {
    if b.len() != ENC_PUBLIC_KEY_LEN {
        return false;
    }
    let Ok(pk) = libcrux_ml_kem::mlkem768::MlKem768PublicKey::try_from(&b[..1184]) else { return false };
    libcrux_ml_kem::mlkem768::validate_public_key(&pk)
}
