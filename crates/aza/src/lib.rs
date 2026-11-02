//! aza identity: one account that signs in everywhere, without an accounts server.
//!
//! This crate holds the protocol objects and the checks every reader makes, and the client
//! library: the aza app ([`aza_app`]), app clients ([`client`]), apps checking certificates
//! ([`app`]), hosted-master providers ([`provider`]) and the HTTP client for nodes ([`node`]).
//! Reading change logs, deterministic CBOR and Merkle trees come from the Verus-verified
//! `aza-core`.
pub use aza_core;
pub use aza_core::cbor::Value;

pub mod backup;
pub mod certificate;
pub mod change;
pub mod crypto;
pub mod data;
pub mod error;
pub mod handle;
pub mod identity;
pub mod message;
pub mod node;
pub mod profile;
pub mod record;
pub mod work;

pub use error::{Error, Result};

pub mod app;
pub mod aza_app;
pub mod client;
pub mod provider;
