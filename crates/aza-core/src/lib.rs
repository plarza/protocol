//! The verified core of aza identity.
//!
//! Everything here is checked by Verus (`cargo verus verify`): deterministic CBOR and names in
//! paths (section 3), parsing and reading a change log and finding its heads (section 5),
//! accepting certificates and records (sections 7 and 10), Merkle trees for endorsements
//! (section 10), what a node keeps and who may ask it what (section 11), and counting proof of
//! work (section 12). It takes
//! no cryptographic decisions itself: callers pass in hashes, fingerprints and whether each
//! signature is valid, so the logic can be proven on plain data.
// Verus-friendly style: explicit `i = i + 1`, `&Vec` parameters whose views the specs use, and
// `match` where Verus reasons about each arm.
#![allow(
    unused_imports,
    unused_variables,
    clippy::manual_range_contains,
    clippy::while_let_loop,
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::assign_op_pattern,
    clippy::ptr_arg,
    clippy::single_match,
    clippy::collapsible_if,
    clippy::collapsible_match,
    clippy::len_zero,
    clippy::question_mark,
    clippy::match_like_matches_macro,
    clippy::manual_is_multiple_of,
    clippy::manual_div_ceil,
    clippy::manual_map,
    clippy::type_complexity,
    clippy::unnecessary_to_owned,
    clippy::needless_return
)]

pub mod accept;
pub mod access;
pub mod admit;
pub mod bits;
pub mod cbor;
pub mod dag;
pub mod ed25519;
pub mod endorse;
pub mod float;
pub mod heads;
pub mod log;
pub mod merkle;
pub mod names;
pub mod order;
pub mod parse;
pub mod resolve;
pub mod sort;
pub mod spec;
mod value;
