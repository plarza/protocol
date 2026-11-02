//! The verified core of aza identity.
//!
//! Everything here is checked by Verus (`cargo verus verify`): deterministic CBOR (section 3),
//! reading a change log (section 5.4) and Merkle trees for endorsements (section 10). It takes
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

pub mod bits;
pub mod cbor;
pub mod dag;
pub mod ed25519;
pub mod endorse;
mod float;
pub mod log;
pub mod merkle;
pub mod order;
pub mod resolve;
pub mod spec;
mod value;
