//! Accepting a certificate (section 7) and a public record (section 10), from facts the caller
//! gathers: which identity things name, whether signatures are valid, and what the log says
//! about devices and clients.
use vstd::prelude::*;

verus! {

/// What the log says about a certificate.
pub struct CertFacts {
    /// Its `identity` is the identity whose log this is.
    pub identity: bool,
    /// Its `by` names a device of the identity.
    pub signer: bool,
    /// Its signature is valid for that device's key.
    pub signature: bool,
    /// That device is current at the end of the log.
    pub current: bool,
    /// The log has a revocation of its client key's fingerprint.
    pub revoked: bool,
}

/// Why a certificate fails checks 1 to 3, the first that fails.
pub enum CertFailure {
    OtherIdentity,
    UnknownSigner,
    BadSignature,
    NotCurrent,
    Revoked,
}

/// Checks 1 to 3 of section 7: `None` if the certificate works, else the first check it fails.
pub open spec fn spec_check(f: CertFacts) -> Option<CertFailure> {
    if !f.identity {
        Some(CertFailure::OtherIdentity)
    } else if !f.signer {
        Some(CertFailure::UnknownSigner)
    } else if !f.signature {
        Some(CertFailure::BadSignature)
    } else if !f.current {
        Some(CertFailure::NotCurrent)
    } else if f.revoked {
        Some(CertFailure::Revoked)
    } else {
        None
    }
}

pub fn check(f: &CertFacts) -> (r: Option<CertFailure>)
    ensures
        r == spec_check(*f),
{
    if !f.identity {
        Some(CertFailure::OtherIdentity)
    } else if !f.signer {
        Some(CertFailure::UnknownSigner)
    } else if !f.signature {
        Some(CertFailure::BadSignature)
    } else if !f.current {
        Some(CertFailure::NotCurrent)
    } else if f.revoked {
        Some(CertFailure::Revoked)
    } else {
        None
    }
}

/// What the log and the record say about a public record.
pub struct RecordFacts {
    /// Rule 1: the record's `identity` is its certificate's and the log's, the record's signature
    /// is valid for the certificate's client key, and the certificate's is valid for the key of
    /// its signing device, taken from the change that brought the device in even if discarded.
    pub authentic: bool,
    /// Rule 2: the certificate's `app` is the record's, and its scopes include `publish`.
    pub publish: bool,
    /// Rule 2: the log has a revocation of the certificate's client.
    pub revoked: bool,
    /// The certificate passes checks 1 to 3 of section 7.
    pub works: bool,
    /// Rules 3 and 4: an endorsement of the record counts (`endorse::endorsement_counts`).
    pub endorsed: bool,
}

/// Section 10: anyone accepts the record while its certificate works, and afterwards while an
/// endorsement of it counts; never once its client is revoked.
pub open spec fn spec_record_valid(f: RecordFacts) -> bool {
    f.authentic && f.publish && !f.revoked && (f.works || f.endorsed)
}

pub fn record_valid(f: &RecordFacts) -> (r: bool)
    ensures
        r == spec_record_valid(*f),
{
    f.authentic && f.publish && !f.revoked && (f.works || f.endorsed)
}

} // verus!
