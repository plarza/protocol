//! Who may make each request of the node API, section 11.1, from facts the node gathers about
//! whoever signed the `aza-auth` header.
use vstd::prelude::*;

verus! {

/// The requests that need permission.
pub enum Request {
    GetExport,
    PostImport,
    GetSync,
    PutSync,
    PostEnvelopes,
    GetEnvelopes,
    PutRecord,
    PutEndorsed,
    GetInbox,
    DeleteInbox,
    PutRegistration,
    DeleteRegistration,
    PostKeyPackages,
    DeleteKeyPackages,
    PutProfile,
    PutBlob,
    DeleteBlob,
    PutTag,
}

/// What the node knows about whoever signed the request.
pub enum Who {
    Device {
        /// Current at the end of the newest log the node holds.
        current: bool,
        /// It signed the endorsing change named in a `PUT …/endorsed` body.
        ended: bool,
        /// It is the `{holder}` in the path.
        holder: bool,
    },
    Client {
        /// The log has a revocation of its key.
        revoked: bool,
        /// A certificate the node holds for it passes checks 1 to 3, names the identity in the
        /// path and the request's app, and has the scope the request needs: `read` for
        /// `GET sync`, `write` for `PUT sync`, `publish` for records, `receive` for
        /// registrations, and `read` or `receive` for envelopes.
        scope: bool,
        /// It is registered under the tag in the path (a `receive` client whose certificate passes
        /// checks for the app the tag is bound to).
        registered: bool,
        /// It is the `{holder}` in the path.
        holder: bool,
    },
}

/// Section 11.1's table: a device may make a request only while current (or, to attach its own
/// endorsement, once it ended); a revoked client may make none.
pub open spec fn spec_allowed(r: Request, w: Who) -> bool {
    match w {
        Who::Device { current, ended, holder } => match r {
            Request::PutEndorsed => current || ended,
            Request::GetEnvelopes | Request::GetInbox | Request::DeleteInbox => current && holder,
            Request::PutRecord | Request::PutRegistration | Request::PostKeyPackages => false,
            _ => current,
        },
        Who::Client { revoked, scope, registered, holder } => !revoked && match r {
            Request::GetSync | Request::PutSync | Request::PutRecord | Request::PutRegistration => scope,
            Request::GetEnvelopes => holder && scope,
            Request::GetInbox | Request::DeleteInbox => holder && registered,
            Request::PostKeyPackages => registered,
            _ => false,
        },
    }
}

pub fn allowed(r: &Request, w: &Who) -> (ok: bool)
    ensures
        ok == spec_allowed(*r, *w),
{
    match w {
        Who::Device { current, ended, holder } => match r {
            Request::PutEndorsed => *current || *ended,
            Request::GetEnvelopes | Request::GetInbox | Request::DeleteInbox => *current && *holder,
            Request::PutRecord | Request::PutRegistration | Request::PostKeyPackages => false,
            _ => *current,
        },
        Who::Client { revoked, scope, registered, holder } => !*revoked && match r {
            Request::GetSync | Request::PutSync | Request::PutRecord | Request::PutRegistration => *scope,
            Request::GetEnvelopes => *holder && *scope,
            Request::GetInbox | Request::DeleteInbox => *holder && *registered,
            Request::PostKeyPackages => *registered,
            _ => false,
        },
    }
}

} // verus!
