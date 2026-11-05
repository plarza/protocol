//! Parsing a change, sections 5.1, 5.3 and 13: which fields every change has, which each body
//! type has, and when a change is unparseable, `Invalid` (it keeps its place in the log but does
//! nothing) or `Future` (from a higher version).
//!
//! `parse_change` is proven to return exactly `spec_change`. Three checks need code outside the
//! core, and are passed in as `ext_ok`: encryption keys pass FIPS 203's check, a handle is a
//! registrable domain, and a home node is a node URL (section 11).
use crate::cbor::*;
use vstd::prelude::*;

verus! {

/// The length of a hybrid signing public key, section 3.
pub const PUBLIC_KEY_LEN: usize = 1984;

/// The protocol version this software follows, section 13.
pub const VERSION: u64 = 1;

pub ghost enum BodyV {
    Genesis { key: Seq<u8>, enc: Seq<u8>, next: Seq<u8>, counter: u64, check: Seq<u8> },
    AddDevice { key: Seq<u8>, enc: Seq<u8>, label: Seq<u8> },
    SignOut { device: Seq<u8>, endorse: Option<Seq<u8>> },
    RemoveDevice { device: Seq<u8>, keep: Option<Seq<u8>>, endorse: Option<Seq<u8>> },
    SetMaster { reveal: Seq<u8>, key: Seq<u8>, enc: Seq<u8>, next: Seq<u8>, endorse: Option<Seq<u8>> },
    SetHandle { handle: Option<Seq<u8>> },
    SetHome { node: Seq<u8> },
    RevokeClient { client: Seq<u8> },
    NewSecret { check: Seq<u8> },
    Invalid,
    Future,
}

pub ghost struct ChangeV {
    pub v: u64,
    pub identity: Option<Seq<u8>>,
    pub prev: Seq<Seq<u8>>,
    pub prev_given: bool,
    pub time: u64,
    pub by: Option<Seq<u8>>,
    pub body: BodyV,
    pub sig: Seq<u8>,
}

pub type H = [u8; 32];

pub enum Body {
    Genesis { key: Vec<u8>, enc: Vec<u8>, next: H, counter: u64, check: H },
    AddDevice { key: Vec<u8>, enc: Vec<u8>, label: Vec<u8> },
    SignOut { device: H, endorse: Option<H> },
    RemoveDevice { device: H, keep: Option<H>, endorse: Option<H> },
    SetMaster { reveal: Vec<u8>, key: Vec<u8>, enc: Vec<u8>, next: H, endorse: Option<H> },
    SetHandle { handle: Option<Vec<u8>> },
    SetHome { node: Vec<u8> },
    RevokeClient { client: H },
    NewSecret { check: H },
    Invalid,
    Future,
}

pub struct Change {
    pub v: u64,
    pub identity: Option<H>,
    pub prev: Vec<H>,
    /// `prev` is present, even if empty.
    pub prev_given: bool,
    pub time: u64,
    pub by: Option<H>,
    pub body: Body,
    pub sig: Vec<u8>,
}

pub open spec fn oh(o: Option<H>) -> Option<Seq<u8>> {
    match o {
        Some(h) => Some(h@),
        None => None,
    }
}

impl Body {
    pub open spec fn view(&self) -> BodyV {
        match self {
            Body::Genesis { key, enc, next, counter, check } => BodyV::Genesis { key: key@, enc: enc@, next: next@, counter: *counter, check: check@ },
            Body::AddDevice { key, enc, label } => BodyV::AddDevice { key: key@, enc: enc@, label: label@ },
            Body::SignOut { device, endorse } => BodyV::SignOut { device: device@, endorse: oh(*endorse) },
            Body::RemoveDevice { device, keep, endorse } => BodyV::RemoveDevice { device: device@, keep: oh(*keep), endorse: oh(*endorse) },
            Body::SetMaster { reveal, key, enc, next, endorse } => BodyV::SetMaster { reveal: reveal@, key: key@, enc: enc@, next: next@, endorse: oh(*endorse) },
            Body::SetHandle { handle } => BodyV::SetHandle { handle: match handle { Some(h) => Some(h@), None => None } },
            Body::SetHome { node } => BodyV::SetHome { node: node@ },
            Body::RevokeClient { client } => BodyV::RevokeClient { client: client@ },
            Body::NewSecret { check } => BodyV::NewSecret { check: check@ },
            Body::Invalid => BodyV::Invalid,
            Body::Future => BodyV::Future,
        }
    }
}

impl Change {
    pub open spec fn view(&self) -> ChangeV {
        ChangeV {
            v: self.v,
            identity: oh(self.identity),
            prev: self.prev@.map_values(|h: H| h@),
            prev_given: self.prev_given,
            time: self.time,
            by: oh(self.by),
            body: self.body.view(),
            sig: self.sig@,
        }
    }
}

pub open spec fn view_opt(r: Option<Change>) -> Option<ChangeV> {
    match r {
        Some(c) => Some(c.view()),
        None => None,
    }
}

// Field names.

/// `"v"`
pub open spec fn n_v() -> Seq<u8> {
    seq![118u8]
}

fn b_v() -> (r: [u8; 1])
    ensures
        r@ == n_v(),
{
    let r = [118];
    assert(r@ =~= n_v());
    r
}

/// `"identity"`
pub open spec fn n_identity() -> Seq<u8> {
    seq![105u8, 100, 101, 110, 116, 105, 116, 121]
}

fn b_identity() -> (r: [u8; 8])
    ensures
        r@ == n_identity(),
{
    let r = [105, 100, 101, 110, 116, 105, 116, 121];
    assert(r@ =~= n_identity());
    r
}

/// `"prev"`
pub open spec fn n_prev() -> Seq<u8> {
    seq![112u8, 114, 101, 118]
}

fn b_prev() -> (r: [u8; 4])
    ensures
        r@ == n_prev(),
{
    let r = [112, 114, 101, 118];
    assert(r@ =~= n_prev());
    r
}

/// `"time"`
pub open spec fn n_time() -> Seq<u8> {
    seq![116u8, 105, 109, 101]
}

fn b_time() -> (r: [u8; 4])
    ensures
        r@ == n_time(),
{
    let r = [116, 105, 109, 101];
    assert(r@ =~= n_time());
    r
}

/// `"by"`
pub open spec fn n_by() -> Seq<u8> {
    seq![98u8, 121]
}

fn b_by() -> (r: [u8; 2])
    ensures
        r@ == n_by(),
{
    let r = [98, 121];
    assert(r@ =~= n_by());
    r
}

/// `"body"`
pub open spec fn n_body() -> Seq<u8> {
    seq![98u8, 111, 100, 121]
}

fn b_body() -> (r: [u8; 4])
    ensures
        r@ == n_body(),
{
    let r = [98, 111, 100, 121];
    assert(r@ =~= n_body());
    r
}

/// `"sig"`
pub open spec fn n_sig() -> Seq<u8> {
    seq![115u8, 105, 103]
}

fn b_sig() -> (r: [u8; 3])
    ensures
        r@ == n_sig(),
{
    let r = [115, 105, 103];
    assert(r@ =~= n_sig());
    r
}

/// `"type"`
pub open spec fn n_type() -> Seq<u8> {
    seq![116u8, 121, 112, 101]
}

fn b_type() -> (r: [u8; 4])
    ensures
        r@ == n_type(),
{
    let r = [116, 121, 112, 101];
    assert(r@ =~= n_type());
    r
}

/// `"key"`
pub open spec fn n_key() -> Seq<u8> {
    seq![107u8, 101, 121]
}

fn b_key() -> (r: [u8; 3])
    ensures
        r@ == n_key(),
{
    let r = [107, 101, 121];
    assert(r@ =~= n_key());
    r
}

/// `"enc"`
pub open spec fn n_enc() -> Seq<u8> {
    seq![101u8, 110, 99]
}

fn b_enc() -> (r: [u8; 3])
    ensures
        r@ == n_enc(),
{
    let r = [101, 110, 99];
    assert(r@ =~= n_enc());
    r
}

/// `"next"`
pub open spec fn n_next() -> Seq<u8> {
    seq![110u8, 101, 120, 116]
}

fn b_next() -> (r: [u8; 4])
    ensures
        r@ == n_next(),
{
    let r = [110, 101, 120, 116];
    assert(r@ =~= n_next());
    r
}

/// `"counter"`
pub open spec fn n_counter() -> Seq<u8> {
    seq![99u8, 111, 117, 110, 116, 101, 114]
}

fn b_counter() -> (r: [u8; 7])
    ensures
        r@ == n_counter(),
{
    let r = [99, 111, 117, 110, 116, 101, 114];
    assert(r@ =~= n_counter());
    r
}

/// `"check"`
pub open spec fn n_check() -> Seq<u8> {
    seq![99u8, 104, 101, 99, 107]
}

fn b_check() -> (r: [u8; 5])
    ensures
        r@ == n_check(),
{
    let r = [99, 104, 101, 99, 107];
    assert(r@ =~= n_check());
    r
}

/// `"label"`
pub open spec fn n_label() -> Seq<u8> {
    seq![108u8, 97, 98, 101, 108]
}

fn b_label() -> (r: [u8; 5])
    ensures
        r@ == n_label(),
{
    let r = [108, 97, 98, 101, 108];
    assert(r@ =~= n_label());
    r
}

/// `"device"`
pub open spec fn n_device() -> Seq<u8> {
    seq![100u8, 101, 118, 105, 99, 101]
}

fn b_device() -> (r: [u8; 6])
    ensures
        r@ == n_device(),
{
    let r = [100, 101, 118, 105, 99, 101];
    assert(r@ =~= n_device());
    r
}

/// `"endorse"`
pub open spec fn n_endorse() -> Seq<u8> {
    seq![101u8, 110, 100, 111, 114, 115, 101]
}

fn b_endorse() -> (r: [u8; 7])
    ensures
        r@ == n_endorse(),
{
    let r = [101, 110, 100, 111, 114, 115, 101];
    assert(r@ =~= n_endorse());
    r
}

/// `"keep"`
pub open spec fn n_keep() -> Seq<u8> {
    seq![107u8, 101, 101, 112]
}

fn b_keep() -> (r: [u8; 4])
    ensures
        r@ == n_keep(),
{
    let r = [107, 101, 101, 112];
    assert(r@ =~= n_keep());
    r
}

/// `"reveal"`
pub open spec fn n_reveal() -> Seq<u8> {
    seq![114u8, 101, 118, 101, 97, 108]
}

fn b_reveal() -> (r: [u8; 6])
    ensures
        r@ == n_reveal(),
{
    let r = [114, 101, 118, 101, 97, 108];
    assert(r@ =~= n_reveal());
    r
}

/// `"handle"`
pub open spec fn n_handle() -> Seq<u8> {
    seq![104u8, 97, 110, 100, 108, 101]
}

fn b_handle() -> (r: [u8; 6])
    ensures
        r@ == n_handle(),
{
    let r = [104, 97, 110, 100, 108, 101];
    assert(r@ =~= n_handle());
    r
}

/// `"node"`
pub open spec fn n_node() -> Seq<u8> {
    seq![110u8, 111, 100, 101]
}

fn b_node() -> (r: [u8; 4])
    ensures
        r@ == n_node(),
{
    let r = [110, 111, 100, 101];
    assert(r@ =~= n_node());
    r
}

/// `"client"`
pub open spec fn n_client() -> Seq<u8> {
    seq![99u8, 108, 105, 101, 110, 116]
}

fn b_client() -> (r: [u8; 6])
    ensures
        r@ == n_client(),
{
    let r = [99, 108, 105, 101, 110, 116];
    assert(r@ =~= n_client());
    r
}

/// `"genesis"`
pub open spec fn n_genesis() -> Seq<u8> {
    seq![103u8, 101, 110, 101, 115, 105, 115]
}

fn b_genesis() -> (r: [u8; 7])
    ensures
        r@ == n_genesis(),
{
    let r = [103, 101, 110, 101, 115, 105, 115];
    assert(r@ =~= n_genesis());
    r
}

/// `"add-device"`
pub open spec fn n_add_device() -> Seq<u8> {
    seq![97u8, 100, 100, 45, 100, 101, 118, 105, 99, 101]
}

fn b_add_device() -> (r: [u8; 10])
    ensures
        r@ == n_add_device(),
{
    let r = [97, 100, 100, 45, 100, 101, 118, 105, 99, 101];
    assert(r@ =~= n_add_device());
    r
}

/// `"sign-out"`
pub open spec fn n_sign_out() -> Seq<u8> {
    seq![115u8, 105, 103, 110, 45, 111, 117, 116]
}

fn b_sign_out() -> (r: [u8; 8])
    ensures
        r@ == n_sign_out(),
{
    let r = [115, 105, 103, 110, 45, 111, 117, 116];
    assert(r@ =~= n_sign_out());
    r
}

/// `"remove-device"`
pub open spec fn n_remove_device() -> Seq<u8> {
    seq![114u8, 101, 109, 111, 118, 101, 45, 100, 101, 118, 105, 99, 101]
}

fn b_remove_device() -> (r: [u8; 13])
    ensures
        r@ == n_remove_device(),
{
    let r = [114, 101, 109, 111, 118, 101, 45, 100, 101, 118, 105, 99, 101];
    assert(r@ =~= n_remove_device());
    r
}

/// `"set-master"`
pub open spec fn n_set_master() -> Seq<u8> {
    seq![115u8, 101, 116, 45, 109, 97, 115, 116, 101, 114]
}

fn b_set_master() -> (r: [u8; 10])
    ensures
        r@ == n_set_master(),
{
    let r = [115, 101, 116, 45, 109, 97, 115, 116, 101, 114];
    assert(r@ =~= n_set_master());
    r
}

/// `"set-handle"`
pub open spec fn n_set_handle() -> Seq<u8> {
    seq![115u8, 101, 116, 45, 104, 97, 110, 100, 108, 101]
}

fn b_set_handle() -> (r: [u8; 10])
    ensures
        r@ == n_set_handle(),
{
    let r = [115, 101, 116, 45, 104, 97, 110, 100, 108, 101];
    assert(r@ =~= n_set_handle());
    r
}

/// `"set-home"`
pub open spec fn n_set_home() -> Seq<u8> {
    seq![115u8, 101, 116, 45, 104, 111, 109, 101]
}

fn b_set_home() -> (r: [u8; 8])
    ensures
        r@ == n_set_home(),
{
    let r = [115, 101, 116, 45, 104, 111, 109, 101];
    assert(r@ =~= n_set_home());
    r
}

/// `"revoke-client"`
pub open spec fn n_revoke_client() -> Seq<u8> {
    seq![114u8, 101, 118, 111, 107, 101, 45, 99, 108, 105, 101, 110, 116]
}

fn b_revoke_client() -> (r: [u8; 13])
    ensures
        r@ == n_revoke_client(),
{
    let r = [114, 101, 118, 111, 107, 101, 45, 99, 108, 105, 101, 110, 116];
    assert(r@ =~= n_revoke_client());
    r
}

/// `"new-secret"`
pub open spec fn n_new_secret() -> Seq<u8> {
    seq![110u8, 101, 119, 45, 115, 101, 99, 114, 101, 116]
}

fn b_new_secret() -> (r: [u8; 10])
    ensures
        r@ == n_new_secret(),
{
    let r = [110, 101, 119, 45, 115, 101, 99, 114, 101, 116];
    assert(r@ =~= n_new_secret());
    r
}


// Reading fields.

pub open spec fn key_is(k: Value, name: Seq<u8>) -> bool {
    match k {
        Value::Text(t) => t@ == name,
        _ => false,
    }
}

pub open spec fn find(es: Seq<(Value, Value)>, name: Seq<u8>, i: int) -> Option<Value>
    decreases es.len() - i,
{
    if i < 0 || i >= es.len() {
        None
    } else if key_is(es[i].0, name) {
        Some(es[i].1)
    } else {
        find(es, name, i + 1)
    }
}

/// The value of field `name` of map `m`: the first entry with that text key.
pub open spec fn field(m: Value, name: Seq<u8>) -> Option<Value> {
    match m {
        Value::Map(es) => find(es@, name, 0),
        _ => None,
    }
}

pub open spec fn s_hash(o: Option<Value>) -> Option<Seq<u8>> {
    match o {
        Some(Value::Bytes(b)) => if b.len() == 32 { Some(b@) } else { None },
        _ => None,
    }
}

pub open spec fn s_key(o: Option<Value>) -> Option<Seq<u8>> {
    match o {
        Some(Value::Bytes(b)) => if b.len() == PUBLIC_KEY_LEN { Some(b@) } else { None },
        _ => None,
    }
}

pub open spec fn s_bytes(o: Option<Value>) -> Option<Seq<u8>> {
    match o {
        Some(Value::Bytes(b)) => Some(b@),
        _ => None,
    }
}

pub open spec fn s_text(o: Option<Value>) -> Option<Seq<u8>> {
    match o {
        Some(Value::Text(t)) => Some(t@),
        _ => None,
    }
}

pub open spec fn s_u64(o: Option<Value>) -> Option<u64> {
    match o {
        Some(Value::Uint(n)) => Some(n),
        _ => None,
    }
}

/// An optional hash field: absent, or a hash; anything else breaks the form.
pub open spec fn s_opt_hash(o: Option<Value>) -> Option<Option<Seq<u8>>> {
    match o {
        None => Some(None),
        Some(_) => match s_hash(o) {
            Some(h) => Some(Some(h)),
            None => None,
        },
    }
}

/// An optional text field.
pub open spec fn s_opt_text(o: Option<Value>) -> Option<Option<Seq<u8>>> {
    match o {
        None => Some(None),
        Some(_) => match s_text(o) {
            Some(t) => Some(Some(t)),
            None => None,
        },
    }
}

/// `prev`: absent, or an array of hashes.
pub open spec fn s_prev(o: Option<Value>) -> Option<Seq<Seq<u8>>> {
    match o {
        None => Some(Seq::empty()),
        Some(Value::Array(items)) => if forall|i: int| 0 <= i < items.len() ==> #[trigger] s_hash(Some(items@[i])) is Some {
            Some(items@.map_values(|x: Value| s_hash(Some(x))->Some_0))
        } else {
            None
        },
        _ => None,
    }
}

// Section 5.3: each type's fields. A body that breaks its type's form, or has a type this
// version doesn't define, is `Invalid` (section 13).
pub open spec fn spec_body(m: Value) -> BodyV {
    let t = s_text(field(m, n_type()));
    if t == Some(n_genesis()) {
        match (s_key(field(m, n_key())), s_bytes(field(m, n_enc())), s_hash(field(m, n_next())), s_u64(field(m, n_counter())), s_hash(field(m, n_check()))) {
            (Some(key), Some(enc), Some(next), Some(counter), Some(check)) => BodyV::Genesis { key, enc, next, counter, check },
            _ => BodyV::Invalid,
        }
    } else if t == Some(n_add_device()) {
        match (s_key(field(m, n_key())), s_bytes(field(m, n_enc())), s_text(field(m, n_label()))) {
            (Some(key), Some(enc), Some(label)) => BodyV::AddDevice { key, enc, label },
            _ => BodyV::Invalid,
        }
    } else if t == Some(n_sign_out()) {
        match (s_hash(field(m, n_device())), s_opt_hash(field(m, n_endorse()))) {
            (Some(device), Some(endorse)) => BodyV::SignOut { device, endorse },
            _ => BodyV::Invalid,
        }
    } else if t == Some(n_remove_device()) {
        match (s_hash(field(m, n_device())), s_opt_hash(field(m, n_keep())), s_opt_hash(field(m, n_endorse()))) {
            (Some(device), Some(keep), Some(endorse)) => BodyV::RemoveDevice { device, keep, endorse },
            _ => BodyV::Invalid,
        }
    } else if t == Some(n_set_master()) {
        match (s_key(field(m, n_reveal())), s_key(field(m, n_key())), s_bytes(field(m, n_enc())), s_hash(field(m, n_next())), s_opt_hash(field(m, n_endorse()))) {
            (Some(reveal), Some(key), Some(enc), Some(next), Some(endorse)) => BodyV::SetMaster { reveal, key, enc, next, endorse },
            _ => BodyV::Invalid,
        }
    } else if t == Some(n_set_handle()) {
        match s_opt_text(field(m, n_handle())) {
            Some(handle) => BodyV::SetHandle { handle },
            None => BodyV::Invalid,
        }
    } else if t == Some(n_set_home()) {
        match s_text(field(m, n_node())) {
            Some(node) => BodyV::SetHome { node },
            None => BodyV::Invalid,
        }
    } else if t == Some(n_revoke_client()) {
        match s_hash(field(m, n_client())) {
            Some(client) => BodyV::RevokeClient { client },
            None => BodyV::Invalid,
        }
    } else if t == Some(n_new_secret()) {
        match s_hash(field(m, n_check())) {
            Some(check) => BodyV::NewSecret { check },
            None => BodyV::Invalid,
        }
    } else {
        BodyV::Invalid
    }
}

/// The checks outside the core apply to a body of a known type.
pub open spec fn ext_applies(b: BodyV) -> bool {
    !(b is Invalid || b is Future)
}

/// Section 5.1: which envelope fields a change of this type has.
pub open spec fn fits(b: BodyV, identity: bool, prev_given: bool, by: bool) -> bool {
    match b {
        BodyV::Genesis { .. } => !identity && !prev_given && !by,
        BodyV::SetMaster { .. } => identity && !by,
        BodyV::Future => identity,
        _ => identity && by,
    }
}

/// A change parsed from `v`, or `None` if it can't take a place in any log. `ext_ok` says the
/// checks outside the core pass for its body.
pub open spec fn spec_change(v: Value, ext_ok: bool) -> Option<ChangeV> {
    let version = s_u64(field(v, n_v()));
    let time = s_u64(field(v, n_time()));
    let sig = s_bytes(field(v, n_sig()));
    let body = field(v, n_body());
    let identity = s_opt_hash(field(v, n_identity()));
    let prev = s_prev(field(v, n_prev()));
    let by = s_opt_hash(field(v, n_by()));
    if !(v is Map) || version is None || version == Some(0u64) || time is None || sig is None || !(body matches Some(Value::Map(_)))
        || identity is None || prev is None || by is None {
        None
    } else {
        let ver = version->Some_0;
        let b0 = if ver > VERSION { BodyV::Future } else { spec_body(body->Some_0) };
        let b1 = if !ext_ok && ext_applies(b0) { BodyV::Invalid } else { b0 };
        let id = identity->Some_0;
        let prev_given = field(v, n_prev()) is Some;
        let mk = |b: BodyV| ChangeV { v: ver, identity: id, prev: prev->Some_0, prev_given, time: time->Some_0, by: by->Some_0, body: b, sig: sig->Some_0 };
        if fits(b1, id is Some, prev_given, by->Some_0 is Some) {
            Some(mk(b1))
        } else if id is None {
            None
        } else {
            Some(mk(BodyV::Invalid))
        }
    }
}

// Exec.

fn field_x<'a>(m: &'a Value, name: &[u8]) -> (r: Option<&'a Value>)
    ensures
        match r {
            Some(x) => field(*m, name@) == Some(*x),
            None => field(*m, name@) is None,
        },
{
    match m {
        Value::Map(es) => {
            let mut i: usize = 0;
            while i < es.len()
                invariant
                    i <= es.len(),
                    *m == Value::Map(*es),
                    find(es@, name@, 0) == find(es@, name@, i as int),
                decreases es.len() - i,
            {
                let hit = match &es[i].0 {
                    Value::Text(t) => bytes_eq(t.as_slice(), name),
                    _ => false,
                };
                if hit {
                    proof {
                        assert(key_is(es@[i as int].0, name@));
                        assert(find(es@, name@, i as int) == Some(es@[i as int].1));
                    }
                    return Some(&es[i].1);
                }
                i = i + 1;
            }
            None
        },
        _ => None,
    }
}

pub open spec fn deref(o: Option<&Value>) -> Option<Value> {
    match o {
        Some(x) => Some(*x),
        None => None,
    }
}

fn array32(b: &Vec<u8>) -> (r: H)
    requires
        b.len() == 32,
    ensures
        r@ == b@,
{
    let mut r: H = [0u8; 32];
    let mut i: usize = 0;
    while i < 32
        invariant
            i <= 32,
            b.len() == 32,
            r@.len() == 32,
            forall|j: int| 0 <= j < i ==> r@[j] == b@[j],
        decreases 32 - i,
    {
        r[i] = b[i];
        i = i + 1;
    }
    assert(r@ =~= b@);
    r
}

fn hash_x(o: Option<&Value>) -> (r: Option<H>)
    ensures
        oh(r) == s_hash(deref(o)),
{
    match o {
        Some(Value::Bytes(b)) => if b.len() == 32 { Some(array32(b)) } else { None },
        _ => None,
    }
}

fn key_x(o: Option<&Value>) -> (r: Option<Vec<u8>>)
    ensures
        match r { Some(k) => s_key(deref(o)) == Some(k@), None => s_key(deref(o)) is None },
{
    match o {
        Some(Value::Bytes(b)) => if b.len() == PUBLIC_KEY_LEN { Some(b.clone()) } else { None },
        _ => None,
    }
}

fn bytes_x(o: Option<&Value>) -> (r: Option<Vec<u8>>)
    ensures
        match r { Some(k) => s_bytes(deref(o)) == Some(k@), None => s_bytes(deref(o)) is None },
{
    match o {
        Some(Value::Bytes(b)) => Some(b.clone()),
        _ => None,
    }
}

fn text_x(o: Option<&Value>) -> (r: Option<Vec<u8>>)
    ensures
        match r { Some(k) => s_text(deref(o)) == Some(k@), None => s_text(deref(o)) is None },
{
    match o {
        Some(Value::Text(t)) => Some(t.clone()),
        _ => None,
    }
}

fn u64_x(o: Option<&Value>) -> (r: Option<u64>)
    ensures
        r == s_u64(deref(o)),
{
    match o {
        Some(Value::Uint(n)) => Some(*n),
        _ => None,
    }
}

fn opt_hash_x(o: Option<&Value>) -> (r: Option<Option<H>>)
    ensures
        match r { Some(h) => s_opt_hash(deref(o)) == Some(oh(h)), None => s_opt_hash(deref(o)) is None },
{
    match o {
        None => Some(None),
        Some(_) => match hash_x(o) {
            Some(h) => Some(Some(h)),
            None => None,
        },
    }
}

fn opt_text_x(o: Option<&Value>) -> (r: Option<Option<Vec<u8>>>)
    ensures
        match r {
            Some(Some(t)) => s_opt_text(deref(o)) == Some(Some(t@)),
            Some(None) => s_opt_text(deref(o)) == Some(None::<Seq<u8>>),
            None => s_opt_text(deref(o)) is None,
        },
{
    match o {
        None => Some(None),
        Some(_) => match text_x(o) {
            Some(t) => Some(Some(t)),
            None => None,
        },
    }
}

fn prev_x(o: Option<&Value>) -> (r: Option<Vec<H>>)
    ensures
        match r { Some(p) => s_prev(deref(o)) == Some(p@.map_values(|h: H| h@)), None => s_prev(deref(o)) is None },
{
    match o {
        None => {
            let p: Vec<H> = Vec::new();
            assert(p@.map_values(|h: H| h@) =~= Seq::<Seq<u8>>::empty());
            Some(p)
        },
        Some(Value::Array(items)) => {
            let mut p: Vec<H> = Vec::new();
            let mut i: usize = 0;
            while i < items.len()
                invariant
                    i <= items.len(),
                    deref(o) == Some(Value::Array(*items)),
                    p.len() == i,
                    forall|j: int| 0 <= j < i ==> #[trigger] s_hash(Some(items@[j])) == Some(p@[j]@),
                decreases items.len() - i,
            {
                match hash_x(Some(&items[i])) {
                    Some(h) => p.push(h),
                    None => {
                        assert(s_hash(Some(items@[i as int])) is None);
                        assert(!(forall|j: int| 0 <= j < items.len() ==> #[trigger] s_hash(Some(items@[j])) is Some));
                        assert(deref(o) == Some(Value::Array(*items)));
                        return None;
                    },
                }
                i = i + 1;
            }
            assert(p@.map_values(|h: H| h@) =~= items@.map_values(|x: Value| s_hash(Some(x))->Some_0));
            Some(p)
        },
        _ => None,
    }
}

fn is_name(t: &Option<Vec<u8>>, name: &[u8]) -> (r: bool)
    ensures
        r == (match t { Some(x) => x@ == name@, None => false }),
{
    match t {
        Some(x) => bytes_eq(x.as_slice(), name),
        None => false,
    }
}

pub fn parse_body(m: &Value) -> (b: Body)
    ensures
        b.view() == spec_body(*m),
{
    let t = text_x(field_x(m, &b_type()));
    let ghost ts = s_text(field(*m, n_type()));
    assert(match t { Some(x) => ts == Some(x@), None => ts is None });
    if is_name(&t, &b_genesis()) {
        match (key_x(field_x(m, &b_key())), bytes_x(field_x(m, &b_enc())), hash_x(field_x(m, &b_next())), u64_x(field_x(m, &b_counter())), hash_x(field_x(m, &b_check()))) {
            (Some(key), Some(enc), Some(next), Some(counter), Some(check)) => Body::Genesis { key, enc, next, counter, check },
            _ => Body::Invalid,
        }
    } else if is_name(&t, &b_add_device()) {
        match (key_x(field_x(m, &b_key())), bytes_x(field_x(m, &b_enc())), text_x(field_x(m, &b_label()))) {
            (Some(key), Some(enc), Some(label)) => Body::AddDevice { key, enc, label },
            _ => Body::Invalid,
        }
    } else if is_name(&t, &b_sign_out()) {
        match (hash_x(field_x(m, &b_device())), opt_hash_x(field_x(m, &b_endorse()))) {
            (Some(device), Some(endorse)) => Body::SignOut { device, endorse },
            _ => Body::Invalid,
        }
    } else if is_name(&t, &b_remove_device()) {
        match (hash_x(field_x(m, &b_device())), opt_hash_x(field_x(m, &b_keep())), opt_hash_x(field_x(m, &b_endorse()))) {
            (Some(device), Some(keep), Some(endorse)) => Body::RemoveDevice { device, keep, endorse },
            _ => Body::Invalid,
        }
    } else if is_name(&t, &b_set_master()) {
        match (key_x(field_x(m, &b_reveal())), key_x(field_x(m, &b_key())), bytes_x(field_x(m, &b_enc())), hash_x(field_x(m, &b_next())), opt_hash_x(field_x(m, &b_endorse()))) {
            (Some(reveal), Some(key), Some(enc), Some(next), Some(endorse)) => Body::SetMaster { reveal, key, enc, next, endorse },
            _ => Body::Invalid,
        }
    } else if is_name(&t, &b_set_handle()) {
        match opt_text_x(field_x(m, &b_handle())) {
            Some(handle) => Body::SetHandle { handle },
            None => Body::Invalid,
        }
    } else if is_name(&t, &b_set_home()) {
        match text_x(field_x(m, &b_node())) {
            Some(node) => Body::SetHome { node },
            None => Body::Invalid,
        }
    } else if is_name(&t, &b_revoke_client()) {
        match hash_x(field_x(m, &b_client())) {
            Some(client) => Body::RevokeClient { client },
            None => Body::Invalid,
        }
    } else if is_name(&t, &b_new_secret()) {
        match hash_x(field_x(m, &b_check())) {
            Some(check) => Body::NewSecret { check },
            None => Body::Invalid,
        }
    } else {
        Body::Invalid
    }
}

fn fits_x(b: &Body, identity: bool, prev_given: bool, by: bool) -> (r: bool)
    ensures
        r == fits(b.view(), identity, prev_given, by),
{
    match b {
        Body::Genesis { .. } => !identity && !prev_given && !by,
        Body::SetMaster { .. } => identity && !by,
        Body::Future => identity,
        _ => identity && by,
    }
}

/// Parses a change, exactly as `spec_change`. Call it once with `ext_ok` true, run the checks
/// outside the core on the body, and again with `false` if they fail.
pub fn parse_change(v: &Value, ext_ok: bool) -> (r: Option<Change>)
    ensures
        view_opt(r) == spec_change(*v, ext_ok),
{
    if !matches!(v, Value::Map(_)) {
        return None;
    }
    let version = u64_x(field_x(v, &b_v()));
    let time = u64_x(field_x(v, &b_time()));
    let sig = bytes_x(field_x(v, &b_sig()));
    let body = field_x(v, &b_body());
    let identity = opt_hash_x(field_x(v, &b_identity()));
    let prev_field = field_x(v, &b_prev());
    let prev = prev_x(prev_field);
    let by = opt_hash_x(field_x(v, &b_by()));
    let (ver, time, sig, body, identity, prev, by) = match (version, time, sig, body, identity, prev, by) {
        (Some(ver), Some(time), Some(sig), Some(body), Some(identity), Some(prev), Some(by)) => (ver, time, sig, body, identity, prev, by),
        _ => return None,
    };
    if ver == 0 || !matches!(body, Value::Map(_)) {
        return None;
    }
    let b0 = if ver > VERSION { Body::Future } else { parse_body(body) };
    let applies = !matches!(b0, Body::Invalid | Body::Future);
    let b1 = if !ext_ok && applies { Body::Invalid } else { b0 };
    let prev_given = prev_field.is_some();
    let body = if fits_x(&b1, identity.is_some(), prev_given, by.is_some()) {
        b1
    } else if identity.is_none() {
        return None;
    } else {
        Body::Invalid
    };
    Some(Change { v: ver, identity, prev, prev_given, time, by, body, sig })
}

} // verus!
