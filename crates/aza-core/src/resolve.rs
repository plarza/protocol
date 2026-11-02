//! From parsed changes, named by hashes, to the indices `log::read` works on (section 5.1: "a
//! change only counts as an ancestor if it is actually in the log"), and which key must have
//! signed each change.
//!
//! The caller passes the changes' indices sorted by hash and by device ID; `resolve` checks both
//! orders, then finds every hash by binary search. Everything here is proven against the specs
//! below.
use crate::cbor::*;
use crate::log::*;
use crate::order::*;
use vstd::prelude::*;

verus! {

/// A change as parsed: every reference is a hash. Keys are fingerprints.
pub enum RawBody {
    Genesis { key: Hash, next: Hash, work_ok: bool },
    AddDevice { key: Hash },
    SignOut { device: Hash },
    RemoveDevice { device: Hash, keep: Option<Hash> },
    SetMaster { reveal: Hash, key: Hash, next: Hash },
    SetHandle,
    SetHome,
    RevokeClient,
    NewSecret,
    Future,
    Invalid,
}

pub struct Raw {
    pub hash: Hash,
    /// The device ID this change brings in: its hash without `sig` for `set-master`, else `hash`.
    pub id: Hash,
    pub prev: Vec<Hash>,
    pub by: Option<Hash>,
    pub body: RawBody,
}

/// Whose key must have signed a change.
pub enum Signer {
    /// Its own: `body.key` of a `genesis` change, `body.reveal` of a `set-master` change.
    Own,
    /// The key of the device brought in by this change.
    Device(usize),
    /// No change in the log brings in the device `by` names.
    Nobody,
}

pub open spec fn brings_device(b: RawBody) -> bool {
    b is Genesis || b is AddDevice || b is SetMaster
}

/// The index of the change with this hash (hashes are distinct).
pub open spec fn hash_index(raws: Seq<Raw>, h: Seq<u8>) -> Option<int> {
    if exists|j: int| 0 <= j < raws.len() && #[trigger] raws[j].hash@ == h {
        Some(choose|j: int| 0 <= j < raws.len() && #[trigger] raws[j].hash@ == h)
    } else {
        None
    }
}

/// The lowest-numbered change that brings in the device with this ID.
pub open spec fn device_index(raws: Seq<Raw>, id: Seq<u8>) -> Option<int> {
    if exists|j: int| 0 <= j < raws.len() && brings_device(raws[j].body) && #[trigger] raws[j].id@ == id {
        Some(choose|j: int| 0 <= j < raws.len() && brings_device(raws[j].body) && #[trigger] raws[j].id@ == id
            && forall|k: int| 0 <= k < j ==> !(brings_device(raws[k].body) && #[trigger] raws[k].id@ == id))
    } else {
        None
    }
}

pub open spec fn as_usize(o: Option<int>) -> Option<usize> {
    match o {
        Some(j) => Some(j as usize),
        None => None,
    }
}

/// The `prev` hashes that name changes in the log, as indices, in order.
pub open spec fn prev_map(raws: Seq<Raw>, hs: Seq<Hash>) -> Seq<usize>
    decreases hs.len(),
{
    if hs.len() == 0 {
        Seq::empty()
    } else {
        let rest = prev_map(raws, hs.drop_last());
        match hash_index(raws, hs.last()@) {
            Some(j) => rest.push(j as usize),
            None => rest,
        }
    }
}

pub open spec fn by_spec(raws: Seq<Raw>, i: int) -> By {
    if raws[i].body is Genesis || raws[i].body is SetMaster {
        By::Absent
    } else {
        match raws[i].by {
            None => By::Absent,
            Some(d) => match device_index(raws, d@) {
                Some(j) => By::Change(j as usize),
                None => By::Missing,
            },
        }
    }
}

pub open spec fn body_spec(raws: Seq<Raw>, b: RawBody) -> Body {
    match b {
        RawBody::Genesis { key, next, work_ok } => Body::Genesis { key, next, work_ok },
        RawBody::AddDevice { key } => Body::AddDevice { key },
        RawBody::SignOut { device } => Body::SignOut { device: as_usize(device_index(raws, device@)) },
        RawBody::RemoveDevice { device, keep } => Body::RemoveDevice {
            device: as_usize(device_index(raws, device@)),
            keep: match keep {
                None => Keep::Absent,
                Some(k) => match hash_index(raws, k@) {
                    Some(j) => Keep::Found(j as usize),
                    None => Keep::Missing,
                },
            },
        },
        RawBody::SetMaster { reveal, key, next } => Body::SetMaster { reveal, key, next },
        RawBody::SetHandle => Body::SetHandle,
        RawBody::SetHome => Body::SetHome,
        RawBody::RevokeClient => Body::RevokeClient,
        RawBody::NewSecret => Body::NewSecret,
        RawBody::Future => Body::Future,
        RawBody::Invalid => Body::Invalid,
    }
}

pub open spec fn signer_spec(raws: Seq<Raw>, i: int) -> Signer {
    if raws[i].body is Genesis || raws[i].body is SetMaster {
        Signer::Own
    } else {
        match by_spec(raws, i) {
            By::Change(j) => Signer::Device(j),
            _ => Signer::Nobody,
        }
    }
}

/// Change i is raw change i with every hash resolved (and its signature not yet checked).
pub open spec fn resolved(raws: Seq<Raw>, cs: Seq<Change>, i: int) -> bool {
    &&& cs[i].hash == raws[i].hash
    &&& cs[i].id == raws[i].id
    &&& cs[i].prev@ == prev_map(raws, raws[i].prev@)
    &&& cs[i].by == by_spec(raws, i)
    &&& cs[i].body == body_spec(raws, raws[i].body)
    &&& !cs[i].sig_ok
}

// Ordering hashes.

pub open spec fn hlt(a: Hash, b: Hash) -> bool {
    lex_lt(a@, b@)
}

fn hash_less(x: &Hash, y: &Hash) -> (r: bool)
    ensures
        r == lex_lt(x@, y@),
{
    let mut i: usize = 0;
    assert(x@.skip(0) =~= x@);
    assert(y@.skip(0) =~= y@);
    while i < 32
        invariant
            i <= 32,
            x@.len() == 32,
            y@.len() == 32,
            lex_lt(x@, y@) == lex_lt(x@.skip(i as int), y@.skip(i as int)),
        decreases 32 - i,
    {
        let ghost sa = x@.skip(i as int);
        let ghost sb = y@.skip(i as int);
        assert(sa[0] == x@[i as int] && sb[0] == y@[i as int]);
        if x[i] != y[i] {
            return x[i] < y[i];
        }
        assert(sa.drop_first() =~= x@.skip(i + 1));
        assert(sb.drop_first() =~= y@.skip(i + 1));
        i = i + 1;
    }
    assert(x@.skip(32).len() == 0);
    false
}

fn hash_eq(x: &Hash, y: &Hash) -> (r: bool)
    ensures
        r == (x@ == y@),
{
    eq32(x, y)
}

/// `order` lists indices of `raws` whose hashes strictly increase.
spec fn sorted_by_hash(raws: Seq<Raw>, order: Seq<usize>) -> bool {
    &&& forall|k: int| 0 <= k < order.len() ==> (order[k] as int) < raws.len()
    &&& forall|k1: int, k2: int| #![trigger order[k1], order[k2]] 0 <= k1 < k2 < order.len() ==> lex_lt(raws[order[k1] as int].hash@, raws[order[k2] as int].hash@)
}

/// Keys for device IDs: (ID, index), compared as hash then index.
spec fn id_key_lt(raws: Seq<Raw>, a: int, b: int) -> bool {
    lex_lt(raws[a].id@, raws[b].id@) || (raws[a].id@ == raws[b].id@ && a < b)
}

spec fn sorted_by_id(raws: Seq<Raw>, order: Seq<usize>) -> bool {
    &&& forall|k: int| 0 <= k < order.len() ==> (order[k] as int) < raws.len() && brings_device(raws[order[k] as int].body)
    &&& forall|k1: int, k2: int| #![trigger order[k1], order[k2]] 0 <= k1 < k2 < order.len() ==> id_key_lt(raws, order[k1] as int, order[k2] as int)
}

fn brings_device_x(b: &RawBody) -> (r: bool)
    ensures
        r == brings_device(*b),
{
    match b {
        RawBody::Genesis { .. } | RawBody::AddDevice { .. } | RawBody::SetMaster { .. } => true,
        _ => false,
    }
}

/// Checks that `order` holds every index once, sorted by strictly increasing hash.
fn check_by_hash(raws: &Vec<Raw>, order: &Vec<usize>) -> (ok: bool)
    ensures
        ok ==> sorted_by_hash(raws@, order@),
        ok ==> forall|j: int| 0 <= j < raws.len() ==> #[trigger] order@.contains(j as usize),
{
    let n = raws.len();
    let mut seen: Vec<bool> = Vec::new();
    while seen.len() < n
        invariant
            seen.len() <= n,
            forall|j: int| 0 <= j < seen.len() ==> !seen[j],
        decreases n - seen.len(),
    {
        seen.push(false);
    }
    let mut k: usize = 0;
    while k < order.len()
        invariant
            n == raws.len(),
            seen.len() == n,
            k <= order.len(),
            forall|q: int| 0 <= q < k ==> (order[q] as int) < n,
            forall|q1: int, q2: int| #![trigger order[q1], order[q2]] 0 <= q1 < q2 < k ==> lex_lt(raws@[order[q1] as int].hash@, raws@[order[q2] as int].hash@),
            forall|j: int| 0 <= j < n && #[trigger] seen[j] ==> order@.subrange(0, k as int).contains(j as usize),
        decreases order.len() - k,
    {
        let j = order[k];
        if j >= n {
            return false;
        }
        if k > 0 {
            let p = order[k - 1];
            if !hash_less(&raws[p].hash, &raws[j].hash) {
                return false;
            }
            proof {
                assert forall|q1: int, q2: int| #![trigger order[q1], order[q2]] 0 <= q1 < q2 < k + 1 implies lex_lt(raws@[order[q1] as int].hash@, raws@[order[q2] as int].hash@) by {
                    if q2 == k && q1 < k - 1 {
                        lemma_lex_trans(raws@[order[q1] as int].hash@, raws@[p as int].hash@, raws@[j as int].hash@);
                    }
                }
            }
        }
        seen.set(j, true);
        proof {
            assert forall|i: int| 0 <= i < n && #[trigger] seen[i] implies order@.subrange(0, k + 1).contains(i as usize) by {
                if i == j as int {
                    assert(order@.subrange(0, k + 1)[k as int] == j);
                } else {
                    let q = order@.subrange(0, k as int).index_of(i as usize);
                    assert(order@.subrange(0, k + 1)[q] == i as usize);
                }
            }
        }
        k = k + 1;
    }
    let mut j: usize = 0;
    while j < n
        invariant
            seen.len() == n,
            j <= n,
            forall|i: int| 0 <= i < j ==> #[trigger] seen[i],
        decreases n - j,
    {
        if !seen[j] {
            return false;
        }
        j = j + 1;
    }
    proof {
        assert(order@.subrange(0, order.len() as int) =~= order@);
        assert forall|i: int| 0 <= i < n implies #[trigger] order@.contains(i as usize) by {
            assert(seen[i]);
        }
    }
    true
}

/// Checks that `order` holds every change that brings in a device once, sorted by (ID, index).
fn check_by_id(raws: &Vec<Raw>, order: &Vec<usize>) -> (ok: bool)
    ensures
        ok ==> sorted_by_id(raws@, order@),
        ok ==> forall|j: int| 0 <= j < raws.len() && brings_device(raws@[j].body) ==> #[trigger] order@.contains(j as usize),
{
    let n = raws.len();
    let mut seen: Vec<bool> = Vec::new();
    while seen.len() < n
        invariant
            seen.len() <= n,
            forall|j: int| 0 <= j < seen.len() ==> !seen[j],
        decreases n - seen.len(),
    {
        seen.push(false);
    }
    let mut k: usize = 0;
    while k < order.len()
        invariant
            n == raws.len(),
            seen.len() == n,
            k <= order.len(),
            forall|q: int| 0 <= q < k ==> (order[q] as int) < n && brings_device(raws@[order[q] as int].body),
            forall|q1: int, q2: int| #![trigger order[q1], order[q2]] 0 <= q1 < q2 < k ==> id_key_lt(raws@, order[q1] as int, order[q2] as int),
            forall|j: int| 0 <= j < n && #[trigger] seen[j] ==> order@.subrange(0, k as int).contains(j as usize),
        decreases order.len() - k,
    {
        let j = order[k];
        if j >= n || !brings_device_x(&raws[j].body) {
            return false;
        }
        if k > 0 {
            let p = order[k - 1];
            let lt = hash_less(&raws[p].id, &raws[j].id) || (hash_eq(&raws[p].id, &raws[j].id) && p < j);
            if !lt {
                return false;
            }
            proof {
                assert forall|q1: int, q2: int| #![trigger order[q1], order[q2]] 0 <= q1 < q2 < k + 1 implies id_key_lt(raws@, order[q1] as int, order[q2] as int) by {
                    if q2 == k && q1 < k - 1 {
                        let a = raws@[order[q1] as int].id@;
                        let b = raws@[p as int].id@;
                        let c = raws@[j as int].id@;
                        if lex_lt(a, b) && lex_lt(b, c) {
                            lemma_lex_trans(a, b, c);
                        }
                    }
                }
            }
        }
        seen.set(j, true);
        proof {
            assert forall|i: int| 0 <= i < n && #[trigger] seen[i] implies order@.subrange(0, k + 1).contains(i as usize) by {
                if i == j as int {
                    assert(order@.subrange(0, k + 1)[k as int] == j);
                } else {
                    let q = order@.subrange(0, k as int).index_of(i as usize);
                    assert(order@.subrange(0, k + 1)[q] == i as usize);
                }
            }
        }
        k = k + 1;
    }
    let mut j: usize = 0;
    while j < n
        invariant
            n == raws.len(),
            seen.len() == n,
            j <= n,
            forall|i: int| 0 <= i < j && brings_device(raws@[i].body) ==> #[trigger] seen[i],
        decreases n - j,
    {
        if brings_device_x(&raws[j].body) && !seen[j] {
            return false;
        }
        j = j + 1;
    }
    proof {
        assert(order@.subrange(0, order.len() as int) =~= order@);
        assert forall|i: int| 0 <= i < n && brings_device(raws@[i].body) implies #[trigger] order@.contains(i as usize) by {
            assert(seen[i]);
        }
    }
    true
}

/// The index of the change with hash `h`, by binary search.
fn find_hash(raws: &Vec<Raw>, order: &Vec<usize>, h: &Hash) -> (r: Option<usize>)
    requires
        sorted_by_hash(raws@, order@),
        forall|j: int| 0 <= j < raws.len() ==> #[trigger] order@.contains(j as usize),
    ensures
        r matches Some(j) ==> (j as int) < raws.len() && raws@[j as int].hash@ == h@,
        r is None ==> forall|j: int| 0 <= j < raws.len() ==> raws@[j].hash@ != h@,
{
    let mut lo: usize = 0;
    let mut hi: usize = order.len();
    while lo < hi
        invariant
            sorted_by_hash(raws@, order@),
            lo <= hi <= order.len(),
            forall|k: int| 0 <= k < lo ==> lex_lt(#[trigger] raws@[order[k] as int].hash@, h@),
            forall|k: int| hi <= k < order.len() ==> lex_lt(h@, #[trigger] raws@[order[k] as int].hash@),
        decreases hi - lo,
    {
        let mid = lo + (hi - lo) / 2;
        let j = order[mid];
        if hash_eq(&raws[j].hash, h) {
            return Some(j);
        }
        if hash_less(&raws[j].hash, h) {
            proof {
                assert forall|k: int| 0 <= k < mid + 1 implies lex_lt(#[trigger] raws@[order[k] as int].hash@, h@) by {
                    if k < mid {
                        lemma_lex_trans(raws@[order[k] as int].hash@, raws@[j as int].hash@, h@);
                    }
                }
            }
            lo = mid + 1;
        } else {
            proof {
                lemma_lex_total(raws@[j as int].hash@, h@);
                assert forall|k: int| mid <= k < order.len() implies lex_lt(h@, #[trigger] raws@[order[k] as int].hash@) by {
                    if k > mid {
                        lemma_lex_trans(h@, raws@[j as int].hash@, raws@[order[k] as int].hash@);
                    }
                }
            }
            hi = mid;
        }
    }
    proof {
        assert forall|j: int| 0 <= j < raws.len() implies raws@[j].hash@ != h@ by {
            assert(order@.contains(j as usize));
            let k = order@.index_of(j as usize);
            assert(order[k] == j as usize);
            lemma_lex_irreflexive(h@);
            if k < lo {
                assert(lex_lt(raws@[order[k] as int].hash@, h@));
            } else {
                assert(lex_lt(h@, raws@[order[k] as int].hash@));
            }
        }
    }
    None
}

/// The lowest-numbered change bringing in the device with ID `id`, by binary search.
fn find_device(raws: &Vec<Raw>, order: &Vec<usize>, id: &Hash) -> (r: Option<usize>)
    requires
        sorted_by_id(raws@, order@),
        forall|j: int| 0 <= j < raws.len() && brings_device(raws@[j].body) ==> #[trigger] order@.contains(j as usize),
    ensures
        as_int(r) == device_index(raws@, id@),
{
    // The first position whose ID is not below `id`.
    let mut lo: usize = 0;
    let mut hi: usize = order.len();
    while lo < hi
        invariant
            sorted_by_id(raws@, order@),
            lo <= hi <= order.len(),
            forall|k: int| 0 <= k < lo ==> lex_lt(#[trigger] raws@[order[k] as int].id@, id@),
            forall|k: int| hi <= k < order.len() ==> !lex_lt(#[trigger] raws@[order[k] as int].id@, id@),
        decreases hi - lo,
    {
        let mid = lo + (hi - lo) / 2;
        let j = order[mid];
        if hash_less(&raws[j].id, id) {
            proof {
                assert forall|k: int| 0 <= k < mid + 1 implies lex_lt(#[trigger] raws@[order[k] as int].id@, id@) by {
                    if k < mid {
                        let a = raws@[order[k] as int].id@;
                        let b = raws@[j as int].id@;
                        assert(id_key_lt(raws@, order[k] as int, j as int));
                        if lex_lt(a, b) {
                            lemma_lex_trans(a, b, id@);
                        }
                    }
                }
            }
            lo = mid + 1;
        } else {
            proof {
                assert forall|k: int| mid <= k < order.len() implies !lex_lt(#[trigger] raws@[order[k] as int].id@, id@) by {
                    if k > mid {
                        let b = raws@[j as int].id@;
                        let c = raws@[order[k] as int].id@;
                        assert(id_key_lt(raws@, j as int, order[k] as int));
                        if lex_lt(c, id@) {
                            if lex_lt(b, c) {
                                lemma_lex_trans(b, c, id@);
                            }
                        }
                    }
                }
            }
            hi = mid;
        }
    }
    if lo < order.len() && hash_eq(&raws[order[lo]].id, id) {
        proof {
            assert(raws@.len() == raws.len());
            lemma_device_found(raws@, order@, id@, lo as int);
        }
        Some(order[lo])
    } else {
        proof {
            assert(raws@.len() == raws.len());
            lemma_device_absent(raws@, order@, id@, lo as int);
        }
        None
    }
}

proof fn lemma_device_found(raws: Seq<Raw>, order: Seq<usize>, id: Seq<u8>, lo: int)
    requires
        raws.len() <= usize::MAX,
        sorted_by_id(raws, order),
        forall|j: int| 0 <= j < raws.len() && brings_device(raws[j].body) ==> #[trigger] order.contains(j as usize),
        0 <= lo < order.len(),
        forall|k: int| 0 <= k < lo ==> lex_lt(#[trigger] raws[order[k] as int].id@, id),
        raws[order[lo] as int].id@ == id,
    ensures
        device_index(raws, id) == Some(order[lo] as int),
{
    let j = order[lo] as int;
    assert forall|k: int| 0 <= k < j implies !(brings_device(raws[k].body) && #[trigger] raws[k].id@ == id) by {
        if brings_device(raws[k].body) && raws[k].id@ == id {
            assert(order.contains(k as usize));
            let q = order.index_of(k as usize);
            assert(order[q] == k as usize);
            lemma_lex_irreflexive(id);
            if q < lo {
                assert(lex_lt(raws[order[q] as int].id@, id));
            } else if q > lo {
                assert(id_key_lt(raws, order[lo] as int, order[q] as int));
            }
        }
    }
    let c = choose|c: int| 0 <= c < raws.len() && brings_device(raws[c].body) && #[trigger] raws[c].id@ == id
        && forall|k: int| 0 <= k < c ==> !(brings_device(raws[k].body) && #[trigger] raws[k].id@ == id);
    assert(c == j) by {
        if c > j {
            assert(!(brings_device(raws[j].body) && raws[j].id@ == id));
        }
    }
}

proof fn lemma_device_absent(raws: Seq<Raw>, order: Seq<usize>, id: Seq<u8>, lo: int)
    requires
        raws.len() <= usize::MAX,
        sorted_by_id(raws, order),
        forall|j: int| 0 <= j < raws.len() && brings_device(raws[j].body) ==> #[trigger] order.contains(j as usize),
        0 <= lo <= order.len(),
        forall|k: int| 0 <= k < lo ==> lex_lt(#[trigger] raws[order[k] as int].id@, id),
        forall|k: int| lo <= k < order.len() ==> !lex_lt(#[trigger] raws[order[k] as int].id@, id),
        lo < order.len() ==> raws[order[lo] as int].id@ != id,
    ensures
        device_index(raws, id) is None,
{
    assert forall|k: int| 0 <= k < raws.len() implies !(brings_device(raws[k].body) && #[trigger] raws[k].id@ == id) by {
        if brings_device(raws[k].body) && raws[k].id@ == id {
            assert(order.contains(k as usize));
            let q = order.index_of(k as usize);
            assert(0 <= q < order.len() && order[q] == k as usize);
            assert(raws[order[q] as int].id@ == id);
            lemma_lex_irreflexive(id);
            if q < lo {
                assert(lex_lt(raws[order[q] as int].id@, id));
            } else if q == lo {
                assert(raws[order[lo] as int].id@ != id);
            } else {
                assert(id_key_lt(raws, order[lo] as int, order[q] as int));
                assert(!lex_lt(raws[order[lo] as int].id@, id));
                assert(raws[order[lo] as int].id@ != id);
                assert(false);
            }
        }
    }
}

pub open spec fn as_int(o: Option<usize>) -> Option<int> {
    match o {
        Some(j) => Some(j as int),
        None => None,
    }
}

proof fn lemma_hash_index(raws: Seq<Raw>, h: Seq<u8>, j: int)
    requires
        0 <= j < raws.len(),
        raws[j].hash@ == h,
        forall|a: int, b: int| 0 <= a < raws.len() && 0 <= b < raws.len() && raws[a].hash@ == raws[b].hash@ ==> a == b,
    ensures
        hash_index(raws, h) == Some(j),
{
}

/// Resolves change i.
fn resolve_one(raws: &Vec<Raw>, by_hash: &Vec<usize>, by_id: &Vec<usize>, i: usize) -> (r: (Change, Signer))
    requires
        (i as int) < raws.len(),
        sorted_by_hash(raws@, by_hash@),
        forall|j: int| 0 <= j < raws.len() ==> #[trigger] by_hash@.contains(j as usize),
        sorted_by_id(raws@, by_id@),
        forall|j: int| 0 <= j < raws.len() && brings_device(raws@[j].body) ==> #[trigger] by_id@.contains(j as usize),
        forall|a: int, b: int| 0 <= a < raws.len() && 0 <= b < raws.len() && raws@[a].hash@ == raws@[b].hash@ ==> a == b,
    ensures
        r.0.hash == raws@[i as int].hash,
        r.0.id == raws@[i as int].id,
        r.0.prev@ == prev_map(raws@, raws@[i as int].prev@),
        r.0.by == by_spec(raws@, i as int),
        r.0.body == body_spec(raws@, raws@[i as int].body),
        !r.0.sig_ok,
        r.1 == signer_spec(raws@, i as int),
{
    let n = raws.len();
        let raw = &raws[i];
        let mut prev: Vec<usize> = Vec::new();
        let mut q: usize = 0;
        while q < raw.prev.len()
            invariant
                n == raws.len(),
                i < n,
                *raw == raws@[i as int],
                q <= raw.prev.len(),
                sorted_by_hash(raws@, by_hash@),
                forall|j: int| 0 <= j < raws.len() ==> #[trigger] by_hash@.contains(j as usize),
                forall|a: int, b: int| 0 <= a < raws.len() && 0 <= b < raws.len() && raws@[a].hash@ == raws@[b].hash@ ==> a == b,
                prev@ == prev_map(raws@, raw.prev@.subrange(0, q as int)),
            decreases raw.prev.len() - q,
        {
            let found = find_hash(raws, by_hash, &raw.prev[q]);
            proof {
                let hs = raw.prev@.subrange(0, q + 1);
                assert(hs.drop_last() =~= raw.prev@.subrange(0, q as int));
                assert(hs.last() == raw.prev@[q as int]);
                if let Some(j) = found {
                    lemma_hash_index(raws@, raw.prev@[q as int]@, j as int);
                }
            }
            if let Some(j) = found {
                prev.push(j);
            }
            q = q + 1;
        }
        proof {
            assert(raw.prev@.subrange(0, raw.prev.len() as int) =~= raw.prev@);
        }
        let own = match &raw.body {
            RawBody::Genesis { .. } | RawBody::SetMaster { .. } => true,
            _ => false,
        };
        let by = if own {
            By::Absent
        } else {
            match &raw.by {
                None => By::Absent,
                Some(d) => match find_device(raws, by_id, d) {
                    Some(j) => By::Change(j),
                    None => By::Missing,
                },
            }
        };
        let body = match &raw.body {
            RawBody::Genesis { key, next, work_ok } => Body::Genesis { key: *key, next: *next, work_ok: *work_ok },
            RawBody::AddDevice { key } => Body::AddDevice { key: *key },
            RawBody::SignOut { device } => Body::SignOut { device: find_device(raws, by_id, device) },
            RawBody::RemoveDevice { device, keep } => {
                let k = match keep {
                    None => Keep::Absent,
                    Some(h) => {
                        let found = find_hash(raws, by_hash, h);
                        proof {
                            if let Some(j) = found {
                                lemma_hash_index(raws@, h@, j as int);
                            }
                        }
                        match found {
                            Some(j) => Keep::Found(j),
                            None => Keep::Missing,
                        }
                    },
                };
                Body::RemoveDevice { device: find_device(raws, by_id, device), keep: k }
            },
            RawBody::SetMaster { reveal, key, next } => Body::SetMaster { reveal: *reveal, key: *key, next: *next },
            RawBody::SetHandle => Body::SetHandle,
            RawBody::SetHome => Body::SetHome,
            RawBody::RevokeClient => Body::RevokeClient,
            RawBody::NewSecret => Body::NewSecret,
            RawBody::Future => Body::Future,
            RawBody::Invalid => Body::Invalid,
        };
        let signer = if own {
            Signer::Own
        } else {
            match by {
                By::Change(j) => Signer::Device(j),
                _ => Signer::Nobody,
            }
        };
    (Change { hash: raw.hash, id: raw.id, prev, by, sig_ok: false, body }, signer)
}

/// Resolves every change; `None` if the orders don't check out or two changes share a hash.
#[verifier::rlimit(100)]
pub fn resolve(raws: &Vec<Raw>, by_hash: &Vec<usize>, by_id: &Vec<usize>) -> (r: Option<(Vec<Change>, Vec<Signer>)>)
    ensures
        r matches Some((cs, signers)) ==> {
            &&& cs.len() == raws.len()
            &&& signers.len() == raws.len()
            &&& forall|i: int| 0 <= i < raws.len() ==> #[trigger] resolved(raws@, cs@, i)
            &&& forall|i: int| 0 <= i < raws.len() ==> #[trigger] signers[i] == signer_spec(raws@, i)
        },
{
    if !check_by_hash(raws, by_hash) || !check_by_id(raws, by_id) {
        return None;
    }
    // Sorted strictly by hash, so hashes are distinct.
    proof {
        assert forall|a: int, b: int| 0 <= a < raws.len() && 0 <= b < raws.len() && raws@[a].hash@ == raws@[b].hash@ implies a == b by {
            assert(by_hash@.contains(a as usize));
            assert(by_hash@.contains(b as usize));
            let ka = by_hash@.index_of(a as usize);
            let kb = by_hash@.index_of(b as usize);
            assert(by_hash[ka] == a as usize && by_hash[kb] == b as usize);
            lemma_lex_irreflexive(raws@[a].hash@);
            if ka < kb {
                assert(lex_lt(raws@[by_hash[ka] as int].hash@, raws@[by_hash[kb] as int].hash@));
            } else if kb < ka {
                assert(lex_lt(raws@[by_hash[kb] as int].hash@, raws@[by_hash[ka] as int].hash@));
            }
        }
    }
    let n = raws.len();
    let mut cs: Vec<Change> = Vec::new();
    let mut signers: Vec<Signer> = Vec::new();
    while cs.len() < n
        invariant
            n == raws.len(),
            cs.len() <= n,
            signers.len() == cs.len(),
            sorted_by_hash(raws@, by_hash@),
            forall|j: int| 0 <= j < raws.len() ==> #[trigger] by_hash@.contains(j as usize),
            sorted_by_id(raws@, by_id@),
            forall|j: int| 0 <= j < raws.len() && brings_device(raws@[j].body) ==> #[trigger] by_id@.contains(j as usize),
            forall|a: int, b: int| 0 <= a < raws.len() && 0 <= b < raws.len() && raws@[a].hash@ == raws@[b].hash@ ==> a == b,
            forall|i: int| 0 <= i < cs.len() ==> #[trigger] resolved(raws@, cs@, i),
            forall|i: int| 0 <= i < cs.len() ==> #[trigger] signers[i] == signer_spec(raws@, i),
        decreases n - cs.len(),
    {
        let ghost old_cs = cs@;
        let i = cs.len();
        let (c, signer) = resolve_one(raws, by_hash, by_id, i);
        let ghost cg = c;
        cs.push(c);
        signers.push(signer);
        proof {
            assert forall|i2: int| 0 <= i2 < cs.len() implies #[trigger] resolved(raws@, cs@, i2) by {
                if i2 < i as int {
                    assert(resolved(raws@, old_cs, i2));
                    assert(cs@[i2] == old_cs[i2]);
                } else {
                    assert(cs@[i2] == cg);
                    assert(cg.hash == raws@[i2].hash && cg.id == raws@[i2].id);
                    assert(cg.prev@ == prev_map(raws@, raws@[i2].prev@));
                    assert(cg.by == by_spec(raws@, i2) && cg.body == body_spec(raws@, raws@[i2].body) && !cg.sig_ok);
                }
            }
        }
    }
    Some((cs, signers))
}

} // verus!
