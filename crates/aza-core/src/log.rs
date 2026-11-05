//! Reading a change log, section 5.4.
//!
//! The caller parses each change and passes plain facts: hashes, fingerprints of keys, whether the
//! signature is valid, and the indices of the changes that `prev`, `by` and `body.device` name.
//! `read` then works out the master chain, master changes, master removals, discarded changes,
//! sign-outs and revocations judged on their own, and the result of applying the log in reading
//! order. Verus proves it never indexes out of bounds or overflows on any input, and the
//! properties stated on each function.
use crate::bits::*;
use crate::dag::*;
use crate::order::*;
use crate::spec::*;
use vstd::prelude::*;

verus! {

pub type Hash = [u8; 32];

/// The most changes a log may hold; nodes refuse to store more.
pub const MAX_CHANGES: usize = 1_048_576;

/// The most ordinary devices that haven't been removed, section 4.
pub const MAX_DEVICES: usize = 64;

/// A `keep` field of a `remove-device` change.
pub enum Keep {
    Absent,
    /// The index of the change it names.
    Found(usize),
    /// It names a change that isn't in the log.
    Missing,
}

/// Bodies, keeping only what reading the log needs. Keys are given as fingerprints.
pub enum Body {
    Genesis { key: Hash, next: Hash, work_ok: bool },
    AddDevice { key: Hash },
    /// `device` is the index of the change whose device ID the body names, if it is in the log.
    SignOut { device: Option<usize> },
    RemoveDevice { device: Option<usize>, keep: Keep },
    SetMaster { reveal: Hash, key: Hash, next: Hash },
    SetHandle,
    SetHome,
    RevokeClient,
    NewSecret,
    /// A change with a higher `v` than this software supports (section 13).
    Future,
    /// A supported `v` but an unknown type, or a body that breaks its type's rules of form.
    Invalid,
}

/// The `by` field of a change.
pub enum By {
    /// `genesis` and `set-master` changes have no `by`.
    Absent,
    /// It names a device ID no change in the log brings in.
    Missing,
    /// The index of the change that brought in the device (for a later master, any copy of its
    /// `set-master` change).
    Change(usize),
}

pub struct Change {
    pub hash: Hash,
    /// The device ID this change brings in: its hash without `sig` for `set-master`, else `hash`.
    pub id: Hash,
    /// Indices of the changes `prev` names that are in the log.
    pub prev: Vec<usize>,
    pub by: By,
    /// The signature is valid for the key of device `by` (for `genesis`, `body.key`; for
    /// `set-master`, `body.reveal`).
    pub sig_ok: bool,
    pub body: Body,
}

pub open spec fn change_ok(c: Change, n: nat) -> bool {
    &&& forall|k: int| 0 <= k < c.prev.len() ==> (c.prev[k] as nat) < n
    &&& (c.by matches By::Change(j) ==> (j as nat) < n)
    &&& (c.body matches Body::SignOut { device: Some(d) } ==> (d as nat) < n)
    &&& (c.body matches Body::RemoveDevice { device: Some(d), .. } ==> (d as nat) < n)
    &&& (c.body matches Body::RemoveDevice { keep: Keep::Found(k), .. } ==> (k as nat) < n)
}

pub open spec fn valid(cs: Seq<Change>) -> bool {
    &&& cs.len() <= MAX_CHANGES
    &&& forall|i: int| 0 <= i < cs.len() ==> change_ok(#[trigger] cs[i], cs.len() as nat)
}

/// The result of reading a log. Vectors have one entry per change.
pub struct Reading {
    /// The ancestors of each change.
    pub anc: Vec<Bits>,
    /// Reading order: every change that isn't discarded, each after its ancestors.
    pub order: Vec<usize>,
    /// For each change, the number of the master chain link it is (a copy of).
    pub link: Vec<Option<usize>>,
    /// One change per link of the master chain, starting with the genesis change.
    pub links: Vec<usize>,
    /// The chain ended in a master conflict, so the identity has no master.
    pub conflict: bool,
    pub master_change: Vec<bool>,
    pub discarded: Vec<bool>,
    /// For a master removal, the index of the `add-device` change of the device it removes.
    pub removal: Vec<Option<usize>>,
    /// For a sign-out that counts, the index of the `add-device` change of the device.
    pub sign_out: Vec<Option<usize>>,
    pub revocation: Vec<bool>,
    /// Sign-outs and revocations that are allowed when judged on their own (step 4).
    pub judged: Vec<bool>,
    /// Changes applied in step 5, links included.
    pub applied: Vec<bool>,
    /// The device this change brought in is current at the end of the log.
    pub current: Vec<bool>,
    pub handle: Option<usize>,
    pub home: Option<usize>,
    /// The change announcing the current secret: the genesis change or a `new-secret` change.
    pub secret: usize,
    /// The genesis change and every applied `new-secret` change.
    pub announced: Vec<bool>,
    /// A change of a higher version would pass rules 1, 2 and 4 (section 13).
    pub unreadable: bool,
}

pub fn eq32(a: &Hash, b: &Hash) -> (r: bool)
    ensures
        r == (a@ == b@),
{
    let mut i: usize = 0;
    while i < 32
        invariant
            i <= 32,
            forall|j: int| 0 <= j < i ==> a@[j] == b@[j],
        decreases 32 - i,
    {
        if a[i] != b[i] {
            return false;
        }
        i = i + 1;
    }
    assert(a@ =~= b@);
    true
}

/// Byte order of two hashes, for reading order.
pub fn lt32(a: &Hash, b: &Hash) -> bool {
    let mut i: usize = 0;
    while i < 32
        invariant
            i <= 32,
        decreases 32 - i,
    {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
        i = i + 1;
    }
    false
}

fn change_valid(c: &Change, n: usize) -> (r: bool)
    ensures
        r == change_ok(*c, n as nat),
{
    let mut k: usize = 0;
    while k < c.prev.len()
        invariant
            k <= c.prev.len(),
            forall|m: int| 0 <= m < k ==> (c.prev[m] as nat) < n,
        decreases c.prev.len() - k,
    {
        if c.prev[k] >= n {
            return false;
        }
        k = k + 1;
    }
    match c.by {
        By::Change(j) => if j >= n { return false; },
        _ => {},
    }
    match &c.body {
        Body::SignOut { device: Some(d) } => *d < n,
        Body::RemoveDevice { device, keep } => {
            let d_ok = match device {
                Some(d) => *d < n,
                None => true,
            };
            let k_ok = match keep {
                Keep::Found(k) => *k < n,
                _ => true,
            };
            d_ok && k_ok
        },
        _ => true,
    }
}

fn check_valid(cs: &Vec<Change>) -> (r: bool)
    ensures
        r == valid(cs@),
{
    let n = cs.len();
    if n > MAX_CHANGES {
        return false;
    }
    let mut i: usize = 0;
    while i < n
        invariant
            n == cs.len(),
            n <= MAX_CHANGES,
            i <= n,
            forall|j: int| 0 <= j < i ==> change_ok(#[trigger] cs@[j], n as nat),
        decreases n - i,
    {
        if !change_valid(&cs[i], n) {
            assert(!change_ok(cs@[i as int], n as nat));
            return false;
        }
        i = i + 1;
    }
    true
}

/// Only the genesis change and `set-master` changes are links.
pub open spec fn links_ok(link: Seq<Option<usize>>, cs: Seq<Change>, genesis: usize) -> bool {
    forall|i: int| 0 <= i < link.len() && (#[trigger] link[i]) is Some ==> i == genesis || cs[i].body is SetMaster
}

/// A judged sign-out names an ordinary device: one brought in by an `add-device` change.
pub open spec fn sign_out_form(cs: Seq<Change>, c: int) -> bool {
    cs[c].body matches Body::SignOut { device: Some(a) } ==> (a as int) < cs.len() && cs[a as int].body is AddDevice
}

pub open spec fn judged_ok(judged: Seq<bool>, cs: Seq<Change>) -> bool {
    &&& judged.len() == cs.len()
    &&& forall|c: int| 0 <= c < cs.len() && #[trigger] judged[c] ==> sign_out_form(cs, c)
}

pub open spec fn opt_nat(o: Option<usize>) -> Option<nat> {
    match o {
        Some(x) => Some(x as nat),
        None => None,
    }
}

pub open spec fn opt_int(o: Option<usize>) -> Option<int> {
    match o {
        Some(x) => Some(x as int),
        None => None,
    }
}

/// Everything worked out about the log before step 5, shared by every reading of a sub-log.
struct Facts {
    n: usize,
    in_dag: Vec<bool>,
    anc: Vec<Bits>,
    link: Vec<Option<usize>>,
    links: Vec<usize>,
    conflict: bool,
    master_change: Vec<bool>,
    removal: Vec<Option<usize>>,
    discarded: Vec<bool>,
    order: Vec<usize>,
}

impl Facts {
    spec fn wf(&self, cs: Seq<Change>) -> bool {
        &&& valid(cs)
        &&& self.n == cs.len()
        &&& self.in_dag.len() == self.n
        &&& anc_exact(cs, self.anc@)
        &&& forall|i: int| 0 <= i < self.n ==> #[trigger] self.in_dag[i] == in_dag(cs, i)
        &&& self.link.len() == self.n
        &&& self.master_change.len() == self.n
        &&& self.removal.len() == self.n
        &&& self.discarded.len() == self.n
        &&& forall|k: int| 0 <= k < self.order.len() ==> (self.order[k] as nat) < self.n
        &&& forall|k: int| 0 <= k < self.links.len() ==> (self.links[k] as nat) < self.n
        &&& self.links.len() <= self.n + 1
        &&& forall|k: int| 0 <= k < self.n ==> (#[trigger] self.link[k] matches Some(l) ==> (l as nat) < self.links.len())
        &&& forall|k: int| 0 <= k < self.n ==> (#[trigger] self.removal[k] matches Some(a) ==> (a as nat) < self.n)
    }

    spec fn chain_view(&self) -> ChainSpec {
        ChainSpec {
            link: self.link@.map_values(|o: Option<usize>| opt_nat(o)),
            reps: self.links@.map_values(|x: usize| x as int),
            conflict: self.conflict,
        }
    }

    /// Reading order holds no discarded change.
    spec fn ordered(&self) -> bool {
        forall|k: int| 0 <= k < self.order.len() ==> !self.discarded[#[trigger] self.order[k] as int]
    }

    /// Change j is an ancestor of change i.
    fn is_anc(&self, j: usize, i: usize) -> (r: bool)
        requires
            (i as nat) < self.anc.len(),
        ensures
            r == self.anc[i as int].has(j as nat),
    {
        self.anc[i].get(j)
    }
}

/// `key` is the `key` or `reveal` of some `genesis`, `set-master` or `add-device` change among
/// change i's ancestors.
fn key_among_x(cs: &Vec<Change>, f: &Facts, i: usize, key: &Hash) -> (r: bool)
    requires
        f.wf(cs@),
        (i as nat) < cs.len(),
    ensures
        r == key_among(cs@, i as int, key@),
{
    let mut j: usize = 0;
    while j < f.n
        invariant
            f.wf(cs@),
            (i as nat) < cs.len(),
            j <= f.n,
            forall|jj: int| 0 <= jj < j ==> !(#[trigger] ancestor(cs@, i as int, jj) && in_dag(cs@, jj) && uses_key(cs@[jj].body, key@)),
        decreases f.n - j,
    {
        if f.in_dag[j] && f.is_anc(j, i) {
            let used = match &cs[j].body {
                Body::Genesis { key: k, .. } => eq32(k, key),
                Body::AddDevice { key: k } => eq32(k, key),
                Body::SetMaster { reveal, key: k, .. } => eq32(k, key) || eq32(reveal, key),
                _ => false,
            };
            if used {
                assert(ancestor(cs@, i as int, j as int) && in_dag(cs@, j as int) && uses_key(cs@[j as int].body, key@));
                return true;
            }
        }
        j = j + 1;
    }
    assert forall|jj: int| 0 <= jj < cs.len() implies !(#[trigger] ancestor(cs@, i as int, jj) && in_dag(cs@, jj) && uses_key(cs@[jj].body, key@)) by {}
    false
}

/// `fp` is the `next` of some `genesis` or `set-master` change among change i's ancestors.
fn next_among_x(cs: &Vec<Change>, f: &Facts, i: usize, fp: &Hash) -> (r: bool)
    requires
        f.wf(cs@),
        (i as nat) < cs.len(),
    ensures
        r == next_among(cs@, i as int, fp@),
{
    let mut j: usize = 0;
    while j < f.n
        invariant
            f.wf(cs@),
            (i as nat) < cs.len(),
            j <= f.n,
            forall|jj: int| 0 <= jj < j ==> !(#[trigger] ancestor(cs@, i as int, jj) && in_dag(cs@, jj) && uses_next(cs@[jj].body, fp@)),
        decreases f.n - j,
    {
        if f.in_dag[j] && f.is_anc(j, i) {
            let used = match &cs[j].body {
                Body::Genesis { next, .. } => eq32(next, fp),
                Body::SetMaster { next, .. } => eq32(next, fp),
                _ => false,
            };
            if used {
                assert(ancestor(cs@, i as int, j as int) && in_dag(cs@, j as int) && uses_next(cs@[j as int].body, fp@));
                return true;
            }
        }
        j = j + 1;
    }
    false
}

/// Some copy of link `k` is an ancestor of change i.
fn has_link_x(cs: &Vec<Change>, f: &Facts, k: usize, i: usize) -> (r: bool)
    requires
        f.wf(cs@),
        (i as nat) < cs.len(),
    ensures
        r == has_link(cs@, f.chain_view().link, k as nat, i as int),
{
    let ghost link = f.chain_view().link;
    let mut j: usize = 0;
    while j < f.n
        invariant
            f.wf(cs@),
            (i as nat) < cs.len(),
            j <= f.n,
            link == f.chain_view().link,
            forall|c: int| 0 <= c < j ==> !(link[c] == Some(k as nat) && #[trigger] ancestor(cs@, i as int, c)),
        decreases f.n - j,
    {
        if f.link[j] == Some(k) && f.is_anc(j, i) {
            assert(link[j as int] == Some(k as nat));
            assert(ancestor(cs@, i as int, j as int));
            return true;
        }
        assert(link[j as int] == opt_nat(f.link[j as int]));
        j = j + 1;
    }
    false
}

pub fn next_of_x(b: &Body) -> (r: Hash)
    ensures
        r@ == next_of(*b),
{
    match b {
        Body::Genesis { next, .. } => *next,
        Body::SetMaster { next, .. } => *next,
        _ => {
            let z = [0u8; 32];
            assert(z@ =~= zero32());
            z
        },
    }
}

proof fn lemma_first_cand(cs: Seq<Change>, st: ChainSpec, x: int)
    requires
        next_cand(cs, st, x),
        forall|j: int| #[trigger] next_cand(cs, st, j) ==> x <= j,
    ensures
        first_cand(cs, st) == x,
{
    let y = first_cand(cs, st);
    assert(next_cand(cs, st, y) && forall|j: int| #[trigger] next_cand(cs, st, j) ==> y <= j);
}

pub proof fn lemma_push_contains<T>(s: Seq<T>, x: T, y: T)
    ensures
        s.push(x).contains(y) <==> (s.contains(y) || y == x),
{
    if s.push(x).contains(y) && y != x {
        let q = s.push(x).index_of(y);
        assert(q < s.len());
        assert(s[q] == y);
    }
    if s.contains(y) {
        let q = s.index_of(y);
        assert(s.push(x)[q] == y);
    }
    if y == x {
        assert(s.push(x)[s.len() as int] == y);
    }
}

/// Change i is a candidate next link after link k, whose `next` is `nx`.
fn is_cand(cs: &Vec<Change>, f: &Facts, k: usize, nx: &Hash, i: usize) -> (ok: bool)
    requires
        f.wf(cs@),
        (i as nat) < cs.len(),
    ensures
        ok == cand(cs@, f.chain_view().link, k as nat, nx@, i as int),
{
    reveal(cand);
    assert(f.chain_view().link[i as int] == opt_nat(f.link[i as int]));
    if !(f.in_dag[i] && cs[i].sig_ok && f.link[i].is_none()) {
        return false;
    }
    match &cs[i].body {
        Body::SetMaster { reveal, key, next } => {
            eq32(reveal, nx) && has_link_x(cs, f, k, i) && !eq32(key, reveal) && !key_among_x(cs, f, i, key)
                && !eq32(next, key) && !eq32(next, reveal) && !key_among_x(cs, f, i, next)
        },
        _ => false,
    }
}

/// Every candidate next link after link k, lowest index first.
fn candidates(cs: &Vec<Change>, f: &Facts, k: usize, nx: &Hash) -> (cands: Vec<usize>)
    requires
        f.wf(cs@),
    ensures
        forall|m: int| 0 <= m < cands.len() ==> (cands[m] as nat) < cs.len(),
        forall|m: int, m2: int| 0 <= m < m2 < cands.len() ==> cands[m] < cands[m2],
        forall|c: usize| #[trigger] cands@.contains(c) <==> ((c as nat) < cs.len() && cand(cs@, f.chain_view().link, k as nat, nx@, c as int)),
        forall|m: int| 0 <= m < cands.len() ==> cs@[#[trigger] cands[m] as int].body is SetMaster,
{
    let ghost link = f.chain_view().link;
    let mut cands: Vec<usize> = Vec::new();
    let mut i: usize = 0;
    while i < f.n
        invariant
            f.wf(cs@),
            i <= f.n,
            link == f.chain_view().link,
            forall|m: int| 0 <= m < cands.len() ==> (cands[m] as int) < i,
            forall|m: int, m2: int| 0 <= m < m2 < cands.len() ==> cands[m] < cands[m2],
            forall|c: usize| #[trigger] cands@.contains(c) <==> (c < i && cand(cs@, link, k as nat, nx@, c as int)),
            forall|m: int| 0 <= m < cands.len() ==> cs@[#[trigger] cands[m] as int].body is SetMaster,
        decreases f.n - i,
    {
        let ok = is_cand(cs, f, k, nx, i);
        if ok {
            proof { lemma_cand_form(cs@, link, k as nat, nx@, i as int); }
            proof {
                assert forall|c: usize| #[trigger] cands@.push(i).contains(c) <==> (c < i + 1 && cand(cs@, link, k as nat, nx@, c as int)) by {
                    lemma_push_contains(cands@, i, c);
                }
            }
            cands.push(i);
        }
        i = i + 1;
    }
    cands
}

/// Marks the candidates as copies of link `num`.
fn mark_link(cs: &Vec<Change>, f: &mut Facts, cands: &Vec<usize>, num: usize, Ghost(genesis): Ghost<usize>)
    requires
        old(f).wf(cs@),
        num == old(f).links.len(),
        forall|r: int| 0 <= r < cands.len() ==> (cands[r] as nat) < cs.len(),
        forall|r: int| 0 <= r < cands.len() ==> cs@[#[trigger] cands[r] as int].body is SetMaster,
        links_ok(old(f).link@, cs@, genesis),
    ensures
        final(f).wf(cs@) || final(f).links.len() == num,
        final(f).links@ == old(f).links@,
        final(f).conflict == old(f).conflict,
        final(f).in_dag@ == old(f).in_dag@,
        final(f).anc@ == old(f).anc@,
        final(f).master_change@ == old(f).master_change@,
        final(f).removal@ == old(f).removal@,
        final(f).discarded@ == old(f).discarded@,
        final(f).order@ == old(f).order@,
        final(f).n == old(f).n,
        final(f).link.len() == old(f).link.len(),
        links_ok(final(f).link@, cs@, genesis),
        forall|j: int| 0 <= j < cs.len() ==> #[trigger] final(f).link@[j] == if exists|r: int| 0 <= r < cands.len() && cands[r] as int == j { Some(num) } else { old(f).link@[j] },
{
    let mut q: usize = 0;
    while q < cands.len()
        invariant
            q <= cands.len(),
            f.n == old(f).n,
            f.link.len() == old(f).link.len(),
            f.n == cs.len(),
            old(f).link.len() == cs.len(),
            f.links@ == old(f).links@,
            f.conflict == old(f).conflict,
            f.in_dag@ == old(f).in_dag@,
            f.anc@ == old(f).anc@,
            f.master_change@ == old(f).master_change@,
            f.removal@ == old(f).removal@,
            f.discarded@ == old(f).discarded@,
            f.order@ == old(f).order@,
            forall|r: int| 0 <= r < cands.len() ==> (cands[r] as nat) < cs.len(),
            forall|r: int| 0 <= r < cands.len() ==> cs@[#[trigger] cands[r] as int].body is SetMaster,
            links_ok(f.link@, cs@, genesis),
            forall|j: int| 0 <= j < cs.len() ==> #[trigger] f.link@[j] == if exists|r: int| 0 <= r < q && cands[r] as int == j { Some(num) } else { old(f).link@[j] },
        decreases cands.len() - q,
    {
        f.link.set(cands[q], Some(num));
        proof {
            assert forall|j: int| 0 <= j < cs.len() implies #[trigger] f.link@[j] == if exists|r: int| 0 <= r < q + 1 && cands[r] as int == j { Some(num) } else { old(f).link@[j] } by {
                if j != cands[q as int] as int && exists|r: int| 0 <= r < q + 1 && cands[r] as int == j {
                    let r = choose|r: int| 0 <= r < q + 1 && cands[r] as int == j;
                    assert(r < q);
                }
            }
        }
        q = q + 1;
    }
}

/// Whether some candidate's device ID differs from the first's: a master conflict.
fn ids_differ(cs: &Vec<Change>, cands: &Vec<usize>, first: usize) -> (differ: bool)
    requires
        (first as nat) < cs.len(),
        forall|q: int| 0 <= q < cands.len() ==> (cands[q] as nat) < cs.len(),
    ensures
        differ == exists|q: int| 0 <= q < cands.len() && cs@[#[trigger] cands[q] as int].id@ != cs@[first as int].id@,
{
    let mut differ = false;
    let mut m: usize = 0;
    while m < cands.len()
        invariant
            m <= cands.len(),
            (first as nat) < cs.len(),
            forall|q: int| 0 <= q < cands.len() ==> (cands[q] as nat) < cs.len(),
            differ == exists|q: int| 0 <= q < m && cs@[#[trigger] cands[q] as int].id@ != cs@[first as int].id@,
        decreases cands.len() - m,
    {
        if !eq32(&cs[cands[m]].id, &cs[first].id) {
            differ = true;
        }
        m = m + 1;
    }
    differ
}

/// Adds the next link: marks the candidates as its copies and the first as its change.
fn advance(cs: &Vec<Change>, f: &mut Facts, cands: &Vec<usize>, first: usize, Ghost(genesis): Ghost<usize>, Ghost(st): Ghost<ChainSpec>)
    requires
        old(f).wf(cs@),
        st == old(f).chain_view(),
        old(f).links.len() <= cs.len(),
        last_link(st) + 1 == old(f).links.len(),
        (first as nat) < cs.len(),
        first as int == first_cand(cs@, st),
        forall|r: int| 0 <= r < cands.len() ==> (cands[r] as nat) < cs.len(),
        forall|r: int| 0 <= r < cands.len() ==> cs@[#[trigger] cands[r] as int].body is SetMaster,
        forall|c: usize| #[trigger] cands@.contains(c) <==> ((c as nat) < cs.len() && next_cand(cs@, st, c as int)),
        links_ok(old(f).link@, cs@, genesis),
    ensures
        final(f).wf(cs@),
        final(f).links.len() == old(f).links.len() + 1,
        final(f).links[0] == old(f).links[0],
        final(f).conflict == old(f).conflict,
        final(f).in_dag@ == old(f).in_dag@,
        final(f).anc@ == old(f).anc@,
        final(f).n == old(f).n,
        links_ok(final(f).link@, cs@, genesis),
        final(f).chain_view() == (ChainSpec {
            link: Seq::new(st.link.len(), |i: int| if next_cand(cs@, st, i) { Some((last_link(st) + 1) as nat) } else { st.link[i] }),
            reps: st.reps.push(first as int),
            conflict: false,
        }) || old(f).conflict,
{
    let num = f.links.len();
    let ghost n = f.n;
    mark_link(cs, f, cands, num, Ghost(genesis));
    f.links.push(first);
    proof {
        let nxt = ChainSpec {
            link: Seq::new(st.link.len(), |i: int| if next_cand(cs@, st, i) { Some((last_link(st) + 1) as nat) } else { st.link[i] }),
            reps: st.reps.push(first as int),
            conflict: false,
        };
        let v = f.chain_view();
        assert forall|j: int| 0 <= j < n implies v.link[j] == nxt.link[j] by {
            if next_cand(cs@, st, j) {
                assert(cands@.contains(j as usize));
                let r = cands@.index_of(j as usize);
                assert(cands[r] as int == j);
            } else if exists|r: int| 0 <= r < cands.len() && cands[r] as int == j {
                let r = choose|r: int| 0 <= r < cands.len() && cands[r] as int == j;
                assert(cands@.contains(cands[r]));
            }
        }
        assert(v.link =~= nxt.link);
        assert(v.reps =~= nxt.reps);
        assert forall|j: int| 0 <= j < n implies (#[trigger] f.link[j] matches Some(l) ==> (l as nat) < f.links.len()) by {
            assert(old(f).link[j] matches Some(l) ==> (l as nat) < old(f).links.len());
        }
    }
}

/// Step 1: the master chain. Returns the conflicting next links if it ended in a master conflict.
fn master_chain(cs: &Vec<Change>, f: &mut Facts, genesis: usize) -> (conflicting: Vec<usize>)
    requires
        old(f).wf(cs@),
        old(f).links.len() == 0,
        !old(f).conflict,
        forall|i: int| 0 <= i < old(f).n ==> (#[trigger] old(f).link[i]) is None,
        genesis_ok(cs@, genesis as int),
    ensures
        final(f).wf(cs@),
        final(f).chain_view() == chain(cs@, genesis as int),
        final(f).links.len() >= 1,
        final(f).links[0] == genesis,
        final(f).in_dag@ == old(f).in_dag@,
        final(f).anc@ == old(f).anc@,
        links_ok(final(f).link@, cs@, genesis),
        forall|k: int| 0 <= k < conflicting.len() ==> (conflicting[k] as nat) < cs.len(),
        forall|c: usize| #[trigger] conflicting@.contains(c) <==> (final(f).conflict && next_cand(cs@, chain(cs@, genesis as int), c as int)),
{
    let n = f.n;
    let ghost g = genesis as int;
    f.link.set(genesis, Some(0));
    f.links.push(genesis);
    proof {
        let v = f.chain_view();
        let s = chain_start(cs@, g);
        assert(v.link =~= s.link);
        assert(v.reps =~= s.reps);
    }
    let mut cur_next: Hash = next_of_x(&cs[genesis].body);
    let mut k: usize = 0;
    loop
        invariant
            f.wf(cs@),
            n == f.n,
            k + 1 == f.links.len(),
            f.links[0] == genesis,
            !f.conflict,
            0 <= g < n,
            g == genesis as int,
            f.in_dag@ == old(f).in_dag@,
            f.anc@ == old(f).anc@,
            chain_step(cs@, f.chain_view(), (n + 1 - f.links.len()) as nat) == chain(cs@, g),
            cur_next@ == last_next(cs@, f.chain_view()),
            links_ok(f.link@, cs@, genesis),
        decreases n + 1 - f.links.len(),
    {
        let ghost st = f.chain_view();
        let ghost fuel = (n + 1 - f.links.len()) as nat;
        assert(last_link(st) == k as nat);
        let cands = candidates(cs, f, k, &cur_next);
        assert(forall|c: usize| #[trigger] cands@.contains(c) <==> ((c as nat) < cs.len() && next_cand(cs@, st, c as int)));
        if cands.len() == 0 {
            proof {
                assert forall|x: int| !next_cand(cs@, st, x) by {
                    if next_cand(cs@, st, x) {
                        lemma_cand_form(cs@, st.link, last_link(st), last_next(cs@, st), x);
                        assert(cands@.contains(x as usize));
                    }
                }
            }
            return Vec::new();
        }
        let first = cands[0];
        proof {
            assert(cands@.contains(first));
            assert forall|j: int| #[trigger] next_cand(cs@, st, j) implies first as int <= j by {
                lemma_cand_form(cs@, st.link, last_link(st), last_next(cs@, st), j);
                assert(cands@.contains(j as usize));
                let q = cands@.index_of(j as usize);
                assert(q == 0 || cands[0] < cands[q]);
            }
            lemma_first_cand(cs@, st, first as int);
        }
        let differ = ids_differ(cs, &cands, first);
        proof {
            if differ {
                let q = choose|q: int| 0 <= q < cands.len() && cs@[#[trigger] cands[q] as int].id@ != cs@[first as int].id@;
                assert(cands@.contains(cands[q]));
                assert(next_cand(cs@, st, cands[q] as int));
            } else {
                assert forall|x: int| next_cand(cs@, st, x) implies cs@[x].id@ == cs@[first as int].id@ by {
                    lemma_cand_form(cs@, st.link, last_link(st), last_next(cs@, st), x);
                    assert(cands@.contains(x as usize));
                    let q = cands@.index_of(x as usize);
                    assert(cs@[cands[q] as int].id@ == cs@[first as int].id@);
                }
            }
        }
        if differ {
            f.conflict = true;
            proof {
                let fin = ChainSpec { link: st.link, reps: st.reps, conflict: true };
                assert(f.chain_view() == fin);
                assert(chain_step(cs@, st, fuel) == fin);
                assert forall|c: usize| #[trigger] cands@.contains(c) <==> (f.conflict && next_cand(cs@, chain(cs@, g), c as int)) by {
                    assert(next_cand(cs@, fin, c as int) == next_cand(cs@, st, c as int));
                    if next_cand(cs@, st, c as int) {
                        lemma_cand_form(cs@, st.link, last_link(st), last_next(cs@, st), c as int);
                    }
                }
            }
            return cands;
        }
        if f.links.len() > n {
            return Vec::new();
        }
        let num = f.links.len();
        advance(cs, f, &cands, first, Ghost(genesis), Ghost(st));
        cur_next = next_of_x(&cs[first].body);
        k = num;
    }
}

/// The link whose device ID change i's `by` names, if any.
fn by_link_x(cs: &Vec<Change>, f: &Facts, i: usize) -> (r: Option<usize>)
    requires
        f.wf(cs@),
        (i as nat) < cs.len(),
    ensures
        opt_nat(r) == by_link(cs@, f.chain_view(), i as int),
        r matches Some(k) ==> (k as nat) < f.links.len(),
{
    assert(change_ok(cs@[i as int], cs.len() as nat));
    match cs[i].by {
        By::Change(j) => {
            assert(f.chain_view().link[j as int] == opt_nat(f.link[j as int]));
            f.link[j]
        },
        _ => None,
    }
}

/// The `add-device` change that brought in the ordinary device that signed change i, if any.
fn by_device_x(cs: &Vec<Change>, f: &Facts, i: usize) -> (r: Option<usize>)
    requires
        f.wf(cs@),
        (i as nat) < cs.len(),
    ensures
        opt_int(r) == by_device(cs@, i as int),
        r matches Some(a) ==> (a as nat) < cs.len(),
{
    assert(change_ok(cs@[i as int], cs.len() as nat));
    match cs[i].by {
        By::Change(j) => match &cs[j].body {
            Body::AddDevice { .. } => if f.in_dag[j] { Some(j) } else { None },
            _ => None,
        },
        _ => None,
    }
}

/// Whether change i is a master change.
fn master_change_at(cs: &Vec<Change>, f: &Facts, conflicting: &Vec<usize>, i: usize, Ghost(ch): Ghost<ChainSpec>) -> (mc: bool)
    requires
        f.wf(cs@),
        (i as nat) < cs.len(),
        ch == f.chain_view(),
        forall|k: int| 0 <= k < conflicting.len() ==> (conflicting[k] as nat) < cs.len(),
        forall|c: usize| #[trigger] conflicting@.contains(c) <==> (f.conflict && next_cand(cs@, ch, c as int)),
    ensures
        mc == master_change(cs@, ch, i as int),
{
    let n = f.n;
    assert(ch.link[i as int] == opt_nat(f.link[i as int]));
    if !f.in_dag[i] {
        return false;
    }
    if f.link[i].is_some() {
        return true;
    }
    if !cs[i].sig_ok {
        return false;
    }
    let k = match by_link_x(cs, f, i) {
        Some(k) => k,
        None => return false,
    };
    if !has_link_x(cs, f, k, i) {
        return false;
    }
    // An ancestor of every next link of link k.
    let mut all = true;
    let mut c: usize = 0;
    while c < n
        invariant
            f.wf(cs@),
            n == f.n,
            i < n,
            c <= n,
            (k as nat) < f.links.len(),
            ch == f.chain_view(),
            all == forall|c2: int| 0 <= c2 < c && ch.link[c2] == Some((k + 1) as nat) ==> #[trigger] ancestor(cs@, c2, i as int),
        decreases n - c,
    {
        assert(ch.link[c as int] == opt_nat(f.link[c as int]));
        if f.link[c] == Some(k + 1) && !f.is_anc(i, c) {
            all = false;
        }
        c = c + 1;
    }
    if f.conflict && k + 1 == f.links.len() {
        let ghost copies = all;
        let mut q: usize = 0;
        while q < conflicting.len()
            invariant
                f.wf(cs@),
                n == f.n,
                i < n,
                q <= conflicting.len(),
                forall|r: int| 0 <= r < conflicting.len() ==> (conflicting[r] as nat) < n,
                all == (copies && forall|r: int| 0 <= r < q ==> ancestor(cs@, #[trigger] conflicting[r] as int, i as int)),
            decreases conflicting.len() - q,
        {
            if !f.is_anc(i, conflicting[q]) {
                all = false;
            }
            q = q + 1;
        }
        proof {
            if all {
                assert forall|c2: int| 0 <= c2 < n && #[trigger] next_link(cs@, ch, k as nat, c2) implies ancestor(cs@, c2, i as int) by {
                    if ch.link[c2] != Some((k + 1) as nat) {
                        assert(conflicting@.contains(c2 as usize));
                        let r = conflicting@.index_of(c2 as usize);
                        assert(ancestor(cs@, conflicting[r] as int, i as int));
                    }
                }
            } else if copies {
                let r = choose|r: int| 0 <= r < conflicting.len() && !ancestor(cs@, #[trigger] conflicting[r] as int, i as int);
                assert(conflicting@.contains(conflicting[r]));
                assert(next_link(cs@, ch, k as nat, conflicting[r] as int));
            } else {
                let c2 = choose|c2: int| 0 <= c2 < n && ch.link[c2] == Some((k + 1) as nat) && !#[trigger] ancestor(cs@, c2, i as int);
                assert(next_link(cs@, ch, k as nat, c2));
            }
        }
    } else {
        proof {
            assert forall|c2: int| 0 <= c2 < n && #[trigger] next_link(cs@, ch, k as nat, c2) implies ch.link[c2] == Some((k + 1) as nat) by {}
            if !all {
                let c2 = choose|c2: int| 0 <= c2 < n && ch.link[c2] == Some((k + 1) as nat) && !#[trigger] ancestor(cs@, c2, i as int);
                assert(next_link(cs@, ch, k as nat, c2));
            }
        }
    }
    all
}

/// Step 1, continued: which changes are master changes.
fn master_changes(cs: &Vec<Change>, f: &Facts, conflicting: &Vec<usize>) -> (out: Vec<bool>)
    requires
        f.wf(cs@),
        forall|k: int| 0 <= k < conflicting.len() ==> (conflicting[k] as nat) < cs.len(),
        forall|c: usize| #[trigger] conflicting@.contains(c) <==> (f.conflict && next_cand(cs@, f.chain_view(), c as int)),
    ensures
        out.len() == cs.len(),
        forall|i: int| 0 <= i < cs.len() ==> #[trigger] out[i] == master_change(cs@, f.chain_view(), i),
{
    let ghost ch = f.chain_view();
    let mut out: Vec<bool> = Vec::new();
    while out.len() < f.n
        invariant
            f.wf(cs@),
            out.len() <= f.n,
            ch == f.chain_view(),
            forall|k: int| 0 <= k < conflicting.len() ==> (conflicting[k] as nat) < cs.len(),
            forall|c: usize| #[trigger] conflicting@.contains(c) <==> (f.conflict && next_cand(cs@, ch, c as int)),
            forall|i: int| 0 <= i < out.len() ==> #[trigger] out[i] == master_change(cs@, ch, i),
        decreases f.n - out.len(),
    {
        let mc = master_change_at(cs, f, conflicting, out.len(), Ghost(ch));
        out.push(mc);
    }
    out
}

/// Step 2: master removals.
fn master_removals(cs: &Vec<Change>, f: &Facts) -> (out: Vec<Option<usize>>)
    requires
        f.wf(cs@),
        forall|i: int| 0 <= i < cs.len() ==> #[trigger] f.master_change[i] == master_change(cs@, f.chain_view(), i),
    ensures
        out.len() == cs.len(),
        forall|k: int| 0 <= k < cs.len() ==> (#[trigger] out[k] matches Some(a) ==> (a as nat) < cs.len()),
        forall|k: int| 0 <= k < cs.len() ==> #[trigger] opt_int(out[k]) == removal(cs@, f.chain_view(), k),
{
    let n = f.n;
    let ghost ch = f.chain_view();
    let mut out: Vec<Option<usize>> = Vec::new();
    while out.len() < n
        invariant
            f.wf(cs@),
            n == f.n,
            out.len() <= n,
            ch == f.chain_view(),
            forall|i: int| 0 <= i < n ==> #[trigger] f.master_change[i] == master_change(cs@, ch, i),
            forall|k: int| 0 <= k < out.len() ==> (#[trigger] out[k] matches Some(a) ==> (a as nat) < n),
            forall|k: int| 0 <= k < out.len() ==> #[trigger] opt_int(out[k]) == removal(cs@, ch, k),
        decreases n - out.len(),
    {
        let i = out.len();
        assert(change_ok(cs@[i as int], n as nat));
        let mut r: Option<usize> = None;
        if f.in_dag[i] && f.master_change[i] {
            match &cs[i].body {
                Body::RemoveDevice { device: Some(a), keep } => {
                    let a = *a;
                    let is_add = match &cs[a].body {
                        Body::AddDevice { .. } => true,
                        _ => false,
                    };
                    if is_add && f.in_dag[a] && f.is_anc(a, i) {
                        let keep_ok = match keep {
                            Keep::Absent => true,
                            Keep::Missing => false,
                            Keep::Found(kk) => {
                                let kk = *kk;
                                assert(change_ok(cs@[kk as int], n as nat));
                                let by_ok = match cs[kk].by {
                                    By::Change(b) => b == a,
                                    _ => false,
                                };
                                by_ok && f.in_dag[kk] && f.is_anc(kk, i)
                            },
                        };
                        if keep_ok {
                            r = Some(a);
                        }
                    }
                },
                _ => {},
            }
        }
        proof {
            assert(opt_int(r) == removal(cs@, ch, i as int));
        }
        out.push(r);
    }
    out
}

spec fn not_f(s: Seq<bool>) -> spec_fn(int) -> bool {
    |j: int| !s[j]
}

/// Step 3: discarded changes.
fn discard(cs: &Vec<Change>, f: &Facts) -> (out: Vec<bool>)
    requires
        f.wf(cs@),
        forall|i: int| 0 <= i < cs.len() ==> #[trigger] f.master_change[i] == master_change(cs@, f.chain_view(), i),
        forall|k: int| 0 <= k < cs.len() ==> #[trigger] opt_int(f.removal[k]) == removal(cs@, f.chain_view(), k),
    ensures
        out.len() == cs.len(),
        forall|i: int| 0 <= i < cs.len() ==> #[trigger] out[i] == discarded(cs@, f.chain_view(), i),
{
    let n = f.n;
    let ghost ch = f.chain_view();
    let mut out: Vec<bool> = Vec::new();
    while out.len() < n
        invariant
            f.wf(cs@),
            n == f.n,
            out.len() <= n,
            ch == f.chain_view(),
            forall|i: int| 0 <= i < n ==> #[trigger] f.master_change[i] == master_change(cs@, ch, i),
            forall|k: int| 0 <= k < n ==> #[trigger] opt_int(f.removal[k]) == removal(cs@, ch, k),
            forall|i: int| 0 <= i < out.len() ==> #[trigger] out[i] == disc_base(cs@, ch, i),
        decreases n - out.len(),
    {
        let i = out.len();
        let mut d = !f.in_dag[i];
        let bl = by_link_x(cs, f, i);
        if bl.is_some() && !f.master_change[i] {
            d = true;
        }
        match by_device_x(cs, f, i) {
            Some(a) => {
                // Survives only as `keep`, or an ancestor of it, of every master removal of a.
                let mut j: usize = 0;
                let mut cut = false;
                while j < n
                    invariant
                        f.wf(cs@),
                        n == f.n,
                        (i as nat) < n,
                        (a as nat) < n,
                        j <= n,
                        forall|k: int| 0 <= k < n ==> #[trigger] opt_int(f.removal[k]) == removal(cs@, ch, k),
                        ch == f.chain_view(),
                        cut == exists|r: int| 0 <= r < j && #[trigger] removal(cs@, ch, r) == Some(a as int) && !kept_by(cs@, r, i as int),
                    decreases n - j,
                {
                    if f.removal[j] == Some(a) {
                        assert(change_ok(cs@[j as int], n as nat));
                        let kept = match &cs[j].body {
                            Body::RemoveDevice { keep: Keep::Found(kk), .. } => *kk == i || f.is_anc(i, *kk),
                            _ => false,
                        };
                        if !kept {
                            cut = true;
                        }
                    }
                    assert(opt_int(f.removal[j as int]) == removal(cs@, ch, j as int));
                    j = j + 1;
                }
                if cut {
                    d = true;
                }
                proof {
                    assert(d == disc_base(cs@, ch, i as int));
                }
            },
            None => {
                proof {
                    assert(d == disc_base(cs@, ch, i as int));
                }
            },
        }
        out.push(d);
    }
    proof {
        assert forall|i: int| 0 <= i < n && #[trigger] out[i] implies discarded(cs@, ch, i) by {
            assert(disc_k(cs@, ch, i, 0));
        }
    }
    // A device whose `add-device` change is discarded has all its changes discarded.
    let mut changed = true;
    while changed
        invariant
            f.wf(cs@),
            n == f.n,
            out.len() == n,
            ch == f.chain_view(),
            forall|i: int| 0 <= i < n && #[trigger] disc_base(cs@, ch, i) ==> out[i],
            forall|i: int| 0 <= i < n && #[trigger] out[i] ==> discarded(cs@, ch, i),
            !changed ==> forall|i: int| 0 <= i < n ==> (#[trigger] by_device(cs@, i) matches Some(a) ==> (out[a] ==> out[i])),
        decreases count(n as nat, not_f(out@)) * 2 + if changed { 1nat } else { 0nat },
    {
        changed = false;
        let ghost start = out@;
        let mut i: usize = 0;
        while i < n
            invariant
                f.wf(cs@),
                n == f.n,
                out.len() == n,
                i <= n,
                ch == f.chain_view(),
                forall|i2: int| 0 <= i2 < n && #[trigger] disc_base(cs@, ch, i2) ==> out[i2],
                forall|i2: int| 0 <= i2 < n && #[trigger] out[i2] ==> discarded(cs@, ch, i2),
                !changed ==> forall|i2: int| 0 <= i2 < i ==> (#[trigger] by_device(cs@, i2) matches Some(a) ==> (out[a] ==> out[i2])),
                !changed ==> out@ == start,
                changed ==> count(n as nat, not_f(out@)) < count(n as nat, not_f(start)),
                start.len() == n,
            decreases n - i,
        {
            if !out[i] {
                match by_device_x(cs, f, i) {
                    Some(a) => if out[a] {
                        proof {
                            let k = choose|k: nat| #[trigger] disc_k(cs@, ch, a as int, k);
                            assert(disc_k(cs@, ch, i as int, k + 1));
                        }
                        let ghost prior = out@;
                        out.set(i, true);
                        proof {
                            lemma_count_flip(n as nat, not_f(prior), not_f(out@), i as int);
                        }
                        changed = true;
                    },
                    None => {},
                }
            }
            i = i + 1;
        }
    }
    proof {
        assert forall|i: int| 0 <= i < n implies #[trigger] out[i] == discarded(cs@, ch, i) by {
            if discarded(cs@, ch, i) {
                let k = choose|k: nat| #[trigger] disc_k(cs@, ch, i, k);
                lemma_disc_closed(cs@, ch, out@, i, k);
            }
        }
    }
    out
}

proof fn lemma_disc_closed(cs: Seq<Change>, ch: ChainSpec, out: Seq<bool>, i: int, k: nat)
    requires
        valid(cs),
        out.len() == cs.len(),
        0 <= i < cs.len(),
        forall|i2: int| 0 <= i2 < cs.len() && #[trigger] disc_base(cs, ch, i2) ==> out[i2],
        forall|i2: int| 0 <= i2 < cs.len() ==> (#[trigger] by_device(cs, i2) matches Some(a) ==> (out[a] ==> out[i2])),
        disc_k(cs, ch, i, k),
    ensures
        out[i],
    decreases k,
{
    if !disc_base(cs, ch, i) {
        assert(change_ok(cs[i], cs.len() as nat));
        let a = by_device(cs, i)->Some_0;
        lemma_disc_closed(cs, ch, out, a, (k - 1) as nat);
    }
}

/// The state reached by applying a (sub-)log in reading order, step 5.
struct Applied {
    added: Vec<bool>,
    signed_out: Vec<bool>,
    removed: Vec<bool>,
    applied: Vec<bool>,
    handle: Option<usize>,
    home: Option<usize>,
    secret: usize,
    announced: Vec<bool>,
    unreadable: bool,
    active: usize,
}

impl Applied {
    spec fn wf(&self, n: nat) -> bool {
        &&& self.added.len() == n
        &&& self.signed_out.len() == n
        &&& self.removed.len() == n
        &&& self.applied.len() == n
        &&& self.announced.len() == n
        &&& (self.secret as nat) < n
        &&& self.active <= MAX_DEVICES
    }

    spec fn view_st(&self) -> St {
        St {
            added: self.added@,
            out: self.signed_out@,
            removed: self.removed@,
            applied: self.applied@,
            handle: opt_int(self.handle),
            home: opt_int(self.home),
            secret: self.secret as int,
            announced: self.announced@,
            unreadable: self.unreadable,
            active: self.active as nat,
        }
    }

    /// Ordinary device a (its `add-device` change) is current at this point.
    fn current(&self, a: usize) -> (r: bool)
        requires
            (a as nat) < self.added.len(),
            self.added.len() == self.signed_out.len(),
            self.added.len() == self.removed.len(),
        ensures
            r == cur(self.view_st(), a as int),
    {
        self.added[a] && !self.signed_out[a] && !self.removed[a]
    }
}

/// The facts match steps 1 to 3 and reading order exactly.
spec fn facts_ok(f: &Facts, cs: Seq<Change>, g: int) -> bool {
    &&& f.wf(cs)
    &&& 0 <= g < cs.len()
    &&& links_ok(f.link@, cs, g as usize)
    &&& forall|i: int| 0 <= i < cs.len() ==> #[trigger] f.master_change[i] == master_change(cs, f.chain_view(), i)
    &&& forall|i: int| 0 <= i < cs.len() ==> #[trigger] opt_int(f.removal[i]) == removal(cs, f.chain_view(), i)
    &&& forall|i: int| 0 <= i < cs.len() ==> #[trigger] f.discarded[i] == discarded(cs, f.chain_view(), i)
    &&& forall|k: int| 0 <= k < f.order.len() ==> !discarded(cs, f.chain_view(), #[trigger] f.order[k] as int)
    &&& is_reading_order(cs, disc_seq(cs, f.chain_view()), f.order@)
}

/// The sub-log `sub` holds exactly the ancestors of `sub_s`, or `sub` is the whole log.
spec fn sub_ok(cs: Seq<Change>, sub: Option<&Bits>, sub_s: Option<int>) -> bool {
    match sub {
        None => sub_s is None,
        Some(b) => match sub_s {
            Some(c) => 0 <= c < cs.len() && forall|j: nat| #[trigger] b.has(j) <==> ancestor(cs, c, j as int),
            None => false,
        },
    }
}

fn in_sub(cs: &Vec<Change>, sub: Option<&Bits>, Ghost(sub_s): Ghost<Option<int>>, i: usize) -> (r: bool)
    requires
        sub_ok(cs@, sub, sub_s),
    ensures
        r == in_s(cs@, sub_s, i as int),
{
    match sub {
        Some(b) => b.get(i),
        None => true,
    }
}

/// Whether change s is a sign-out that counts in the sub-log, and of which device.
fn counted_x(cs: &Vec<Change>, f: &Facts, judged: &Vec<bool>, sub: Option<&Bits>, Ghost(sub_s): Ghost<Option<int>>, s: usize) -> (r: Option<usize>)
    requires
        f.wf(cs@),
        judged.len() == cs.len(),
        sub_ok(cs@, sub, sub_s),
        (s as nat) < cs.len(),
        forall|i: int| 0 <= i < cs.len() ==> #[trigger] opt_int(f.removal[i]) == removal(cs@, f.chain_view(), i),
        forall|i: int| 0 <= i < cs.len() ==> #[trigger] f.discarded[i] == discarded(cs@, f.chain_view(), i),
    ensures
        opt_int(r) == counted(cs@, f.chain_view(), judged@, sub_s, s as int),
        r matches Some(a) ==> (a as nat) < cs.len(),
{
    let ghost ch = f.chain_view();
    if !in_sub(cs, sub, Ghost(sub_s), s) || f.discarded[s] || !judged[s] {
        return None;
    }
    assert(change_ok(cs@[s as int], cs.len() as nat));
    assert(in_s(cs@, sub_s, s as int));
    assert(f.discarded[s as int] == discarded(cs@, ch, s as int));
    assert(!discarded(cs@, ch, s as int) && judged@[s as int]);
    match &cs[s].body {
        Body::SignOut { device: Some(a) } => {
            let a = *a;
            // Once the master removes the device, its removal's `keep` alone decides.
            let mut r: usize = 0;
            while r < f.n
                invariant
                    f.wf(cs@),
                    ch == f.chain_view(),
                    sub_ok(cs@, sub, sub_s),
                    r <= f.n,
                    (a as nat) < cs.len(),
                    (s as nat) < cs.len(),
                    cs@[s as int].body == (Body::SignOut { device: Some(a) }),
                    in_s(cs@, sub_s, s as int),
                    !discarded(cs@, ch, s as int),
                    judged@[s as int],
                    forall|i: int| 0 <= i < cs.len() ==> #[trigger] opt_int(f.removal[i]) == removal(cs@, ch, i),
                    forall|r2: int| 0 <= r2 < r ==> !(#[trigger] removal(cs@, ch, r2) == Some(a as int) && in_s(cs@, sub_s, r2)),
                decreases f.n - r,
            {
                assert(opt_int(f.removal[r as int]) == removal(cs@, ch, r as int));
                if f.removal[r] == Some(a) && in_sub(cs, sub, Ghost(sub_s), r) {
                    assert(removal(cs@, ch, r as int) == Some(a as int) && in_s(cs@, sub_s, r as int));
                    assert(removed_in(cs@, ch, sub_s, a as int));
                    assert(cs@[s as int].body == Body::SignOut { device: Some(a) });
                    assert(counted(cs@, ch, judged@, sub_s, s as int) is None);
                    return None;
                }
                r = r + 1;
            }
            Some(a)
        },
        _ => None,
    }
}

/// The sign-outs that count in the sub-log, as (sign-out, device), in index order.
fn counted_list(cs: &Vec<Change>, f: &Facts, judged: &Vec<bool>, sub: Option<&Bits>, Ghost(sub_s): Ghost<Option<int>>) -> (outs: Vec<(usize, usize)>)
    requires
        f.wf(cs@),
        judged.len() == cs.len(),
        sub_ok(cs@, sub, sub_s),
        forall|i: int| 0 <= i < cs.len() ==> #[trigger] opt_int(f.removal[i]) == removal(cs@, f.chain_view(), i),
        forall|i: int| 0 <= i < cs.len() ==> #[trigger] f.discarded[i] == discarded(cs@, f.chain_view(), i),
    ensures
        forall|m: int| 0 <= m < outs.len() ==> (outs[m].0 as nat) < cs.len() && (outs[m].1 as nat) < cs.len(),
        forall|m: int| 0 <= m < outs.len() ==> counted(cs@, f.chain_view(), judged@, sub_s, #[trigger] outs[m].0 as int) == Some(outs[m].1 as int),
        forall|s: int| 0 <= s < cs.len() && #[trigger] counted(cs@, f.chain_view(), judged@, sub_s, s) is Some
            ==> exists|m: int| 0 <= m < outs.len() && outs[m].0 as int == s,
{
    let ghost ch = f.chain_view();
    let mut outs: Vec<(usize, usize)> = Vec::new();
    let mut s: usize = 0;
    while s < f.n
        invariant
            f.wf(cs@),
            ch == f.chain_view(),
            judged.len() == cs.len(),
            sub_ok(cs@, sub, sub_s),
            s <= f.n,
            forall|i: int| 0 <= i < cs.len() ==> #[trigger] opt_int(f.removal[i]) == removal(cs@, ch, i),
            forall|i: int| 0 <= i < cs.len() ==> #[trigger] f.discarded[i] == discarded(cs@, ch, i),
            forall|m: int| 0 <= m < outs.len() ==> (outs[m].0 as nat) < cs.len() && (outs[m].1 as nat) < cs.len(),
            forall|m: int| 0 <= m < outs.len() ==> counted(cs@, ch, judged@, sub_s, #[trigger] outs[m].0 as int) == Some(outs[m].1 as int),
            forall|s2: int| 0 <= s2 < s && #[trigger] counted(cs@, ch, judged@, sub_s, s2) is Some
                ==> exists|m: int| 0 <= m < outs.len() && outs[m].0 as int == s2,
        decreases f.n - s,
    {
        let ghost old_outs = outs@;
        match counted_x(cs, f, judged, sub, Ghost(sub_s), s) {
            Some(a) => {
                outs.push((s, a));
                proof {
                    assert forall|s2: int| 0 <= s2 < s + 1 && #[trigger] counted(cs@, ch, judged@, sub_s, s2) is Some
                        implies exists|m: int| 0 <= m < outs.len() && outs[m].0 as int == s2 by {
                        if s2 == s as int {
                            assert(outs[outs.len() - 1].0 as int == s2);
                        } else {
                            let m = choose|m: int| 0 <= m < old_outs.len() && old_outs[m].0 as int == s2;
                            assert(outs[m] == old_outs[m]);
                        }
                    }
                }
            },
            None => {},
        }
        s = s + 1;
    }
    outs
}

/// Rule 4 for change x.
fn rule4_x(cs: &Vec<Change>, f: &Facts, judged: &Vec<bool>, Ghost(sub_s): Ghost<Option<int>>, outs: &Vec<(usize, usize)>, x: usize) -> (r: bool)
    requires
        f.wf(cs@),
        (x as nat) < cs.len(),
        judged.len() == cs.len(),
        forall|m: int| 0 <= m < outs.len() ==> (outs[m].0 as nat) < cs.len() && (outs[m].1 as nat) < cs.len(),
        forall|m: int| 0 <= m < outs.len() ==> counted(cs@, f.chain_view(), judged@, sub_s, #[trigger] outs[m].0 as int) == Some(outs[m].1 as int),
        forall|s: int| 0 <= s < cs.len() && #[trigger] counted(cs@, f.chain_view(), judged@, sub_s, s) is Some
            ==> exists|m: int| 0 <= m < outs.len() && outs[m].0 as int == s,
    ensures
        r == rule4(cs@, f.chain_view(), judged@, sub_s, x as int),
{
    let ghost ch = f.chain_view();
    match by_device_x(cs, f, x) {
        None => true,
        Some(a) => {
            let mut ok = true;
            let mut m: usize = 0;
            while m < outs.len()
                invariant
                    f.wf(cs@),
                    (x as nat) < cs.len(),
                    m <= outs.len(),
                    forall|q: int| 0 <= q < outs.len() ==> (outs[q].0 as nat) < cs.len() && (outs[q].1 as nat) < cs.len(),
                    ok == forall|q: int| 0 <= q < m && #[trigger] outs[q].1 == a ==> ancestor(cs@, outs[q].0 as int, x as int),
                decreases outs.len() - m,
            {
                if outs[m].1 == a && !f.is_anc(x, outs[m].0) {
                    ok = false;
                }
                m = m + 1;
            }
            proof {
                if ok {
                    assert forall|s: int| 0 <= s < cs.len() && #[trigger] counted(cs@, ch, judged@, sub_s, s) == Some(a as int)
                        implies ancestor(cs@, s, x as int) by {
                        let q = choose|q: int| 0 <= q < outs.len() && outs[q].0 as int == s;
                        assert(counted(cs@, ch, judged@, sub_s, outs[q].0 as int) == Some(outs[q].1 as int));
                        assert(outs[q].1 == a);
                    }
                } else {
                    let q = choose|q: int| 0 <= q < outs.len() && #[trigger] outs[q].1 == a && !ancestor(cs@, outs[q].0 as int, x as int);
                    assert(counted(cs@, ch, judged@, sub_s, outs[q].0 as int) == Some(a as int));
                }
            }
            ok
        },
    }
}

/// Applies one change: step 5 for change x.
#[verifier::rlimit(50)]
fn step_x(cs: &Vec<Change>, f: &Facts, judged: &Vec<bool>, sub: Option<&Bits>, Ghost(sub_s): Ghost<Option<int>>,
    outs: &Vec<(usize, usize)>, st: &mut Applied, x: usize, Ghost(g): Ghost<int>)
    requires
        facts_ok(f, cs@, g),
        old(st).wf(cs.len() as nat),
        (x as nat) < cs.len(),
        judged.len() == cs.len(),
        sub_ok(cs@, sub, sub_s),
        forall|m: int| 0 <= m < outs.len() ==> (outs[m].0 as nat) < cs.len() && (outs[m].1 as nat) < cs.len(),
        forall|m: int| 0 <= m < outs.len() ==> counted(cs@, f.chain_view(), judged@, sub_s, #[trigger] outs[m].0 as int) == Some(outs[m].1 as int),
        forall|s: int| 0 <= s < cs.len() && #[trigger] counted(cs@, f.chain_view(), judged@, sub_s, s) is Some
            ==> exists|m: int| 0 <= m < outs.len() && outs[m].0 as int == s,
    ensures
        final(st).wf(cs.len() as nat),
        final(st).view_st() == step(cs@, f.chain_view(), judged@, sub_s, old(st).view_st(), x as int),
{
    let ghost ch = f.chain_view();
    let ghost s0 = st.view_st();
    let n = f.n;
    assert(change_ok(cs@[x as int], n as nat));
    if !in_sub(cs, sub, Ghost(sub_s), x) {
        return;
    }
    assert(ch.link[x as int] == opt_nat(f.link[x as int]));
    if f.link[x].is_some() {
        st.applied.set(x, true);
        match &cs[x].body {
            Body::Genesis { .. } => {
                st.secret = x;
                st.announced.set(x, true);
            },
            _ => {},
        }
        assert(st.view_st() =~= step(cs@, ch, judged@, sub_s, s0, x as int));
        return;
    }
    assert(opt_int(f.removal[x as int]) == removal(cs@, ch, x as int));
    match f.removal[x] {
        Some(a) => {
            if st.added[a] && !st.removed[a] && st.active > 0 {
                st.active = st.active - 1;
            }
            st.removed.set(a, true);
            st.applied.set(x, true);
            assert(st.view_st() =~= step(cs@, ch, judged@, sub_s, s0, x as int));
            return;
        },
        None => {},
    }
    let c = counted_x(cs, f, judged, sub, Ghost(sub_s), x);
    match c {
        Some(a) => {
            st.signed_out.set(a, true);
            st.applied.set(x, true);
            assert(st.view_st() =~= step(cs@, ch, judged@, sub_s, s0, x as int));
            return;
        },
        None => {},
    }
    match &cs[x].body {
        Body::RevokeClient => {
            if judged[x] {
                st.applied.set(x, true);
            }
            assert(st.view_st() =~= step(cs@, ch, judged@, sub_s, s0, x as int));
            return;
        },
        Body::SignOut { .. } | Body::SetMaster { .. } | Body::RemoveDevice { .. } | Body::Invalid | Body::Genesis { .. } => {
            return;
        },
        _ => {},
    }
    let by = by_device_x(cs, f, x);
    let r2 = f.master_change[x] || match by {
        Some(a) => st.current(a),
        None => false,
    };
    assert(r2 == rule2(cs@, ch, s0, x as int));
    let r4 = rule4_x(cs, f, judged, Ghost(sub_s), outs, x);
    if !cs[x].sig_ok || !r2 || !r4 {
        return;
    }
    match &cs[x].body {
        Body::Future => {
            if sub.is_none() {
                st.unreadable = true;
            }
        },
        Body::AddDevice { key } => {
            if !key_among_x(cs, f, x, key) && !next_among_x(cs, f, x, key) && st.active < MAX_DEVICES {
                st.active = st.active + 1;
                st.added.set(x, true);
                st.applied.set(x, true);
            }
        },
        Body::SetHandle => {
            st.handle = Some(x);
            st.applied.set(x, true);
        },
        Body::SetHome => {
            st.home = Some(x);
            st.applied.set(x, true);
        },
        Body::NewSecret => {
            if f.master_change[x] {
                st.secret = x;
                st.announced.set(x, true);
                st.applied.set(x, true);
            }
        },
        _ => {},
    }
    assert(st.view_st() =~= step(cs@, ch, judged@, sub_s, s0, x as int));
}

proof fn lemma_step_keeps(cs: Seq<Change>, ch: ChainSpec, judged: Seq<bool>, sub: Option<int>, st: St, x: int, g: int, mc: Seq<bool>, disc: Seq<bool>, link: Seq<Option<usize>>, gu: usize)
    requires
        g == gu as int,
        0 <= x < cs.len(),
        0 <= g < cs.len(),
        !disc[x],
        disc.len() == cs.len(),
        mc.len() == cs.len(),
        forall|i: int| 0 <= i < cs.len() ==> #[trigger] mc[i] == master_change(cs, ch, i),
        links_ok(link, cs, gu),
        link.len() == cs.len(),
        forall|i: int| 0 <= i < cs.len() ==> #[trigger] ch.link[i] == opt_nat(link[i]),
        st.applied.len() == cs.len(),
        st.announced.len() == cs.len(),
        forall|i: int| 0 <= i < cs.len() && #[trigger] st.applied[i] ==> !disc[i],
        forall|i: int| 0 <= i < cs.len() && #[trigger] st.announced[i] ==> i == g || mc[i],
    ensures
        forall|i: int| 0 <= i < cs.len() && #[trigger] step(cs, ch, judged, sub, st, x).applied[i] ==> !disc[i],
        forall|i: int| 0 <= i < cs.len() && #[trigger] step(cs, ch, judged, sub, st, x).announced[i] ==> i == g || mc[i],
{
    assert(ch.link[x] == opt_nat(link[x]));
    if ch.link[x] is Some && cs[x].body is Genesis {
        assert(link[x] is Some);
        assert(x == g);
    }
}

/// Step 5 over the sub-log `sub` (the ancestors of some change), or the whole log if `None`.
fn apply(cs: &Vec<Change>, f: &Facts, judged: &Vec<bool>, sub: Option<&Bits>, Ghost(sub_s): Ghost<Option<int>>, genesis: usize) -> (st: Applied)
    requires
        facts_ok(f, cs@, genesis as int),
        judged.len() == cs.len(),
        sub_ok(cs@, sub, sub_s),
    ensures
        st.wf(cs.len() as nat),
        st.view_st() == outcome(cs@, f.chain_view(), judged@, sub_s, genesis as int, f.order@),
        forall|i: int| 0 <= i < cs.len() && #[trigger] st.applied[i] ==> !f.discarded[i],
        forall|i: int| 0 <= i < cs.len() && #[trigger] st.announced[i] ==> i == genesis || f.master_change[i],
{
    let n = f.n;
    let ghost ch = f.chain_view();
    let ghost g = genesis as int;
    let mut st = Applied {
        added: Vec::new(),
        signed_out: Vec::new(),
        removed: Vec::new(),
        applied: Vec::new(),
        handle: None,
        home: None,
        secret: genesis,
        announced: Vec::new(),
        unreadable: false,
        active: 0,
    };
    while st.added.len() < n
        invariant
            st.added.len() <= n,
            n == cs.len(),
            st.added.len() == st.signed_out.len(),
            st.added.len() == st.removed.len(),
            st.added.len() == st.applied.len(),
            st.added.len() == st.announced.len(),
            st.secret == genesis,
            !st.unreadable && st.active == 0 && st.handle is None && st.home is None,
            forall|i: int| 0 <= i < st.added.len() ==> !st.added[i] && !st.signed_out[i] && !st.removed[i] && !st.applied[i] && !st.announced[i],
        decreases n - st.added.len(),
    {
        st.added.push(false);
        st.signed_out.push(false);
        st.removed.push(false);
        st.applied.push(false);
        st.announced.push(false);
    }
    proof {
        let i0 = st_init(n as nat, g);
        assert(st.added@ =~= i0.added);
        assert(st.signed_out@ =~= i0.out);
        assert(st.removed@ =~= i0.removed);
        assert(st.applied@ =~= i0.applied);
        assert(st.announced@ =~= i0.announced);
        assert(st.view_st() == i0);
        assert(f.wf(cs@));
    }
    let outs = counted_list(cs, f, judged, sub, Ghost(sub_s));
    let mut t: usize = 0;
    while t < f.order.len()
        invariant
            facts_ok(f, cs@, g),
            g == genesis as int,
            n == cs.len(),
            ch == f.chain_view(),
            judged.len() == n,
            sub_ok(cs@, sub, sub_s),
            st.wf(n as nat),
            t <= f.order.len(),
            st.view_st() == run(cs@, ch, judged@, sub_s, g, f.order@, t as nat),
            forall|m: int| 0 <= m < outs.len() ==> (outs[m].0 as nat) < n && (outs[m].1 as nat) < n,
            forall|m: int| 0 <= m < outs.len() ==> counted(cs@, ch, judged@, sub_s, #[trigger] outs[m].0 as int) == Some(outs[m].1 as int),
            forall|s: int| 0 <= s < n && #[trigger] counted(cs@, ch, judged@, sub_s, s) is Some
                ==> exists|m: int| 0 <= m < outs.len() && outs[m].0 as int == s,
            forall|i: int| 0 <= i < n && #[trigger] st.applied[i] ==> !f.discarded[i],
            forall|i: int| 0 <= i < n && #[trigger] st.announced[i] ==> i == genesis || f.master_change[i],
        decreases f.order.len() - t,
    {
        let x = f.order[t];
        let ghost before = st.view_st();
        proof {
            assert(!discarded(cs@, ch, x as int));
            assert(!f.discarded[x as int]);
            assert forall|i: int| 0 <= i < n implies #[trigger] ch.link[i] == opt_nat(f.link@[i]) by {}
            lemma_step_keeps(cs@, ch, judged@, sub_s, before, x as int, g, f.master_change@, f.discarded@, f.link@, genesis);
        }
        step_x(cs, f, judged, sub, Ghost(sub_s), &outs, &mut st, x, Ghost(g));
        t = t + 1;
    }
    st
}

/// Step 4: judge each sign-out and revocation on its own, against the reading of its ancestors,
/// in reading order so that every non-discarded ancestor is judged first.
fn judge(cs: &Vec<Change>, f: &Facts, genesis: usize) -> (judged: Vec<bool>)
    requires
        facts_ok(f, cs@, genesis as int),
    ensures
        is_judgment(cs@, f.chain_view(), genesis as int, f.order@, judged@),
        judged_ok(judged@, cs@),
{
    let n = f.n;
    let ghost ch = f.chain_view();
    let ghost g = genesis as int;
    let ghost order = f.order@;
    let mut judged: Vec<bool> = Vec::new();
    while judged.len() < n
        invariant
            judged.len() <= n,
            n == cs.len(),
            forall|c: int| 0 <= c < judged.len() ==> !#[trigger] judged[c],
        decreases n - judged.len(),
    {
        judged.push(false);
    }
    let mut t: usize = 0;
    while t < f.order.len()
        invariant
            facts_ok(f, cs@, g),
            g == genesis as int,
            n == cs.len(),
            ch == f.chain_view(),
            order == f.order@,
            judged.len() == n,
            t <= f.order.len(),
            judged_ok(judged@, cs@),
            forall|k: int| 0 <= k < t ==> #[trigger] judged[order[k] as int] == judge_ok(cs@, ch, g, order, judged@, order[k] as int),
            forall|c: int| 0 <= c < n && !order.subrange(0, t as int).contains(c as usize) ==> !#[trigger] judged[c],
        decreases f.order.len() - t,
    {
        let c = f.order[t];
        let ghost before = judged@;
        proof {
            assert(f.order@.contains(c));
            assert((c as nat) < n);
        }
        assert(change_ok(cs@[c as int], n as nat));
        let candidate = match &cs[c].body {
            Body::SignOut { .. } | Body::RevokeClient => !f.discarded[c] && cs[c].sig_ok,
            _ => false,
        };
        let mut verdict = false;
        if candidate {
            let sub = f.anc[c].clone_bits();
            proof {
                assert forall|j: nat| #[trigger] sub.has(j) <==> ancestor(cs@, c as int, j as int) by {
                    assert(f.anc[c as int].has(j) <==> ancestor(cs@, c as int, j as int));
                }
            }
            let st = apply(cs, f, &judged, Some(&sub), Ghost(Some(c as int)), genesis);
            let by = by_device_x(cs, f, c);
            let r2 = f.master_change[c] || match by {
                Some(a) => st.current(a),
                None => false,
            };
            let r3 = match &cs[c].body {
                Body::SignOut { device: Some(a) } => {
                    let a = *a;
                    let ordinary = match &cs[a].body {
                        Body::AddDevice { .. } => true,
                        _ => false,
                    };
                    ordinary && st.current(a)
                },
                Body::RevokeClient => true,
                _ => false,
            };
            verdict = r2 && r3;
        }
        proof {
            assert(verdict == judge_ok(cs@, ch, g, order, before, c as int));
        }
        if verdict {
            judged.set(c, true);
        }
        proof {
            // c is not its own ancestor, nor an ancestor of anything judged before it.
            assert(eligible(disc_seq(cs@, ch), c as int));
            assert(!disc_k(cs@, ch, c as int, 0));
            assert(in_dag(cs@, c as int));
            assert(agree(cs@, ch, c as int, before, judged@)) by {
                assert forall|d: int| 0 <= d < n && #[trigger] ancestor(cs@, c as int, d) && !discarded(cs@, ch, d) implies before[d] == judged@[d] by {
                    if d == c as int {
                        assert(ancestor(cs@, c as int, c as int));
                    }
                }
            }
            lemma_judge_frame(cs@, ch, g, order, before, judged@, c as int);
            assert forall|k: int| 0 <= k < t + 1 implies #[trigger] judged[order[k] as int] == judge_ok(cs@, ch, g, order, judged@, order[k] as int) by {
                if k < t {
                    let e = order[k] as int;
                    assert(agree(cs@, ch, e, before, judged@)) by {
                        assert forall|d: int| 0 <= d < n && #[trigger] ancestor(cs@, e, d) && !discarded(cs@, ch, d) implies before[d] == judged@[d] by {
                            if d == c as int {
                                // c is an eligible ancestor of order[k], so it was taken before k.
                                assert(ready(cs@, disc_seq(cs@, ch), order.subrange(0, k), e));
                                assert(order.subrange(0, k).contains(c));
                                let q = order.subrange(0, k).index_of(c);
                                assert(order[q] == c);
                                assert(order[t as int] == c);
                            }
                        }
                    }
                    lemma_judge_frame(cs@, ch, g, order, before, judged@, e);
                    assert(order[k] != c);
                }
            }
            assert forall|c2: int| 0 <= c2 < n && !order.subrange(0, t + 1).contains(c2 as usize) implies !#[trigger] judged[c2] by {
                assert(c2 != c as int) by {
                    if c2 == c as int {
                        assert(order.subrange(0, t + 1)[t as int] == c);
                    }
                }
                if order.subrange(0, t as int).contains(c2 as usize) {
                    let q = order.subrange(0, t as int).index_of(c2 as usize);
                    assert(order.subrange(0, t + 1)[q] == c2 as usize);
                }
            }
            assert forall|c2: int| 0 <= c2 < cs.len() && #[trigger] judged@[c2] implies sign_out_form(cs@, c2) by {
                if c2 == c as int && verdict {
                    assert(judge_ok(cs@, ch, g, order, before, c as int));
                }
            }
        }
        t = t + 1;
    }
    proof {
        assert(order.subrange(0, order.len() as int) =~= order);
        assert forall|c: int| 0 <= c < cs.len() implies #[trigger] judged@[c] == judge_ok(cs@, ch, g, order, judged@, c) by {
            if order.contains(c as usize) {
                let k = order.index_of(c as usize);
                assert(judged[order[k] as int] == judge_ok(cs@, ch, g, order, judged@, order[k] as int));
            } else {
                assert(!eligible(disc_seq(cs@, ch), c));
                assert(discarded(cs@, ch, c));
            }
        }
    }
    judged
}

/// Reads a log, section 5.4. `genesis` is the index of the change whose hash is the identity
/// ID. Returns `None` if the indices don't fit the log or the genesis change is invalid, in
/// which case there is no identity.
#[verifier::rlimit(100)]
pub fn read(cs: &Vec<Change>, genesis: usize) -> (r: Option<Reading>)
    ensures
        r is Some <==> valid(cs@) && genesis_ok(cs@, genesis as int),
        r matches Some(rd) ==> {
            let ch = chain(cs@, genesis as int);
            &&& anc_exact(cs@, rd.anc@)
            &&& rd.link.len() == cs.len()
            &&& rd.master_change.len() == cs.len()
            &&& rd.discarded.len() == cs.len()
            &&& rd.removal.len() == cs.len()
            &&& rd.sign_out.len() == cs.len()
            &&& rd.revocation.len() == cs.len()
            &&& rd.applied.len() == cs.len()
            &&& rd.current.len() == cs.len()
            &&& rd.announced.len() == cs.len()
            &&& (rd.secret as nat) < cs.len()
            // Steps 1 to 3 and reading order, exactly as section 5.4 describes them.
            &&& rd.link@.map_values(|o: Option<usize>| opt_nat(o)) == ch.link
            &&& rd.links@.map_values(|x: usize| x as int) == ch.reps
            &&& rd.conflict == ch.conflict
            &&& forall|i: int| 0 <= i < cs.len() ==> #[trigger] rd.master_change[i] == master_change(cs@, ch, i)
            &&& forall|i: int| 0 <= i < cs.len() ==> #[trigger] opt_int(rd.removal[i]) == removal(cs@, ch, i)
            &&& forall|i: int| 0 <= i < cs.len() ==> #[trigger] rd.discarded[i] == discarded(cs@, ch, i)
            &&& is_reading_order(cs@, disc_seq(cs@, ch), rd.order@)
            // Step 4 and step 5, exactly as section 5.4 describes them.
            &&& is_judgment(cs@, ch, genesis as int, rd.order@, rd.judged@)
            &&& {
                let st = outcome(cs@, ch, rd.judged@, None, genesis as int, rd.order@);
                &&& rd.applied@ == st.applied
                &&& rd.announced@ == st.announced
                &&& opt_int(rd.handle) == st.handle
                &&& opt_int(rd.home) == st.home
                &&& rd.secret as int == st.secret
                &&& rd.unreadable == st.unreadable
                &&& forall|i: int| 0 <= i < cs.len() ==> #[trigger] rd.current[i] == if cs@[i].body is AddDevice {
                    cur(st, i)
                } else {
                    !ch.conflict && ch.link[i] == Some(last_link(ch))
                }
            }
            &&& forall|i: int| 0 <= i < cs.len() ==> #[trigger] opt_int(rd.sign_out[i]) == counted(cs@, ch, rd.judged@, None, i)
            &&& forall|i: int| 0 <= i < cs.len() ==> #[trigger] rd.revocation[i] == (cs@[i].body is RevokeClient && !discarded(cs@, ch, i) && rd.judged[i])
            // Discarded changes are ignored from step 3 on: none is applied.
            &&& forall|i: int| 0 <= i < cs.len() && #[trigger] rd.applied[i] ==> !rd.discarded[i]
            // Only the master announces a data secret.
            &&& forall|i: int| 0 <= i < cs.len() && #[trigger] rd.announced[i] ==> i == genesis || rd.master_change[i]
            // Only ordinary devices are signed out.
            &&& forall|i: int| 0 <= i < cs.len() ==> (#[trigger] rd.sign_out[i] matches Some(a)
                ==> (a as int) < cs.len() && cs@[a as int].body is AddDevice)
        },
{
    if !check_valid(cs) || genesis >= cs.len() {
        return None;
    }
    let n = cs.len();
    let anc = ancestors(cs);
    let dag_flags = dag(cs, &anc);
    let genesis_ok = match &cs[genesis].body {
        Body::Genesis { key, next, work_ok } => *work_ok && cs[genesis].sig_ok && !eq32(key, next)
            && cs[genesis].prev.len() == 0 && dag_flags[genesis],
        _ => false,
    };
    if !genesis_ok {
        return None;
    }
    let mut f = Facts {
        n,
        in_dag: dag_flags,
        anc,
        link: Vec::new(),
        links: Vec::new(),
        conflict: false,
        master_change: Vec::new(),
        removal: Vec::new(),
        discarded: Vec::new(),
        order: Vec::new(),
    };
    while f.link.len() < n
        invariant
            f.link.len() <= n,
            f.link.len() == f.master_change.len(),
            f.link.len() == f.removal.len(),
            f.link.len() == f.discarded.len(),
            forall|k: int| 0 <= k < f.link.len() ==> f.removal[k] is None,
            forall|k: int| 0 <= k < f.link.len() ==> f.link[k] is None,
        decreases n - f.link.len(),
    {
        f.link.push(None);
        f.master_change.push(false);
        f.removal.push(None);
        f.discarded.push(false);
    }
    assert(f.wf(cs@));
    let ghost g = genesis as int;
    let conflicting = master_chain(cs, &mut f, genesis);
    let ghost ch = chain(cs@, g);
    f.master_change = master_changes(cs, &f, &conflicting);
    f.removal = master_removals(cs, &f);
    f.discarded = discard(cs, &f);
    proof {
        assert(f.discarded@ =~= disc_seq(cs@, ch));
        assert forall|j: int| 0 <= j < n && !(#[trigger] f.discarded@[j]) implies in_dag(cs@, j) by {
            if !in_dag(cs@, j) {
                assert(disc_k(cs@, ch, j, 0));
            }
        }
    }
    f.order = reading_order(cs, &f.anc, &f.discarded);
    proof {
        assert forall|k: int| 0 <= k < f.order.len() implies !f.discarded[#[trigger] f.order[k] as int] by {
            assert(f.order@.contains(f.order[k]));
        }
        assert forall|k: int| 0 <= k < f.order.len() implies (f.order[k] as nat) < n by {
            assert(f.order@.contains(f.order[k]));
        }
    }
    proof {
        assert forall|k: int| 0 <= k < f.order.len() implies !discarded(cs@, ch, #[trigger] f.order[k] as int) by {
            assert(f.order@.contains(f.order[k]));
        }
        assert(facts_ok(&f, cs@, g));
    }
    let judged = judge(cs, &f, genesis);
    let st = apply(cs, &f, &judged, None, Ghost(None), genesis);
    let ghost fin = outcome(cs@, ch, judged@, None, g, f.order@);

    let mut sign_out: Vec<Option<usize>> = Vec::new();
    let mut revocation: Vec<bool> = Vec::new();
    let mut current: Vec<bool> = Vec::new();
    let last = f.links.len() - 1;
    let mut i: usize = 0;
    while i < n
        invariant
            f.wf(cs@),
            st.wf(n as nat),
            n == f.n,
            i <= n,
            sign_out.len() == i,
            revocation.len() == i,
            current.len() == i,
            judged_ok(judged@, cs@),
            facts_ok(&f, cs@, g),
            ch == f.chain_view(),
            judged.len() == n,
            last + 1 == f.links.len(),
            st.view_st() == fin,
            forall|k: int| 0 <= k < i ==> (#[trigger] sign_out[k] matches Some(a)
                ==> (a as int) < n && cs@[a as int].body is AddDevice),
            forall|k: int| 0 <= k < i ==> #[trigger] opt_int(sign_out[k]) == counted(cs@, ch, judged@, None, k),
            forall|k: int| 0 <= k < i ==> #[trigger] revocation[k] == (cs@[k].body is RevokeClient && !discarded(cs@, ch, k) && judged[k]),
            forall|k: int| 0 <= k < i ==> #[trigger] current[k] == if cs@[k].body is AddDevice {
                cur(fin, k)
            } else {
                !ch.conflict && ch.link[k] == Some(last_link(ch))
            },
        decreases n - i,
    {
        let so = counted_x(cs, &f, &judged, None, Ghost(None), i);
        proof {
            if let Some(a) = so {
                assert(judged[i as int]);
                assert(sign_out_form(cs@, i as int));
            }
        }
        sign_out.push(so);
        revocation.push(match &cs[i].body {
            Body::RevokeClient => !f.discarded[i] && judged[i],
            _ => false,
        });
        assert(ch.link[i as int] == opt_nat(f.link[i as int]));
        let cur = match &cs[i].body {
            Body::AddDevice { .. } => st.current(i),
            _ => !f.conflict && f.link[i] == Some(last),
        };
        current.push(cur);
        i = i + 1;
    }
    Some(Reading {
        anc: f.anc,
        order: f.order,
        link: f.link,
        links: f.links,
        conflict: f.conflict,
        master_change: f.master_change,
        discarded: f.discarded,
        removal: f.removal,
        sign_out,
        revocation,
        judged,
        applied: st.applied,
        current,
        handle: st.handle,
        home: st.home,
        secret: st.secret,
        announced: st.announced,
        unreadable: st.unreadable,
    })
}

} // verus!
