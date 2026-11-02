//! Section 5.4 as a specification. Each function transcribes a rule of the README's section 5.4; `log::read` is
//! proven to compute exactly these.
use crate::dag::*;
use crate::log::*;
use crate::order::*;
use vstd::prelude::*;

verus! {

// Keys among ancestors (section 5.3).

/// `key` is the `key` or `reveal` of this body (a `genesis`, `set-master` or `add-device`).
pub open spec fn uses_key(b: Body, key: Seq<u8>) -> bool {
    match b {
        Body::Genesis { key: k, .. } => k@ == key,
        Body::AddDevice { key: k } => k@ == key,
        Body::SetMaster { reveal, key: k, .. } => k@ == key || reveal@ == key,
        _ => false,
    }
}

/// `fp` is the `next` of this body (a `genesis` or `set-master`).
pub open spec fn uses_next(b: Body, fp: Seq<u8>) -> bool {
    match b {
        Body::Genesis { next, .. } => next@ == fp,
        Body::SetMaster { next, .. } => next@ == fp,
        _ => false,
    }
}

/// `key` is the `key` or `reveal` of a `genesis`, `set-master` or `add-device` change among
/// change i's ancestors.
pub open spec fn key_among(cs: Seq<Change>, i: int, key: Seq<u8>) -> bool {
    exists|j: int| 0 <= j < cs.len() && #[trigger] ancestor(cs, i, j) && in_dag(cs, j) && uses_key(cs[j].body, key)
}

/// `fp` is the `next` of a `genesis` or `set-master` change among change i's ancestors.
pub open spec fn next_among(cs: Seq<Change>, i: int, fp: Seq<u8>) -> bool {
    exists|j: int| 0 <= j < cs.len() && #[trigger] ancestor(cs, i, j) && in_dag(cs, j) && uses_next(cs[j].body, fp)
}

// The genesis change (section 5.2).

pub open spec fn genesis_ok(cs: Seq<Change>, g: int) -> bool {
    &&& 0 <= g < cs.len()
    &&& in_dag(cs, g)
    &&& cs[g].sig_ok
    &&& cs[g].prev.len() == 0
    &&& match cs[g].body {
        Body::Genesis { key, next, work_ok } => work_ok && key@ != next@,
        _ => false,
    }
}

pub open spec fn zero32() -> Seq<u8> {
    Seq::new(32, |i: int| 0u8)
}

pub open spec fn next_of(b: Body) -> Seq<u8> {
    match b {
        Body::Genesis { next, .. } => next@,
        Body::SetMaster { next, .. } => next@,
        _ => zero32(),
    }
}

// Step 1: the master chain.

/// The chain so far: which link (if any) each change is a copy of, one change per link (the
/// lowest-numbered copy), and whether it ended in a master conflict.
pub struct ChainSpec {
    pub link: Seq<Option<nat>>,
    pub reps: Seq<int>,
    pub conflict: bool,
}

/// Some copy of link k is among change i's ancestors.
pub open spec fn has_link(cs: Seq<Change>, link: Seq<Option<nat>>, k: nat, i: int) -> bool {
    exists|c: int| 0 <= c < cs.len() && link[c] == Some(k) && #[trigger] ancestor(cs, i, c)
}

/// Change i is a next link after link k, whose `next` is `nx`: the fingerprint of its `reveal`
/// is `nx`, its signature is valid for `reveal`, link k is among its ancestors, its `key` differs
/// from its `reveal` and isn't the `key` or `reveal` of any `genesis`, `set-master` or
/// `add-device` among its ancestors, and its `next` isn't its own `key`, its `reveal`, or any
/// `key` or `reveal` among its ancestors. Changes already in the chain aren't candidates again.
#[verifier::opaque]
pub open spec fn cand(cs: Seq<Change>, link: Seq<Option<nat>>, k: nat, nx: Seq<u8>, i: int) -> bool {
    &&& 0 <= i < cs.len()
    &&& in_dag(cs, i)
    &&& cs[i].sig_ok
    &&& link[i] is None
    &&& match cs[i].body {
        Body::SetMaster { reveal, key, next } => {
            &&& reveal@ == nx
            &&& has_link(cs, link, k, i)
            &&& key@ != reveal@
            &&& !key_among(cs, i, key@)
            &&& next@ != key@
            &&& next@ != reveal@
            &&& !key_among(cs, i, next@)
        },
        _ => false,
    }
}

pub proof fn lemma_cand_form(cs: Seq<Change>, link: Seq<Option<nat>>, k: nat, nx: Seq<u8>, i: int)
    requires
        cand(cs, link, k, nx, i),
    ensures
        0 <= i < cs.len(),
        cs[i].body is SetMaster,
{
    reveal(cand);
}

pub open spec fn last_link(st: ChainSpec) -> nat {
    (st.reps.len() - 1) as nat
}

pub open spec fn last_next(cs: Seq<Change>, st: ChainSpec) -> Seq<u8> {
    next_of(cs[st.reps.last()].body)
}

/// A candidate next link after the chain's last link.
pub open spec fn next_cand(cs: Seq<Change>, st: ChainSpec, i: int) -> bool {
    cand(cs, st.link, last_link(st), last_next(cs, st), i)
}

/// The lowest-numbered candidate.
pub open spec fn first_cand(cs: Seq<Change>, st: ChainSpec) -> int {
    choose|i: int| next_cand(cs, st, i) && forall|j: int| #[trigger] next_cand(cs, st, j) ==> i <= j
}

/// Candidates that are identical apart from `sig` share their device ID and count as one; next
/// links that differ in anything else are a master conflict. `fuel` caps the chain at as many
/// links as there are changes, which a log without SHA-256 collisions never reaches.
pub open spec fn chain_step(cs: Seq<Change>, st: ChainSpec, fuel: nat) -> ChainSpec
    decreases fuel,
{
    if !(exists|i: int| next_cand(cs, st, i)) {
        st
    } else {
        let first = first_cand(cs, st);
        if exists|i: int| next_cand(cs, st, i) && cs[i].id@ != cs[first].id@ {
            ChainSpec { link: st.link, reps: st.reps, conflict: true }
        } else if fuel == 0 {
            st
        } else {
            let k = last_link(st);
            chain_step(
                cs,
                ChainSpec {
                    link: Seq::new(st.link.len(), |i: int| if next_cand(cs, st, i) { Some((k + 1) as nat) } else { st.link[i] }),
                    reps: st.reps.push(first),
                    conflict: false,
                },
                (fuel - 1) as nat,
            )
        }
    }
}

pub open spec fn chain_start(cs: Seq<Change>, g: int) -> ChainSpec {
    ChainSpec { link: Seq::new(cs.len(), |i: int| if i == g { Some(0nat) } else { None }), reps: seq![g], conflict: false }
}

pub open spec fn chain(cs: Seq<Change>, g: int) -> ChainSpec {
    chain_step(cs, chain_start(cs, g), cs.len() as nat)
}

/// Change c is a next link of link k: a copy of link k + 1, or, when the chain ended in a master
/// conflict at link k, one of the conflicting next links.
pub open spec fn next_link(cs: Seq<Change>, ch: ChainSpec, k: nat, c: int) -> bool {
    ch.link[c] == Some((k + 1) as nat) || (ch.conflict && k == last_link(ch) && next_cand(cs, ch, c))
}

/// The link whose device ID change i's `by` names.
pub open spec fn by_link(cs: Seq<Change>, ch: ChainSpec, i: int) -> Option<nat> {
    match cs[i].by {
        By::Change(j) => ch.link[j as int],
        _ => None,
    }
}

/// A master change: a link itself, or a change by a link's device, signed by its master key,
/// that has that link among its ancestors and is an ancestor of every next link of that link.
pub open spec fn master_change(cs: Seq<Change>, ch: ChainSpec, i: int) -> bool {
    &&& in_dag(cs, i)
    &&& (ch.link[i] is Some || (cs[i].sig_ok && match by_link(cs, ch, i) {
        Some(k) => has_link(cs, ch.link, k, i) && forall|c: int| 0 <= c < cs.len() && #[trigger] next_link(cs, ch, k, c) ==> ancestor(cs, c, i),
        None => false,
    }))
}

// Step 2: master removals.

pub open spec fn keep_ok(cs: Seq<Change>, i: int, a: int, keep: Keep) -> bool {
    match keep {
        Keep::Absent => true,
        Keep::Missing => false,
        Keep::Found(kk) => cs[kk as int].by == By::Change(a as usize) && in_dag(cs, kk as int) && ancestor(cs, i, kk as int),
    }
}

/// A master removal: a master change removing a device whose `add-device` change is among its
/// ancestors, with `keep`, if given, a change by that device among its ancestors. Returns the
/// device's `add-device` change.
pub open spec fn removal(cs: Seq<Change>, ch: ChainSpec, i: int) -> Option<int> {
    if in_dag(cs, i) && master_change(cs, ch, i) {
        match cs[i].body {
            Body::RemoveDevice { device: Some(a), keep } => if cs[a as int].body is AddDevice && in_dag(cs, a as int)
                && ancestor(cs, i, a as int) && keep_ok(cs, i, a as int, keep) {
                Some(a as int)
            } else {
                None
            },
            _ => None,
        }
    } else {
        None
    }
}

// Step 3: discarded changes.

/// The `add-device` change of the ordinary device that signed change i.
pub open spec fn by_device(cs: Seq<Change>, i: int) -> Option<int> {
    match cs[i].by {
        By::Change(j) => if cs[j as int].body is AddDevice && in_dag(cs, j as int) { Some(j as int) } else { None },
        _ => None,
    }
}

/// Change i is removal r's `keep`, or an ancestor of it.
pub open spec fn kept_by(cs: Seq<Change>, r: int, i: int) -> bool {
    match cs[r].body {
        Body::RemoveDevice { keep: Keep::Found(kk), .. } => kk as int == i || ancestor(cs, kk as int, i),
        _ => false,
    }
}

/// Discarded without looking at other discarded changes: outside the log proper, signed by a
/// link's master key but not a master change, or by a removed device and not kept by every one
/// of its master removals.
pub open spec fn disc_base(cs: Seq<Change>, ch: ChainSpec, i: int) -> bool {
    ||| !in_dag(cs, i)
    ||| (by_link(cs, ch, i) is Some && !master_change(cs, ch, i))
    ||| match by_device(cs, i) {
        Some(a) => exists|r: int| 0 <= r < cs.len() && #[trigger] removal(cs, ch, r) == Some(a) && !kept_by(cs, r, i),
        None => false,
    }
}

/// ... or the `add-device` change that added its signer is discarded, through k such steps.
pub open spec fn disc_k(cs: Seq<Change>, ch: ChainSpec, i: int, k: nat) -> bool
    decreases k,
{
    disc_base(cs, ch, i) || (k > 0 && match by_device(cs, i) {
        Some(a) => disc_k(cs, ch, a, (k - 1) as nat),
        None => false,
    })
}

pub open spec fn discarded(cs: Seq<Change>, ch: ChainSpec, i: int) -> bool {
    exists|k: nat| #[trigger] disc_k(cs, ch, i, k)
}

pub open spec fn disc_seq(cs: Seq<Change>, ch: ChainSpec) -> Seq<bool> {
    Seq::new(cs.len(), |i: int| discarded(cs, ch, i))
}

// Steps 4 and 5: judging on their own, and applying changes.

/// The state while applying changes in reading order.
pub struct St {
    pub added: Seq<bool>,
    pub out: Seq<bool>,
    pub removed: Seq<bool>,
    pub applied: Seq<bool>,
    pub handle: Option<int>,
    pub home: Option<int>,
    pub secret: int,
    pub announced: Seq<bool>,
    pub unreadable: bool,
    /// Ordinary devices added and not removed.
    pub active: nat,
}

/// Change x is in the (sub-)log: the whole log, or the ancestors of change c.
pub open spec fn in_s(cs: Seq<Change>, sub: Option<int>, x: int) -> bool {
    match sub {
        None => true,
        Some(c) => ancestor(cs, c, x),
    }
}

pub open spec fn removed_in(cs: Seq<Change>, ch: ChainSpec, sub: Option<int>, a: int) -> bool {
    exists|r: int| 0 <= r < cs.len() && #[trigger] removal(cs, ch, r) == Some(a) && in_s(cs, sub, r)
}

/// A sign-out that counts in the (sub-)log: not discarded, allowed when judged on its own, and
/// its device has no master removal there. Returns the device's `add-device` change.
pub open spec fn counted(cs: Seq<Change>, ch: ChainSpec, judged: Seq<bool>, sub: Option<int>, s: int) -> Option<int> {
    if in_s(cs, sub, s) && !discarded(cs, ch, s) && judged[s] {
        match cs[s].body {
            Body::SignOut { device: Some(a) } => if removed_in(cs, ch, sub, a as int) { None } else { Some(a as int) },
            _ => None,
        }
    } else {
        None
    }
}

/// Ordinary device a is current: added, and no sign-out or master removal of it reached yet.
pub open spec fn cur(st: St, a: int) -> bool {
    st.added[a] && !st.out[a] && !st.removed[a]
}

/// Rule 2: a master change, or `by` is a current ordinary device.
pub open spec fn rule2(cs: Seq<Change>, ch: ChainSpec, st: St, x: int) -> bool {
    master_change(cs, ch, x) || match by_device(cs, x) {
        Some(a) => cur(st, a),
        None => false,
    }
}

/// Rule 4: an ancestor of every sign-out of `by`.
pub open spec fn rule4(cs: Seq<Change>, ch: ChainSpec, judged: Seq<bool>, sub: Option<int>, x: int) -> bool {
    match by_device(cs, x) {
        Some(a) => forall|s: int| 0 <= s < cs.len() && #[trigger] counted(cs, ch, judged, sub, s) == Some(a) ==> ancestor(cs, s, x),
        None => true,
    }
}

/// Rule 3 and the effect of a change that passed rules 1, 2 and 4.
pub open spec fn effect(cs: Seq<Change>, ch: ChainSpec, sub: Option<int>, st: St, x: int) -> St {
    match cs[x].body {
        Body::Future => if sub is None { St { unreadable: true, ..st } } else { st },
        Body::AddDevice { key } => if !key_among(cs, x, key@) && !next_among(cs, x, key@) && st.active < MAX_DEVICES {
            St { active: st.active + 1, added: st.added.update(x, true), applied: st.applied.update(x, true), ..st }
        } else {
            st
        },
        Body::SetHandle => St { handle: Some(x), applied: st.applied.update(x, true), ..st },
        Body::SetHome => St { home: Some(x), applied: st.applied.update(x, true), ..st },
        Body::NewSecret => if master_change(cs, ch, x) {
            St { secret: x, announced: st.announced.update(x, true), applied: st.applied.update(x, true), ..st }
        } else {
            st
        },
        _ => st,
    }
}

/// Applies change x. Links are applied as step 1 decides; master removals, sign-outs and
/// revocations take effect when reached; sign-outs that don't count, `set-master` changes that
/// aren't links, removals that aren't master removals and invalid changes do nothing; any other
/// change applies if it passes rules 1 to 4.
pub open spec fn step(cs: Seq<Change>, ch: ChainSpec, judged: Seq<bool>, sub: Option<int>, st: St, x: int) -> St {
    if !in_s(cs, sub, x) {
        st
    } else if ch.link[x] is Some {
        if cs[x].body is Genesis {
            St { applied: st.applied.update(x, true), secret: x, announced: st.announced.update(x, true), ..st }
        } else {
            St { applied: st.applied.update(x, true), ..st }
        }
    } else if removal(cs, ch, x) is Some {
        let a = removal(cs, ch, x)->Some_0;
        St {
            active: if st.added[a] && !st.removed[a] && st.active > 0 { (st.active - 1) as nat } else { st.active },
            removed: st.removed.update(a, true),
            applied: st.applied.update(x, true),
            ..st
        }
    } else if counted(cs, ch, judged, sub, x) is Some {
        let a = counted(cs, ch, judged, sub, x)->Some_0;
        St { out: st.out.update(a, true), applied: st.applied.update(x, true), ..st }
    } else {
        match cs[x].body {
            Body::RevokeClient => if judged[x] { St { applied: st.applied.update(x, true), ..st } } else { st },
            Body::SignOut { .. } | Body::SetMaster { .. } | Body::RemoveDevice { .. } | Body::Invalid | Body::Genesis { .. } => st,
            _ => if cs[x].sig_ok && rule2(cs, ch, st, x) && rule4(cs, ch, judged, sub, x) {
                effect(cs, ch, sub, st, x)
            } else {
                st
            },
        }
    }
}

pub open spec fn st_init(n: nat, g: int) -> St {
    St {
        added: Seq::new(n, |i: int| false),
        out: Seq::new(n, |i: int| false),
        removed: Seq::new(n, |i: int| false),
        applied: Seq::new(n, |i: int| false),
        handle: None,
        home: None,
        secret: g,
        announced: Seq::new(n, |i: int| false),
        unreadable: false,
        active: 0,
    }
}

/// The state after applying the first t changes of reading order.
pub open spec fn run(cs: Seq<Change>, ch: ChainSpec, judged: Seq<bool>, sub: Option<int>, g: int, order: Seq<usize>, t: nat) -> St
    decreases t,
{
    if t == 0 || t > order.len() {
        st_init(cs.len() as nat, g)
    } else {
        step(cs, ch, judged, sub, run(cs, ch, judged, sub, g, order, (t - 1) as nat), order[t - 1] as int)
    }
}

pub open spec fn outcome(cs: Seq<Change>, ch: ChainSpec, judged: Seq<bool>, sub: Option<int>, g: int, order: Seq<usize>) -> St {
    run(cs, ch, judged, sub, g, order, order.len())
}

/// Step 4: a sign-out or revocation judged on its own: read the log of only its ancestors, then
/// check it against rules 1 to 3 at the end of that reading.
pub open spec fn judge_ok(cs: Seq<Change>, ch: ChainSpec, g: int, order: Seq<usize>, judged: Seq<bool>, c: int) -> bool {
    let st = outcome(cs, ch, judged, Some(c), g, order);
    &&& (cs[c].body is SignOut || cs[c].body is RevokeClient)
    &&& !discarded(cs, ch, c)
    &&& cs[c].sig_ok
    &&& rule2(cs, ch, st, c)
    &&& match cs[c].body {
        Body::SignOut { device: Some(a) } => cs[a as int].body is AddDevice && cur(st, a as int) && by_device(cs, c) != Some(a as int),
        Body::RevokeClient => true,
        _ => false,
    }
}

/// Every change is judged exactly as step 4 says, given the judgments of its ancestors.
pub open spec fn is_judgment(cs: Seq<Change>, ch: ChainSpec, g: int, order: Seq<usize>, judged: Seq<bool>) -> bool {
    &&& judged.len() == cs.len()
    &&& forall|c: int| 0 <= c < cs.len() ==> #[trigger] judged[c] == judge_ok(cs, ch, g, order, judged, c)
}

/// Two judgments agree on the non-discarded ancestors of change c.
pub open spec fn agree(cs: Seq<Change>, ch: ChainSpec, c: int, j1: Seq<bool>, j2: Seq<bool>) -> bool {
    forall|d: int| 0 <= d < cs.len() && #[trigger] ancestor(cs, c, d) && !discarded(cs, ch, d) ==> j1[d] == j2[d]
}

proof fn lemma_counted_frame(cs: Seq<Change>, ch: ChainSpec, j1: Seq<bool>, j2: Seq<bool>, c: int, s: int)
    requires
        agree(cs, ch, c, j1, j2),
        0 <= s < cs.len(),
    ensures
        counted(cs, ch, j1, Some(c), s) == counted(cs, ch, j2, Some(c), s),
{
}

proof fn lemma_run_frame(cs: Seq<Change>, ch: ChainSpec, j1: Seq<bool>, j2: Seq<bool>, c: int, g: int, order: Seq<usize>, t: nat)
    requires
        agree(cs, ch, c, j1, j2),
        forall|k: int| 0 <= k < order.len() ==> (order[k] as int) < cs.len() && !discarded(cs, ch, #[trigger] order[k] as int),
    ensures
        run(cs, ch, j1, Some(c), g, order, t) == run(cs, ch, j2, Some(c), g, order, t),
    decreases t,
{
    if t > 0 && t <= order.len() {
        lemma_run_frame(cs, ch, j1, j2, c, g, order, (t - 1) as nat);
        let x = order[t - 1] as int;
        assert(!discarded(cs, ch, x));
        assert forall|s: int| 0 <= s < cs.len() implies #[trigger] counted(cs, ch, j1, Some(c), s) == counted(cs, ch, j2, Some(c), s) by {
            lemma_counted_frame(cs, ch, j1, j2, c, s);
        }
        if let Some(a) = by_device(cs, x) {
            if rule4(cs, ch, j1, Some(c), x) {
                assert forall|s: int| 0 <= s < cs.len() && #[trigger] counted(cs, ch, j2, Some(c), s) == Some(a) implies ancestor(cs, s, x) by {
                    assert(counted(cs, ch, j1, Some(c), s) == counted(cs, ch, j2, Some(c), s));
                }
            }
            if rule4(cs, ch, j2, Some(c), x) {
                assert forall|s: int| 0 <= s < cs.len() && #[trigger] counted(cs, ch, j1, Some(c), s) == Some(a) implies ancestor(cs, s, x) by {
                    assert(counted(cs, ch, j1, Some(c), s) == counted(cs, ch, j2, Some(c), s));
                }
            }
        }
        assert(rule4(cs, ch, j1, Some(c), x) == rule4(cs, ch, j2, Some(c), x));
    }
}

/// Judging a change looks only at the judgments of its non-discarded ancestors.
pub proof fn lemma_judge_frame(cs: Seq<Change>, ch: ChainSpec, g: int, order: Seq<usize>, j1: Seq<bool>, j2: Seq<bool>, c: int)
    requires
        agree(cs, ch, c, j1, j2),
        forall|k: int| 0 <= k < order.len() ==> (order[k] as int) < cs.len() && !discarded(cs, ch, #[trigger] order[k] as int),
    ensures
        judge_ok(cs, ch, g, order, j1, c) == judge_ok(cs, ch, g, order, j2, c),
{
    lemma_run_frame(cs, ch, j1, j2, c, g, order, order.len());
}

proof fn lemma_judgment_agree(cs: Seq<Change>, ch: ChainSpec, g: int, order: Seq<usize>, j1: Seq<bool>, j2: Seq<bool>, c: int, bound: nat)
    requires
        valid(cs),
        is_judgment(cs, ch, g, order, j1),
        is_judgment(cs, ch, g, order, j2),
        forall|k: int| 0 <= k < order.len() ==> (order[k] as int) < cs.len() && !discarded(cs, ch, #[trigger] order[k] as int),
        forall|j: int| 0 <= j < cs.len() && !discarded(cs, ch, j) ==> in_dag(cs, j),
        0 <= c < cs.len(),
        anc_card(cs, c) <= bound,
    ensures
        j1[c] == j2[c],
    decreases bound,
{
    if !discarded(cs, ch, c) {
        assert forall|d: int| 0 <= d < cs.len() && #[trigger] ancestor(cs, c, d) && !discarded(cs, ch, d) implies j1[d] == j2[d] by {
            lemma_anc_card_drops(cs, c, d);
            lemma_judgment_agree(cs, ch, g, order, j1, j2, d, (bound - 1) as nat);
        }
        lemma_judge_frame(cs, ch, g, order, j1, j2, c);
    }
}

/// Only one judgment fits step 4.
pub proof fn lemma_judgment_unique(cs: Seq<Change>, ch: ChainSpec, g: int, order: Seq<usize>, j1: Seq<bool>, j2: Seq<bool>)
    requires
        valid(cs),
        is_judgment(cs, ch, g, order, j1),
        is_judgment(cs, ch, g, order, j2),
        forall|k: int| 0 <= k < order.len() ==> (order[k] as int) < cs.len() && !discarded(cs, ch, #[trigger] order[k] as int),
        forall|j: int| 0 <= j < cs.len() && !discarded(cs, ch, j) ==> in_dag(cs, j),
    ensures
        j1 == j2,
{
    assert forall|c: int| 0 <= c < cs.len() implies j1[c] == j2[c] by {
        lemma_judgment_agree(cs, ch, g, order, j1, j2, c, anc_card(cs, c));
    }
    assert(j1 =~= j2);
}

} // verus!
