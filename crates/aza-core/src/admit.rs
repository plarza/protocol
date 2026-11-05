//! Which uploaded changes a node keeps (section 11): a node limits a log only per signing device,
//! so a stolen device can never stop the others repairing the identity.
//!
//! - A master change is always kept, so the master can always repair.
//! - A `genesis` change that isn't the identity's, or a `set-master` that doesn't reveal the next
//!   key of a link, is refused: anyone can sign one with a key of their own. A `set-master` that
//!   does counts toward that link's allowance, so competing handoffs still reach the log.
//! - An `add-device` that wouldn't be applied is refused, so every device a node holds changes
//!   for was once current, and a thief controls at most 64 devices.
//! - A device's first sign-out of each other device is always kept.
//! - Otherwise a device's changes are kept up to `ALLOWANCE`.
use crate::log::*;
use crate::spec::*;
use vstd::prelude::*;

verus! {

/// How many changes a device signs that count toward its allowance.
pub const ALLOWANCE: u64 = 128;

/// The first link, from the `k`-th on, whose `next` is `h`.
pub open spec fn link_with_next(cs: Seq<Change>, links: Seq<usize>, h: Seq<u8>, k: int) -> Option<int>
    decreases links.len() - k,
{
    if k < 0 || k >= links.len() {
        None
    } else if next_of(cs[links[k] as int].body) == h {
        Some(links[k] as int)
    } else {
        link_with_next(cs, links, h, k + 1)
    }
}

/// The device whose allowance change i counts toward: the device `by` names, or for a
/// `set-master` the link whose next key it reveals.
pub open spec fn signer(cs: Seq<Change>, links: Seq<usize>, i: int) -> Option<int> {
    match cs[i].body {
        Body::SetMaster { reveal, .. } => link_with_next(cs, links, reveal@, 0),
        _ => match cs[i].by {
            By::Change(j) => Some(j as int),
            _ => None,
        },
    }
}

/// Change j is a kept sign-out by device s of device d.
pub open spec fn kept_out(cs: Seq<Change>, links: Seq<usize>, kept: Seq<bool>, j: int, s: int, d: usize) -> bool {
    kept[j] && signer(cs, links, j) == Some(s) && cs[j].body == (Body::SignOut { device: Some(d) })
}

/// The device a sign-out names, if it is in the log.
pub open spec fn out_device(b: Body) -> Option<usize> {
    match b {
        Body::SignOut { device } => device,
        _ => None,
    }
}

/// Change i is its signer's first kept sign-out of the device it names.
pub open spec fn first_out(cs: Seq<Change>, links: Seq<usize>, kept: Seq<bool>, i: int) -> bool {
    let d = out_device(cs[i].body);
    let s = signer(cs, links, i);
    &&& d is Some
    &&& s is Some
    &&& forall|j: int| 0 <= j < i ==> !#[trigger] kept_out(cs, links, kept, j, s->Some_0, d->Some_0)
}

/// Change i counts toward its signer's allowance.
pub open spec fn counted(cs: Seq<Change>, links: Seq<usize>, mc: Seq<bool>, kept: Seq<bool>, i: int) -> bool {
    !mc[i] && !first_out(cs, links, kept, i)
}

/// How many of the first `k` changes are kept and count toward device s's allowance.
pub open spec fn count(cs: Seq<Change>, links: Seq<usize>, mc: Seq<bool>, kept: Seq<bool>, s: int, k: int) -> nat
    decreases k,
{
    if k <= 0 {
        0
    } else {
        let j = k - 1;
        count(cs, links, mc, kept, s, j) + if kept[j] && counted(cs, links, mc, kept, j) && signer(cs, links, j) == Some(s) { 1nat } else { 0nat }
    }
}

/// Whether a node keeps uploaded change i, given what it kept of the changes before it.
pub open spec fn admit_one(cs: Seq<Change>, links: Seq<usize>, mc: Seq<bool>, applied: Seq<bool>, kept: Seq<bool>, i: int) -> bool {
    if mc[i] {
        true
    } else if cs[i].body is Genesis {
        false
    } else {
        match signer(cs, links, i) {
            None => false,
            Some(s) => {
                if cs[i].body is AddDevice && !applied[i] {
                    false
                } else if first_out(cs, links, kept, i) {
                    true
                } else {
                    count(cs, links, mc, kept, s, i) < ALLOWANCE
                }
            },
        }
    }
}

/// What a node holds of the first `k` changes: those it stored already, and the uploaded ones it
/// keeps, decided in order.
pub open spec fn decisions(cs: Seq<Change>, links: Seq<usize>, mc: Seq<bool>, applied: Seq<bool>, stored: Seq<bool>, fresh: Seq<bool>, k: nat) -> Seq<bool>
    decreases k,
{
    if k == 0 {
        Seq::empty()
    } else {
        let prev = decisions(cs, links, mc, applied, stored, fresh, (k - 1) as nat);
        let i = (k - 1) as int;
        prev.push(stored[i] || (fresh[i] && admit_one(cs, links, mc, applied, prev, i)))
    }
}

proof fn lemma_decisions_len(cs: Seq<Change>, links: Seq<usize>, mc: Seq<bool>, applied: Seq<bool>, stored: Seq<bool>, fresh: Seq<bool>, k: nat)
    ensures
        decisions(cs, links, mc, applied, stored, fresh, k).len() == k,
    decreases k,
{
    if k > 0 {
        lemma_decisions_len(cs, links, mc, applied, stored, fresh, (k - 1) as nat);
    }
}

/// `first_out` and `count` only look at decisions before the change they ask about.
proof fn lemma_prefix(cs: Seq<Change>, links: Seq<usize>, mc: Seq<bool>, a: Seq<bool>, b: Seq<bool>, s: int, k: int)
    requires
        0 <= k <= a.len(),
        k <= b.len(),
        forall|j: int| 0 <= j < k ==> a[j] == b[j],
    ensures
        count(cs, links, mc, a, s, k) == count(cs, links, mc, b, s, k),
        forall|i: int| 0 <= i < k ==> first_out(cs, links, a, i) == first_out(cs, links, b, i),
    decreases k,
{
    if k > 0 {
        lemma_prefix(cs, links, mc, a, b, s, k - 1);
        lemma_first_out_prefix(cs, links, a, b, k - 1);
    }
}

proof fn lemma_first_out_prefix(cs: Seq<Change>, links: Seq<usize>, a: Seq<bool>, b: Seq<bool>, i: int)
    requires
        0 <= i,
        i <= a.len(),
        i <= b.len(),
        forall|j: int| 0 <= j < i ==> a[j] == b[j],
    ensures
        first_out(cs, links, a, i) == first_out(cs, links, b, i),
{
    if out_device(cs[i].body) is Some && signer(cs, links, i) is Some {
        let d = out_device(cs[i].body)->Some_0;
        let s = signer(cs, links, i)->Some_0;
        assert forall|j: int| 0 <= j < i implies kept_out(cs, links, a, j, s, d) == kept_out(cs, links, b, j, s, d) by {}
        if first_out(cs, links, a, i) {
            assert forall|j: int| 0 <= j < i implies !#[trigger] kept_out(cs, links, b, j, s, d) by {
                assert(!kept_out(cs, links, a, j, s, d));
            }
        }
        if first_out(cs, links, b, i) {
            assert forall|j: int| 0 <= j < i implies !#[trigger] kept_out(cs, links, a, j, s, d) by {
                assert(!kept_out(cs, links, b, j, s, d));
            }
        }
    }
}

fn signer_x(cs: &Vec<Change>, links: &Vec<usize>, i: usize) -> (r: Option<usize>)
    requires
        i < cs.len(),
        valid(cs@),
        forall|k: int| 0 <= k < links.len() ==> (links[k] as int) < cs.len(),
    ensures
        r matches Some(s) ==> (s as int) < cs.len() && signer(cs@, links@, i as int) == Some(s as int),
        r is None ==> signer(cs@, links@, i as int) is None,
{
    match &cs[i].body {
        Body::SetMaster { reveal, .. } => {
            assert(signer(cs@, links@, i as int) == link_with_next(cs@, links@, reveal@, 0));
            let mut k: usize = 0;
            while k < links.len()
                invariant
                    k <= links.len(),
                    forall|q: int| 0 <= q < links.len() ==> (links[q] as int) < cs.len(),
                    link_with_next(cs@, links@, reveal@, 0) == link_with_next(cs@, links@, reveal@, k as int),
                    signer(cs@, links@, i as int) == link_with_next(cs@, links@, reveal@, 0),
                decreases links.len() - k,
            {
                if eq32(&next_of_x(&cs[links[k]].body), reveal) {
                    assert(link_with_next(cs@, links@, reveal@, k as int) == Some(links[k as int] as int));
                    return Some(links[k]);
                }
                k = k + 1;
            }
            None
        },
        _ => match cs[i].by {
            By::Change(j) => {
                assert(change_ok(cs@[i as int], cs.len() as nat));
                Some(j)
            },
            _ => None,
        },
    }
}

/// Which changes a node holds once an upload is decided. `stored` marks the changes it already
/// holds; `fresh` the uploaded ones whose signatures it checked. Both describe the log read with
/// every one of them.
pub fn admit(cs: &Vec<Change>, links: &Vec<usize>, master_change: &Vec<bool>, applied: &Vec<bool>, stored: &Vec<bool>, fresh: &Vec<bool>) -> (kept: Vec<bool>)
    requires
        valid(cs@),
        forall|k: int| 0 <= k < links.len() ==> (links[k] as int) < cs.len(),
        master_change.len() == cs.len(),
        applied.len() == cs.len(),
        stored.len() == cs.len(),
        fresh.len() == cs.len(),
    ensures
        kept@ == decisions(cs@, links@, master_change@, applied@, stored@, fresh@, cs.len() as nat),
{
    let n = cs.len();
    let ghost mc = master_change@;
    let ghost ap = applied@;
    let mut kept: Vec<bool> = Vec::new();
    // counts[s]: kept changes of device s that count toward its allowance.
    let mut counts: Vec<u64> = Vec::new();
    while counts.len() < n
        invariant
            counts.len() <= n,
            forall|s: int| 0 <= s < counts.len() ==> counts[s] == 0,
        decreases n - counts.len(),
    {
        counts.push(0);
    }
    // Every kept sign-out, as (signer, device signed out).
    let mut outs: Vec<(usize, usize)> = Vec::new();
    let mut i: usize = 0;
    while i < n
        invariant
            i <= n == cs.len() == master_change.len() == applied.len() == stored.len() == fresh.len() <= MAX_CHANGES,
            valid(cs@),
            forall|k: int| 0 <= k < links.len() ==> (links[k] as int) < cs.len(),
            mc == master_change@,
            ap == applied@,
            kept@ == decisions(cs@, links@, mc, ap, stored@, fresh@, i as nat),
            counts.len() == n,
            forall|s: int| 0 <= s < n ==> #[trigger] counts[s] as nat == count(cs@, links@, mc, kept@, s, i as int),
            forall|s: int| 0 <= s < n ==> #[trigger] counts[s] <= i,
            forall|s: usize, d: usize| #[trigger] outs@.contains((s, d)) <==> exists|j: int| 0 <= j < i && #[trigger] kept_out(cs@, links@, kept@, j, s as int, d),
        decreases n - i,
    {
        let ghost prev = kept@;
        proof { lemma_decisions_len(cs@, links@, mc, ap, stored@, fresh@, i as nat); }
        let by_dev = signer_x(cs, links, i);
        // The (signer, device) of a sign-out with a signer, if this is one.
        let out: Option<(usize, usize)> = match (&cs[i].body, by_dev) {
            (Body::SignOut { device: Some(d) }, Some(s)) => Some((s, *d)),
            _ => None,
        };
        assert(out matches Some((s, d)) ==> out_device(cs@[i as int].body) == Some(d) && by_dev == Some(s)
            && cs@[i as int].body == (Body::SignOut { device: Some(d) }));
        assert(out is None ==> !(out_device(cs@[i as int].body) is Some && by_dev is Some));
        // Whether it is its signer's first kept sign-out of that device.
        let mut first = false;
        if let Some((s, d)) = out {
            let mut q: usize = 0;
            first = true;
            while q < outs.len()
                invariant
                    q <= outs.len(),
                    first == forall|r: int| 0 <= r < q ==> outs@[r] != (s, d),
                decreases outs.len() - q,
            {
                if outs[q].0 == s && outs[q].1 == d {
                    first = false;
                }
                q = q + 1;
            }
            proof {
                if first {
                    assert(!outs@.contains((s, d)));
                    assert forall|j: int| 0 <= j < i implies !#[trigger] kept_out(cs@, links@, prev, j, s as int, d) by {}
                } else {
                    let r = choose|r: int| 0 <= r < outs.len() && outs@[r] == (s, d);
                    assert(outs@.contains((s, d)));
                    let j = choose|j: int| 0 <= j < i && #[trigger] kept_out(cs@, links@, prev, j, s as int, d);
                    assert(kept_out(cs@, links@, prev, j, s as int, d));
                    assert(cs@[i as int].body == (Body::SignOut { device: Some(d) }));
                    assert(signer(cs@, links@, i as int) == Some(s as int));
                    assert(signer(cs@, links@, i as int)->Some_0 == s as int);
                    assert(out_device(cs@[i as int].body)->Some_0 == d);
                    assert(kept_out(cs@, links@, prev, j, signer(cs@, links@, i as int)->Some_0, out_device(cs@[i as int].body)->Some_0));
                    assert(!(forall|j2: int| 0 <= j2 < i ==> !#[trigger] kept_out(cs@, links@, prev, j2, s as int, d)));
                    assert(!first_out(cs@, links@, prev, i as int));
                }
            }
        } else {
            assert(!first_out(cs@, links@, prev, i as int));
        }
        assert(first == first_out(cs@, links@, prev, i as int));
        let admitted = if master_change[i] {
            true
        } else if matches!(cs[i].body, Body::Genesis { .. }) {
            false
        } else {
            match by_dev {
                None => false,
                Some(s) => {
                    if matches!(cs[i].body, Body::AddDevice { .. }) && !applied[i] {
                        false
                    } else if first {
                        true
                    } else {
                        counts[s] < ALLOWANCE
                    }
                },
            }
        };
        assert(admitted == admit_one(cs@, links@, mc, ap, prev, i as int));
        let keep = stored[i] || (fresh[i] && admitted);
        kept.push(keep);
        proof {
            assert(kept@ =~= decisions(cs@, links@, mc, ap, stored@, fresh@, (i + 1) as nat));
            assert forall|j: int| 0 <= j < i implies prev[j] == kept@[j] by {}
            assert forall|s: int| 0 <= s < n implies count(cs@, links@, mc, kept@, s, i as int) == count(cs@, links@, mc, prev, s, i as int) by {
                lemma_prefix(cs@, links@, mc, prev, kept@, s, i as int);
            }
            lemma_first_out_prefix(cs@, links@, prev, kept@, i as int);
        }
        let counts_it = keep && !master_change[i] && !first;
        if counts_it {
            if let Some(s) = by_dev {
                counts.set(s, counts[s] + 1);
            }
        }
        let ghost old_outs = outs@;
        if keep {
            if let Some(p) = out {
                outs.push(p);
            }
        }
        proof {
            assert forall|s: int| 0 <= s < n implies #[trigger] counts[s] as nat == count(cs@, links@, mc, kept@, s, (i + 1) as int) by {}
            assert forall|s: usize, d: usize| #[trigger] outs@.contains((s, d)) <==> exists|j: int| 0 <= j < i + 1 && #[trigger] kept_out(cs@, links@, kept@, j, s as int, d) by {
                assert forall|j: int| 0 <= j < i implies kept_out(cs@, links@, kept@, j, s as int, d) == kept_out(cs@, links@, prev, j, s as int, d) by {}
                let here = kept_out(cs@, links@, kept@, i as int, s as int, d);
                assert(here == (keep && out == Some((s, d))));
                let before = exists|j: int| 0 <= j < i && #[trigger] kept_out(cs@, links@, prev, j, s as int, d);
                assert(old_outs.contains((s, d)) == before);
                if keep && out is Some {
                    assert(outs@ == old_outs.push(out->Some_0));
                    assert(outs@.contains((s, d)) == (old_outs.contains((s, d)) || out == Some((s, d)))) by {
                        if outs@.contains((s, d)) {
                            let r = choose|r: int| 0 <= r < outs.len() && outs@[r] == (s, d);
                            if r < old_outs.len() {
                                assert(old_outs[r] == (s, d));
                            }
                        }
                        if old_outs.contains((s, d)) {
                            let r = choose|r: int| 0 <= r < old_outs.len() && old_outs[r] == (s, d);
                            assert(outs@[r] == (s, d));
                        }
                        if out == Some((s, d)) {
                            assert(outs@[old_outs.len() as int] == (s, d));
                        }
                    }
                } else {
                    assert(outs@ == old_outs);
                }
                if exists|j: int| 0 <= j < i + 1 && #[trigger] kept_out(cs@, links@, kept@, j, s as int, d) {
                    let j = choose|j: int| 0 <= j < i + 1 && #[trigger] kept_out(cs@, links@, kept@, j, s as int, d);
                    if j < i {
                        assert(kept_out(cs@, links@, prev, j, s as int, d));
                    }
                }
                if before {
                    let j = choose|j: int| 0 <= j < i && #[trigger] kept_out(cs@, links@, prev, j, s as int, d);
                    assert(kept_out(cs@, links@, kept@, j, s as int, d));
                }
            }
        }
        i = i + 1;
    }
    kept
}

} // verus!
