//! Ancestors (section 5.1): the changes a change's `prev` names, the changes theirs name, and so
//! on back to the start. `ancestors` is proven to compute exactly this relation, and `dag` exactly
//! which changes sit on no cycle (a cycle needs a SHA-256 collision; such changes are ignored).
use crate::bits::*;
use crate::log::*;
use crate::order::*;
use vstd::prelude::*;

verus! {

pub open spec fn prev_at(cs: Seq<Change>, i: int, q: int) -> int {
    cs[i].prev@[q] as int
}

/// Change j is reached from change i through at most k + 1 `prev` links.
pub open spec fn reach(cs: Seq<Change>, i: int, j: int, k: nat) -> bool
    decreases k,
{
    exists|q: int|
        0 <= q < cs[i].prev.len() && (#[trigger] prev_at(cs, i, q) == j || (k > 0 && reach(cs, prev_at(cs, i, q), j, (k - 1) as nat)))
}

/// Change j is an ancestor of change i.
pub open spec fn ancestor(cs: Seq<Change>, i: int, j: int) -> bool {
    exists|k: nat| #[trigger] reach(cs, i, j, k)
}

/// Change i is in the log proper: neither it nor any of its ancestors is its own ancestor.
pub open spec fn in_dag(cs: Seq<Change>, i: int) -> bool {
    &&& 0 <= i < cs.len()
    &&& !ancestor(cs, i, i)
    &&& forall|j: int| #[trigger] ancestor(cs, i, j) ==> !ancestor(cs, j, j)
}

pub proof fn lemma_prev_is_ancestor(cs: Seq<Change>, i: int, q: int)
    requires
        0 <= q < cs[i].prev.len(),
    ensures
        ancestor(cs, i, prev_at(cs, i, q)),
{
    assert(reach(cs, i, prev_at(cs, i, q), 0));
}

pub proof fn lemma_ancestor_through(cs: Seq<Change>, i: int, q: int, j: int)
    requires
        0 <= q < cs[i].prev.len(),
        ancestor(cs, prev_at(cs, i, q), j),
    ensures
        ancestor(cs, i, j),
{
    let k = choose|k: nat| #[trigger] reach(cs, prev_at(cs, i, q), j, k);
    assert(reach(cs, i, j, k + 1));
}

proof fn lemma_reach_trans(cs: Seq<Change>, i: int, j: int, l: int, k: nat)
    requires
        reach(cs, i, j, k),
        ancestor(cs, j, l),
    ensures
        ancestor(cs, i, l),
    decreases k,
{
    let q = choose|q: int|
        0 <= q < cs[i].prev.len() && (#[trigger] prev_at(cs, i, q) == j || (k > 0 && reach(cs, prev_at(cs, i, q), j, (k - 1) as nat)));
    let p = prev_at(cs, i, q);
    if p != j {
        lemma_reach_trans(cs, p, j, l, (k - 1) as nat);
    }
    lemma_ancestor_through(cs, i, q, l);
}

pub proof fn lemma_ancestor_trans(cs: Seq<Change>, i: int, j: int, l: int)
    requires
        ancestor(cs, i, j),
        ancestor(cs, j, l),
    ensures
        ancestor(cs, i, l),
{
    let k = choose|k: nat| #[trigger] reach(cs, i, j, k);
    lemma_reach_trans(cs, i, j, l, k);
}

proof fn lemma_reach_in_range(cs: Seq<Change>, i: int, j: int, k: nat)
    requires
        valid(cs),
        0 <= i < cs.len(),
        reach(cs, i, j, k),
    ensures
        0 <= j < cs.len(),
    decreases k,
{
    let q = choose|q: int|
        0 <= q < cs[i].prev.len() && (#[trigger] prev_at(cs, i, q) == j || (k > 0 && reach(cs, prev_at(cs, i, q), j, (k - 1) as nat)));
    assert(change_ok(cs[i], cs.len() as nat));
    let p = prev_at(cs, i, q);
    if p != j {
        lemma_reach_in_range(cs, p, j, (k - 1) as nat);
    }
}

pub proof fn lemma_ancestor_in_range(cs: Seq<Change>, i: int, j: int)
    requires
        valid(cs),
        0 <= i < cs.len(),
        ancestor(cs, i, j),
    ensures
        0 <= j < cs.len(),
{
    let k = choose|k: nat| #[trigger] reach(cs, i, j, k);
    lemma_reach_in_range(cs, i, j, k);
}

/// The ancestors of a change in the log proper are in it too.
pub proof fn lemma_dag_closed(cs: Seq<Change>, i: int, j: int)
    requires
        valid(cs),
        in_dag(cs, i),
        ancestor(cs, i, j),
    ensures
        in_dag(cs, j),
{
    lemma_ancestor_in_range(cs, i, j);
    assert forall|l: int| #[trigger] ancestor(cs, j, l) implies !ancestor(cs, l, l) by {
        lemma_ancestor_trans(cs, i, j, l);
    }
}

/// `anc[i]` holds exactly the ancestors of change i.
pub open spec fn anc_exact(cs: Seq<Change>, anc: Seq<Bits>) -> bool {
    &&& anc.len() == cs.len()
    &&& forall|i: int| 0 <= i < cs.len() ==> (#[trigger] anc[i]).words.len() == words_for(cs.len() as nat)
    &&& forall|i: int, j: nat| 0 <= i < cs.len() ==> (#[trigger] anc[i].has(j) <==> ancestor(cs, i, j as int))
}

spec fn sound(cs: Seq<Change>, anc: Seq<Bits>) -> bool {
    forall|i: int, j: nat| 0 <= i < cs.len() && #[trigger] anc[i].has(j) ==> ancestor(cs, i, j as int)
}

/// After its `q`th `prev`, change i's set holds that change and everything in its set.
spec fn covers(cs: Seq<Change>, anc: Seq<Bits>, i: int, q: int) -> bool {
    let p = prev_at(cs, i, q);
    &&& anc[i].has(p as nat)
    &&& forall|j: nat| #[trigger] anc[p].has(j) ==> anc[i].has(j)
}

spec fn closed(cs: Seq<Change>, anc: Seq<Bits>) -> bool {
    forall|i: int, q: int| 0 <= i < cs.len() && 0 <= q < cs[i].prev.len() ==> #[trigger] covers(cs, anc, i, q)
}

proof fn lemma_closed_complete(cs: Seq<Change>, anc: Seq<Bits>, i: int, j: int, k: nat)
    requires
        valid(cs),
        closed(cs, anc),
        0 <= i < cs.len(),
        reach(cs, i, j, k),
    ensures
        j >= 0 && anc[i].has(j as nat),
    decreases k,
{
    let q = choose|q: int|
        0 <= q < cs[i].prev.len() && (#[trigger] prev_at(cs, i, q) == j || (k > 0 && reach(cs, prev_at(cs, i, q), j, (k - 1) as nat)));
    assert(change_ok(cs[i], cs.len() as nat));
    assert(covers(cs, anc, i, q));
    let p = prev_at(cs, i, q);
    if p != j {
        lemma_closed_complete(cs, anc, p, j, (k - 1) as nat);
    }
}

spec fn same_sets(a: Seq<Bits>, b: Seq<Bits>) -> bool {
    &&& a.len() == b.len()
    &&& forall|i: int| 0 <= i < a.len() ==> (#[trigger] a[i]).words@ == b[i].words@
}

spec fn has_f(b: Bits) -> spec_fn(int) -> bool {
    |j: int| j >= 0 && b.has(j as nat)
}

spec fn row(b: Bits, n: nat) -> nat {
    count(n, has_f(b))
}

/// How many (change, ancestor) pairs the sets hold so far: the fixpoint's progress measure.
spec fn total(anc: Seq<Bits>, n: nat, m: nat) -> nat
    decreases m,
{
    if m == 0 {
        0
    } else {
        total(anc, n, (m - 1) as nat) + row(anc[m - 1], n)
    }
}

proof fn lemma_total_le(anc: Seq<Bits>, n: nat, m: nat)
    ensures
        total(anc, n, m) <= m * n,
    decreases m,
{
    if m > 0 {
        lemma_total_le(anc, n, (m - 1) as nat);
        lemma_count_le(n, has_f(anc[m - 1]));
        assert((m - 1) * n + n == m * n) by (nonlinear_arith);
    }
}

proof fn lemma_total_update(anc: Seq<Bits>, n: nat, m: nat, i: int, b: Bits)
    requires
        0 <= i < anc.len(),
        m <= anc.len(),
    ensures
        i < m ==> total(anc.update(i, b), n, m) + row(anc[i], n) == total(anc, n, m) + row(b, n),
        i >= m ==> total(anc.update(i, b), n, m) == total(anc, n, m),
    decreases m,
{
    if m > 0 {
        lemma_total_update(anc, n, (m - 1) as nat, i, b);
    }
}

/// The ancestors of every change, computed to a fixpoint. Correct whatever the order of the
/// changes; if each change comes after those its `prev` names, two passes suffice. Each pass that
/// changes anything adds a pair, and there are at most n * n, so it ends.
pub fn ancestors(cs: &Vec<Change>) -> (anc: Vec<Bits>)
    requires
        valid(cs@),
    ensures
        anc_exact(cs@, anc@),
{
    let n = cs.len();
    let mut anc: Vec<Bits> = Vec::new();
    while anc.len() < n
        invariant
            anc.len() <= n,
            n <= MAX_CHANGES,
            forall|i: int| 0 <= i < anc.len() ==> (#[trigger] anc[i]).words.len() == words_for(n as nat),
            forall|i: int, j: nat| 0 <= i < anc.len() ==> !(#[trigger] anc[i].has(j)),
        decreases n - anc.len(),
    {
        anc.push(Bits::new(n));
    }
    let mut changed = true;
    while changed
        invariant
            valid(cs@),
            n == cs.len(),
            anc.len() == n,
            forall|i: int| 0 <= i < n ==> (#[trigger] anc[i]).words.len() == words_for(n as nat),
            sound(cs@, anc@),
            !changed ==> closed(cs@, anc@),
        decreases (n * n - total(anc@, n as nat, n as nat)) * 2 + if changed { 1int } else { 0int },
    {
        proof { lemma_total_le(anc@, n as nat, n as nat); }
        changed = false;
        let ghost start = anc@;
        let mut i: usize = 0;
        while i < n
            invariant
                valid(cs@),
                n == cs.len(),
                anc.len() == n,
                i <= n,
                forall|i2: int| 0 <= i2 < n ==> (#[trigger] anc[i2]).words.len() == words_for(n as nat),
                sound(cs@, anc@),
                !changed ==> same_sets(anc@, start),
                !changed ==> forall|i2: int, q: int| 0 <= i2 < i && 0 <= q < cs@[i2].prev.len() ==> #[trigger] covers(cs@, anc@, i2, q),
                total(anc@, n as nat, n as nat) >= total(start, n as nat, n as nat),
                changed ==> total(anc@, n as nat, n as nat) > total(start, n as nat, n as nat),
                start.len() == n,
            decreases n - i,
        {
            assert(change_ok(cs@[i as int], n as nat));
            let mut q: usize = 0;
            while q < cs[i].prev.len()
                invariant
                    valid(cs@),
                    n == cs.len(),
                    anc.len() == n,
                    i < n,
                    q <= cs@[i as int].prev.len(),
                    change_ok(cs@[i as int], n as nat),
                    forall|i2: int| 0 <= i2 < n ==> (#[trigger] anc[i2]).words.len() == words_for(n as nat),
                    sound(cs@, anc@),
                    !changed ==> same_sets(anc@, start),
                    !changed ==> forall|i2: int, q2: int| 0 <= i2 < i && 0 <= q2 < cs@[i2].prev.len() ==> #[trigger] covers(cs@, anc@, i2, q2),
                    !changed ==> forall|q2: int| 0 <= q2 < q ==> #[trigger] covers(cs@, anc@, i as int, q2),
                    total(anc@, n as nat, n as nat) >= total(start, n as nat, n as nat),
                    changed ==> total(anc@, n as nat, n as nat) > total(start, n as nat, n as nat),
                    start.len() == n,
                decreases cs@[i as int].prev.len() - q,
            {
                let p = cs[i].prev[q];
                let other = anc[p].clone_bits();
                let mut b = anc[i].clone_bits();
                let ghost orig = b;
                let c1 = b.union(&other);
                let ghost mid = b;
                proof { lemma_index_fits(p as nat, n as nat); }
                let c2 = b.set(p);
                let ghost before = anc@;
                let ghost newb = b;
                anc.set(i, b);
                proof {
                    lemma_total_update(before, n as nat, n as nat, i as int, newb);
                    assert(anc@ == before.update(i as int, newb));
                    assert forall|j: int| 0 <= j < n && #[trigger] has_f(before[i as int])(j) implies has_f(newb)(j) by {
                        assert(orig.has(j as nat) == before[i as int].has(j as nat));
                    }
                    lemma_count_mono(n as nat, has_f(before[i as int]), has_f(newb));
                }
                proof {
                    lemma_prev_is_ancestor(cs@, i as int, q as int);
                    assert forall|i2: int, j: nat| 0 <= i2 < n && #[trigger] anc@[i2].has(j) implies ancestor(cs@, i2, j as int) by {
                        if i2 == i as int && !before[i2].has(j) && j != p as nat {
                            assert(other.has(j));
                            assert(other.words@ == before[p as int].words@);
                            assert(before[p as int].has(j));
                            lemma_ancestor_through(cs@, i as int, q as int, j as int);
                        }
                    }
                    if c1 || c2 {
                        // The set gained a pair.
                        let j: nat = if c1 {
                            choose|j: nat| mid.has(j) && !orig.has(j)
                        } else {
                            p as nat
                        };
                        assert(newb.has(j) && !before[i as int].has(j)) by {
                            assert(orig.has(j) == before[i as int].has(j));
                        }
                        assert(anc@[i as int].has(j));
                        lemma_ancestor_in_range(cs@, i as int, j as int);
                        lemma_count_strict(n as nat, has_f(before[i as int]), has_f(newb), j as int);
                    }
                    if !c1 && !c2 && !changed {
                        assert(anc@[i as int].words@ == before[i as int].words@);
                        assert forall|i2: int| 0 <= i2 < n implies (#[trigger] anc@[i2]).words@ == before[i2].words@ by {}
                        assert forall|i2: int, j: nat| 0 <= i2 < n implies (#[trigger] anc@[i2].has(j)) == before[i2].has(j) by {
                            assert(anc@[i2].words@ == before[i2].words@);
                        }
                        assert(covers(cs@, anc@, i as int, q as int));
                        assert forall|i2: int, q2: int| 0 <= i2 < i && 0 <= q2 < cs@[i2].prev.len()
                            implies #[trigger] covers(cs@, anc@, i2, q2) by {
                            assert(covers(cs@, before, i2, q2));
                            let p2 = prev_at(cs@, i2, q2);
                            assert forall|j: nat| #[trigger] anc@[p2].has(j) implies anc@[i2].has(j) by {
                                assert(before[p2].has(j));
                            }
                        }
                        assert forall|q2: int| 0 <= q2 < q implies #[trigger] covers(cs@, anc@, i as int, q2) by {
                            assert(covers(cs@, before, i as int, q2));
                            let p2 = prev_at(cs@, i as int, q2);
                            assert forall|j: nat| #[trigger] anc@[p2].has(j) implies anc@[i as int].has(j) by {
                                assert(before[p2].has(j));
                            }
                        }
                        assert(same_sets(anc@, start));
                    }
                }
                if c1 || c2 {
                    changed = true;
                }
                q = q + 1;
            }
            i = i + 1;
        }
        proof { lemma_total_le(anc@, n as nat, n as nat); }
    }
    proof {
        assert forall|i: int, j: nat| 0 <= i < n implies (#[trigger] anc@[i].has(j) <==> ancestor(cs@, i, j as int)) by {
            if ancestor(cs@, i, j as int) {
                let k = choose|k: nat| #[trigger] reach(cs@, i, j as int, k);
                lemma_closed_complete(cs@, anc@, i, j as int, k);
            }
        }
    }
    anc
}

/// Which changes are in the log proper.
pub fn dag(cs: &Vec<Change>, anc: &Vec<Bits>) -> (d: Vec<bool>)
    requires
        valid(cs@),
        anc_exact(cs@, anc@),
    ensures
        d.len() == cs.len(),
        forall|i: int| 0 <= i < cs.len() ==> #[trigger] d[i] == in_dag(cs@, i),
{
    let n = cs.len();
    let mut cyclic: Vec<bool> = Vec::new();
    while cyclic.len() < n
        invariant
            cyclic.len() <= n,
            n == cs.len(),
            anc_exact(cs@, anc@),
            forall|j: int| 0 <= j < cyclic.len() ==> #[trigger] cyclic[j] == ancestor(cs@, j, j),
        decreases n - cyclic.len(),
    {
        let j = cyclic.len();
        cyclic.push(anc[j].get(j));
    }
    let mut d: Vec<bool> = Vec::new();
    while d.len() < n
        invariant
            valid(cs@),
            d.len() <= n,
            n == cs.len(),
            anc_exact(cs@, anc@),
            cyclic.len() == n,
            forall|j: int| 0 <= j < n ==> #[trigger] cyclic[j] == ancestor(cs@, j, j),
            forall|i: int| 0 <= i < d.len() ==> #[trigger] d[i] == in_dag(cs@, i),
        decreases n - d.len(),
    {
        let i = d.len();
        let mut ok = !cyclic[i];
        let mut from: usize = 0;
        proof { lemma_words_small(n as nat); }
        loop
            invariant
                valid(cs@),
                n == cs.len(),
                i < n,
                anc_exact(cs@, anc@),
                cyclic.len() == n,
                forall|j: int| 0 <= j < n ==> #[trigger] cyclic[j] == ancestor(cs@, j, j),
                ok == (!ancestor(cs@, i as int, i as int) && forall|j: nat| j < from && #[trigger] anc[i as int].has(j) ==> !ancestor(cs@, j as int, j as int)),
                anc[i as int].words.len() <= 0x100_0000,
                from <= n,
            ensures
                ok == (!ancestor(cs@, i as int, i as int) && forall|j: nat| j < from && #[trigger] anc[i as int].has(j) ==> !ancestor(cs@, j as int, j as int)),
                forall|j: nat| from <= j ==> !#[trigger] anc[i as int].has(j),
            decreases n - from,
        {
            match anc[i].next_set(from) {
                Some(x) => {
                    proof { lemma_ancestor_in_range(cs@, i as int, x as int); }
                    if cyclic[x] {
                        ok = false;
                    }
                    from = x + 1;
                },
                None => {
                    break;
                },
            }
        }
        proof {
            assert forall|j: int| #[trigger] ancestor(cs@, i as int, j) implies (ok ==> !ancestor(cs@, j, j)) by {
                lemma_ancestor_in_range(cs@, i as int, j);
                assert(anc[i as int].has(j as nat));
                assert((j as nat) < from);
            }
            if !ok && !ancestor(cs@, i as int, i as int) {
                let j = choose|j: nat| j < from && #[trigger] anc[i as int].has(j) && ancestor(cs@, j as int, j as int);
                assert(ancestor(cs@, i as int, j as int));
            }
            assert(ok == in_dag(cs@, i as int));
        }
        d.push(ok);
    }
    d
}

pub proof fn lemma_words_small(n: nat)
    requires
        n <= MAX_CHANGES,
    ensures
        words_for(n) <= 0x100_0000,
{
}

} // verus!
