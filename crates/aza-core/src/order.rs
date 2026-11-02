//! Reading order (section 5.4, step 5): "repeatedly take, out of the changes not yet taken whose
//! ancestors (other than discarded ones) have all been taken, the one with the smallest hash."
//!
//! `reading_order` is proven to return an order meeting that description exactly
//! (`is_reading_order`), and `lemma_reading_order_unique` proves only one order does. Ties
//! between equal hashes (two copies of one change, which the caller removes) go to the lower
//! index, so the order is total.
use crate::bits::*;
use crate::cbor::*;
use crate::dag::*;
use crate::log::*;
use vstd::prelude::*;

verus! {

// Counting.

pub open spec fn count(n: nat, f: spec_fn(int) -> bool) -> nat
    decreases n,
{
    if n == 0 {
        0
    } else {
        count((n - 1) as nat, f) + if f(n - 1) { 1nat } else { 0nat }
    }
}

pub proof fn lemma_count_le(n: nat, f: spec_fn(int) -> bool)
    ensures
        count(n, f) <= n,
    decreases n,
{
    if n > 0 {
        lemma_count_le((n - 1) as nat, f);
    }
}

pub proof fn lemma_count_ext(n: nat, f: spec_fn(int) -> bool, g: spec_fn(int) -> bool)
    requires
        forall|j: int| 0 <= j < n ==> #[trigger] f(j) == g(j),
    ensures
        count(n, f) == count(n, g),
    decreases n,
{
    if n > 0 {
        lemma_count_ext((n - 1) as nat, f, g);
    }
}

pub proof fn lemma_count_zero(n: nat, f: spec_fn(int) -> bool)
    ensures
        count(n, f) == 0 <==> forall|j: int| 0 <= j < n ==> !#[trigger] f(j),
    decreases n,
{
    if n > 0 {
        lemma_count_zero((n - 1) as nat, f);
    }
}

/// Turning one member off lowers the count by one.
pub proof fn lemma_count_flip(n: nat, f: spec_fn(int) -> bool, g: spec_fn(int) -> bool, x: int)
    requires
        0 <= x < n,
        f(x),
        !g(x),
        forall|j: int| 0 <= j < n && j != x ==> #[trigger] f(j) == g(j),
    ensures
        count(n, g) + 1 == count(n, f),
    decreases n,
{
    if n - 1 == x {
        lemma_count_ext((n - 1) as nat, f, g);
    } else {
        lemma_count_flip((n - 1) as nat, f, g, x);
    }
}

/// A strict subset counts fewer.
pub proof fn lemma_count_strict(n: nat, f: spec_fn(int) -> bool, g: spec_fn(int) -> bool, x: int)
    requires
        0 <= x < n,
        g(x),
        !f(x),
        forall|j: int| 0 <= j < n && #[trigger] f(j) ==> g(j),
    ensures
        count(n, f) < count(n, g),
    decreases n,
{
    if n - 1 == x {
        lemma_count_mono((n - 1) as nat, f, g);
    } else {
        lemma_count_strict((n - 1) as nat, f, g, x);
    }
}

pub proof fn lemma_count_mono(n: nat, f: spec_fn(int) -> bool, g: spec_fn(int) -> bool)
    requires
        forall|j: int| 0 <= j < n && #[trigger] f(j) ==> g(j),
    ensures
        count(n, f) <= count(n, g),
    decreases n,
{
    if n > 0 {
        lemma_count_mono((n - 1) as nat, f, g);
    }
}

proof fn lemma_count_skip(a: nat, b: nat, f: spec_fn(int) -> bool)
    requires
        a <= b,
        forall|j: int| a <= j < b ==> !#[trigger] f(j),
    ensures
        count(b, f) == count(a, f),
    decreases b - a,
{
    if a < b {
        lemma_count_skip(a, (b - 1) as nat, f);
    }
}

// Byte order of hashes, with the index breaking ties.

pub proof fn lemma_lex_irreflexive(a: Seq<u8>)
    ensures
        !lex_lt(a, a),
    decreases a.len(),
{
    if a.len() > 0 {
        lemma_lex_irreflexive(a.drop_first());
    }
}

pub proof fn lemma_lex_trans(a: Seq<u8>, b: Seq<u8>, c: Seq<u8>)
    requires
        lex_lt(a, b),
        lex_lt(b, c),
    ensures
        lex_lt(a, c),
    decreases a.len(),
{
    if a.len() > 0 && b.len() > 0 && c.len() > 0 && a[0] == b[0] && b[0] == c[0] {
        lemma_lex_trans(a.drop_first(), b.drop_first(), c.drop_first());
    }
}

pub proof fn lemma_lex_total(a: Seq<u8>, b: Seq<u8>)
    requires
        a.len() == b.len(),
        a != b,
    ensures
        lex_lt(a, b) || lex_lt(b, a),
    decreases a.len(),
{
    if a.len() > 0 && a[0] == b[0] {
        if a.drop_first() == b.drop_first() {
            assert(a =~= seq![a[0]] + a.drop_first());
            assert(b =~= seq![b[0]] + b.drop_first());
        }
        lemma_lex_total(a.drop_first(), b.drop_first());
    } else if a.len() == 0 {
        assert(a =~= b);
    }
}

pub proof fn lemma_lex_asym(a: Seq<u8>, b: Seq<u8>)
    requires
        lex_lt(a, b),
    ensures
        !lex_lt(b, a),
{
    if lex_lt(b, a) {
        lemma_lex_trans(a, b, a);
        lemma_lex_irreflexive(a);
    }
}

pub open spec fn key_lt(cs: Seq<Change>, a: int, b: int) -> bool {
    lex_lt(cs[a].hash@, cs[b].hash@) || (cs[a].hash@ == cs[b].hash@ && a < b)
}

pub proof fn lemma_key_order(cs: Seq<Change>, a: int, b: int, c: int)
    ensures
        !key_lt(cs, a, a),
        key_lt(cs, a, b) ==> !key_lt(cs, b, a),
        key_lt(cs, a, b) && key_lt(cs, b, c) ==> key_lt(cs, a, c),
        a != b ==> key_lt(cs, a, b) || key_lt(cs, b, a),
{
    lemma_lex_irreflexive(cs[a].hash@);
    if lex_lt(cs[a].hash@, cs[b].hash@) {
        lemma_lex_asym(cs[a].hash@, cs[b].hash@);
    }
    if lex_lt(cs[b].hash@, cs[a].hash@) {
        lemma_lex_asym(cs[b].hash@, cs[a].hash@);
    }
    if key_lt(cs, a, b) && key_lt(cs, b, c) {
        if lex_lt(cs[a].hash@, cs[b].hash@) && lex_lt(cs[b].hash@, cs[c].hash@) {
            lemma_lex_trans(cs[a].hash@, cs[b].hash@, cs[c].hash@);
        }
    }
    if cs[a].hash@ != cs[b].hash@ {
        lemma_lex_total(cs[a].hash@, cs[b].hash@);
    }
}

pub fn key_less(cs: &Vec<Change>, a: usize, b: usize) -> (r: bool)
    requires
        a < cs.len(),
        b < cs.len(),
    ensures
        r == key_lt(cs@, a as int, b as int),
{
    let x = &cs[a].hash;
    let y = &cs[b].hash;
    let mut i: usize = 0;
    assert(x@.skip(0) =~= x@);
    assert(y@.skip(0) =~= y@);
    while i < 32
        invariant
            i <= 32,
            x@.len() == 32,
            y@.len() == 32,
            *x == cs@[a as int].hash,
            *y == cs@[b as int].hash,
            lex_lt(x@, y@) == lex_lt(x@.skip(i as int), y@.skip(i as int)),
            forall|k: int| 0 <= k < i ==> x@[k] == y@[k],
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
    assert(x@ =~= y@);
    assert(x@.skip(32).len() == 0);
    a < b
}

// The specification.

/// A change reading order covers: in the log proper and not discarded.
pub open spec fn eligible(disc: Seq<bool>, j: int) -> bool {
    0 <= j < disc.len() && !disc[j]
}

/// Change c may be taken after `taken`: eligible, not taken yet, and every eligible ancestor
/// taken.
pub open spec fn ready(cs: Seq<Change>, disc: Seq<bool>, taken: Seq<usize>, c: int) -> bool {
    &&& eligible(disc, c)
    &&& !taken.contains(c as usize)
    &&& forall|j: int| #[trigger] ancestor(cs, c, j) && eligible(disc, j) ==> taken.contains(j as usize)
}

pub open spec fn is_reading_order(cs: Seq<Change>, disc: Seq<bool>, order: Seq<usize>) -> bool {
    &&& order.no_duplicates()
    &&& forall|j: usize| eligible(disc, j as int) <==> #[trigger] order.contains(j)
    &&& forall|k: int| 0 <= k < order.len() ==> ready(cs, disc, order.subrange(0, k), #[trigger] order[k] as int)
    &&& forall|k: int, c: int| 0 <= k < order.len() && #[trigger] ready(cs, disc, order.subrange(0, k), c)
        ==> c == order[k] as int || key_lt(cs, order[k] as int, c)
}

/// Discarded changes include every change outside the log proper.
pub open spec fn disc_ok(cs: Seq<Change>, disc: Seq<bool>) -> bool {
    &&& disc.len() == cs.len()
    &&& forall|j: int| 0 <= j < cs.len() && !(#[trigger] disc[j]) ==> in_dag(cs, j)
}

spec fn pend_f(cs: Seq<Change>, disc: Seq<bool>, taken: Seq<bool>, c: int) -> spec_fn(int) -> bool {
    |j: int| !disc[j] && !taken[j] && ancestor(cs, c, j)
}

spec fn pending(cs: Seq<Change>, disc: Seq<bool>, taken: Seq<bool>, c: int) -> nat {
    count(cs.len() as nat, pend_f(cs, disc, taken, c))
}

spec fn taken_f(taken: Seq<bool>) -> spec_fn(int) -> bool {
    |j: int| taken[j]
}

pub open spec fn anc_card(cs: Seq<Change>, c: int) -> nat {
    count(cs.len() as nat, |j: int| ancestor(cs, c, j))
}

pub proof fn lemma_anc_card_drops(cs: Seq<Change>, c: int, j: int)
    requires
        valid(cs),
        in_dag(cs, c),
        ancestor(cs, c, j),
    ensures
        anc_card(cs, j) < anc_card(cs, c),
{
    lemma_ancestor_in_range(cs, c, j);
    assert forall|l: int| 0 <= l < cs.len() && ancestor(cs, j, l) implies ancestor(cs, c, l) by {
        lemma_ancestor_trans(cs, c, j, l);
    }
    lemma_count_strict(cs.len() as nat, |l: int| ancestor(cs, j, l), |l: int| ancestor(cs, c, l), j);
}

/// While an eligible change is untaken, some eligible untaken change has no eligible untaken
/// ancestor: the log proper has no cycles.
proof fn lemma_some_ready(cs: Seq<Change>, disc: Seq<bool>, taken: Seq<bool>, c: int, bound: nat) -> (r: int)
    requires
        valid(cs),
        disc_ok(cs, disc),
        taken.len() == cs.len(),
        eligible(disc, c),
        !taken[c],
        anc_card(cs, c) <= bound,
    ensures
        eligible(disc, r),
        !taken[r],
        pending(cs, disc, taken, r) == 0,
    decreases bound,
{
    lemma_count_zero(cs.len() as nat, |j: int| !disc[j] && !taken[j] && ancestor(cs, c, j));
    if pending(cs, disc, taken, c) == 0 {
        c
    } else {
        let j = choose|j: int| 0 <= j < cs.len() && !disc[j] && !taken[j] && ancestor(cs, c, j);
        lemma_anc_card_drops(cs, c, j);
        lemma_some_ready(cs, disc, taken, j, (bound - 1) as nat)
    }
}

// The algorithm.

spec fn taken_matches(order: Seq<usize>, taken: Seq<bool>) -> bool {
    forall|j: int| 0 <= j < taken.len() ==> (#[trigger] taken[j] <==> order.contains(j as usize))
}

/// For each change, the changes it is an ancestor of.
fn descendants(cs: &Vec<Change>, anc: &Vec<Bits>) -> (desc: Vec<Bits>)
    requires
        valid(cs@),
        anc_exact(cs@, anc@),
    ensures
        desc.len() == cs.len(),
        forall|x: int| 0 <= x < cs.len() ==> (#[trigger] desc[x]).words.len() == words_for(cs.len() as nat),
        forall|x: int, c: nat| 0 <= x < cs.len() && c < cs.len() ==> (#[trigger] desc[x].has(c) <==> ancestor(cs@, c as int, x)),
        forall|x: int, c: nat| 0 <= x < cs.len() && #[trigger] desc[x].has(c) ==> c < cs.len(),
{
    let n = cs.len();
    let mut desc: Vec<Bits> = Vec::new();
    while desc.len() < n
        invariant
            desc.len() <= n,
            n <= MAX_CHANGES,
            forall|x: int| 0 <= x < desc.len() ==> (#[trigger] desc[x]).words.len() == words_for(n as nat),
            forall|x: int, c: nat| 0 <= x < desc.len() ==> !(#[trigger] desc[x].has(c)),
        decreases n - desc.len(),
    {
        desc.push(Bits::new(n));
    }
    let mut c: usize = 0;
    while c < n
        invariant
            valid(cs@),
            n == cs.len(),
            c <= n,
            anc_exact(cs@, anc@),
            desc.len() == n,
            forall|x: int| 0 <= x < n ==> (#[trigger] desc[x]).words.len() == words_for(n as nat),
            forall|x: int, c2: nat| 0 <= x < n && c2 < n ==> (#[trigger] desc[x].has(c2) <==> (c2 < c && ancestor(cs@, c2 as int, x))),
            forall|x: int, c2: nat| 0 <= x < n && #[trigger] desc[x].has(c2) ==> c2 < n,
        decreases n - c,
    {
        let mut from: usize = 0;
        proof { lemma_words_small(n as nat); }
        loop
            invariant
                valid(cs@),
                n == cs.len(),
                c < n,
                from <= n,
                anc_exact(cs@, anc@),
                desc.len() == n,
                anc[c as int].words.len() <= 0x100_0000,
                forall|x: int| 0 <= x < n ==> (#[trigger] desc[x]).words.len() == words_for(n as nat),
                forall|x: int, c2: nat| 0 <= x < n && c2 < n ==> (#[trigger] desc[x].has(c2) <==>
                    ((c2 < c && ancestor(cs@, c2 as int, x)) || (c2 == c && x < from && ancestor(cs@, c as int, x)))),
                forall|x: int, c2: nat| 0 <= x < n && #[trigger] desc[x].has(c2) ==> c2 < n,
            ensures
                forall|x: int, c2: nat| 0 <= x < n && c2 < n ==> (#[trigger] desc[x].has(c2) <==>
                    ((c2 < c && ancestor(cs@, c2 as int, x)) || (c2 == c && x < from && ancestor(cs@, c as int, x)))),
                forall|x: nat| from <= x ==> !#[trigger] anc[c as int].has(x),
            decreases n - from,
        {
            match anc[c].next_set(from) {
                Some(x) => {
                    proof {
                        lemma_ancestor_in_range(cs@, c as int, x as int);
                        lemma_index_fits(c as nat, n as nat);
                    }
                    let ghost old_desc = desc@;
                    let mut b = desc[x].clone_bits();
                    let _ = b.set(c);
                    desc.set(x, b);
                    proof {
                        assert(ancestor(cs@, c as int, x as int));
                        assert forall|y: int, c2: nat| 0 <= y < n && c2 < n implies (#[trigger] desc[y].has(c2) <==>
                            ((c2 < c && ancestor(cs@, c2 as int, y)) || (c2 == c && y < x + 1 && ancestor(cs@, c as int, y)))) by {
                            assert(old_desc[y].has(c2) <==>
                                ((c2 < c && ancestor(cs@, c2 as int, y)) || (c2 == c && y < from && ancestor(cs@, c as int, y))));
                            if c2 == c && from <= y < x {
                                assert(!anc[c as int].has(y as nat));
                                assert(!ancestor(cs@, c as int, y));
                            }
                            if y != x as int {
                                assert(desc[y] == old_desc[y]);
                            } else {
                                assert(b.has(c2) == (c2 == c as nat || old_desc[y].has(c2)));
                            }
                        }
                        assert forall|y: int, c2: nat| 0 <= y < n && #[trigger] desc[y].has(c2) implies c2 < n by {
                            if y != x as int {
                                assert(desc[y] == old_desc[y]);
                            } else {
                                assert(b.has(c2) == (c2 == c as nat || old_desc[y].has(c2)));
                                if c2 != c as nat {
                                    assert(old_desc[y].has(c2));
                                }
                            }
                        }
                    }
                    from = x + 1;
                },
                None => break,
            }
        }
        proof {
            assert forall|x: int, c2: nat| 0 <= x < n && c2 < n implies (#[trigger] desc[x].has(c2) <==> (c2 < c + 1 && ancestor(cs@, c2 as int, x))) by {
                if c2 == c && ancestor(cs@, c as int, x) {
                    assert(anc[c as int].has(x as nat));
                }
            }
        }
        c = c + 1;
    }
    desc
}

/// The reading order of the changes that `disc` doesn't mark.
pub fn reading_order(cs: &Vec<Change>, anc: &Vec<Bits>, disc: &Vec<bool>) -> (order: Vec<usize>)
    requires
        valid(cs@),
        anc_exact(cs@, anc@),
        disc_ok(cs@, disc@),
    ensures
        is_reading_order(cs@, disc@, order@),
{
    let n = cs.len();
    let desc = descendants(cs, anc);
    let mut waiting: Vec<usize> = Vec::new();
    let mut taken: Vec<bool> = Vec::new();
    let mut ready_list: Vec<usize> = Vec::new();
    let ghost none: Seq<bool> = Seq::new(n as nat, |j: int| false);
    // Initially, every eligible change waits for its eligible ancestors.
    while waiting.len() < n
        invariant
            valid(cs@),
            n == cs.len(),
            anc_exact(cs@, anc@),
            disc_ok(cs@, disc@),
            waiting.len() <= n,
            taken.len() == waiting.len(),
            none.len() == n,
            forall|j: int| 0 <= j < n ==> !#[trigger] none[j],
            forall|j: int| 0 <= j < taken.len() ==> !#[trigger] taken[j],
            forall|c: int| 0 <= c < waiting.len() && !disc[c] ==> #[trigger] waiting[c] as nat == pending(cs@, disc@, none, c),
            forall|c: usize| ready_list@.contains(c) <==> (c < waiting.len() && !disc[c as int] && waiting[c as int] == 0),
            ready_list@.no_duplicates(),
        decreases n - waiting.len(),
    {
        let i = waiting.len();
        let mut cnt: usize = 0;
        let ghost f = pend_f(cs@, disc@, none, i as int);
        let mut from: usize = 0;
        proof { lemma_words_small(n as nat); }
        loop
            invariant
                valid(cs@),
                n == cs.len(),
                i < n,
                from <= n,
                anc_exact(cs@, anc@),
                disc.len() == n,
                anc[i as int].words.len() <= 0x100_0000,
                f == pend_f(cs@, disc@, none, i as int),
                none.len() == n,
                forall|j: int| 0 <= j < n ==> !#[trigger] none[j],
                cnt as nat == count(from as nat, f),
            ensures
                cnt as nat == count(from as nat, f),
                forall|x: nat| from <= x ==> !#[trigger] anc[i as int].has(x),
            decreases n - from,
        {
            match anc[i].next_set(from) {
                Some(x) => {
                    proof {
                        lemma_ancestor_in_range(cs@, i as int, x as int);
                        assert forall|j: int| from <= j < x implies !#[trigger] f(j) by {
                            assert(!anc[i as int].has(j as nat));
                        }
                        lemma_count_skip(from as nat, x as nat, f);
                        lemma_count_le(x as nat, f);
                    }
                    if !disc[x] {
                        cnt = cnt + 1;
                    }
                    from = x + 1;
                },
                None => break,
            }
        }
        proof {
            assert forall|j: int| from <= j < n implies !#[trigger] f(j) by {
                if j >= 0 && ancestor(cs@, i as int, j) {
                    assert(anc[i as int].has(j as nat));
                }
            }
            lemma_count_skip(from as nat, n as nat, f);
            lemma_count_ext(n as nat, f, pend_f(cs@, disc@, none, i as int));
        }
        let ghost old_ready = ready_list@;
        if !disc[i] && cnt == 0 {
            proof { assert(!ready_list@.contains(i)); }
            ready_list.push(i);
        }
        waiting.push(cnt);
        taken.push(false);
        proof {
            assert forall|c: usize| ready_list@.contains(c) <==> (c < waiting.len() && !disc[c as int] && waiting[c as int] == 0) by {
                if ready_list@.contains(c) && c != i {
                    assert(old_ready.contains(c));
                }
                if c < waiting.len() && !disc[c as int] && waiting[c as int] == 0 && c != i {
                    assert(old_ready.contains(c));
                    let q = old_ready.index_of(c);
                    assert(ready_list@[q] == c);
                }
                if c == i {
                    assert(!old_ready.contains(i));
                    if !disc[i as int] && cnt == 0 {
                        assert(ready_list@[ready_list.len() - 1] == i);
                    }
                }
            }
        }
    }
    proof {
        assert(taken@ =~= none);
        assert forall|c: int| 0 <= c < n && !disc[c] implies #[trigger] waiting[c] as nat == pending(cs@, disc@, taken@, c) by {}
    }
    let mut order: Vec<usize> = Vec::new();
    proof {
        lemma_count_zero(n as nat, taken_f(taken@));
        assert(order@ =~= Seq::<usize>::empty());
    }
    while ready_list.len() > 0
        invariant
            valid(cs@),
            n == cs.len(),
            anc_exact(cs@, anc@),
            disc_ok(cs@, disc@),
            desc.len() == n,
            forall|x: int| 0 <= x < n ==> (#[trigger] desc[x]).words.len() == words_for(n as nat),
            forall|x: int, c: nat| 0 <= x < n && c < n ==> (#[trigger] desc[x].has(c) <==> ancestor(cs@, c as int, x)),
            forall|x: int, c: nat| 0 <= x < n && #[trigger] desc[x].has(c) ==> c < n,
            waiting.len() == n,
            taken.len() == n,
            taken_matches(order@, taken@),
            order@.no_duplicates(),
            order.len() == count(n as nat, taken_f(taken@)),
            forall|k: int| 0 <= k < order.len() ==> (order[k] as int) < n && eligible(disc@, order[k] as int),
            forall|c: int| 0 <= c < n && !disc[c] && !taken[c] ==> #[trigger] waiting[c] as nat == pending(cs@, disc@, taken@, c),
            forall|c: usize| ready_list@.contains(c) <==> (c < n && !disc[c as int] && !taken[c as int] && waiting[c as int] == 0),
            ready_list@.no_duplicates(),
            forall|k: int| 0 <= k < order.len() ==> ready(cs@, disc@, order@.subrange(0, k), #[trigger] order[k] as int),
            forall|k: int, c: int| 0 <= k < order.len() && #[trigger] ready(cs@, disc@, order@.subrange(0, k), c)
                ==> c == order[k] as int || key_lt(cs@, order[k] as int, c),
        decreases n - order.len(),
    {
        // The smallest ready change.
        let mut best: usize = 0;
        let mut m: usize = 1;
        proof {
            assert forall|q: int| 0 <= q < ready_list.len() implies (ready_list[q] as int) < n by {
                assert(ready_list@.contains(ready_list[q]));
            }
        }
        while m < ready_list.len()
            invariant
                n == cs.len(),
                best < m,
                best < ready_list.len(),
                m <= ready_list.len(),
                forall|q: int| 0 <= q < ready_list.len() ==> (ready_list[q] as int) < n,
                forall|q: int| 0 <= q < m ==> q == best || key_lt(cs@, ready_list[best as int] as int, #[trigger] ready_list[q] as int),
                ready_list@.no_duplicates(),
            decreases ready_list.len() - m,
        {
            proof {
                assert(ready_list@.contains(ready_list[m as int]));
            }
            if key_less(cs, ready_list[m], ready_list[best]) {
                proof {
                    assert forall|q: int| 0 <= q < m + 1 implies q == m || key_lt(cs@, ready_list[m as int] as int, #[trigger] ready_list[q] as int) by {
                        if q < m && q != best {
                            lemma_key_order(cs@, ready_list[m as int] as int, ready_list[best as int] as int, ready_list[q] as int);
                        }
                    }
                }
                best = m;
            } else {
                proof {
                    lemma_key_order(cs@, ready_list[m as int] as int, ready_list[best as int] as int, 0);
                    assert(ready_list[m as int] != ready_list[best as int]);
                }
            }
            m = m + 1;
        }
        let x = ready_list[best];
        let ghost before_ready = ready_list@;
        let ghost before_taken = taken@;
        let ghost before_order = order@;
        assert(ready_list@.contains(x));
        proof {
            // x is ready: its pending count is zero.
            assert(waiting[x as int] == 0);
            assert(pending(cs@, disc@, taken@, x as int) == 0);
            lemma_count_zero(n as nat, pend_f(cs@, disc@, taken@, x as int));
            assert forall|j: int| #[trigger] ancestor(cs@, x as int, j) && eligible(disc@, j) implies order@.contains(j as usize) by {
                lemma_ancestor_in_range(cs@, x as int, j);
                assert(!pend_f(cs@, disc@, taken@, x as int)(j));
                assert(taken[j]);
            }
            assert(order@.subrange(0, order.len() as int) =~= order@);
            assert(ready(cs@, disc@, order@, x as int));
            // and the smallest ready change.
            assert forall|c: int| ready(cs@, disc@, order@, c) implies c == x as int || key_lt(cs@, x as int, c) by {
                assert forall|j: int| 0 <= j < n implies !#[trigger] pend_f(cs@, disc@, taken@, c)(j) by {
                    if !disc@[j] && ancestor(cs@, c, j) {
                        assert(order@.contains(j as usize));
                    }
                }
                lemma_count_zero(n as nat, pend_f(cs@, disc@, taken@, c));
                assert(waiting[c] == 0);
                assert(ready_list@.contains(c as usize));
                let q = ready_list@.index_of(c as usize);
                assert(q == best || key_lt(cs@, x as int, ready_list[q] as int));
            }
        }
        ready_list.remove(best);
        taken.set(x, true);
        order.push(x);
        proof {
            lemma_count_flip(n as nat, taken_f(taken@), taken_f(before_taken), x as int);
            assert forall|j: int| 0 <= j < n implies (#[trigger] taken@[j] <==> order@.contains(j as usize)) by {
                if j == x as int {
                    assert(order@[order.len() - 1] == x);
                } else {
                    assert(before_taken[j] <==> before_order.contains(j as usize));
                    assert(before_order.contains(j as usize) == order@.contains(j as usize)) by {
                        assert(order@ == before_order.push(x));
                        if order@.contains(j as usize) {
                            let k = order@.index_of(j as usize);
                            assert(k < before_order.len());
                            assert(before_order[k] == j as usize);
                        }
                        if before_order.contains(j as usize) {
                            let k = before_order.index_of(j as usize);
                            assert(order@[k] == j as usize);
                        }
                    }
                }
            }
            assert forall|k: int| 0 <= k < order.len() implies ready(cs@, disc@, order@.subrange(0, k), #[trigger] order[k] as int) by {
                assert(order@.subrange(0, k) =~= if k < before_order.len() { before_order.subrange(0, k) } else { before_order });
            }
            assert forall|k: int, c: int| 0 <= k < order.len() && #[trigger] ready(cs@, disc@, order@.subrange(0, k), c)
                implies c == order[k] as int || key_lt(cs@, order[k] as int, c) by {
                assert(order@.subrange(0, k) =~= if k < before_order.len() { before_order.subrange(0, k) } else { before_order });
            }
            assert forall|c: usize| (c < n && !disc[c as int] && !taken[c as int] && waiting[c as int] == 0) implies ready_list@.contains(c) by {
                assert(c != x);
                assert(!before_taken[c as int]);
                assert(before_ready.contains(c));
                let q = before_ready.index_of(c);
                assert(q != best);
                if q < best {
                    assert(ready_list@[q] == c);
                } else {
                    assert(ready_list@[q - 1] == c);
                }
            }
            assert forall|c: usize| ready_list@.contains(c) implies (c < n && !disc[c as int] && !taken[c as int] && waiting[c as int] == 0) by {
                let q = ready_list@.index_of(c);
                assert(before_ready.contains(c));
                assert(c != x) by {
                    if c == x {
                        assert(before_ready[best as int] == x);
                        assert(q < best ==> before_ready[q] == c);
                        assert(q >= best ==> before_ready[q + 1] == c);
                    }
                }
            }
        }
        // Each change x is an ancestor of now waits for one fewer.
        let ghost after_take_ready = ready_list@;
        let mut from: usize = 0;
        proof { lemma_words_small(n as nat); }
        loop
            invariant
                valid(cs@),
                n == cs.len(),
                (x as int) < n,
                from <= n,
                anc_exact(cs@, anc@),
                disc_ok(cs@, disc@),
                desc.len() == n,
                desc[x as int].words.len() <= 0x100_0000,
                forall|y: int| 0 <= y < n ==> (#[trigger] desc[y]).words.len() == words_for(n as nat),
                forall|y: int, c: nat| 0 <= y < n && c < n ==> (#[trigger] desc[y].has(c) <==> ancestor(cs@, c as int, y)),
                forall|y: int, c: nat| 0 <= y < n && #[trigger] desc[y].has(c) ==> c < n,
                waiting.len() == n,
                taken.len() == n,
                taken[x as int],
                !disc[x as int],
                !before_taken[x as int],
                forall|j: int| 0 <= j < n && j != x ==> taken@[j] == before_taken[j],
                before_taken.len() == n,
                forall|c: int| 0 <= c < n && !disc[c] && !taken[c] && c < from ==> #[trigger] waiting[c] as nat == pending(cs@, disc@, taken@, c),
                forall|c: int| 0 <= c < n && !disc[c] && !taken[c] && c >= from ==> #[trigger] waiting[c] as nat == pending(cs@, disc@, before_taken, c),
                forall|c: usize| ready_list@.contains(c) <==> (c < n && !disc[c as int] && !taken[c as int] && waiting[c as int] == 0),
                ready_list@.no_duplicates(),
            ensures
                forall|c: int| 0 <= c < n && !disc[c] && !taken[c] && c < from ==> #[trigger] waiting[c] as nat == pending(cs@, disc@, taken@, c),
                forall|c: int| 0 <= c < n && !disc[c] && !taken[c] && c >= from ==> #[trigger] waiting[c] as nat == pending(cs@, disc@, before_taken, c),
                forall|c: nat| from <= c ==> !#[trigger] desc[x as int].has(c),
                forall|c: usize| ready_list@.contains(c) <==> (c < n && !disc[c as int] && !taken[c as int] && waiting[c as int] == 0),
                ready_list@.no_duplicates(),
            decreases n - from,
        {
            match desc[x].next_set(from) {
                Some(c) => {
                    proof {
                        assert(desc[x as int].has(c as nat));
                        // Changes between `from` and c don't have x as an ancestor: nothing changes for them.
                        assert forall|d: int| 0 <= d < n && !disc[d] && !taken[d] && from <= d < c implies
                            pending(cs@, disc@, before_taken, d) == pending(cs@, disc@, taken@, d) by {
                            assert(!desc[x as int].has(d as nat));
                            lemma_count_ext(n as nat, pend_f(cs@, disc@, before_taken, d),
                                pend_f(cs@, disc@, taken@, d));
                        }
                    }
                    if !disc[c] && !taken[c] {
                        proof {
                            lemma_count_flip(n as nat, pend_f(cs@, disc@, before_taken, c as int),
                                pend_f(cs@, disc@, taken@, c as int), x as int);
                        }
                        let ghost old_ready = ready_list@;
                        let ghost old_waiting = waiting@;
                        proof {
                            assert(!ready_list@.contains(c));
                        }
                        let w = waiting[c] - 1;
                        waiting.set(c, w);
                        if w == 0 {
                            ready_list.push(c);
                        }
                        proof {
                            assert forall|c2: usize| ready_list@.contains(c2) <==> (c2 < n && !disc[c2 as int] && !taken[c2 as int] && waiting[c2 as int] == 0) by {
                                assert(old_ready.contains(c2) <==> (c2 < n && !disc[c2 as int] && !taken[c2 as int] && old_waiting[c2 as int] == 0));
                                if c2 == c {
                                    if w == 0 {
                                        assert(ready_list@[ready_list.len() - 1] == c);
                                    } else {
                                        assert(ready_list@ == old_ready);
                                    }
                                }
                                if c2 != c && ready_list@.contains(c2) {
                                    let q = ready_list@.index_of(c2);
                                    assert(q < old_ready.len());
                                    assert(old_ready[q] == c2);
                                }
                                if c2 != c && (c2 as int) < n {
                                    assert(waiting[c2 as int] == old_waiting[c2 as int]);
                                    if ready_list@.contains(c2) {
                                        assert(old_ready.contains(c2));
                                    }
                                    if old_ready.contains(c2) {
                                        let q = old_ready.index_of(c2);
                                        assert(ready_list@[q] == c2);
                                    }
                                }
                            }
                        }
                    }
                    from = c + 1;
                },
                None => break,
            }
        }
        proof {
            assert forall|c: int| 0 <= c < n && !disc[c] && !taken[c] implies #[trigger] waiting[c] as nat == pending(cs@, disc@, taken@, c) by {
                if c >= from {
                    assert(!desc[x as int].has(c as nat));
                    lemma_count_ext(n as nat, pend_f(cs@, disc@, before_taken, c),
                        pend_f(cs@, disc@, taken@, c));
                }
            }
            lemma_count_le(n as nat, taken_f(taken@));
        }
    }
    proof {
        assert forall|j: usize| #[trigger] order@.contains(j) implies eligible(disc@, j as int) by {
            let k = order@.index_of(j);
            assert(eligible(disc@, order[k] as int));
        }
        // Nothing is ready, so every eligible change has been taken.
        assert forall|j: usize| eligible(disc@, j as int) implies #[trigger] order@.contains(j) by {
            if !taken[j as int] {
                let r = lemma_some_ready(cs@, disc@, taken@, j as int, anc_card(cs@, j as int));
                assert(waiting[r] == 0);
                assert(ready_list@.contains(r as usize));
            }
        }
    }
    order
}

proof fn lemma_prefixes_agree(cs: Seq<Change>, disc: Seq<bool>, a: Seq<usize>, b: Seq<usize>, k: int)
    requires
        is_reading_order(cs, disc, a),
        is_reading_order(cs, disc, b),
        0 <= k <= a.len(),
        k <= b.len(),
    ensures
        a.subrange(0, k) == b.subrange(0, k),
    decreases k,
{
    if k > 0 {
        let j = k - 1;
        lemma_prefixes_agree(cs, disc, a, b, j);
        let x = a[j] as int;
        let y = b[j] as int;
        assert(ready(cs, disc, a.subrange(0, j), x));
        assert(ready(cs, disc, b.subrange(0, j), y));
        assert(x == y) by {
            if x != y {
                assert(key_lt(cs, x, y));
                assert(key_lt(cs, y, x));
                lemma_key_order(cs, x, y, x);
            }
        }
        assert(a.subrange(0, k) =~= a.subrange(0, j).push(a[j]));
        assert(b.subrange(0, k) =~= b.subrange(0, j).push(b[j]));
    }
}

/// Only one order fits the description.
pub proof fn lemma_reading_order_unique(cs: Seq<Change>, disc: Seq<bool>, a: Seq<usize>, b: Seq<usize>)
    requires
        is_reading_order(cs, disc, a),
        is_reading_order(cs, disc, b),
    ensures
        a == b,
{
    let m: int = if a.len() < b.len() { a.len() as int } else { b.len() as int };
    lemma_prefixes_agree(cs, disc, a, b, m);
    if a.len() < b.len() {
        let y = b[m];
        assert(eligible(disc, y as int));
        assert(a.contains(y));
        let i = a.index_of(y);
        assert(a.subrange(0, m)[i] == b.subrange(0, m)[i]);
        assert(b[i] == y);
    } else if b.len() < a.len() {
        let y = a[m];
        assert(eligible(disc, y as int));
        assert(b.contains(y));
        let i = b.index_of(y);
        assert(a.subrange(0, m)[i] == b.subrange(0, m)[i]);
        assert(a[i] == y);
    }
    assert(a.len() == b.len());
    assert forall|i: int| 0 <= i < a.len() implies a[i] == b[i] by {
        assert(a.subrange(0, m)[i] == b.subrange(0, m)[i]);
    }
    assert(a =~= b);
}

} // verus!
