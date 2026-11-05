//! Putting a map's entries in deterministic order, section 3: keys sorted by their encodings,
//! bytewise, each key once. Every map this software signs goes through `sort_entries`, so what
//! it signs is in the one form other readers accept.
use crate::cbor::*;
use vstd::prelude::*;

verus! {

#[verifier::opaque]
pub open spec fn key_enc(e: (Value, Value)) -> Seq<u8> {
    spec_encode(e.0)
}

/// Keys strictly increase.
pub open spec fn sorted(es: Seq<(Value, Value)>) -> bool {
    forall|i: int, j: int| 0 <= i < j < es.len() ==> lex_lt(#[trigger] key_enc(es[i]), #[trigger] key_enc(es[j]))
}

/// `es[j]` is the first entry of `es` with its key.
pub open spec fn first_of(es: Seq<(Value, Value)>, j: int) -> bool {
    0 <= j < es.len() && forall|k: int| 0 <= k < j ==> key_enc(#[trigger] es[k]) != key_enc(es[j])
}

pub proof fn lemma_lex_irreflexive(a: Seq<u8>)
    ensures
        !lex_lt(a, a),
    decreases a.len(),
{
    if a.len() > 0 {
        lemma_lex_irreflexive(a.drop_first());
    }
}

pub proof fn lemma_lex_transitive(a: Seq<u8>, b: Seq<u8>, c: Seq<u8>)
    requires
        lex_lt(a, b),
        lex_lt(b, c),
    ensures
        lex_lt(a, c),
    decreases a.len(),
{
    if a.len() > 0 && b.len() > 0 && c.len() > 0 && a[0] == b[0] && b[0] == c[0] {
        lemma_lex_transitive(a.drop_first(), b.drop_first(), c.drop_first());
    }
}

pub proof fn lemma_lex_total(a: Seq<u8>, b: Seq<u8>)
    requires
        a != b,
    ensures
        lex_lt(a, b) || lex_lt(b, a),
    decreases a.len(),
{
    if a.len() == 0 && b.len() == 0 {
        assert(a =~= b);
    } else if a.len() > 0 && b.len() > 0 && a[0] == b[0] {
        if a.drop_first() == b.drop_first() {
            assert(a =~= seq![a[0]] + a.drop_first());
            assert(b =~= seq![b[0]] + b.drop_first());
            assert(a =~= b);
        }
        lemma_lex_total(a.drop_first(), b.drop_first());
    }
}

pub proof fn lemma_lex_asymmetric(a: Seq<u8>, b: Seq<u8>)
    requires
        lex_lt(a, b),
    ensures
        !lex_lt(b, a),
{
    if lex_lt(b, a) {
        lemma_lex_transitive(a, b, a);
        lemma_lex_irreflexive(a);
    }
}


pub open spec fn first_from(orig: Seq<(Value, Value)>, n: int, j: int) -> bool {
    n <= j < orig.len() && forall|q: int| n <= q < j ==> key_enc(#[trigger] orig[q]) != key_enc(orig[j])
}


proof fn lemma_sorted_distinct(es: Seq<(Value, Value)>, i: int, j: int)
    requires
        sorted(es),
        0 <= i < es.len(),
        0 <= j < es.len(),
        i != j,
    ensures
        key_enc(es[i]) != key_enc(es[j]),
{
    if i < j {
        assert(lex_lt(key_enc(es[i]), key_enc(es[j])));
    } else {
        assert(lex_lt(key_enc(es[j]), key_enc(es[i])));
    }
    lemma_lex_irreflexive(key_enc(es[i]));
}

pub open spec fn step_ok(orig: Seq<(Value, Value)>, n: int, before: Seq<(Value, Value)>, out: Seq<(Value, Value)>, p: int, same: bool) -> bool {
    &&& 0 <= n < orig.len()
    &&& sorted(before)
    &&& same ==> 0 <= p < before.len() && key_enc(before[p]) == key_enc(orig[n]) && out == before.update(p, orig[n])
    &&& !same ==> 0 <= p <= before.len() && out == before.insert(p, orig[n])
        && (forall|i: int| 0 <= i < p ==> lex_lt(key_enc(#[trigger] before[i]), key_enc(orig[n])))
        && (p < before.len() ==> lex_lt(key_enc(orig[n]), key_enc(before[p])))
}

/// Taking entry n, which goes at p (replacing the kept entry with its key, or inserted where its
/// key belongs), keeps the entries sorted.
proof fn lemma_step_sorted(orig: Seq<(Value, Value)>, n: int, before: Seq<(Value, Value)>, out: Seq<(Value, Value)>, p: int, same: bool)
    requires
        step_ok(orig, n, before, out, p, same),
    ensures
        sorted(out),
{
    let k = key_enc(orig[n]);
    if same {
        assert forall|i: int, j: int| 0 <= i < j < out.len() implies lex_lt(#[trigger] key_enc(out[i]), #[trigger] key_enc(out[j])) by {
            assert(key_enc(out[i]) == key_enc(before[i]));
            assert(key_enc(out[j]) == key_enc(before[j]));
        }
    } else {
        assert forall|i: int| p <= i < before.len() implies lex_lt(k, key_enc(#[trigger] before[i])) by {
            if i > p {
                assert(lex_lt(key_enc(before[p]), key_enc(before[i])));
                lemma_lex_transitive(k, key_enc(before[p]), key_enc(before[i]));
            }
        }
        assert forall|i: int, j: int| 0 <= i < j < out.len() implies lex_lt(#[trigger] key_enc(out[i]), #[trigger] key_enc(out[j])) by {
            if j < p {
                assert(out[i] == before[i] && out[j] == before[j]);
            } else if j == p {
                assert(out[i] == before[i] && out[j] == orig[n]);
            } else if i < p {
                assert(out[i] == before[i] && out[j] == before[j - 1]);
                lemma_lex_transitive(key_enc(before[i]), k, key_enc(before[j - 1]));
            } else if i == p {
                assert(out[i] == orig[n] && out[j] == before[j - 1]);
            } else {
                assert(out[i] == before[i - 1] && out[j] == before[j - 1]);
            }
        }
    }
}



fn key_of(e: &(Value, Value)) -> (k: Vec<u8>)
    ensures
        k@ == key_enc(*e),
{
    let k = encode(&e.0);
    proof { reveal(key_enc); }
    k
}

/// The entries `idx` picks out of `es`.
pub open spec fn chosen(es: Seq<(Value, Value)>, idx: Seq<usize>) -> Seq<(Value, Value)> {
    idx.map_values(|i: usize| es[i as int])
}

pub open spec fn keys_ok(keys: Seq<Vec<u8>>, out: Seq<(Value, Value)>) -> bool {
    keys.len() == out.len() && forall|i: int| 0 <= i < out.len() ==> #[trigger] keys[i]@ == key_enc(out[i])
}

pub open spec fn in_range(idx: Seq<usize>, n: nat) -> bool {
    forall|i: int| 0 <= i < idx.len() ==> (#[trigger] idx[i] as nat) < n
}

/// Puts entry `j` of `es` where its key belongs among those `acc` picks, replacing one with the
/// same key. Returns where, and whether it replaced one.
fn place(es: &Vec<(Value, Value)>, acc: &mut Vec<usize>, keys: &mut Vec<Vec<u8>>, j: usize) -> (r: (usize, bool))
    requires
        j < es.len(),
        in_range(old(acc)@, es.len() as nat),
        sorted(chosen(es@, old(acc)@)),
        keys_ok(old(keys)@, chosen(es@, old(acc)@)),
    ensures
        in_range(final(acc)@, es.len() as nat),
        keys_ok(final(keys)@, chosen(es@, final(acc)@)),
        r.1 ==> 0 <= r.0 < old(acc).len() && key_enc(es@[old(acc)@[r.0 as int] as int]) == key_enc(es@[j as int])
            && final(acc)@ == old(acc)@.update(r.0 as int, j),
        !r.1 ==> r.0 <= old(acc).len() && final(acc)@ == old(acc)@.insert(r.0 as int, j)
            && (forall|i: int| 0 <= i < r.0 ==> lex_lt(key_enc(#[trigger] chosen(es@, old(acc)@)[i]), key_enc(es@[j as int])))
            && (r.0 < old(acc).len() ==> lex_lt(key_enc(es@[j as int]), key_enc(chosen(es@, old(acc)@)[r.0 as int]))),
{
    let ghost before = chosen(es@, acc@);
    let ghost abefore = acc@;
    let ghost kbefore = keys@;
    let k = key_of(&es[j]);
    let mut p: usize = 0;
    while p < keys.len() && lex_less(keys[p].as_slice(), k.as_slice())
        invariant
            p <= keys.len(),
            keys@ == kbefore,
            acc@ == abefore,
            keys_ok(keys@, before),
            forall|i: int| 0 <= i < p ==> lex_lt(key_enc(#[trigger] before[i]), k@),
        decreases keys.len() - p,
    {
        p = p + 1;
    }
    if p < keys.len() && bytes_eq(keys[p].as_slice(), k.as_slice()) {
        acc.set(p, j);
        proof {
            assert(chosen(es@, acc@) =~= before.update(p as int, es@[j as int]));
            assert forall|i: int| 0 <= i < acc.len() implies (#[trigger] acc@[i] as nat) < es.len() by {
                if i != p {
                    assert(acc@[i] == abefore[i]);
                }
            }
        }
        (p, true)
    } else {
        proof {
            if p < keys.len() {
                assert(!lex_lt(key_enc(before[p as int]), k@));
                lemma_lex_total(k@, key_enc(before[p as int]));
            }
        }
        acc.insert(p, j);
        keys.insert(p, k);
        proof {
            assert(chosen(es@, acc@) =~= before.insert(p as int, es@[j as int]));
            assert forall|i: int| 0 <= i < acc.len() implies (#[trigger] acc@[i] as nat) < es.len() by {
                if i < p {
                    assert(acc@[i] == abefore[i]);
                } else if i > p {
                    assert(acc@[i] == abefore[i - 1]);
                }
            }
            let out = chosen(es@, acc@);
            assert forall|i: int| 0 <= i < out.len() implies #[trigger] keys@[i]@ == key_enc(out[i]) by {
                if i < p {
                    assert(out[i] == before[i] && keys@[i] == kbefore[i]);
                } else if i > p {
                    assert(out[i] == before[i - 1] && keys@[i] == kbefore[i - 1]);
                }
            }
        }
        (p, false)
    }
}

/// Every picked entry is the first among `orig[n..]` with its key.
pub open spec fn idx_first(orig: Seq<(Value, Value)>, n: int, idx: Seq<usize>) -> bool {
    forall|i: int| 0 <= i < idx.len() ==> first_from(orig, n, #[trigger] idx[i] as int)
}

proof fn lemma_step_index(orig: Seq<(Value, Value)>, m: int, abefore: Seq<usize>, acc: Seq<usize>, p: int, same: bool)
    requires
        0 <= m < orig.len(),
        in_range(abefore, orig.len() as nat),
        idx_first(orig, m + 1, abefore),
        sorted(chosen(orig, abefore)),
        same ==> 0 <= p < abefore.len() && key_enc(orig[abefore[p] as int]) == key_enc(orig[m]) && acc == abefore.update(p, m as usize),
        !same ==> 0 <= p <= abefore.len() && acc == abefore.insert(p, m as usize)
            && (forall|i: int| 0 <= i < p ==> lex_lt(key_enc(#[trigger] chosen(orig, abefore)[i]), key_enc(orig[m])))
            && (p < abefore.len() ==> lex_lt(key_enc(orig[m]), key_enc(chosen(orig, abefore)[p]))),
        orig.len() <= usize::MAX,
    ensures
        idx_first(orig, m, acc),
{
    let before = chosen(orig, abefore);
    let k = key_enc(orig[m]);
    assert forall|i: int| 0 <= i < acc.len() implies first_from(orig, m, #[trigger] acc[i] as int) by {
        if i == p {
            assert((m as usize) as int == m);
            assert(acc[i] as int == m);
            assert(first_from(orig, m, m));
        } else {
            let i0 = if same || i < p { i } else { i - 1 };
            assert(acc[i] == abefore[i0]);
            let jj = abefore[i0] as int;
            assert(first_from(orig, m + 1, jj));
            assert(before[i0] == orig[jj]);
            if key_enc(orig[jj]) == k {
                if same {
                    assert(before[p] == orig[abefore[p] as int]);
                    lemma_sorted_distinct(before, i0, p);
                } else if i0 < p {
                    // Every entry before p has a smaller key than k.
                    assert(lex_lt(key_enc(before[i0]), k));
                    lemma_lex_irreflexive(k);
                } else {
                    lemma_lex_irreflexive(k);
                    if i0 > p {
                        assert(lex_lt(key_enc(before[p]), key_enc(before[i0])));
                        lemma_lex_transitive(k, key_enc(before[p]), key_enc(before[i0]));
                    }
                }
            }
        }
    }
}

/// Every key of `es` is the key of a picked entry.
pub open spec fn covers(es: Seq<(Value, Value)>, idx: Seq<usize>) -> bool {
    covers_from(es, 0, idx)
}

/// Some picked entry has key `k`.
pub open spec fn has_key(orig: Seq<(Value, Value)>, idx: Seq<usize>, k: Seq<u8>) -> bool {
    exists|i: int| 0 <= i < idx.len() && #[trigger] key_enc(orig[idx[i] as int]) == k
}

/// Every key of `orig[n..]` is the key of a picked entry.
pub open spec fn covers_from(orig: Seq<(Value, Value)>, n: int, idx: Seq<usize>) -> bool {
    forall|j: int| n <= j < orig.len() ==> #[trigger] has_key(orig, idx, key_enc(orig[j]))
}

proof fn lemma_step_cover_idx(orig: Seq<(Value, Value)>, m: int, abefore: Seq<usize>, acc: Seq<usize>, p: int, same: bool)
    requires
        0 <= m < orig.len(),
        orig.len() <= usize::MAX,
        in_range(abefore, orig.len() as nat),
        covers_from(orig, m + 1, abefore),
        same ==> 0 <= p < abefore.len() && key_enc(orig[abefore[p] as int]) == key_enc(orig[m]) && acc == abefore.update(p, m as usize),
        !same ==> 0 <= p <= abefore.len() && acc == abefore.insert(p, m as usize),
    ensures
        covers_from(orig, m, acc),
{
    assert((m as usize) as int == m);
    assert forall|j: int| m <= j < orig.len() implies #[trigger] has_key(orig, acc, key_enc(orig[j])) by {
        if j == m {
            assert(acc[p] as int == m);
            assert(key_enc(orig[acc[p] as int]) == key_enc(orig[j]));
        } else {
            assert(has_key(orig, abefore, key_enc(orig[j])));
            let i0 = choose|i0: int| 0 <= i0 < abefore.len() && #[trigger] key_enc(orig[abefore[i0] as int]) == key_enc(orig[j]);
            if same {
                if i0 == p {
                    assert(acc[p] as int == m);
                    assert(key_enc(orig[acc[p] as int]) == key_enc(orig[j]));
                } else {
                    assert(acc[i0] == abefore[i0]);
                    assert(key_enc(orig[acc[i0] as int]) == key_enc(orig[j]));
                }
            } else if i0 < p {
                assert(acc[i0] == abefore[i0]);
                assert(key_enc(orig[acc[i0] as int]) == key_enc(orig[j]));
            } else {
                assert(acc[i0 + 1] == abefore[i0]);
                assert(key_enc(orig[acc[i0 + 1] as int]) == key_enc(orig[j]));
            }
        }
    }
}

/// Which entries a map in deterministic order keeps, in order: sorted by key, each key once, the
/// first entry with it.
pub fn sort_entries(entries: &Vec<(Value, Value)>) -> (out: Vec<usize>)
    ensures
        in_range(out@, entries.len() as nat),
        sorted(chosen(entries@, out@)),
        forall|i: int| 0 <= i < out.len() ==> first_of(entries@, #[trigger] out@[i] as int),
        covers(entries@, out@),
{
    let ghost orig = entries@;
    let mut acc: Vec<usize> = Vec::new();
    let mut keys: Vec<Vec<u8>> = Vec::new();
    let mut m: usize = entries.len();
    proof { assert(chosen(orig, acc@) =~= Seq::<(Value, Value)>::empty()); }
    // Entries are taken from the end, so an earlier entry with the same key replaces a later one.
    while m > 0
        invariant
            m <= entries.len(),
            orig == entries@,
            in_range(acc@, entries.len() as nat),
            keys_ok(keys@, chosen(orig, acc@)),
            sorted(chosen(orig, acc@)),
            idx_first(orig, m as int, acc@),
            covers_from(orig, m as int, acc@),
        decreases m,
    {
        m = m - 1;
        let ghost before = chosen(orig, acc@);
        let ghost abefore = acc@;
        let (p, same) = place(entries, &mut acc, &mut keys, m);
        proof {
            let out = chosen(orig, acc@);
            if same {
                assert(out =~= before.update(p as int, orig[m as int]));
            } else {
                assert(out =~= before.insert(p as int, orig[m as int]));
            }
            assert(step_ok(orig, m as int, before, out, p as int, same));
            lemma_step_sorted(orig, m as int, before, out, p as int, same);
            lemma_step_cover_idx(orig, m as int, abefore, acc@, p as int, same);
            lemma_step_index(orig, m as int, abefore, acc@, p as int, same);
        }
    }
    proof {
        assert forall|i: int| 0 <= i < acc.len() implies first_of(orig, #[trigger] acc@[i] as int) by {
            assert(first_from(orig, 0, acc@[i] as int));
        }
        assert(covers_from(orig, 0, acc@));
    }
    acc
}

} // verus!
