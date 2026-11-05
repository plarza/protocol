//! Merkle trees as in RFC 9162 section 2.1, for endorsements (section 10).
//!
//! `root` and `path` are proven equal to the RFC's recursive definitions `spec_mth` and
//! `spec_path`; `verify` follows section 2.1.3.2 step by step (`spec_verify`), and
//! `lemma_path_verifies` proves every proof `path` makes verifies against `root`.
use vstd::arithmetic::power2::*;
use vstd::prelude::*;

verus! {

pub uninterp spec fn spec_sha256(data: Seq<u8>) -> Seq<u8>;

#[verifier::external_body]
pub fn sha256(data: &[u8]) -> (r: Vec<u8>)
    ensures
        r@ == spec_sha256(data@),
        r.len() == 32,
{
    libcrux_sha2::sha256(data).to_vec()
}

/// The largest power of two smaller than `n`, searching up from `k`.
pub open spec fn spec_split_from(n: nat, k: nat) -> nat
    decreases n - k,
{
    if k >= 1 && k * 2 < n {
        spec_split_from(n, k * 2)
    } else {
        k
    }
}

pub open spec fn spec_split(n: nat) -> nat {
    spec_split_from(n, 1)
}

proof fn lemma_split_from_bounds(n: nat, k: nat)
    requires
        1 <= k < n,
    ensures
        k <= spec_split_from(n, k) < n,
        spec_split_from(n, k) >= 1,
    decreases n - k,
{
    if k * 2 < n {
        lemma_split_from_bounds(n, k * 2);
    }
}

pub open spec fn spec_leaf(d: Seq<u8>) -> Seq<u8> {
    spec_sha256(seq![0u8] + d)
}

pub open spec fn spec_node(l: Seq<u8>, r: Seq<u8>) -> Seq<u8> {
    spec_sha256(seq![1u8] + l + r)
}

/// MTH(D[lo:hi]).
pub open spec fn spec_mth(d: Seq<Seq<u8>>, lo: nat, hi: nat) -> Seq<u8>
    decreases hi - lo,
{
    if hi <= lo {
        spec_sha256(Seq::empty())
    } else if hi - lo == 1 {
        spec_leaf(d[lo as int])
    } else {
        let k = spec_split((hi - lo) as nat);
        if 1 <= k < hi - lo {
            spec_node(spec_mth(d, lo, lo + k), spec_mth(d, lo + k, hi))
        } else {
            Seq::empty()
        }
    }
}

/// PATH(m, D[lo:hi]).
pub open spec fn spec_path(m: nat, d: Seq<Seq<u8>>, lo: nat, hi: nat) -> Seq<Seq<u8>>
    decreases hi - lo,
{
    if hi <= lo + 1 {
        Seq::empty()
    } else {
        let k = spec_split((hi - lo) as nat);
        if !(1 <= k < hi - lo) {
            Seq::empty()
        } else if m < k {
            spec_path(m, d, lo, lo + k).push(spec_mth(d, lo + k, hi))
        } else {
            spec_path((m - k) as nat, d, lo + k, hi).push(spec_mth(d, lo, lo + k))
        }
    }
}

pub open spec fn views(d: Seq<Vec<u8>>) -> Seq<Seq<u8>> {
    d.map(|_i, v: Vec<u8>| v@)
}

fn split(n: usize) -> (k: usize)
    requires
        n >= 2,
    ensures
        k == spec_split(n as nat),
        1 <= k < n,
{
    let mut k: usize = 1;
    proof { lemma_split_from_bounds(n as nat, 1); }
    while k < n / 2 + n % 2 && k * 2 < n
        invariant
            1 <= k < n,
            spec_split_from(n as nat, k as nat) == spec_split(n as nat),
        decreases n - k,
    {
        k = k * 2;
    }
    k
}

fn concat3(a: u8, b: &[u8], c: &[u8]) -> (r: Vec<u8>)
    ensures
        r@ == seq![a] + b@ + c@,
{
    let mut out: Vec<u8> = Vec::new();
    out.push(a);
    out.extend_from_slice(b);
    out.extend_from_slice(c);
    out
}

pub fn leaf_hash(d: &[u8]) -> (r: Vec<u8>)
    ensures
        r@ == spec_leaf(d@),
{
    let empty: Vec<u8> = Vec::new();
    let input = concat3(0, d, empty.as_slice());
    assert(input@ =~= seq![0u8] + d@);
    sha256(input.as_slice())
}

pub fn node_hash(l: &[u8], r: &[u8]) -> (h: Vec<u8>)
    ensures
        h@ == spec_node(l@, r@),
{
    let input = concat3(1, l, r);
    sha256(input.as_slice())
}

fn mth(d: &Vec<Vec<u8>>, lo: usize, hi: usize) -> (r: Vec<u8>)
    requires
        lo <= hi <= d.len(),
    ensures
        r@ == spec_mth(views(d@), lo as nat, hi as nat),
    decreases hi - lo,
{
    if hi == lo {
        let empty: Vec<u8> = Vec::new();
        sha256(empty.as_slice())
    } else if hi - lo == 1 {
        assert(views(d@)[lo as int] == d@[lo as int]@);
        leaf_hash(d[lo].as_slice())
    } else {
        let k = split(hi - lo);
        let l = mth(d, lo, lo + k);
        let r = mth(d, lo + k, hi);
        node_hash(l.as_slice(), r.as_slice())
    }
}

/// The root of the tree over the leaf data `d`.
pub fn root(d: &Vec<Vec<u8>>) -> (r: Vec<u8>)
    ensures
        r@ == spec_mth(views(d@), 0, d.len() as nat),
{
    mth(d, 0, d.len())
}

fn path_in(m: usize, d: &Vec<Vec<u8>>, lo: usize, hi: usize) -> (r: Vec<Vec<u8>>)
    requires
        lo <= hi <= d.len(),
    ensures
        views(r@) == spec_path(m as nat, views(d@), lo as nat, hi as nat),
    decreases hi - lo,
{
    if hi - lo <= 1 {
        let r: Vec<Vec<u8>> = Vec::new();
        assert(views(r@) =~= Seq::empty());
        r
    } else {
        let k = split(hi - lo);
        if m < k {
            let mut p = path_in(m, d, lo, lo + k);
            let sib = mth(d, lo + k, hi);
            let ghost before = p@;
            p.push(sib);
            assert(views(p@) =~= views(before).push(sib@));
            p
        } else {
            let mut p = path_in(m - k, d, lo + k, hi);
            let sib = mth(d, lo, lo + k);
            let ghost before = p@;
            p.push(sib);
            assert(views(p@) =~= views(before).push(sib@));
            p
        }
    }
}

/// The inclusion path of leaf `m`.
pub fn path(m: usize, d: &Vec<Vec<u8>>) -> (r: Vec<Vec<u8>>)
    ensures
        views(r@) == spec_path(m as nat, views(d@), 0, d.len() as nat),
{
    path_in(m, d, 0, d.len())
}

/// Step 7.4's inner loop: right-shift `fn` and `sn` equally until `fn`'s low bit is set or `fn`
/// is 0.
pub open spec fn spec_shift(f: int, s: int) -> (int, int)
    decreases f,
{
    if f > 0 && f % 2 == 0 {
        spec_shift(f / 2, s / 2)
    } else {
        (f, s)
    }
}

/// One element `p` of an inclusion proof, RFC 9162 section 2.1.3.2 step 7, from `r`, `fn` and `sn`.
pub open spec fn spec_step(r: Seq<u8>, f: int, s: int, p: Seq<u8>) -> Option<(Seq<u8>, int, int)> {
    if s == 0 {
        None
    } else if f % 2 == 1 || f == s {
        let (f2, s2) = if f % 2 == 0 { spec_shift(f, s) } else { (f, s) };
        Some((spec_node(p, r), f2 / 2, s2 / 2))
    } else {
        Some((spec_node(r, p), f / 2, s / 2))
    }
}

/// Step 7 over every element of `proof`, or `None` if `sn` reached 0 too early.
pub open spec fn spec_fold(r: Seq<u8>, f: int, s: int, proof: Seq<Seq<u8>>) -> Option<(Seq<u8>, int, int)>
    decreases proof.len(),
{
    if proof.len() == 0 {
        Some((r, f, s))
    } else {
        match spec_step(r, f, s, proof[0]) {
            Some((r2, f2, s2)) => spec_fold(r2, f2, s2, proof.drop_first()),
            None => None,
        }
    }
}

/// RFC 9162 section 2.1.3.2: `proof` shows that `leaf` is the leaf data at `index` of a tree of
/// `size` leaves whose root is `root`.
pub open spec fn spec_verify(leaf: Seq<u8>, index: int, size: int, proof: Seq<Seq<u8>>, root: Seq<u8>) -> bool {
    &&& index < size
    &&& spec_fold(spec_leaf(leaf), index, size - 1, proof) matches Some((r, _, s))
    &&& s == 0
    &&& r == root
}

proof fn lemma_fold_push(r: Seq<u8>, f: int, s: int, proof: Seq<Seq<u8>>, x: Seq<u8>)
    ensures
        spec_fold(r, f, s, proof.push(x)) == match spec_fold(r, f, s, proof) {
            Some((r2, f2, s2)) => spec_step(r2, f2, s2, x),
            None => None,
        },
    decreases proof.len(),
{
    reveal_with_fuel(spec_fold, 2);
    if proof.len() == 0 {
        assert(proof.push(x).drop_first() =~= Seq::<Seq<u8>>::empty());
        assert(proof.push(x)[0] == x);
    } else {
        assert(proof.push(x).drop_first() =~= proof.drop_first().push(x));
        assert(proof.push(x)[0] == proof[0]);
        match spec_step(r, f, s, proof[0]) {
            Some((r2, f2, s2)) => lemma_fold_push(r2, f2, s2, proof.drop_first(), x),
            None => {},
        }
    }
}

/// The smallest `a` with 2^a >= n.
pub open spec fn spec_clog(n: nat) -> nat
    decreases n,
{
    if n <= 1 {
        0
    } else {
        1 + spec_clog(((n + 1) / 2) as nat)
    }
}

proof fn lemma_clog(n: nat)
    requires
        n >= 1,
    ensures
        n <= pow2(spec_clog(n)),
        n >= 2 ==> spec_clog(n) >= 1 && pow2((spec_clog(n) - 1) as nat) < n,
    decreases n,
{
    if n >= 2 {
        let h = ((n + 1) / 2) as nat;
        lemma_clog(h);
        let c = spec_clog(h);
        let e = spec_clog(n);
        assert(e == c + 1);
        lemma_pow2_unfold(e);
        assert(pow2(e) == 2 * pow2(c));
        if h >= 2 {
            lemma_pow2_unfold(c);
        } else {
            assert(c == 0);
            lemma2_to64();
        }
    } else {
        lemma2_to64();
    }
}

proof fn lemma_pow2_mono(e1: nat, e2: nat)
    requires
        e1 <= e2,
    ensures
        pow2(e1) <= pow2(e2),
{
    if e1 < e2 {
        lemma_pow2_strictly_increases(e1, e2);
    }
}

/// `spec_split` of a size between 2^(a-1) (exclusive) and 2^a is 2^(a-1).
proof fn lemma_split_pow2(n: nat, a: nat, j: nat)
    requires
        a >= 1,
        j <= a - 1,
        pow2((a - 1) as nat) < n <= pow2(a),
    ensures
        spec_split_from(n, pow2(j)) == pow2((a - 1) as nat),
    decreases a - 1 - j,
{
    lemma_pow2_pos(j);
    lemma_pow2_unfold(j + 1);
    if j < a - 1 {
        lemma_pow2_mono(j + 1, (a - 1) as nat);
        lemma_split_pow2(n, a, j + 1);
    } else {
        lemma_pow2_unfold(a);
    }
}

proof fn lemma_shift_pow2(q: int, j: nat)
    requires
        q >= 1,
        q % 2 == 1,
    ensures
        spec_shift(q * pow2(j), q * pow2(j)) == (q, q),
    decreases j,
{
    if j > 0 {
        lemma_pow2_unfold(j);
        let p = pow2((j - 1) as nat) as int;
        lemma_pow2_pos((j - 1) as nat);
        assert(q * pow2(j) == 2 * (q * p)) by (nonlinear_arith) requires pow2(j) == 2 * p;
        assert(q * p >= 1) by (nonlinear_arith) requires q >= 1, p >= 1;
        assert((2 * (q * p)) / 2 == q * p);
        lemma_shift_pow2(q, (j - 1) as nat);
    } else {
        lemma2_to64();
        assert(q * pow2(0) == q) by (nonlinear_arith) requires pow2(0) == 1;
    }
}

/// Step 7 over `PATH(m, D[lo:hi])`, started with `fn` and `sn` as `F·2^a + m` and `S·2^a + x`,
/// ends at `MTH(D[lo:hi])` with `fn` and `sn` as `F` and `S`: either the subtree is a full left
/// subtree (`F < S`), or it is on the right edge (`F == S`) and `x` is its last index.
proof fn lemma_fold_path(d: Seq<Seq<u8>>, lo: nat, hi: nat, m: nat, a: nat, f: int, s: int, x: int)
    requires
        lo < hi,
        m < hi - lo,
        hi - lo <= pow2(a),
        hi - lo >= 2 ==> a >= 1 && pow2((a - 1) as nat) < hi - lo,
        hi - lo == 1 ==> a == 0,
        0 <= f <= s,
        0 <= x < pow2(a),
        (f < s && hi - lo == pow2(a)) || (f == s && x == hi - lo - 1),
    ensures
        spec_fold(spec_leaf(d[(lo + m) as int]), f * pow2(a) + m, s * pow2(a) + x, spec_path(m, d, lo, hi))
            == Some((spec_mth(d, lo, hi), f, s)),
    decreases hi - lo,
{
    let n = (hi - lo) as nat;
    let leaf = spec_leaf(d[(lo + m) as int]);
    lemma_pow2_pos(a);
    if n == 1 {
        lemma2_to64();
        assert(pow2(a) == 1);
        assert(f * pow2(a) == f) by (nonlinear_arith) requires pow2(a) == 1;
        assert(s * pow2(a) == s) by (nonlinear_arith) requires pow2(a) == 1;
        assert(spec_path(m, d, lo, hi) =~= Seq::empty());
    } else {
        let k = spec_split(n);
        let h = pow2((a - 1) as nat) as int;
        lemma_pow2_unfold(a);
        lemma_pow2_pos((a - 1) as nat);
        lemma2_to64();
        lemma_split_pow2(n, a, 0);
        assert(k == h);
        if a - 1 >= 1 {
            lemma_pow2_unfold((a - 1) as nat);
            lemma_pow2_pos((a - 2) as nat);
        }
        // fn and sn split at the child's level: f·2^a + m = (2f + m / h)·h + m % h.
        let sc = 2 * s + x / h;
        let xc = x % h;
        assert(s * pow2(a) + x == sc * h + xc) by (nonlinear_arith)
            requires pow2(a) == 2 * h, h >= 1, sc == 2 * s + x / h, xc == x % h;
        assert(x / h < 2) by (nonlinear_arith) requires x < 2 * h, h >= 1, x >= 0;
        assert(0 <= xc < h) by (nonlinear_arith) requires h >= 1, xc == x % h, x >= 0;
        if m < k {
            let fc = 2 * f;
            assert(f * pow2(a) + m == fc * h + m) by (nonlinear_arith) requires pow2(a) == 2 * h, fc == 2 * f;
            if f == s {
                assert(x / h >= 1) by (nonlinear_arith) requires x >= h, h >= 1;
            }
            if h >= 2 {
                lemma_pow2_unfold((a - 1) as nat);
            }
            lemma_fold_path(d, lo, lo + k, m, (a - 1) as nat, fc, sc, xc);
            lemma_fold_push(leaf, fc * h + m, sc * h + xc, spec_path(m, d, lo, lo + k), spec_mth(d, lo + k, hi));
            assert(fc % 2 == 0);
            assert(sc / 2 == s);
        } else {
            let mc = (m - k) as nat;
            assert(d[(lo + m) as int] == d[((lo + k) as nat + mc) as int]);
            if f < s {
                let fc = 2 * f + 1;
                assert(f * pow2(a) + m == fc * h + mc) by (nonlinear_arith)
                    requires pow2(a) == 2 * h, fc == 2 * f + 1, m == h + mc;
                assert(n - k == h);
                if h >= 2 {
                    lemma_pow2_unfold((a - 1) as nat);
                }
                lemma_fold_path(d, lo + k, hi, mc, (a - 1) as nat, fc, sc, xc);
                lemma_fold_push(leaf, fc * h + mc, sc * h + xc, spec_path(mc, d, lo + k, hi), spec_mth(d, lo, lo + k));
                assert(fc % 2 == 1);
                assert(fc / 2 == f);
                assert(sc / 2 == s);
            } else {
                // The right edge: the child's level is ac = clog(n - k) <= a - 1.
                let nc = (n - k) as nat;
                lemma_clog(nc);
                let ac = spec_clog(nc);
                if ac > a - 1 {
                    lemma_pow2_mono((a - 1) as nat, (ac - 1) as nat);
                    assert(false);
                }
                let j = (a - 1 - ac) as nat;
                let q = 2 * f + 1;
                lemma_pow2_adds(j, ac);
                lemma_pow2_adds(j + 1, ac);
                lemma_pow2_unfold(j + 1);
                let pj = pow2(j) as int;
                let pc = pow2(ac) as int;
                lemma_pow2_pos(ac);
                lemma_pow2_pos(j);
                let fc = q * pj;
                assert(h == pj * pc);
                assert(pow2(a) == 2 * pj * pc) by (nonlinear_arith) requires pow2(a) == 2 * h, h == pj * pc;
                assert(f * pow2(a) + m == fc * pc + mc) by (nonlinear_arith)
                    requires pow2(a) == 2 * pj * pc, fc == q * pj, q == 2 * f + 1, m == h + mc, h == pj * pc;
                assert(s * pow2(a) + x == fc * pc + (nc - 1)) by (nonlinear_arith)
                    requires pow2(a) == 2 * pj * pc, fc == q * pj, q == 2 * f + 1, x == n - 1, n == h + nc,
                        h == pj * pc, f == s;
                assert(fc >= 1) by (nonlinear_arith) requires q >= 1, pj >= 1, fc == q * pj;
                lemma_fold_path(d, lo + k, hi, mc, ac, fc, fc, (nc - 1) as int);
                lemma_fold_push(leaf, fc * pc + mc, fc * pc + (nc - 1), spec_path(mc, d, lo + k, hi), spec_mth(d, lo, lo + k));
                assert((2 * f + 1) % 2 == 1);
                lemma_shift_pow2(q, j);
                if fc % 2 != 0 {
                    // fc is odd only when j == 0, where shifting does nothing.
                    if j > 0 {
                        lemma_pow2_unfold(j);
                        let t = q * pow2((j - 1) as nat);
                        assert(fc == 2 * t) by (nonlinear_arith)
                            requires fc == q * pj, pj == 2 * pow2((j - 1) as nat), t == q * pow2((j - 1) as nat);
                    }
                    lemma2_to64();
                    assert(fc == q);
                }
                assert(q / 2 == f);
            }
        }
    }
}

/// The inclusion proof `path` makes for leaf `m` always verifies against `root`.
pub proof fn lemma_path_verifies(d: Seq<Seq<u8>>, m: nat)
    requires
        m < d.len(),
    ensures
        spec_verify(d[m as int], m as int, d.len() as int, spec_path(m, d, 0, d.len()), spec_mth(d, 0, d.len())),
{
    let n = d.len();
    lemma_clog(n);
    let a = spec_clog(n);
    lemma_pow2_pos(a);
    assert(0 * pow2(a) + m == m);
    assert(0 * pow2(a) + (n - 1) == n - 1);
    lemma_fold_path(d, 0, n, m, a, 0, 0, n - 1);
}

/// Checks an inclusion proof, RFC 9162 section 2.1.3.2: `leaf` is the leaf data at `index` of
/// a tree of `size` leaves whose root is `root`.
pub fn verify(leaf: &[u8], index: u64, size: u64, proof: &Vec<Vec<u8>>, root: &[u8]) -> (ok: bool)
    ensures
        ok == spec_verify(leaf@, index as int, size as int, views(proof@), root@),
{
    if index >= size {
        return false;
    }
    let ghost all = views(proof@);
    let mut f: u64 = index;
    let mut s: u64 = size - 1;
    let mut r = leaf_hash(leaf);
    let mut i: usize = 0;
    assert(all.skip(0) =~= all);
    while i < proof.len()
        invariant
            f <= s,
            i <= proof.len(),
            all == views(proof@),
            index < size,
            spec_fold(spec_leaf(leaf@), index as int, size - 1, all)
                == spec_fold(r@, f as int, s as int, all.skip(i as int)),
        decreases proof.len() - i,
    {
        let p = &proof[i];
        let ghost rest = all.skip(i as int);
        assert(rest[0] == p@);
        assert(rest.drop_first() =~= all.skip(i + 1));
        if s == 0 {
            return false;
        }
        if f % 2 == 1 || f == s {
            r = node_hash(p.as_slice(), r.as_slice());
            if f % 2 == 0 {
                let ghost f0 = f as int;
                let ghost s0 = s as int;
                while f % 2 == 0 && f != 0
                    invariant
                        f <= s,
                        spec_shift(f as int, s as int) == spec_shift(f0, s0),
                    decreases f,
                {
                    f = f / 2;
                    s = s / 2;
                }
            }
        } else {
            r = node_hash(r.as_slice(), p.as_slice());
        }
        f = f / 2;
        s = s / 2;
        i = i + 1;
    }
    assert(all.skip(i as int) =~= Seq::<Seq<u8>>::empty());
    s == 0 && crate::cbor::bytes_eq(r.as_slice(), root)
}

} // verus!
