//! Merkle trees as in RFC 9162 section 2.1, for endorsements (section 10).
//!
//! `root` and `path` are proven equal to the RFC's recursive definitions `spec_mth` and
//! `spec_path`; `verify` follows section 2.1.3.2 step by step.
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

/// Checks an inclusion proof, RFC 9162 section 2.1.3.2: `leaf` is the leaf data at `index` of
/// a tree of `size` leaves whose root is `root`.
pub fn verify(leaf: &[u8], index: u64, size: u64, proof: &Vec<Vec<u8>>, root: &[u8]) -> bool {
    if index >= size {
        return false;
    }
    let mut f: u64 = index;
    let mut s: u64 = size - 1;
    let mut r = leaf_hash(leaf);
    let mut i: usize = 0;
    while i < proof.len()
        invariant
            f <= s,
        decreases proof.len() - i,
    {
        let p = &proof[i];
        if s == 0 {
            return false;
        }
        if f % 2 == 1 || f == s {
            r = node_hash(p.as_slice(), r.as_slice());
            if f % 2 == 0 {
                while f % 2 == 0 && f != 0
                    invariant
                        f <= s,
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
    s == 0 && crate::cbor::bytes_eq(r.as_slice(), root)
}

} // verus!
