//! The encoding rules section 3 adds to Ed25519 verification: `S` < L, canonical encodings of
//! `R` and `A` (RFC 8032 section 5.1.3), and `A` not of small order. The curve equation itself
//! is checked by HACL*'s formally verified Ed25519 (`libcrux-ed25519`) in the caller.
use vstd::prelude::*;

verus! {

pub open spec fn pow256(n: nat) -> nat
    decreases n,
{
    if n == 0 { 1 } else { 256 * pow256((n - 1) as nat) }
}

/// The little-endian number a byte string encodes.
pub open spec fn le_val(s: Seq<u8>) -> nat
    decreases s.len(),
{
    if s.len() == 0 {
        0
    } else {
        le_val(s.subrange(0, s.len() - 1)) + (s[s.len() - 1] as nat) * pow256((s.len() - 1) as nat)
    }
}

/// The order of the base point, L = 2^252 + 27742317777372353535851937790883648493, given by
/// its little-endian bytes.
pub open spec fn order_l() -> nat {
    le_val(L_BYTES@)
}

/// The field prime, p = 2^255 - 19, given by its little-endian bytes.
pub open spec fn prime_p() -> nat {
    le_val(P_BYTES@)
}

pub open spec fn one() -> nat {
    le_val(ONE_BYTES@)
}

pub open spec fn prime_p_minus_1() -> nat {
    le_val(PM1_BYTES@)
}

/// The y-coordinate of an encoded point: its little-endian value with the sign bit cleared.
pub open spec fn y_of(e: Seq<u8>) -> nat {
    le_val(e.update(31, (e[31] & 0x7f) as u8))
}

pub open spec fn sign_bit(e: Seq<u8>) -> bool {
    e[31] >= 0x80
}

/// RFC 8032 section 5.1.3: decoding fails if y >= p, or if x = 0 (y = 1 or y = p - 1) with the
/// sign bit set.
pub open spec fn canonical_point(e: Seq<u8>) -> bool {
    &&& y_of(e) < prime_p()
    &&& !(sign_bit(e) && (y_of(e) == one() || y_of(e) == prime_p_minus_1()))
}

pub const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

pub const ONE_BYTES: [u8; 32] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

pub const PM1_BYTES: [u8; 32] = [
    0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

pub const P_BYTES: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// The eight points of small order, canonically encoded (the torsion subgroup of edwards25519).
pub const SMALL_ORDER: [[u8; 32]; 8] = [
    [0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
     0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80],
    [0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
     0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05],
    [0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    [0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
     0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x85],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
     0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0xfa],
];

pub open spec fn small_order(e: Seq<u8>) -> bool {
    exists|k: int| 0 <= k < 8 && e == #[trigger] SMALL_ORDER[k]@
}

/// The encoding rules section 3 adds: S < L, R and A canonical, A not of small order.
pub open spec fn strict_encoding(a: Seq<u8>, r: Seq<u8>, s: Seq<u8>) -> bool {
    &&& le_val(s) < order_l()
    &&& canonical_point(a)
    &&& canonical_point(r)
    &&& !small_order(a)
}

proof fn lemma_le_bound(s: Seq<u8>)
    ensures
        le_val(s) < pow256(s.len()),
    decreases s.len(),
{
    if s.len() > 0 {
        let t = (s.len() - 1) as nat;
        lemma_le_bound(s.subrange(0, t as int));
        assert(le_val(s) < pow256(s.len())) by (nonlinear_arith)
            requires
                le_val(s) == le_val(s.subrange(0, t as int)) + (s[t as int] as nat) * pow256(t),
                le_val(s.subrange(0, t as int)) < pow256(t),
                s[t as int] <= 255,
                pow256(s.len()) == 256 * pow256(t);
    }
}

/// Comparing little-endian numbers of equal length from the top byte down.
proof fn lemma_le_lt(a: Seq<u8>, b: Seq<u8>, t: nat)
    requires
        a.len() == b.len(),
        t <= a.len(),
        forall|j: int| t <= j < a.len() ==> a[j] == b[j],
    ensures
        (le_val(a) < le_val(b)) == (le_val(a.subrange(0, t as int)) < le_val(b.subrange(0, t as int))),
    decreases a.len() - t,
{
    if t < a.len() {
        let u = (a.len() - 1) as nat;
        let a2 = a.subrange(0, u as int);
        let b2 = b.subrange(0, u as int);
        assert(a2.subrange(0, t as int) =~= a.subrange(0, t as int));
        assert(b2.subrange(0, t as int) =~= b.subrange(0, t as int));
        lemma_le_lt(a2, b2, t);
    } else {
        assert(a.subrange(0, t as int) =~= a);
        assert(b.subrange(0, t as int) =~= b);
    }
}

proof fn lemma_le_top(a: Seq<u8>, b: Seq<u8>)
    requires
        a.len() == b.len(),
        a.len() > 0,
    ensures
        a[a.len() - 1] < b[b.len() - 1] ==> le_val(a) < le_val(b),
        a[a.len() - 1] > b[b.len() - 1] ==> le_val(a) > le_val(b),
{
    let t = (a.len() - 1) as nat;
    lemma_le_bound(a.subrange(0, t as int));
    lemma_le_bound(b.subrange(0, t as int));
    let pa = le_val(a.subrange(0, t as int));
    let pb = le_val(b.subrange(0, t as int));
    let x = a[t as int] as nat;
    let y = b[t as int] as nat;
    let w = pow256(t);
    assert(x < y ==> pa + x * w < pb + y * w) by (nonlinear_arith)
        requires pa < w, pb >= 0;
    assert(x > y ==> pa + x * w > pb + y * w) by (nonlinear_arith)
        requires pb < w, pa >= 0;
}

/// `le_val(a) < le_val(c)` for 32-byte strings.
pub fn le_less(a: &[u8; 32], c: &[u8; 32]) -> (r: bool)
    ensures
        r == (le_val(a@) < le_val(c@)),
{
    let mut t: usize = 32;
    while t > 0
        invariant
            t <= 32,
            a@.len() == 32,
            c@.len() == 32,
            forall|j: int| t <= j < 32 ==> a@[j] == c@[j],
        decreases t,
    {
        let k = t - 1;
        if a[k] != c[k] {
            proof {
                lemma_le_lt(a@, c@, t as nat);
                lemma_le_top(a@.subrange(0, t as int), c@.subrange(0, t as int));
            }
            return a[k] < c[k];
        }
        t = k;
    }
    proof {
        lemma_le_lt(a@, c@, 0);
    }
    false
}

fn masked(e: &[u8; 32]) -> (m: [u8; 32])
    ensures
        m@ == e@.update(31, (e@[31] & 0x7f) as u8),
{
    let mut m = *e;
    m[31] = e[31] & 0x7f;
    assert(m@ =~= e@.update(31, (e@[31] & 0x7f) as u8));
    m
}

fn eq_bytes(a: &[u8; 32], b: &[u8; 32]) -> (r: bool)
    ensures
        r == (a@ == b@),
{
    let mut i: usize = 0;
    while i < 32
        invariant
            i <= 32,
            a@.len() == 32,
            b@.len() == 32,
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

fn canonical_point_x(e: &[u8; 32]) -> (r: bool)
    ensures
        r == canonical_point(e@),
{
    let y = masked(e);
    let p = P_BYTES;
    if !le_less(&y, &p) {
        return false;
    }
    let one_b = ONE_BYTES;
    let p1 = PM1_BYTES;
    let x_zero = eq_bytes(&y, &one_b) || eq_bytes(&y, &p1);
    proof {
        // y is 1 or p - 1 exactly when its 32 bytes are.
        if le_val(y@) == one() && !(y@ == one_b@) {
            lemma_le_inj(y@, one_b@);
        }
        if le_val(y@) == prime_p_minus_1() && !(y@ == p1@) {
            lemma_le_inj(y@, p1@);
        }
    }
    !(e[31] >= 0x80 && x_zero)
}

/// Equal little-endian values of equal length are equal byte strings.
proof fn lemma_le_inj(a: Seq<u8>, b: Seq<u8>)
    requires
        a.len() == b.len(),
        le_val(a) == le_val(b),
    ensures
        a == b,
    decreases a.len(),
{
    if a.len() > 0 {
        let t = (a.len() - 1) as nat;
        lemma_le_top(a, b);
        assert(a[t as int] == b[t as int]);
        lemma_le_inj(a.subrange(0, t as int), b.subrange(0, t as int));
        assert(a =~= a.subrange(0, t as int).push(a[t as int]));
        assert(b =~= b.subrange(0, t as int).push(b[t as int]));
    } else {
        assert(a =~= b);
    }
}

/// The encoding rules of section 3 for public key `a`, and signature `r` and `s`.
pub fn strict_encoding_ok(a: &[u8; 32], r: &[u8; 32], s: &[u8; 32]) -> (ok: bool)
    ensures
        ok == strict_encoding(a@, r@, s@),
{
    let l = L_BYTES;
    if !le_less(s, &l) || !canonical_point_x(a) || !canonical_point_x(r) {
        return false;
    }
    let table = SMALL_ORDER;
    let mut k: usize = 0;
    while k < 8
        invariant
            k <= 8,
            table == SMALL_ORDER,
            forall|j: int| 0 <= j < k ==> a@ != #[trigger] SMALL_ORDER[j]@,
        decreases 8 - k,
    {
        if eq_bytes(a, &table[k]) {
            return false;
        }
        k = k + 1;
    }
    true
}

} // verus!
