//! Shortest-form floats for deterministic CBOR, section 3: a float is canonical only if no
//! narrower width holds the same value, and NaN is only ever half-precision 0x7e00.
//!
//! The value of a float is defined from IEEE 754's fields (`ieee`), exactly, as a whole number
//! of 2^-1074, the smallest double. `shortest` is proven to decide `spec_float_shortest` with
//! integer arithmetic alone, so no floating-point operation is trusted.
use vstd::arithmetic::div_mod::*;
use vstd::arithmetic::power2::*;
use vstd::prelude::*;

verus! {

/// The value of a float: not a number, an infinity, or a sign and a magnitude in units of
/// 2^-1074. Zero keeps its sign, so 0.0 and -0.0 are different values here, as in CBOR.
pub enum Float {
    NaN,
    Inf(bool),
    Num(bool, nat),
}

/// IEEE 754's exponent bias for `w` exponent bits.
pub open spec fn bias(w: nat) -> int {
    pow2((w - 1) as nat) - 1
}

/// The power of two, over 2^-1074, of a subnormal's last bit; also of the smallest normal's.
pub open spec fn kmin(p: nat, w: nat) -> int {
    1075 - bias(w) - p
}

/// The largest finite float's power of two, over 2^-1074, of its last bit.
pub open spec fn kmax(p: nat, w: nat) -> int {
    pow2(w) - 2 + 1074 - bias(w) - p
}

/// The float with `p` fraction bits and `w` exponent bits whose encoding is `bits`.
pub open spec fn ieee(bits: nat, p: nat, w: nat) -> Float {
    let frac = bits % pow2(p);
    let e = (bits / pow2(p)) % pow2(w);
    let sign = (bits / pow2(p + w)) % 2 == 1;
    if e == pow2(w) - 1 {
        if frac == 0 { Float::Inf(sign) } else { Float::NaN }
    } else if e == 0 {
        Float::Num(sign, frac * pow2(kmin(p, w) as nat))
    } else {
        Float::Num(sign, (frac + pow2(p)) * pow2((e + kmin(p, w) - 1) as nat))
    }
}

pub open spec fn half(h: u16) -> Float {
    ieee(h as nat, 10, 5)
}

pub open spec fn single(g: u32) -> Float {
    ieee(g as nat, 23, 8)
}

pub open spec fn double(x: u64) -> Float {
    ieee(x as nat, 52, 11)
}

/// A float is in its shortest form: no narrower width holds the same value, and NaN only as
/// half-precision 0x7e00.
pub open spec fn spec_float_shortest(width: u8, bits: u64) -> bool {
    if width == 2 {
        !(half(bits as u16) is NaN) || bits == 0x7e00
    } else if width == 4 {
        let v = single(bits as u32);
        !(v is NaN) && !(exists|h: u16| half(h) == v)
    } else if width == 8 {
        let v = double(bits);
        !(v is NaN) && !(exists|h: u16| half(h) == v) && !(exists|g: u32| single(g) == v)
    } else {
        false
    }
}

/// `n` units of 2^-1074 are a finite value of the format: a subnormal, or a normal with `p + 1`
/// significant bits and an exponent in range.
pub open spec fn fits(n: nat, p: nat, w: nat) -> bool {
    exists|m: nat, k: nat| #[trigger] (m * pow2(k)) == n && fits_at(m, k, p, w)
}

pub open spec fn fits_at(m: nat, k: nat, p: nat, w: nat) -> bool {
    (m < pow2(p) && k == kmin(p, w)) || (pow2(p) <= m < pow2(p + 1) && kmin(p, w) <= k <= kmax(p, w))
}

/// The number of bits `x` needs.
pub open spec fn bitlen(x: nat) -> nat
    decreases x,
{
    if x == 0 { 0 } else { 1 + bitlen(x / 2) }
}

/// The formats `ieee` is used with: their constants, and a sign bit that fits in 64 bits.
pub open spec fn format(p: nat, w: nat) -> bool {
    (p == 10 && w == 5) || (p == 23 && w == 8) || (p == 52 && w == 11)
}

proof fn lemma_format(p: nat, w: nat)
    requires
        format(p, w),
    ensures
        pow2(p) >= 2,
        pow2(w) >= 4,
        bias(w) >= 1,
        kmin(p, w) >= 0,
        kmin(p, w) <= kmax(p, w),
        p + w + 1 <= 64,
        pow2(p + w) * 2 == pow2(p + w + 1),
        pow2(p) * pow2(w) == pow2(p + w),
        p == 10 ==> pow2(p) == 1024 && pow2(w) == 32 && kmin(p, w) == 1050 && kmax(p, w) == 1079 && pow2(p + w + 1) == 0x10000,
        p == 23 ==> pow2(p) == 0x80_0000 && pow2(w) == 256 && kmin(p, w) == 925 && kmax(p, w) == 1178 && pow2(p + w + 1) == 0x1_0000_0000,
        p == 52 ==> pow2(p) == 0x10_0000_0000_0000 && pow2(w) == 2048 && kmin(p, w) == 0 && kmax(p, w) == 2045,
{
    lemma2_to64();
    lemma2_to64_rest();
    lemma_pow2_adds(p, w);
    lemma_pow2_adds(p + w, 1);
}

proof fn lemma_div_mod_parts(x: int, d: int, q: int, r: int)
    requires
        d > 0,
        0 <= r < d,
        x == q * d + r,
    ensures
        x / d == q,
        x % d == r,
{
    lemma_fundamental_div_mod_converse(x, d, q, r);
}

/// A finite value of the format has an encoding with that value, for either sign.
proof fn lemma_encode(s: bool, m: nat, k: nat, p: nat, w: nat) -> (b: nat)
    requires
        format(p, w),
        fits_at(m, k, p, w),
    ensures
        b < pow2(p + w + 1),
        ieee(b, p, w) == Float::Num(s, m * pow2(k)),
{
    lemma_format(p, w);
    let pp = pow2(p) as int;
    let pw = pow2(w) as int;
    let (e, frac): (int, int) = if m < pp { (0, m as int) } else { (k - kmin(p, w) + 1, m - pp) };
    let sb: int = if s { 1 } else { 0 };
    let b = sb * pow2(p + w) + e * pp + frac;
    lemma_pow2_adds(p, 1);
    lemma2_to64();
    assert(0 <= e < pw - 1);
    assert(0 <= frac < pp);
    // b = (sb·2^w + e)·2^p + frac, and sb·2^w + e = sb·2^w + e.
    let hi = sb * pw + e;
    assert(b == hi * pp + frac) by (nonlinear_arith)
        requires b == sb * pow2(p + w) + e * pp + frac, pow2(p + w) == pp * pw, hi == sb * pw + e;
    lemma_div_mod_parts(b, pp, hi, frac);
    lemma_div_mod_parts(hi, pw, sb, e);
    assert(b / (pow2(p + w) as int) == sb) by {
        assert(b == sb * pow2(p + w) + (e * pp + frac));
        assert(e * pp + frac < pp * pw) by (nonlinear_arith)
            requires 0 <= e < pw - 1, 0 <= frac < pp;
        assert(0 <= e * pp + frac) by (nonlinear_arith) requires 0 <= e, 0 <= frac, pp > 0;
        lemma_div_mod_parts(b, pow2(p + w) as int, sb, e * pp + frac);
    }
    assert(b < pow2(p + w + 1)) by (nonlinear_arith)
        requires b == hi * pp + frac, hi == sb * pw + e, sb <= 1, e < pw - 1, frac < pp,
            pow2(p + w + 1) == 2 * (pp * pw), pp > 0, pw > 0;
    assert(b >= 0) by (nonlinear_arith) requires b == hi * pp + frac, hi >= 0, frac >= 0, pp > 0;
    if m >= pp {
        assert(frac + pp == m);
        assert(e + kmin(p, w) - 1 == k);
    }
    b as nat
}

/// Every finite encoding's value fits the format.
proof fn lemma_decode_fits(b: nat, p: nat, w: nat)
    requires
        format(p, w),
    ensures
        ieee(b, p, w) matches Float::Num(_, n) ==> fits(n, p, w),
{
    lemma_format(p, w);
    let frac = b % pow2(p);
    let e = (b / pow2(p)) % pow2(w);
    lemma_mod_bound(b as int, pow2(p) as int);
    lemma_mod_bound((b / pow2(p)) as int, pow2(w) as int);
    if ieee(b, p, w) is Num {
        if e == 0 {
            assert(fits_at(frac, kmin(p, w) as nat, p, w));
        } else {
            let m = (frac + pow2(p)) as nat;
            let k = (e + kmin(p, w) - 1) as nat;
            lemma_pow2_adds(p, 1);
            lemma2_to64();
            assert(fits_at(m, k, p, w));
        }
    }
}

proof fn lemma_mod_bound(x: int, d: int)
    requires
        x >= 0,
        d > 0,
    ensures
        0 <= x % d < d,
        x / d >= 0,
{
    lemma_mod_pos_bound(x, d);
    lemma_div_pos_is_pos(x, d);
}

/// The infinity of the format with sign `s`.
proof fn lemma_inf(s: bool, p: nat, w: nat) -> (b: nat)
    requires
        format(p, w),
    ensures
        b < pow2(p + w + 1),
        ieee(b, p, w) == Float::Inf(s),
{
    lemma_format(p, w);
    let pp = pow2(p) as int;
    let pw = pow2(w) as int;
    let sb: int = if s { 1 } else { 0 };
    let hi = sb * pw + (pw - 1);
    let b = hi * pp;
    lemma_div_mod_parts(b, pp, hi, 0);
    lemma_div_mod_parts(hi, pw, sb, pw - 1);
    assert(b == sb * pow2(p + w) + (pw - 1) * pp) by (nonlinear_arith)
        requires b == hi * pp, hi == sb * pw + (pw - 1), pow2(p + w) == pp * pw;
    assert((pw - 1) * pp < pp * pw && (pw - 1) * pp >= 0) by (nonlinear_arith) requires pw >= 4, pp >= 2;
    lemma_div_mod_parts(b, pow2(p + w) as int, sb, (pw - 1) * pp);
    assert(b < pow2(p + w + 1)) by (nonlinear_arith)
        requires b == hi * pp, hi == sb * pw + (pw - 1), sb <= 1, pow2(p + w + 1) == 2 * (pp * pw), pp > 0;
    assert(b >= 0) by (nonlinear_arith) requires b == hi * pp, hi >= 0, pp > 0;
    b as nat
}

proof fn lemma_bitlen_bounds(x: nat)
    ensures
        x < pow2(bitlen(x)),
        x >= 1 ==> pow2((bitlen(x) - 1) as nat) <= x,
    decreases x,
{
    lemma2_to64();
    if x > 0 {
        lemma_bitlen_bounds(x / 2);
        lemma_pow2_unfold(bitlen(x));
        if x / 2 >= 1 {
            lemma_pow2_unfold(bitlen(x / 2));
        }
    }
}

/// `x < 2^j` exactly when `x` needs at most `j` bits.
proof fn lemma_bitlen_lt(x: nat, j: nat)
    ensures
        (x < pow2(j)) == (bitlen(x) <= j),
{
    lemma_bitlen_bounds(x);
    if bitlen(x) <= j {
        lemma_pow2_mono(bitlen(x), j);
    } else {
        lemma_pow2_mono(j, (bitlen(x) - 1) as nat);
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

/// Shifting left by `t` adds `t` bits.
proof fn lemma_bitlen_shift(x: nat, t: nat)
    requires
        x >= 1,
    ensures
        bitlen(x * pow2(t)) == bitlen(x) + t,
    decreases t,
{
    lemma2_to64();
    if t > 0 {
        lemma_pow2_unfold(t);
        let y = x * pow2((t - 1) as nat);
        lemma_pow2_pos((t - 1) as nat);
        assert(x * pow2(t) == 2 * y) by (nonlinear_arith) requires pow2(t) == 2 * pow2((t - 1) as nat), y == x * pow2((t - 1) as nat);
        assert(y >= 1) by (nonlinear_arith) requires x >= 1, pow2((t - 1) as nat) >= 1, y == x * pow2((t - 1) as nat);
        assert((2 * y) / 2 == y);
        lemma_bitlen_shift(x, (t - 1) as nat);
    } else {
        assert(x * pow2(0) == x);
    }
}

/// Factors of two are unique: an odd `m` times 2^k equals `M` times 2^K only with `k >= K` and
/// `M == m·2^(k-K)`.
proof fn lemma_odd_factor(m: nat, k: nat, mm: nat, kk: nat)
    requires
        m % 2 == 1,
        m * pow2(k) == mm * pow2(kk),
    ensures
        k >= kk,
        mm == m * pow2((k - kk) as nat),
{
    lemma_pow2_pos(k);
    lemma_pow2_pos(kk);
    if k < kk {
        let d = (kk - k) as nat;
        lemma_pow2_adds(d, k);
        lemma_pow2_unfold(d);
        let q = mm * pow2((d - 1) as nat);
        assert(m * pow2(k) == (2 * q) * pow2(k)) by (nonlinear_arith)
            requires m * pow2(k) == mm * pow2(kk), pow2(kk) == pow2(d) * pow2(k),
                pow2(d) == 2 * pow2((d - 1) as nat), q == mm * pow2((d - 1) as nat);
        assert(m == 2 * q) by (nonlinear_arith) requires m * pow2(k) == (2 * q) * pow2(k), pow2(k) > 0;
        assert(false);
    } else {
        let d = (k - kk) as nat;
        lemma_pow2_adds(d, kk);
        assert((m * pow2(d)) * pow2(kk) == mm * pow2(kk)) by (nonlinear_arith)
            requires m * pow2(k) == mm * pow2(kk), pow2(k) == pow2(d) * pow2(kk);
        assert(mm == m * pow2(d)) by (nonlinear_arith)
            requires (m * pow2(d)) * pow2(kk) == mm * pow2(kk), pow2(kk) > 0;
    }
}

/// With `n == m·2^k` and `m` odd, `n` fits the format exactly when `m` needs at most `p + 1`
/// bits, its last bit is no smaller than the format's smallest, and its first no larger than
/// the format's largest.
proof fn lemma_fits_odd(n: nat, m: nat, k: nat, p: nat, w: nat)
    requires
        format(p, w),
        m % 2 == 1,
        n == m * pow2(k),
    ensures
        fits(n, p, w) == (bitlen(m) <= p + 1 && k >= kmin(p, w) && k + bitlen(m) <= kmax(p, w) + p + 1),
{
    lemma_format(p, w);
    let l = bitlen(m);
    lemma_bitlen_bounds(m);
    lemma_pow2_adds(p, 1);
    lemma2_to64();
    if fits(n, p, w) {
        let (mm, kk) = choose|mm: nat, kk: nat| #[trigger] (mm * pow2(kk)) == n && fits_at(mm, kk, p, w);
        lemma_odd_factor(m, k, mm, kk);
        lemma_bitlen_shift(m, (k - kk) as nat);
        if mm < pow2(p) {
            lemma_bitlen_lt(mm, p);
        } else {
            lemma_bitlen_lt(mm, p + 1);
            if bitlen(mm) < p + 1 {
                lemma_bitlen_lt(mm, p);
            }
        }
    }
    if l <= p + 1 && k >= kmin(p, w) && k + l <= kmax(p, w) + p + 1 {
        let room = (p + 1 - l) as nat;
        let t: nat = if (k - kmin(p, w)) as nat <= room { (k - kmin(p, w)) as nat } else { room };
        let mm = m * pow2(t);
        let kk = (k - t) as nat;
        lemma_bitlen_shift(m, t);
        lemma_pow2_adds(t, kk);
        assert(mm * pow2(kk) == n) by (nonlinear_arith)
            requires mm == m * pow2(t), n == m * pow2(k), pow2(k) == pow2(t) * pow2(kk), t + kk == k;
        lemma_bitlen_lt(mm, p);
        lemma_bitlen_lt(mm, p + 1);
        assert(fits_at(mm, kk, p, w));
    }
}

/// The value of `bits` in the format: `None` for NaN or an infinity, otherwise its magnitude as
/// an odd `m` times 2^k, with `m == 0` for zero.
fn magnitude(bits: u64, p: u64, w: u64, pp: u64, pw: u64, k0: u64) -> (r: Option<(u64, u64)>)
    requires
        format(p as nat, w as nat),
        pp == pow2(p as nat),
        pw == pow2(w as nat),
        k0 == kmin(p as nat, w as nat),
        bits < pow2((p + w + 1) as nat),
    ensures
        r is None <==> (ieee(bits as nat, p as nat, w as nat) is NaN || ieee(bits as nat, p as nat, w as nat) is Inf),
        r matches Some((m, k)) ==> ieee(bits as nat, p as nat, w as nat) matches Float::Num(_, n)
            && n == m * pow2(k as nat) && (m == 0 || m % 2 == 1) && m < pow2((p + 1) as nat) && k <= 2100,
{
    proof { lemma_format(p as nat, w as nat); lemma_pow2_adds(p as nat, 1); lemma2_to64(); }
    let frac = bits % pp;
    let e = (bits / pp) % pw;
    proof {
        lemma_mod_bound(bits as int, pp as int);
        lemma_mod_bound((bits / pp) as int, pw as int);
    }
    if e == pw - 1 {
        return None;
    }
    let mut m: u64 = if e == 0 { frac } else { frac + pp };
    let mut k: u64 = if e == 0 { k0 } else { e + k0 - 1 };
    if m == 0 {
        proof { assert(0 * pow2(k as nat) == 0); }
        return Some((0, 0));
    }
    let ghost n = m * pow2(k as nat);
    proof {
        assert(k <= kmax(p as nat, w as nat));
        lemma_bitlen_lt(m as nat, (p + 1) as nat);
    }
    while m % 2 == 0
        invariant
            m >= 1,
            n == m * pow2(k as nat),
            m < pow2((p + 1) as nat),
            k + bitlen(m as nat) <= 2045 + 53,
        decreases m,
    {
        proof {
            lemma_pow2_unfold((k + 1) as nat);
            assert(m * pow2(k as nat) == (m / 2) * pow2((k + 1) as nat)) by (nonlinear_arith)
                requires m % 2 == 0, pow2((k + 1) as nat) == 2 * pow2(k as nat);
        }
        m = m / 2;
        k = k + 1;
    }
    Some((m, k))
}

/// `bitlen` of an exec number.
fn bit_length(x: u64) -> (l: u64)
    ensures
        l == bitlen(x as nat),
        l <= 64,
{
    let mut t = x;
    let mut l: u64 = 0;
    proof {
        lemma2_to64();
        lemma_bitlen_lt(x as nat, 64);
    }
    while t > 0
        invariant
            bitlen(x as nat) == l + bitlen(t as nat),
            l + bitlen(t as nat) <= 64,
        decreases t,
    {
        t = t / 2;
        l = l + 1;
    }
    l
}

/// Whether `m·2^k`, with `m` odd, fits the format whose constants these are.
fn fits_odd(m: u64, k: u64, p: u64, kmin: u64, kmax: u64) -> (r: bool)
    requires
        p <= 64,
        kmax <= 2100,
        k <= 2100,
    ensures
        r == (bitlen(m as nat) <= p + 1 && k >= kmin && k + bitlen(m as nat) <= kmax + p + 1),
{
    let l = bit_length(m);
    l <= p + 1 && k >= kmin && k + l <= kmax + p + 1
}

/// Decides `spec_float_shortest` with integer arithmetic.
pub fn shortest(width: u8, bits: u64) -> (r: bool)
    ensures
        r == spec_float_shortest(width, bits),
{
    proof {
        lemma_format(10, 5);
        lemma_format(23, 8);
        lemma_format(52, 11);
        lemma2_to64();
        lemma2_to64_rest();
    }
    if width == 2 {
        let h = bits as u16 as u64;
        let frac = h % 1024;
        let e = (h / 1024) % 32;
        !(e == 31 && frac != 0) || bits == 0x7e00
    } else if width == 4 {
        let g = bits as u32 as u64;
        let ghost v = single(bits as u32);
        match magnitude(g, 23, 8, 0x80_0000, 256, 925) {
            None => {
                proof {
                    if let Float::Inf(s) = v {
                        let b = lemma_inf(s, 10, 5);
                        assert(half(b as u16) == v);
                    }
                }
                false
            },
            Some((m, k)) => {
                let ghost n = v->Num_1;
                let ghost s = v->Num_0;
                if m == 0 {
                    proof { half_witness(s, n, 0, 1050); }
                    return false;
                }
                let f16 = fits_odd(m, k, 10, 1050, 1079);
                proof { lemma_shortest_against_half(s, n, m as nat, k as nat, v, f16); }
                !f16
            },
        }
    } else if width == 8 {
        let ghost v = double(bits);
        match magnitude(bits, 52, 11, 0x10_0000_0000_0000, 2048, 0) {
            None => {
                proof {
                    if let Float::Inf(s) = v {
                        let b = lemma_inf(s, 10, 5);
                        assert(half(b as u16) == v);
                    }
                }
                false
            },
            Some((m, k)) => {
                let ghost n = v->Num_1;
                let ghost s = v->Num_0;
                if m == 0 {
                    proof { half_witness(s, n, 0, 1050); }
                    return false;
                }
                let f16 = fits_odd(m, k, 10, 1050, 1079);
                let f32 = fits_odd(m, k, 23, 925, 1178);
                proof {
                    lemma_shortest_against_half(s, n, m as nat, k as nat, v, f16);
                    lemma_shortest_against_single(s, n, m as nat, k as nat, v, f32);
                }
                !f16 && !f32
            },
        }
    } else {
        false
    }
}

/// Zero, or any value that fits half precision, has a half-precision encoding.
proof fn half_witness(s: bool, n: nat, m: nat, k: nat)
    requires
        fits_at(m, k, 10, 5),
        n == m * pow2(k),
    ensures
        exists|h: u16| half(h) == Float::Num(s, n),
{
    lemma_format(10, 5);
    let b = lemma_encode(s, m, k, 10, 5);
    assert(half(b as u16) == Float::Num(s, n));
}

proof fn lemma_shortest_against_half(s: bool, n: nat, m: nat, k: nat, v: Float, f16: bool)
    requires
        v == Float::Num(s, n),
        m % 2 == 1,
        n == m * pow2(k),
        f16 == (bitlen(m) <= 10 + 1 && k >= 1050 && k + bitlen(m) <= 1079 + 10 + 1),
    ensures
        f16 == (exists|h: u16| half(h) == v),
{
    lemma_format(10, 5);
    lemma_fits_odd(n, m, k, 10, 5);
    if f16 {
        let (mm, kk) = choose|mm: nat, kk: nat| #[trigger] (mm * pow2(kk)) == n && fits_at(mm, kk, 10, 5);
        half_witness(s, n, mm, kk);
    }
    if exists|h: u16| half(h) == v {
        let h = choose|h: u16| half(h) == v;
        lemma_decode_fits(h as nat, 10, 5);
    }
}

proof fn lemma_shortest_against_single(s: bool, n: nat, m: nat, k: nat, v: Float, f32: bool)
    requires
        v == Float::Num(s, n),
        m % 2 == 1,
        n == m * pow2(k),
        f32 == (bitlen(m) <= 23 + 1 && k >= 925 && k + bitlen(m) <= 1178 + 23 + 1),
    ensures
        f32 == (exists|g: u32| single(g) == v),
{
    lemma_format(23, 8);
    lemma_fits_odd(n, m, k, 23, 8);
    if f32 {
        let (mm, kk) = choose|mm: nat, kk: nat| #[trigger] (mm * pow2(kk)) == n && fits_at(mm, kk, 23, 8);
        let b = lemma_encode(s, mm, kk, 23, 8);
        assert(single(b as u32) == v);
    }
    if exists|g: u32| single(g) == v {
        let g = choose|g: u32| single(g) == v;
        lemma_decode_fits(g as nat, 23, 8);
    }
}

} // verus!
