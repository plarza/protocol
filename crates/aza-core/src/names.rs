//! Names in paths and certificates, section 3 and section 7: identity IDs and other hashes as
//! lowercase hex, item names percent-encoded as one path segment, and app IDs.
//!
//! `decode_name` and `decode_hex` accept exactly the encodings `spec_encode_name` and
//! `spec_hex` produce, so every name and hash has one form in a path, the form `aza-auth` signs.
use crate::cbor::utf8_ok;
use vstd::prelude::*;

verus! {

// Hex.

pub open spec fn hex_digit(n: u8) -> u8 {
    if n < 10 { (48 + n) as u8 } else { (87 + n) as u8 }
}

/// The lowercase hex of `b`, two digits per byte.
pub open spec fn spec_hex(b: Seq<u8>) -> Seq<u8>
    decreases b.len(),
{
    if b.len() == 0 {
        Seq::empty()
    } else {
        spec_hex(b.drop_last()) + seq![hex_digit(b.last() / 16), hex_digit(b.last() % 16)]
    }
}

proof fn lemma_hex_len(b: Seq<u8>)
    ensures
        spec_hex(b).len() == 2 * b.len(),
    decreases b.len(),
{
    if b.len() > 0 {
        lemma_hex_len(b.drop_last());
    }
}

proof fn lemma_hex_at(b: Seq<u8>, j: int)
    requires
        0 <= j < b.len(),
    ensures
        spec_hex(b).len() == 2 * b.len(),
        spec_hex(b)[2 * j] == hex_digit(b[j] / 16),
        spec_hex(b)[2 * j + 1] == hex_digit(b[j] % 16),
    decreases b.len(),
{
    lemma_hex_len(b);
    if j < b.len() - 1 {
        lemma_hex_at(b.drop_last(), j);
        lemma_hex_len(b.drop_last());
    }
}

fn digit(n: u8) -> (c: u8)
    requires
        n < 16,
    ensures
        c == hex_digit(n),
{
    if n < 10 { 48 + n } else { 87 + n }
}

/// The value of a lowercase hex digit.
fn digit_value(c: u8) -> (r: Option<u8>)
    ensures
        r matches Some(n) ==> n < 16 && hex_digit(n) == c,
        r is None ==> forall|n: u8| n < 16 ==> hex_digit(n) != c,
{
    if 48 <= c && c <= 57 {
        Some(c - 48)
    } else if 97 <= c && c <= 102 {
        Some(c - 87)
    } else {
        None
    }
}

pub fn encode_hex(b: &[u8]) -> (r: Vec<u8>)
    requires
        b.len() < 0x4000_0000,
    ensures
        r@ == spec_hex(b@),
{
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < b.len()
        invariant
            i <= b.len(),
            out@ == spec_hex(b@.subrange(0, i as int)),
        decreases b.len() - i,
    {
        assert(b@.subrange(0, i + 1).drop_last() =~= b@.subrange(0, i as int));
        out.push(digit(b[i] / 16));
        out.push(digit(b[i] % 16));
        i = i + 1;
        assert(out@ =~= spec_hex(b@.subrange(0, i as int)));
    }
    assert(b@.subrange(0, b.len() as int) =~= b@);
    out
}

/// The 32 bytes whose lowercase hex is `s`: exactly the inverse of `spec_hex`.
pub fn decode_hex32(s: &[u8]) -> (r: Option<[u8; 32]>)
    ensures
        r matches Some(h) ==> spec_hex(h@) == s@,
        (exists|h: Seq<u8>| h.len() == 32 && #[trigger] spec_hex(h) == s@) ==> r is Some,
{
    proof {
        if exists|h: Seq<u8>| h.len() == 32 && #[trigger] spec_hex(h) == s@ {
            let h = choose|h: Seq<u8>| h.len() == 32 && #[trigger] spec_hex(h) == s@;
            lemma_hex_len(h);
        }
    }
    if s.len() != 64 {
        return None;
    }
    let mut h: [u8; 32] = [0u8; 32];
    let mut j: usize = 0;
    while j < 32
        invariant
            j <= 32,
            s.len() == 64,
            h@.len() == 32,
            forall|k: int| 0 <= k < j ==> hex_digit(#[trigger] h@[k] / 16) == s@[2 * k] && hex_digit(h@[k] % 16) == s@[2 * k + 1],
            forall|g: Seq<u8>| g.len() == 32 && #[trigger] spec_hex(g) == s@ ==> forall|k: int| 0 <= k < j ==> g[k] == h@[k],
        decreases 32 - j,
    {
        let hi = match digit_value(s[2 * j]) {
            Some(v) => v,
            None => {
                proof {
                    assert forall|g: Seq<u8>| g.len() == 32 implies spec_hex(g) != s@ by {
                        lemma_hex_at(g, j as int);
                        assert(g[j as int] / 16 < 16);
                    }
                }
                return None;
            },
        };
        let lo = match digit_value(s[2 * j + 1]) {
            Some(v) => v,
            None => {
                proof {
                    assert forall|g: Seq<u8>| g.len() == 32 implies spec_hex(g) != s@ by {
                        lemma_hex_at(g, j as int);
                        assert(g[j as int] % 16 < 16);
                    }
                }
                return None;
            },
        };
        let ghost before = h@;
        h[j] = hi * 16 + lo;
        proof {
            assert(h@[j as int] / 16 == hi && h@[j as int] % 16 == lo) by (nonlinear_arith)
                requires h@[j as int] == hi * 16 + lo, hi < 16, lo < 16;
            assert forall|g: Seq<u8>| g.len() == 32 && #[trigger] spec_hex(g) == s@ implies forall|k: int| 0 <= k < j + 1 ==> g[k] == h@[k] by {
                lemma_hex_at(g, j as int);
                // Both digits determine the byte.
                assert(hex_digit(g[j as int] / 16) == hex_digit(hi));
                assert(hex_digit(g[j as int] % 16) == hex_digit(lo));
                assert(g[j as int] / 16 == hi && g[j as int] % 16 == lo);
                assert(g[j as int] == (g[j as int] / 16) * 16 + g[j as int] % 16);
                assert forall|k: int| 0 <= k < j + 1 implies g[k] == h@[k] by {
                    if k < j {
                        assert(h@[k] == before[k]);
                    }
                }
            }
            assert forall|k: int| 0 <= k < j + 1 implies hex_digit(#[trigger] h@[k] / 16) == s@[2 * k] && hex_digit(h@[k] % 16) == s@[2 * k + 1] by {
                if k < j {
                    assert(h@[k] == before[k]);
                }
            }
        }
        j = j + 1;
    }
    proof {
        lemma_hex_len(h@);
        assert forall|i: int| 0 <= i < 64 implies spec_hex(h@)[i] == s@[i] by {
            lemma_hex_at(h@, i / 2);
            if i % 2 == 0 {
                assert(2 * (i / 2) == i);
            } else {
                assert(2 * (i / 2) + 1 == i);
            }
        }
        assert(spec_hex(h@) =~= s@);
    }
    Some(h)
}

// Item names, section 3: one path segment, RFC 3986 percent-encoding of every byte other than
// letters, digits, `-`, `.`, `_` and `~`, with uppercase hex.

pub open spec fn unreserved(b: u8) -> bool {
    (65 <= b <= 90) || (97 <= b <= 122) || (48 <= b <= 57) || b == 45 || b == 46 || b == 95 || b == 126
}

pub open spec fn upper_digit(n: u8) -> u8 {
    if n < 10 { (48 + n) as u8 } else { (55 + n) as u8 }
}

pub open spec fn spec_encode_byte(b: u8) -> Seq<u8> {
    if unreserved(b) { seq![b] } else { seq![37u8, upper_digit(b / 16), upper_digit(b % 16)] }
}

pub open spec fn spec_encode_name(s: Seq<u8>) -> Seq<u8>
    decreases s.len(),
{
    if s.len() == 0 { Seq::empty() } else { spec_encode_name(s.drop_last()) + spec_encode_byte(s.last()) }
}

fn is_unreserved(b: u8) -> (r: bool)
    ensures
        r == unreserved(b),
{
    (65 <= b && b <= 90) || (97 <= b && b <= 122) || (48 <= b && b <= 57) || b == 45 || b == 46 || b == 95 || b == 126
}

fn upper(n: u8) -> (c: u8)
    requires
        n < 16,
    ensures
        c == upper_digit(n),
{
    if n < 10 { 48 + n } else { 55 + n }
}

fn upper_value(c: u8) -> (r: Option<u8>)
    ensures
        r matches Some(n) ==> n < 16 && upper_digit(n) == c,
        r is None ==> forall|n: u8| n < 16 ==> upper_digit(n) != c,
{
    if 48 <= c && c <= 57 {
        Some(c - 48)
    } else if 65 <= c && c <= 70 {
        Some(c - 55)
    } else {
        None
    }
}

pub fn encode_name(s: &[u8]) -> (r: Vec<u8>)
    requires
        s.len() < 0x2000_0000,
    ensures
        r@ == spec_encode_name(s@),
{
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < s.len()
        invariant
            i <= s.len(),
            out@ == spec_encode_name(s@.subrange(0, i as int)),
            out.len() <= 3 * i,
        decreases s.len() - i,
    {
        assert(s@.subrange(0, i + 1).drop_last() =~= s@.subrange(0, i as int));
        let b = s[i];
        if is_unreserved(b) {
            out.push(b);
        } else {
            out.push(37);
            out.push(upper(b / 16));
            out.push(upper(b % 16));
        }
        i = i + 1;
        assert(out@ =~= spec_encode_name(s@.subrange(0, i as int)));
    }
    assert(s@.subrange(0, s.len() as int) =~= s@);
    out
}

proof fn lemma_encoded_len(s: Seq<u8>)
    ensures
        spec_encode_name(s).len() >= s.len(),
    decreases s.len(),
{
    if s.len() > 0 {
        lemma_encoded_len(s.drop_last());
    }
}

/// The encodings of the first `k` bytes of `n` are a prefix of the encoding of `n`.
proof fn lemma_encode_prefix(n: Seq<u8>, k: int)
    requires
        0 <= k <= n.len(),
    ensures
        spec_encode_name(n) == spec_encode_name(n.take(k)) + spec_encode_name(n.skip(k)),
    decreases n.len() - k,
{
    if k == n.len() {
        assert(n.take(k) =~= n);
        assert(n.skip(k) =~= Seq::<u8>::empty());
        assert(spec_encode_name(n) =~= spec_encode_name(n) + Seq::<u8>::empty());
    } else {
        lemma_encode_concat(n.take(k), n.skip(k));
        assert(n.take(k) + n.skip(k) =~= n);
    }
}

proof fn lemma_encode_concat(a: Seq<u8>, b: Seq<u8>)
    ensures
        spec_encode_name(a + b) == spec_encode_name(a) + spec_encode_name(b),
    decreases b.len(),
{
    if b.len() == 0 {
        assert(a + b =~= a);
        assert(spec_encode_name(a) + spec_encode_name(b) =~= spec_encode_name(a));
    } else {
        lemma_encode_concat(a, b.drop_last());
        assert((a + b).drop_last() =~= a + b.drop_last());
        assert((a + b).last() == b.last());
        assert(spec_encode_name(a + b) =~= spec_encode_name(a) + spec_encode_name(b));
    }
}

proof fn lemma_encode_first(n: Seq<u8>)
    requires
        n.len() > 0,
    ensures
        spec_encode_name(n) == spec_encode_byte(n[0]) + spec_encode_name(n.drop_first()),
{
    lemma_encode_concat(seq![n[0]], n.drop_first());
    assert(seq![n[0]] + n.drop_first() =~= n);
    assert(seq![n[0]].drop_last() =~= Seq::<u8>::empty());
    reveal_with_fuel(spec_encode_name, 2);
    assert(spec_encode_name(seq![n[0]]) =~= spec_encode_byte(n[0]));
}

/// The name whose encoding is `seg`: valid UTF-8 encoded exactly as `spec_encode_name` does.
pub fn decode_name(seg: &[u8]) -> (r: Option<Vec<u8>>)
    ensures
        r matches Some(n) ==> crate::cbor::spec_utf8(n@) && spec_encode_name(n@) == seg@,
        (exists|n: Seq<u8>| crate::cbor::spec_utf8(n) && #[trigger] spec_encode_name(n) == seg@) ==> r is Some,
{
    let ghost target: Option<Seq<u8>> = if exists|n: Seq<u8>| crate::cbor::spec_utf8(n) && #[trigger] spec_encode_name(n) == seg@ {
        Some(choose|n: Seq<u8>| crate::cbor::spec_utf8(n) && #[trigger] spec_encode_name(n) == seg@)
    } else {
        None
    };
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    proof {
        if let Some(n) = target {
            lemma_encoded_len(n);
            assert(n.take(0) =~= Seq::<u8>::empty());
            lemma_encode_prefix(n, 0);
        }
    }
    while i < seg.len()
        invariant
            i <= seg.len(),
            spec_encode_name(out@) == seg@.subrange(0, i as int),
            target is Some <==> exists|n: Seq<u8>| crate::cbor::spec_utf8(n) && #[trigger] spec_encode_name(n) == seg@,
            target matches Some(n) ==> out.len() <= n.len() && out@ == n.take(out.len() as int)
                && spec_encode_name(n) == seg@ && crate::cbor::spec_utf8(n),
        decreases seg.len() - i,
    {
        let ghost k = out.len() as int;
        proof {
            if let Some(n) = target {
                lemma_encode_prefix(n, k);
                if k == n.len() {
                    assert(n.take(k) =~= n);
                    lemma_encoded_len(n);
                    assert(false);
                }
                lemma_encode_first(n.skip(k));
                assert(seg@.subrange(i as int, seg.len() as int) =~= spec_encode_name(n.skip(k)));
            }
        }
        let c = seg[i];
        let b: u8;
        if is_unreserved(c) {
            b = c;
            i = i + 1;
        } else if c == 37 && seg.len() - i >= 3 {
            let hi = upper_value(seg[i + 1]);
            let lo = upper_value(seg[i + 2]);
            match (hi, lo) {
                (Some(h), Some(l)) => {
                    let v = h * 16 + l;
                    proof {
                        assert(v / 16 == h && v % 16 == l) by (nonlinear_arith) requires v == h * 16 + l, h < 16, l < 16;
                    }
                    if is_unreserved(v) {
                        proof {
                            if let Some(n) = target {
                                let x = n.skip(k)[0];
                                assert(seg@[i as int] == spec_encode_byte(x)[0]);
                                if !unreserved(x) {
                                    assert(seg@[i + 1] == upper_digit(x / 16) && seg@[i + 2] == upper_digit(x % 16));
                                    assert(x / 16 == h && x % 16 == l);
                                    assert(x == (x / 16) * 16 + x % 16);
                                }
                                assert(false);
                            }
                        }
                        return None;
                    }
                    b = v;
                    i = i + 3;
                },
                _ => {
                    proof {
                        if let Some(n) = target {
                            let x = n.skip(k)[0];
                            assert(seg@[i as int] == spec_encode_byte(x)[0]);
                            assert(!unreserved(x));
                            assert(seg@[i + 1] == upper_digit(x / 16) && seg@[i + 2] == upper_digit(x % 16));
                            assert(x / 16 < 16 && x % 16 < 16);
                            assert(false);
                        }
                    }
                    return None;
                },
            }
        } else {
            proof {
                if let Some(n) = target {
                    let x = n.skip(k)[0];
                    assert(seg@[i as int] == spec_encode_byte(x)[0]);
                    lemma_encoded_len(n.skip(k).drop_first());
                    assert(seg.len() - i >= spec_encode_byte(x).len());
                    assert(false);
                }
            }
            return None;
        }
        let ghost before = out@;
        out.push(b);
        proof {
            assert(out@.drop_last() =~= before);
            assert(spec_encode_name(out@) == spec_encode_name(before) + spec_encode_byte(b));
            assert(spec_encode_name(out@) =~= seg@.subrange(0, i as int));
            if let Some(n) = target {
                let x = n.skip(k)[0];
                // The byte read is the target's next byte.
                if unreserved(x) {
                    assert(b == x);
                } else {
                    assert(upper_digit(x / 16) == upper_digit(b / 16));
                    assert(upper_digit(x % 16) == upper_digit(b % 16));
                    assert(x / 16 == b / 16 && x % 16 == b % 16);
                    assert(x == (x / 16) * 16 + x % 16);
                    assert(b == (b / 16) * 16 + b % 16);
                }
                assert(out@ =~= n.take(k + 1));
            }
        }
    }
    proof {
        assert(seg@.subrange(0, seg.len() as int) =~= seg@);
        if let Some(n) = target {
            lemma_encode_prefix(n, out.len() as int);
            lemma_encoded_len(n.skip(out.len() as int));
            if out.len() < n.len() {
                assert(spec_encode_name(n.skip(out.len() as int)).len() >= 1);
                assert(false);
            }
            assert(out@ =~= n);
        }
    }
    if !utf8_ok(out.as_slice()) {
        return None;
    }
    Some(out)
}

// App IDs, section 7: a domain name of at least two lowercase labels of letters, digits and
// hyphens, each 1 to 63 bytes and neither starting nor ending with a hyphen, 253 bytes at most.

pub open spec fn label_byte(b: u8) -> bool {
    (97 <= b <= 122) || (48 <= b <= 57) || b == 45
}

pub open spec fn label_ok(l: Seq<u8>) -> bool {
    &&& 1 <= l.len() <= 63
    &&& forall|i: int| 0 <= i < l.len() ==> label_byte(#[trigger] l[i])
    &&& l[0] != 45
    &&& l.last() != 45
}

/// The index of the first dot in `s`, or its length.
pub open spec fn first_dot(s: Seq<u8>) -> nat
    decreases s.len(),
{
    if s.len() == 0 {
        0
    } else if s[0] == 46 {
        0
    } else {
        1 + first_dot(s.drop_first())
    }
}

proof fn lemma_first_dot(s: Seq<u8>, i: int)
    requires
        0 <= i <= s.len(),
        i < s.len() ==> s[i] == 46,
        forall|j: int| 0 <= j < i ==> s[j] != 46,
    ensures
        first_dot(s) == i,
    decreases i,
{
    if i > 0 {
        lemma_first_dot(s.drop_first(), i - 1);
    }
}

/// `s` split at its dots: each label is OK, and there are at least `min` of them.
pub open spec fn labels_ok(s: Seq<u8>, min: nat) -> bool
    decreases s.len(),
{
    let i = first_dot(s);
    if i < s.len() {
        label_ok(s.take(i as int)) && labels_ok(s.skip((i + 1) as int), if min > 0 { (min - 1) as nat } else { 0 })
    } else {
        label_ok(s) && min <= 1
    }
}

pub open spec fn spec_app_id(s: Seq<u8>) -> bool {
    s.len() <= 253 && labels_ok(s, 2)
}

/// The first dot at or after `from`, or `s.len()`.
fn next_dot(s: &[u8], from: usize) -> (r: usize)
    requires
        from <= s.len(),
    ensures
        from <= r <= s.len(),
        r < s.len() ==> s[r as int] == 46,
        forall|j: int| from <= j < r ==> s[j] != 46,
{
    let mut i = from;
    while i < s.len() && s[i] != 46
        invariant
            from <= i <= s.len(),
            forall|j: int| from <= j < i ==> s[j] != 46,
        decreases s.len() - i,
    {
        i = i + 1;
    }
    i
}

fn label_at(s: &[u8], from: usize, to: usize) -> (r: bool)
    requires
        from <= to <= s.len(),
    ensures
        r == label_ok(s@.subrange(from as int, to as int)),
{
    let ghost l = s@.subrange(from as int, to as int);
    let n = to - from;
    if n < 1 || n > 63 || s[from] == 45 || s[to - 1] == 45 {
        return false;
    }
    let mut i = from;
    while i < to
        invariant
            from <= i <= to <= s.len(),
            l == s@.subrange(from as int, to as int),
            forall|j: int| 0 <= j < i - from ==> label_byte(#[trigger] l[j]),
        decreases to - i,
    {
        let b = s[i];
        if !((97 <= b && b <= 122) || (48 <= b && b <= 57) || b == 45) {
            assert(l[i - from] == b);
            return false;
        }
        i = i + 1;
    }
    true
}

pub fn is_app_id(s: &[u8]) -> (r: bool)
    ensures
        r == spec_app_id(s@),
{
    if s.len() > 253 {
        return false;
    }
    let mut from: usize = 0;
    let mut count: usize = 0;
    // labels_ok(s, 2) == labels_ok(s.skip(from), 2 - count) for the part not yet read.
    proof { assert(s@.skip(0) =~= s@); }
    loop
        invariant
            from <= s.len() <= 253,
            count <= 2,
            labels_ok(s@, 2) == labels_ok(s@.skip(from as int), (2 - count) as nat),
        decreases s.len() - from,
    {
        let ghost rest = s@.skip(from as int);
        let to = next_dot(s, from);
        let ok = label_at(s, from, to);
        proof {
            assert(s@.subrange(from as int, to as int) =~= rest.take(to - from));
        }
        proof {
            let i = (to - from) as int;
            assert forall|j: int| 0 <= j < i implies rest[j] != 46 by {
                assert(rest[j] == s@[from + j]);
            }
            lemma_first_dot(rest, i);
        }
        if to == s.len() {
            proof {
                assert(rest.take(to - from) =~= rest);
            }
            return ok && count >= 1;
        }
        proof {
            assert(rest.skip(to - from + 1) =~= s@.skip(to + 1));
        }
        if !ok {
            return false;
        }
        from = to + 1;
        if count < 2 {
            count = count + 1;
        }
    }
}

} // verus!
