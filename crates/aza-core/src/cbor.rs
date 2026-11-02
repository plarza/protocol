//! Deterministic CBOR (RFC 8949 section 4.2.1), section 3.
//!
//! `encode` is proven to produce exactly `spec_encode`, and `decode` only returns a value whose
//! `spec_encode` is exactly the input and which is `canonical`. Since `spec_encode` is a function,
//! two different byte strings can never decode to the same value: every value has one byte form.
use vstd::prelude::*;

verus! {

pub enum Value {
    Uint(u64),
    /// The integer `-1 - n`.
    Nint(u64),
    Bytes(Vec<u8>),
    /// UTF-8 text, kept as bytes.
    Text(Vec<u8>),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Tag(u64, Box<Value>),
    /// Simple values: 20 false, 21 true, 22 null, 23 undefined.
    Simple(u8),
    Float16(u16),
    Float32(u32),
    Float64(u64),
}

pub open spec fn be_bytes(x: u64, n: nat) -> Seq<u8>
    decreases n,
{
    if n == 0 {
        Seq::empty()
    } else {
        be_bytes(x / 256, (n - 1) as nat).push((x % 256) as u8)
    }
}

pub open spec fn spec_head(major: u8, arg: u64) -> Seq<u8> {
    let m = (major * 32) as u8;
    if arg < 24 {
        seq![(m + arg) as u8]
    } else if arg <= 0xff {
        seq![(m + 24) as u8] + be_bytes(arg, 1)
    } else if arg <= 0xffff {
        seq![(m + 25) as u8] + be_bytes(arg, 2)
    } else if arg <= 0xffff_ffff {
        seq![(m + 26) as u8] + be_bytes(arg, 4)
    } else {
        seq![(m + 27) as u8] + be_bytes(arg, 8)
    }
}

pub open spec fn spec_encode(v: Value) -> Seq<u8>
    decreases v, 1nat, 0nat,
{
    match v {
        Value::Uint(n) => spec_head(0, n),
        Value::Nint(n) => spec_head(1, n),
        Value::Bytes(b) => spec_head(2, b.len() as u64) + b@,
        Value::Text(t) => spec_head(3, t.len() as u64) + t@,
        Value::Array(items) => spec_head(4, items.len() as u64) + spec_encode_items(v, items.len() as nat),
        Value::Map(entries) => spec_head(5, entries.len() as u64) + spec_encode_items(v, entries.len() as nat),
        Value::Tag(t, b) => spec_head(6, t) + spec_encode(*b),
        Value::Simple(s) => if s < 24 { seq![(0xe0 + s) as u8] } else { seq![0xf8u8, s] },
        Value::Float16(x) => seq![0xf9u8] + be_bytes(x as u64, 2),
        Value::Float32(x) => seq![0xfau8] + be_bytes(x as u64, 4),
        Value::Float64(x) => seq![0xfbu8] + be_bytes(x, 8),
    }
}

/// The encoding of the first `k` items of an array, or the first `k` entries of a map.
pub open spec fn spec_encode_items(v: Value, k: nat) -> Seq<u8>
    decreases v, 0nat, k,
{
    if k == 0 {
        Seq::empty()
    } else {
        match v {
            Value::Array(items) => if k <= items.len() {
                spec_encode_items(v, (k - 1) as nat) + spec_encode(items[k - 1])
            } else {
                Seq::empty()
            },
            Value::Map(entries) => if k <= entries.len() {
                spec_encode_items(v, (k - 1) as nat) + spec_encode(entries[k - 1].0) + spec_encode(entries[k - 1].1)
            } else {
                Seq::empty()
            },
            _ => Seq::empty(),
        }
    }
}

/// Bytewise lexicographic order, which deterministic encoding uses for map keys.
pub open spec fn lex_lt(a: Seq<u8>, b: Seq<u8>) -> bool
    decreases a.len(),
{
    if a.len() == 0 {
        b.len() > 0
    } else if b.len() == 0 {
        false
    } else if a[0] != b[0] {
        a[0] < b[0]
    } else {
        lex_lt(a.drop_first(), b.drop_first())
    }
}

/// UTF-8 as RFC 3629 section 4 defines it: the length of the character at the start of `s`, or
/// 0 if no valid character starts there.
pub open spec fn utf8_char_len(s: Seq<u8>) -> nat {
    let tail = |b: u8| 0x80 <= b <= 0xbf;
    if s.len() == 0 {
        0
    } else if s[0] <= 0x7f {
        1
    } else if 0xc2 <= s[0] <= 0xdf {
        if s.len() >= 2 && tail(s[1]) { 2 } else { 0 }
    } else if s[0] == 0xe0 {
        if s.len() >= 3 && 0xa0 <= s[1] <= 0xbf && tail(s[2]) { 3 } else { 0 }
    } else if (0xe1 <= s[0] <= 0xec) || (0xee <= s[0] <= 0xef) {
        if s.len() >= 3 && tail(s[1]) && tail(s[2]) { 3 } else { 0 }
    } else if s[0] == 0xed {
        if s.len() >= 3 && 0x80 <= s[1] <= 0x9f && tail(s[2]) { 3 } else { 0 }
    } else if s[0] == 0xf0 {
        if s.len() >= 4 && 0x90 <= s[1] <= 0xbf && tail(s[2]) && tail(s[3]) { 4 } else { 0 }
    } else if 0xf1 <= s[0] <= 0xf3 {
        if s.len() >= 4 && tail(s[1]) && tail(s[2]) && tail(s[3]) { 4 } else { 0 }
    } else if s[0] == 0xf4 {
        if s.len() >= 4 && 0x80 <= s[1] <= 0x8f && tail(s[2]) && tail(s[3]) { 4 } else { 0 }
    } else {
        0
    }
}

/// `UTF8-octets = *( UTF8-char )`.
pub open spec fn spec_utf8(s: Seq<u8>) -> bool
    decreases s.len(),
{
    if s.len() == 0 {
        true
    } else {
        let k = utf8_char_len(s);
        k > 0 && k <= s.len() && spec_utf8(s.skip(k as int))
    }
}

/// A float is in its shortest form, and NaN only as half-precision 0x7e00.
pub uninterp spec fn spec_float_shortest(width: u8, bits: u64) -> bool;

pub open spec fn canonical(v: Value) -> bool
    decreases v, 1nat, 0nat,
{
    match v {
        Value::Text(t) => spec_utf8(t@),
        Value::Array(items) => canonical_items(v, items.len() as nat),
        Value::Map(entries) => canonical_items(v, entries.len() as nat),
        Value::Tag(_, b) => canonical(*b),
        Value::Simple(s) => s < 24 || s >= 32,
        Value::Float16(x) => spec_float_shortest(2, x as u64),
        Value::Float32(x) => spec_float_shortest(4, x as u64),
        Value::Float64(x) => spec_float_shortest(8, x),
        _ => true,
    }
}

/// The first `k` items are canonical and, for a map, keys strictly increase.
pub open spec fn canonical_items(v: Value, k: nat) -> bool
    decreases v, 0nat, k,
{
    if k == 0 {
        true
    } else {
        match v {
            Value::Array(items) => k <= items.len() && canonical_items(v, (k - 1) as nat) && canonical(items[k - 1]),
            Value::Map(entries) => k <= entries.len() && canonical_items(v, (k - 1) as nat)
                && canonical(entries[k - 1].0) && canonical(entries[k - 1].1)
                && (k >= 2 ==> lex_lt(spec_encode(entries[k - 2].0), spec_encode(entries[k - 1].0))),
            _ => false,
        }
    }
}

fn push_be(out: &mut Vec<u8>, x: u64, n: usize)
    requires
        n <= 8,
    ensures
        final(out)@ == old(out)@ + be_bytes(x, n as nat),
    decreases n,
{
    if n > 0 {
        push_be(out, x / 256, n - 1);
        out.push((x % 256) as u8);
        assert(be_bytes(x, n as nat) == be_bytes(x / 256, (n - 1) as nat).push((x % 256) as u8));
    }
}

fn push_head(out: &mut Vec<u8>, major: u8, arg: u64)
    requires
        major < 8,
    ensures
        final(out)@ == old(out)@ + spec_head(major, arg),
{
    let m: u8 = major * 32;
    if arg < 24 {
        out.push(m + arg as u8);
    } else if arg <= 0xff {
        out.push(m + 24);
        push_be(out, arg, 1);
    } else if arg <= 0xffff {
        out.push(m + 25);
        push_be(out, arg, 2);
    } else if arg <= 0xffff_ffff {
        out.push(m + 26);
        push_be(out, arg, 4);
    } else {
        out.push(m + 27);
        push_be(out, arg, 8);
    }
}

pub fn encode_into(v: &Value, out: &mut Vec<u8>)
    ensures
        final(out)@ == old(out)@ + spec_encode(*v),
    decreases v,
{
    match v {
        Value::Uint(n) => push_head(out, 0, *n),
        Value::Nint(n) => push_head(out, 1, *n),
        Value::Bytes(b) => {
            push_head(out, 2, b.len() as u64);
            out.extend_from_slice(b.as_slice());
        },
        Value::Text(t) => {
            push_head(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_slice());
        },
        Value::Array(items) => {
            push_head(out, 4, items.len() as u64);
            let ghost start = out@;
            let mut i: usize = 0;
            while i < items.len()
                invariant
                    i <= items.len(),
                    out@ == start + spec_encode_items(*v, i as nat),
                    *v == Value::Array(*items),
                decreases items.len() - i,
            {
                assert(decreases_to!(*v => items[i as int]));
                encode_into(&items[i], out);
                assert(spec_encode_items(*v, (i + 1) as nat)
                    == spec_encode_items(*v, i as nat) + spec_encode(items[i as int]));
                i = i + 1;
            }
            assert(out@ == old(out)@ + spec_encode(*v));
        },
        Value::Map(entries) => {
            push_head(out, 5, entries.len() as u64);
            let ghost start = out@;
            let mut i: usize = 0;
            while i < entries.len()
                invariant
                    i <= entries.len(),
                    out@ == start + spec_encode_items(*v, i as nat),
                    *v == Value::Map(*entries),
                decreases entries.len() - i,
            {
                assert(decreases_to!(*v => entries[i as int]));
                encode_into(&entries[i].0, out);
                encode_into(&entries[i].1, out);
                assert(spec_encode_items(*v, (i + 1) as nat)
                    == spec_encode_items(*v, i as nat) + spec_encode(entries[i as int].0) + spec_encode(entries[i as int].1));
                i = i + 1;
            }
            assert(out@ == old(out)@ + spec_encode(*v));
        },
        Value::Tag(t, b) => {
            push_head(out, 6, *t);
            encode_into(b, out);
        },
        Value::Simple(s) => {
            if *s < 24 {
                out.push(0xe0 + *s);
            } else {
                out.push(0xf8);
                out.push(*s);
            }
        },
        Value::Float16(x) => {
            out.push(0xf9);
            push_be(out, *x as u64, 2);
        },
        Value::Float32(x) => {
            out.push(0xfa);
            push_be(out, *x as u64, 4);
        },
        Value::Float64(x) => {
            out.push(0xfb);
            push_be(out, *x, 8);
        },
    }
}

pub fn encode(v: &Value) -> (r: Vec<u8>)
    ensures
        r@ == spec_encode(*v),
{
    let mut out = Vec::new();
    encode_into(v, &mut out);
    assert(out@ == Seq::<u8>::empty() + spec_encode(*v));
    out
}

pub fn lex_less(a: &[u8], b: &[u8]) -> (r: bool)
    ensures
        r == lex_lt(a@, b@),
{
    let mut i: usize = 0;
    assert(a@.skip(0) =~= a@);
    assert(b@.skip(0) =~= b@);
    while i < a.len() && i < b.len() && a[i] == b[i]
        invariant
            i <= a.len(),
            i <= b.len(),
            lex_lt(a@, b@) == lex_lt(a@.skip(i as int), b@.skip(i as int)),
        decreases a.len() - i,
    {
        let ghost sa = a@.skip(i as int);
        let ghost sb = b@.skip(i as int);
        assert(sa.drop_first() == a@.skip(i + 1));
        assert(sb.drop_first() == b@.skip(i + 1));
        i = i + 1;
    }
    let ghost sa = a@.skip(i as int);
    let ghost sb = b@.skip(i as int);
    if i == a.len() {
        assert(sa.len() == 0);
        i < b.len()
    } else if i == b.len() {
        false
    } else {
        assert(sa[0] == a[i as int] && sb[0] == b[i as int]);
        a[i] < b[i]
    }
}

fn tail_byte(b: u8) -> (r: bool)
    ensures
        r == (0x80 <= b <= 0xbf),
{
    0x80 <= b && b <= 0xbf
}

fn byte_at(b: &[u8], i: usize, j: usize) -> (r: u8)
    requires
        i <= b.len(),
        j < b.len() - i,
    ensures
        r == b@.skip(i as int)[j as int],
{
    b[i + j]
}

fn utf8_char_len_at(b: &[u8], i: usize) -> (k: usize)
    requires
        i <= b.len(),
    ensures
        k as nat == utf8_char_len(b@.skip(i as int)),
{
    let ghost s = b@.skip(i as int);
    let n = b.len() - i;
    if n == 0 {
        return 0;
    }
    assert(s[0] == b@[i as int]);
    let b0 = b[i];
    if b0 <= 0x7f {
        1
    } else if 0xc2 <= b0 && b0 <= 0xdf {
        if n >= 2 && tail_byte(byte_at(b, i, 1)) { 2 } else { 0 }
    } else if b0 == 0xe0 {
        if n >= 3 && 0xa0 <= byte_at(b, i, 1) && byte_at(b, i, 1) <= 0xbf && tail_byte(byte_at(b, i, 2)) { 3 } else { 0 }
    } else if (0xe1 <= b0 && b0 <= 0xec) || (0xee <= b0 && b0 <= 0xef) {
        if n >= 3 && tail_byte(byte_at(b, i, 1)) && tail_byte(byte_at(b, i, 2)) { 3 } else { 0 }
    } else if b0 == 0xed {
        if n >= 3 && 0x80 <= byte_at(b, i, 1) && byte_at(b, i, 1) <= 0x9f && tail_byte(byte_at(b, i, 2)) { 3 } else { 0 }
    } else if b0 == 0xf0 {
        if n >= 4 && 0x90 <= byte_at(b, i, 1) && byte_at(b, i, 1) <= 0xbf && tail_byte(byte_at(b, i, 2)) && tail_byte(byte_at(b, i, 3)) { 4 } else { 0 }
    } else if 0xf1 <= b0 && b0 <= 0xf3 {
        if n >= 4 && tail_byte(byte_at(b, i, 1)) && tail_byte(byte_at(b, i, 2)) && tail_byte(byte_at(b, i, 3)) { 4 } else { 0 }
    } else if b0 == 0xf4 {
        if n >= 4 && 0x80 <= byte_at(b, i, 1) && byte_at(b, i, 1) <= 0x8f && tail_byte(byte_at(b, i, 2)) && tail_byte(byte_at(b, i, 3)) { 4 } else { 0 }
    } else {
        0
    }
}

/// Validates UTF-8 against RFC 3629.
pub fn utf8_ok(b: &[u8]) -> (r: bool)
    ensures
        r == spec_utf8(b@),
{
    let mut i: usize = 0;
    assert(b@.skip(0) =~= b@);
    while i < b.len()
        invariant
            i <= b.len(),
            spec_utf8(b@) == spec_utf8(b@.skip(i as int)),
        decreases b.len() - i,
    {
        let k = utf8_char_len_at(b, i);
        if k == 0 || k > b.len() - i {
            return false;
        }
        assert(b@.skip(i as int).skip(k as int) =~= b@.skip((i + k) as int));
        i = i + k;
    }
    assert(b@.skip(i as int).len() == 0);
    true
}

#[verifier::external_body]
pub fn float_shortest(width: u8, bits: u64) -> (r: bool)
    ensures
        r == spec_float_shortest(width, bits),
{
    crate::float::shortest(width, bits)
}

pub fn is_canonical(v: &Value) -> (r: bool)
    ensures
        r == canonical(*v),
    decreases v,
{
    match v {
        Value::Text(t) => utf8_ok(t.as_slice()),
        Value::Array(items) => {
            let mut i: usize = 0;
            while i < items.len()
                invariant
                    i <= items.len(),
                    canonical_items(*v, i as nat),
                    *v == Value::Array(*items),
                decreases items.len() - i,
            {
                assert(decreases_to!(*v => items[i as int]));
                if !is_canonical(&items[i]) {
                    proof { lemma_canonical_items_prefix(*v, (i + 1) as nat, items.len() as nat); }
                    return false;
                }
                i = i + 1;
            }
            true
        },
        Value::Map(entries) => {
            let mut i: usize = 0;
            let mut prev: Vec<u8> = Vec::new();
            while i < entries.len()
                invariant
                    i <= entries.len(),
                    canonical_items(*v, i as nat),
                    *v == Value::Map(*entries),
                    i > 0 ==> prev@ == spec_encode(entries[i - 1].0),
                decreases entries.len() - i,
            {
                proof { lemma_entry_decreases(*v, *entries, i as int); }
                let key = encode(&entries[i].0);
                let ordered = i == 0 || lex_less(prev.as_slice(), key.as_slice());
                if !ordered || !is_canonical(&entries[i].0) || !is_canonical(&entries[i].1) {
                    proof { lemma_canonical_items_prefix(*v, (i + 1) as nat, entries.len() as nat); }
                    return false;
                }
                prev = key;
                i = i + 1;
            }
            true
        },
        Value::Tag(_, b) => is_canonical(b),
        Value::Simple(s) => *s < 24 || *s >= 32,
        Value::Float16(x) => float_shortest(2, *x as u64),
        Value::Float32(x) => float_shortest(4, *x as u64),
        Value::Float64(x) => float_shortest(8, *x),
        _ => true,
    }
}

proof fn lemma_entry_decreases(v: Value, entries: Vec<(Value, Value)>, i: int)
    requires
        v == Value::Map(entries),
        0 <= i < entries.len(),
    ensures
        decreases_to!(v => entries[i]),
        decreases_to!(v => entries[i].0),
        decreases_to!(v => entries[i].1),
{
    vstd::std_specs::vec::axiom_vec_index_decreases(entries, i);
    assert(decreases_to!(v => v->Map_0));
}

proof fn lemma_canonical_items_prefix(v: Value, k: nat, n: nat)
    requires
        k <= n,
        !canonical_items(v, k),
    ensures
        !canonical_items(v, n),
    decreases n - k,
{
    if k < n {
        lemma_canonical_items_prefix(v, k + 1, n);
    }
}

/// Values may nest at most this deep.
pub const MAX_DEPTH: usize = 64;

fn read_be(b: &[u8], pos: usize, n: usize) -> (r: u64)
    requires
        n <= 8,
        pos + n <= b.len(),
{
    let mut x: u64 = 0;
    let mut i: usize = 0;
    while i < n
        invariant
            i <= n,
            n <= 8,
            pos + n <= b.len(),
            x < pow256(i as nat),
        decreases n - i,
    {
        proof { lemma_pow256_step(i as nat); lemma_pow256_bound(i as nat); }
        assert(x * 256 + 255 < pow256((i + 1) as nat)) by (nonlinear_arith)
            requires x < pow256(i as nat), pow256((i + 1) as nat) == pow256(i as nat) * 256;
        x = x * 256 + b[pos + i] as u64;
        i = i + 1;
    }
    x
}

spec fn pow256(n: nat) -> int
    decreases n,
{
    if n == 0 { 1 } else { 256 * pow256((n - 1) as nat) }
}

proof fn lemma_pow256_step(n: nat)
    ensures
        pow256(n + 1) == pow256(n) * 256,
{
    assert(pow256(n + 1) == 256 * pow256(n));
}

proof fn lemma_pow256_bound(n: nat)
    requires
        n < 8,
    ensures
        pow256(n + 1) <= 0x1_0000_0000_0000_0000,
        pow256(n) >= 1,
{
    reveal_with_fuel(pow256, 9);
}

/// Reads one head: its major type, its argument and the position after it.
fn read_head(b: &[u8], pos: usize) -> (r: Option<(u8, u64, usize)>)
    requires
        pos <= b.len(),
    ensures
        r matches Some((major, _, end)) ==> major < 8 && pos < end <= b.len(),
{
    if pos >= b.len() {
        return None;
    }
    let ib = b[pos];
    let major = ib / 32;
    let info = ib % 32;
    if info < 24 {
        Some((major, info as u64, pos + 1))
    } else if info <= 27 {
        let n: usize = if info == 24 { 1 } else if info == 25 { 2 } else if info == 26 { 4 } else { 8 };
        if b.len() - pos - 1 < n {
            return None;
        }
        Some((major, read_be(b, pos + 1, n), pos + 1 + n))
    } else {
        None
    }
}

fn parse(b: &[u8], pos: usize, depth: usize) -> (r: Option<(Value, usize)>)
    requires
        pos <= b.len(),
    ensures
        r matches Some((_, end)) ==> pos < end <= b.len(),
    decreases MAX_DEPTH - depth,
{
    if depth >= MAX_DEPTH {
        return None;
    }
    let (major, arg, mut p) = match read_head(b, pos) {
        Some(h) => h,
        None => return None,
    };
    if major == 0 {
        Some((Value::Uint(arg), p))
    } else if major == 1 {
        Some((Value::Nint(arg), p))
    } else if major == 2 || major == 3 {
        if arg > (b.len() - p) as u64 {
            return None;
        }
        let n = arg as usize;
        let bytes = slice_to_vec(b, p, n);
        if major == 2 {
            Some((Value::Bytes(bytes), p + n))
        } else {
            Some((Value::Text(bytes), p + n))
        }
    } else if major == 4 {
        if arg > (b.len() - p) as u64 {
            return None;
        }
        let n = arg as usize;
        let mut items: Vec<Value> = Vec::new();
        let mut i: usize = 0;
        while i < n
            invariant
                pos < p <= b.len(),
                depth < MAX_DEPTH,
            decreases n - i,
        {
            match parse(b, p, depth + 1) {
                Some((item, end)) => {
                    items.push(item);
                    p = end;
                },
                None => return None,
            }
            i = i + 1;
        }
        Some((Value::Array(items), p))
    } else if major == 5 {
        if arg > (b.len() - p) as u64 {
            return None;
        }
        let n = arg as usize;
        let mut entries: Vec<(Value, Value)> = Vec::new();
        let mut i: usize = 0;
        while i < n
            invariant
                pos < p <= b.len(),
                depth < MAX_DEPTH,
            decreases n - i,
        {
            let (key, end) = match parse(b, p, depth + 1) {
                Some(x) => x,
                None => return None,
            };
            let (value, end2) = match parse(b, end, depth + 1) {
                Some(x) => x,
                None => return None,
            };
            entries.push((key, value));
            p = end2;
            i = i + 1;
        }
        Some((Value::Map(entries), p))
    } else if major == 6 {
        match parse(b, p, depth + 1) {
            Some((inner, end)) => Some((Value::Tag(arg, Box::new(inner)), end)),
            None => None,
        }
    } else {
        let info = b[pos] % 32;
        if info < 24 {
            Some((Value::Simple(info), p))
        } else if info == 24 {
            Some((Value::Simple(arg as u8), p))
        } else if info == 25 {
            Some((Value::Float16(arg as u16), p))
        } else if info == 26 {
            Some((Value::Float32(arg as u32), p))
        } else {
            Some((Value::Float64(arg), p))
        }
    }
}

fn slice_to_vec(b: &[u8], start: usize, n: usize) -> (r: Vec<u8>)
    requires
        start + n <= b.len(),
    ensures
        r@ == b@.subrange(start as int, start + n),
{
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let mut i: usize = 0;
    while i < n
        invariant
            i <= n,
            start + n <= b.len(),
            out@ == b@.subrange(start as int, start + i),
        decreases n - i,
    {
        out.push(b[start + i]);
        i = i + 1;
    }
    out
}

pub fn bytes_eq(a: &[u8], b: &[u8]) -> (r: bool)
    ensures
        r == (a@ == b@),
{
    if a.len() != b.len() {
        return false;
    }
    let mut i: usize = 0;
    while i < a.len()
        invariant
            a.len() == b.len(),
            i <= a.len(),
            forall|j: int| 0 <= j < i ==> a@[j] == b@[j],
        decreases a.len() - i,
    {
        if a[i] != b[i] {
            return false;
        }
        i = i + 1;
    }
    assert(a@ =~= b@);
    true
}

/// Decodes exactly one deterministically encoded value that fills `b`, rejecting every other form.
pub fn decode(b: &[u8]) -> (r: Option<Value>)
    ensures
        r matches Some(v) ==> spec_encode(v) == b@ && canonical(v),
{
    let (v, end) = match parse(b, 0, 0) {
        Some(x) => x,
        None => return None,
    };
    if end != b.len() {
        return None;
    }
    let again = encode(&v);
    if !bytes_eq(again.as_slice(), b) || !is_canonical(&v) {
        return None;
    }
    Some(v)
}

/// Each byte string decodes to at most one value and each value has at most one byte string.
pub proof fn lemma_one_byte_form(a: Seq<u8>, b: Seq<u8>, v: Value)
    requires
        spec_encode(v) == a,
        spec_encode(v) == b,
    ensures
        a == b,
{
}

} // verus!
