//! Deterministic CBOR (RFC 8949 section 4.2.1), section 3.
//!
//! `encode` is proven to produce exactly `spec_encode`, and `decode` only returns a value whose
//! `spec_encode` is exactly the input and which is `canonical`. Since `spec_encode` is a function,
//! two different byte strings can never decode to the same value: every value has one byte form.
//! `decode` also accepts the encoding of every canonical value at most `MAX_DEPTH` deep.
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


pub open spec fn canonical(v: Value) -> bool
    decreases v, 1nat, 0nat,
{
    match v {
        Value::Text(t) => spec_utf8(t@),
        Value::Array(items) => canonical_items(v, items.len() as nat),
        Value::Map(entries) => canonical_items(v, entries.len() as nat),
        Value::Tag(_, b) => canonical(*b),
        Value::Simple(s) => s < 24 || s >= 32,
        Value::Float16(x) => crate::float::spec_float_shortest(2, x as u64),
        Value::Float32(x) => crate::float::spec_float_shortest(4, x as u64),
        Value::Float64(x) => crate::float::spec_float_shortest(8, x),
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

pub fn float_shortest(width: u8, bits: u64) -> (r: bool)
    ensures
        r == crate::float::spec_float_shortest(width, bits),
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

/// The unsigned integer `s` holds, most significant byte first.
pub open spec fn be_value(s: Seq<u8>) -> nat
    decreases s.len(),
{
    if s.len() == 0 {
        0
    } else {
        (be_value(s.drop_last()) * 256 + s.last()) as nat
    }
}

proof fn lemma_be_value_bound(s: Seq<u8>)
    ensures
        be_value(s) < pow256(s.len()),
    decreases s.len(),
{
    if s.len() > 0 {
        lemma_be_value_bound(s.drop_last());
        let p = pow256((s.len() - 1) as nat);
        assert(pow256(s.len()) == 256 * p);
        assert(be_value(s.drop_last()) * 256 + s.last() < 256 * p) by (nonlinear_arith)
            requires be_value(s.drop_last()) < p, s.last() < 256;
    }
}

proof fn lemma_be_roundtrip(x: u64, n: nat)
    requires
        x < pow256(n),
    ensures
        be_value(be_bytes(x, n)) == x,
        be_bytes(x, n).len() == n,
    decreases n,
{
    if n > 0 {
        let p = pow256((n - 1) as nat);
        assert(pow256(n) == 256 * p);
        assert(x / 256 < p) by (nonlinear_arith)
            requires x < 256 * p, p >= 1;
        lemma_be_roundtrip(x / 256, (n - 1) as nat);
        let s = be_bytes(x, n);
        assert(s.drop_last() == be_bytes(x / 256, (n - 1) as nat));
        assert(s.last() == (x % 256) as u8);
        assert((x / 256) * 256 + x % 256 == x) by (nonlinear_arith);
    } else {
        assert(x == 0);
    }
}

proof fn lemma_pow256_pos(n: nat)
    ensures
        pow256(n) >= 1,
    decreases n,
{
    if n > 0 {
        lemma_pow256_pos((n - 1) as nat);
    }
}

fn read_be(b: &[u8], pos: usize, n: usize) -> (r: u64)
    requires
        n <= 8,
        pos + n <= b.len(),
    ensures
        r as nat == be_value(b@.subrange(pos as int, pos + n)),
{
    let mut x: u64 = 0;
    let mut i: usize = 0;
    while i < n
        invariant
            i <= n,
            n <= 8,
            pos + n <= b.len(),
            x < pow256(i as nat),
            x as nat == be_value(b@.subrange(pos as int, pos + i)),
        decreases n - i,
    {
        proof {
            lemma_pow256_step(i as nat);
            lemma_pow256_bound(i as nat);
            assert(b@.subrange(pos as int, pos + i + 1).drop_last() =~= b@.subrange(pos as int, pos + i));
        }
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

/// How many argument bytes follow an initial byte whose additional information is 24 to 27.
pub open spec fn arg_len(info: u8) -> nat {
    if info == 24 { 1 } else if info == 25 { 2 } else if info == 26 { 4 } else { 8 }
}

/// One head read from `b` at `pos`: its major type, its argument and the position after it.
pub open spec fn spec_read_head(b: Seq<u8>, pos: int) -> Option<(u8, u64, int)> {
    if pos < 0 || pos >= b.len() {
        None
    } else {
        let ib = b[pos];
        let info = ib % 32;
        if info < 24 {
            Some((ib / 32, info as u64, pos + 1))
        } else if info <= 27 {
            let n = arg_len(info);
            if b.len() - pos - 1 < n {
                None
            } else {
                Some((ib / 32, be_value(b.subrange(pos + 1, pos + 1 + n)) as u64, pos + 1 + n))
            }
        } else {
            None
        }
    }
}

/// Reads one head: its major type, its argument and the position after it.
fn read_head(b: &[u8], pos: usize) -> (r: Option<(u8, u64, usize)>)
    requires
        pos <= b.len(),
    ensures
        r matches Some((major, _, end)) ==> major < 8 && pos < end <= b.len(),
        r is Some == spec_read_head(b@, pos as int) is Some,
        r matches Some((major, arg, end)) ==> spec_read_head(b@, pos as int) == Some((major, arg, end as int)),
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


/// `b` holds `e` starting at `pos`.
pub open spec fn starts_with(b: Seq<u8>, pos: int, e: Seq<u8>) -> bool {
    0 <= pos && pos + e.len() <= b.len() && b.subrange(pos, pos + e.len()) == e
}

proof fn lemma_starts_split(b: Seq<u8>, pos: int, x: Seq<u8>, y: Seq<u8>)
    requires
        starts_with(b, pos, x + y),
    ensures
        starts_with(b, pos, x),
        starts_with(b, pos + x.len(), y),
{
    assert(b.subrange(pos, pos + x.len()) =~= (x + y).subrange(0, x.len() as int));
    assert((x + y).subrange(0, x.len() as int) =~= x);
    assert(b.subrange(pos + x.len(), pos + x.len() + y.len()) =~= (x + y).subrange(x.len() as int, (x.len() + y.len()) as int));
    assert((x + y).subrange(x.len() as int, (x.len() + y.len()) as int) =~= y);
}

/// How deeply `v` nests: 1 for a value with nothing inside it.
pub open spec fn height(v: Value) -> nat
    decreases v, 1nat, 0nat,
{
    match v {
        Value::Array(items) => 1 + height_items(v, items.len() as nat),
        Value::Map(entries) => 1 + height_items(v, entries.len() as nat),
        Value::Tag(_, b) => 1 + height(*b),
        _ => 1,
    }
}

/// The greatest height among the first `k` items of an array, or keys and values of a map.
pub open spec fn height_items(v: Value, k: nat) -> nat
    decreases v, 0nat, k,
{
    if k == 0 {
        0
    } else {
        match v {
            Value::Array(items) => if k <= items.len() {
                vstd::math::max(height_items(v, (k - 1) as nat) as int, height(items[k - 1]) as int) as nat
            } else {
                0
            },
            Value::Map(entries) => if k <= entries.len() {
                vstd::math::max(
                    height_items(v, (k - 1) as nat) as int,
                    vstd::math::max(height(entries[k - 1].0) as int, height(entries[k - 1].1) as int),
                ) as nat
            } else {
                0
            },
            _ => 0,
        }
    }
}

proof fn lemma_height_items(v: Value, k: nat, i: int)
    requires
        0 <= i < k,
    ensures
        v matches Value::Array(items) ==> (k <= items.len() ==> height(items[i]) <= height_items(v, k)),
        v matches Value::Map(entries) ==> (k <= entries.len() ==> height(entries[i].0) <= height_items(v, k)
            && height(entries[i].1) <= height_items(v, k)),
    decreases k,
{
    if i < k - 1 {
        lemma_height_items(v, (k - 1) as nat, i);
    }
}

proof fn lemma_items_prefix(v: Value, i: nat, n: nat)
    requires
        i <= n,
        v matches Value::Array(items) ==> n <= items.len(),
        v matches Value::Map(entries) ==> n <= entries.len(),
    ensures
        spec_encode_items(v, n) == spec_encode_items(v, i) + spec_encode_items(v, n).subrange(
            spec_encode_items(v, i).len() as int,
            spec_encode_items(v, n).len() as int,
        ),
        spec_encode_items(v, i).len() <= spec_encode_items(v, n).len(),
    decreases n - i,
{
    if i < n {
        lemma_items_prefix(v, i + 1, n);
        let a = spec_encode_items(v, i);
        let b = spec_encode_items(v, i + 1);
        let c = spec_encode_items(v, n);
        assert(b.subrange(0, a.len() as int) =~= a);
        assert(c.subrange(0, b.len() as int) =~= b);
        assert(c =~= a + c.subrange(a.len() as int, c.len() as int));
    } else {
        assert(spec_encode_items(v, n) =~= spec_encode_items(v, i) + Seq::empty());
    }
}

/// Two arrays, or two maps, that agree on their first `k` items encode them alike.
proof fn lemma_items_same(v: Value, w: Value, k: nat)
    requires
        (v matches Value::Array(a) && w matches Value::Array(b) && k <= a.len() && k <= b.len()
            && a@.subrange(0, k as int) == b@.subrange(0, k as int))
        || (v matches Value::Map(a) && w matches Value::Map(b) && k <= a.len() && k <= b.len()
            && a@.subrange(0, k as int) == b@.subrange(0, k as int)),
    ensures
        spec_encode_items(v, k) == spec_encode_items(w, k),
        canonical_items(v, k) == canonical_items(w, k),
    decreases k,
{
    if k > 0 {
        match (v, w) {
            (Value::Array(a), Value::Array(b)) => {
                assert(a@.subrange(0, k - 1) =~= a@.subrange(0, k as int).subrange(0, k - 1));
                assert(b@.subrange(0, k - 1) =~= b@.subrange(0, k as int).subrange(0, k - 1));
                assert(a@[k - 1] == a@.subrange(0, k as int)[k - 1]);
                assert(b@[k - 1] == b@.subrange(0, k as int)[k - 1]);
            },
            (Value::Map(a), Value::Map(b)) => {
                assert(a@.subrange(0, k - 1) =~= a@.subrange(0, k as int).subrange(0, k - 1));
                assert(b@.subrange(0, k - 1) =~= b@.subrange(0, k as int).subrange(0, k - 1));
                assert(a@[k - 1] == a@.subrange(0, k as int)[k - 1]);
                assert(b@[k - 1] == b@.subrange(0, k as int)[k - 1]);
                if k >= 2 {
                    assert(a@[k - 2] == a@.subrange(0, k as int)[k - 2]);
                    assert(b@[k - 2] == b@.subrange(0, k as int)[k - 2]);
                }
            },
            _ => {},
        }
        lemma_items_same(v, w, (k - 1) as nat);
    }
}

proof fn lemma_encode_nonempty(v: Value)
    ensures
        spec_encode(v).len() >= 1,
{
}

proof fn lemma_items_len(v: Value, k: nat)
    requires
        v matches Value::Array(items) ==> k <= items.len(),
        v matches Value::Map(entries) ==> k <= entries.len(),
        v is Array || v is Map,
    ensures
        spec_encode_items(v, k).len() >= k,
    decreases k,
{
    if k > 0 {
        lemma_items_len(v, (k - 1) as nat);
        match v {
            Value::Array(items) => lemma_encode_nonempty(items[k - 1]),
            Value::Map(entries) => lemma_encode_nonempty(entries[k - 1].0),
            _ => {},
        }
    }
}

/// A head written by `spec_head` reads back as the same major type and argument.
proof fn lemma_read_spec_head(b: Seq<u8>, pos: int, major: u8, arg: u64)
    requires
        major < 8,
        starts_with(b, pos, spec_head(major, arg)),
    ensures
        spec_read_head(b, pos) == Some((major, arg, pos + spec_head(major, arg).len())),
{
    let h = spec_head(major, arg);
    let ib = b[pos];
    assert(ib == h[0]);
    let m = (major * 32) as u8;
    assert(major * 32 < 256);
    assert(m == major * 32);
    reveal_with_fuel(pow256, 9);
    if arg < 24 {
        assert(ib / 32 == major && ib % 32 == arg) by (nonlinear_arith)
            requires ib == m + arg, m == major * 32, arg < 24, major < 8;
    } else {
        let (info, n): (u8, nat) = if arg <= 0xff { (24, 1) } else if arg <= 0xffff { (25, 2) } else if arg <= 0xffff_ffff { (26, 4) } else { (27, 8) };
        assert(h == seq![(m + info) as u8] + be_bytes(arg, n));
        assert(ib / 32 == major && ib % 32 == info) by (nonlinear_arith)
            requires ib == m + info, m == major * 32, 24 <= info <= 27, major < 8;
        assert(arg < pow256(n));
        lemma_be_roundtrip(arg, n);
        assert(b.subrange(pos + 1, pos + 1 + n) =~= h.subrange(1, 1 + n as int));
        assert(h.subrange(1, 1 + n as int) =~= be_bytes(arg, n));
    }
}

/// A float or simple value reads back as major type 7 with its bits, or its number, as argument.
proof fn lemma_read_major7(b: Seq<u8>, pos: int, v: Value)
    requires
        v is Simple || v is Float16 || v is Float32 || v is Float64,
        starts_with(b, pos, spec_encode(v)),
    ensures
        spec_read_head(b, pos) matches Some((major, arg, end)) && major == 7 && end == pos + spec_encode(v).len()
            && match v {
                Value::Simple(s) => (if s < 24 { b[pos] % 32 == s } else { b[pos] % 32 == 24 }) && arg == s as u64,
                Value::Float16(x) => b[pos] % 32 == 25 && arg == x as u64,
                Value::Float32(x) => b[pos] % 32 == 26 && arg == x as u64,
                Value::Float64(x) => b[pos] % 32 == 27 && arg == x,
                _ => false,
            },
{
    let e = spec_encode(v);
    assert(b[pos] == e[0]);
    reveal_with_fuel(pow256, 9);
    match v {
        Value::Simple(s) => {
            if s >= 24 {
                lemma_be_roundtrip(s as u64, 1);
                assert(b.subrange(pos + 1, pos + 2) =~= seq![s]);
                assert(be_bytes(s as u64, 1) =~= seq![s]);
            }
        },
        Value::Float16(x) => {
            lemma_be_roundtrip(x as u64, 2);
            assert(b.subrange(pos + 1, pos + 3) =~= e.subrange(1, 3));
            assert(e.subrange(1, 3) =~= be_bytes(x as u64, 2));
        },
        Value::Float32(x) => {
            lemma_be_roundtrip(x as u64, 4);
            assert(b.subrange(pos + 1, pos + 5) =~= e.subrange(1, 5));
            assert(e.subrange(1, 5) =~= be_bytes(x as u64, 4));
        },
        Value::Float64(x) => {
            lemma_be_roundtrip(x, 8);
            assert(b.subrange(pos + 1, pos + 9) =~= e.subrange(1, 9));
            assert(e.subrange(1, 9) =~= be_bytes(x, 8));
        },
        _ => {},
    }
}

/// `parse` at `pos` and `depth` is aimed at `t`: `t`'s encoding is at `pos` and fits the depth.
pub open spec fn aimed(b: Seq<u8>, pos: int, depth: nat, t: Option<Value>) -> bool {
    t matches Some(v) && depth + height(v) <= MAX_DEPTH && starts_with(b, pos, spec_encode(v))
}

/// `parse` hit `t`: it read exactly `t`'s encoding, into a value that encodes the same way and is
/// canonical whenever `t` is.
pub open spec fn hit(r: Option<(Value, usize)>, pos: int, t: Value) -> bool {
    r matches Some((v, end)) && end == pos + spec_encode(t).len() && spec_encode(v) == spec_encode(t)
        && (canonical(t) ==> canonical(v))
}

/// Parses one value at `pos`. `target` is ghost: when it is aimed at `pos`, `parse` hits it.
fn parse(b: &[u8], pos: usize, depth: usize, Ghost(target): Ghost<Option<Value>>) -> (r: Option<(Value, usize)>)
    requires
        pos <= b.len(),
    ensures
        r matches Some((_, end)) ==> pos < end <= b.len(),
        aimed(b@, pos as int, depth as nat, target) ==> hit(r, pos as int, target->Some_0),
    decreases MAX_DEPTH - depth,
{
    let ghost aim = aimed(b@, pos as int, depth as nat, target);
    let ghost t = target->Some_0;
    if depth >= MAX_DEPTH {
        return None;
    }
    proof {
        if aim {
            match t {
                Value::Uint(n) => lemma_read_spec_head(b@, pos as int, 0, n),
                Value::Nint(n) => lemma_read_spec_head(b@, pos as int, 1, n),
                Value::Bytes(x) => {
                    lemma_starts_split(b@, pos as int, spec_head(2, x.len() as u64), x@);
                    lemma_read_spec_head(b@, pos as int, 2, x.len() as u64);
                },
                Value::Text(x) => {
                    lemma_starts_split(b@, pos as int, spec_head(3, x.len() as u64), x@);
                    lemma_read_spec_head(b@, pos as int, 3, x.len() as u64);
                },
                Value::Array(items) => {
                    lemma_starts_split(b@, pos as int, spec_head(4, items.len() as u64), spec_encode_items(t, items.len() as nat));
                    lemma_read_spec_head(b@, pos as int, 4, items.len() as u64);
                },
                Value::Map(entries) => {
                    lemma_starts_split(b@, pos as int, spec_head(5, entries.len() as u64), spec_encode_items(t, entries.len() as nat));
                    lemma_read_spec_head(b@, pos as int, 5, entries.len() as u64);
                },
                Value::Tag(tag, inner) => {
                    lemma_starts_split(b@, pos as int, spec_head(6, tag), spec_encode(*inner));
                    lemma_read_spec_head(b@, pos as int, 6, tag);
                },
                _ => lemma_read_major7(b@, pos as int, t),
            }
        }
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
        let ghost tn = if t is Array { t->Array_0.len() as nat } else { 0 };
        let ghost body = spec_encode_items(t, tn);
        proof {
            if aim {
                lemma_items_len(t, tn);
            }
        }
        if arg > (b.len() - p) as u64 {
            return None;
        }
        let n = arg as usize;
        let ghost start = p as int;
        let mut items: Vec<Value> = Vec::new();
        let mut i: usize = 0;
        while i < n
            invariant
                pos < p <= b.len(),
                depth < MAX_DEPTH,
                i <= n,
                items.len() == i,
                aim == aimed(b@, pos as int, depth as nat, target),
                t == target->Some_0,
                aim ==> tn == t->Array_0.len(),
                aim ==> t is Array && n == tn && starts_with(b@, start, body)
                    && depth + height(t) <= MAX_DEPTH && body == spec_encode_items(t, tn),
                aim ==> p == start + spec_encode_items(t, i as nat).len()
                    && spec_encode_items(Value::Array(items), i as nat) == spec_encode_items(t, i as nat)
                    && (canonical_items(t, i as nat) ==> canonical_items(Value::Array(items), i as nat)),
            decreases n - i,
        {
            let ghost child = if aim { Some(t->Array_0[i as int]) } else { None };
            proof {
                if aim {
                    let items_t = t->Array_0;
                    assert(spec_encode_items(t, (i + 1) as nat) == spec_encode_items(t, i as nat) + spec_encode(items_t[i as int]));
                    lemma_items_prefix(t, (i + 1) as nat, tn);
                    lemma_starts_split(b@, start, spec_encode_items(t, (i + 1) as nat),
                        body.subrange(spec_encode_items(t, (i + 1) as nat).len() as int, body.len() as int));
                    lemma_starts_split(b@, start, spec_encode_items(t, i as nat), spec_encode(items_t[i as int]));
                    lemma_height_items(t, tn, i as int);
                }
            }
            match parse(b, p, depth + 1, Ghost(child)) {
                Some((item, end)) => {
                    let ghost before = items;
                    items.push(item);
                    proof {
                        if aim {
                            assert(before@.subrange(0, i as int) =~= items@.subrange(0, i as int));
                            lemma_items_same(Value::Array(before), Value::Array(items), i as nat);
                            assert(items@[i as int] == item);
                            assert(spec_encode_items(Value::Array(items), (i + 1) as nat)
                                == spec_encode_items(Value::Array(items), i as nat) + spec_encode(item));
                            assert(spec_encode_items(t, (i + 1) as nat)
                                == spec_encode_items(t, i as nat) + spec_encode(t->Array_0[i as int]));
                        }
                    }
                    p = end;
                },
                None => return None,
            }
            i = i + 1;
        }
        Some((Value::Array(items), p))
    } else if major == 5 {
        let ghost tn = if t is Map { t->Map_0.len() as nat } else { 0 };
        let ghost body = spec_encode_items(t, tn);
        proof {
            if aim {
                lemma_items_len(t, tn);
            }
        }
        if arg > (b.len() - p) as u64 {
            return None;
        }
        let n = arg as usize;
        let ghost start = p as int;
        let mut entries: Vec<(Value, Value)> = Vec::new();
        let mut i: usize = 0;
        while i < n
            invariant
                pos < p <= b.len(),
                depth < MAX_DEPTH,
                i <= n,
                entries.len() == i,
                aim == aimed(b@, pos as int, depth as nat, target),
                t == target->Some_0,
                aim ==> tn == t->Map_0.len(),
                aim ==> t is Map && n == tn && starts_with(b@, start, body)
                    && depth + height(t) <= MAX_DEPTH && body == spec_encode_items(t, tn),
                aim ==> p == start + spec_encode_items(t, i as nat).len()
                    && spec_encode_items(Value::Map(entries), i as nat) == spec_encode_items(t, i as nat)
                    && (i > 0 ==> spec_encode(entries@[i - 1].0) == spec_encode(t->Map_0[i - 1].0))
                    && (canonical_items(t, i as nat) ==> canonical_items(Value::Map(entries), i as nat)),
            decreases n - i,
        {
            let ghost kchild = if aim { Some(t->Map_0[i as int].0) } else { None };
            let ghost vchild = if aim { Some(t->Map_0[i as int].1) } else { None };
            proof {
                if aim {
                    let es = t->Map_0;
                    assert(spec_encode_items(t, (i + 1) as nat)
                        == spec_encode_items(t, i as nat) + spec_encode(es[i as int].0) + spec_encode(es[i as int].1));
                    lemma_items_prefix(t, (i + 1) as nat, tn);
                    lemma_starts_split(b@, start, spec_encode_items(t, (i + 1) as nat),
                        body.subrange(spec_encode_items(t, (i + 1) as nat).len() as int, body.len() as int));
                    lemma_starts_split(b@, start, spec_encode_items(t, i as nat) + spec_encode(es[i as int].0),
                        spec_encode(es[i as int].1));
                    lemma_starts_split(b@, start, spec_encode_items(t, i as nat), spec_encode(es[i as int].0));
                    lemma_height_items(t, tn, i as int);
                }
            }
            let (key, end) = match parse(b, p, depth + 1, Ghost(kchild)) {
                Some(x) => x,
                None => return None,
            };
            let (value, end2) = match parse(b, end, depth + 1, Ghost(vchild)) {
                Some(x) => x,
                None => return None,
            };
            let ghost before = entries;
            entries.push((key, value));
            proof {
                if aim {
                    assert(before@.subrange(0, i as int) =~= entries@.subrange(0, i as int));
                    lemma_items_same(Value::Map(before), Value::Map(entries), i as nat);
                    let es = t->Map_0;
                    let m = Value::Map(entries);
                    assert(entries@[i as int] == (key, value));
                    assert(spec_encode_items(m, (i + 1) as nat)
                        == spec_encode_items(m, i as nat) + spec_encode(key) + spec_encode(value));
                    assert(spec_encode_items(t, (i + 1) as nat)
                        == spec_encode_items(t, i as nat) + spec_encode(es[i as int].0) + spec_encode(es[i as int].1));
                    if i >= 1 {
                        assert(entries@[i - 1] == before@[i - 1]);
                    }
                }
            }
            p = end2;
            i = i + 1;
        }
        Some((Value::Map(entries), p))
    } else if major == 6 {
        let ghost child = if aim { Some(*t->Tag_1) } else { None };
        match parse(b, p, depth + 1, Ghost(child)) {
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
        (exists|w: Value| canonical(w) && height(w) <= MAX_DEPTH && spec_encode(w) == b@) ==> r is Some,
{
    let ghost target = if exists|w: Value| canonical(w) && height(w) <= MAX_DEPTH && spec_encode(w) == b@ {
        Some(choose|w: Value| canonical(w) && height(w) <= MAX_DEPTH && spec_encode(w) == b@)
    } else {
        None
    };
    proof {
        if target is Some {
            assert(b@.subrange(0, b@.len() as int) =~= b@);
        }
    }
    let (v, end) = match parse(b, 0, 0, Ghost(target)) {
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
