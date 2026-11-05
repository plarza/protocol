//! Fixed-size bit sets, used for the ancestors of each change.
use vstd::prelude::*;

verus! {

pub struct Bits {
    pub words: Vec<u64>,
}

pub open spec fn words_for(n: nat) -> nat {
    (n + 63) / 64
}

pub open spec fn bit(w: u64, k: u64) -> bool {
    (w >> k) & 1 == 1
}

pub proof fn lemma_index_fits(i: nat, n: nat)
    requires
        i < n,
    ensures
        i / 64 < words_for(n),
{
    assert(i / 64 < (n + 63) / 64) by (nonlinear_arith)
        requires i < n;
}

proof fn lemma_set_bit(w: u64, k: u64, j: u64)
    requires
        k < 64,
        j < 64,
    ensures
        bit(w | (1u64 << k), j) == (j == k || bit(w, j)),
{
    assert(((w | (1u64 << k)) >> j) & 1 == 1 <==> (j == k || (w >> j) & 1 == 1)) by (bit_vector)
        requires k < 64, j < 64;
}

proof fn lemma_or_bit(a: u64, b: u64, j: u64)
    requires
        j < 64,
    ensures
        bit(a | b, j) == (bit(a, j) || bit(b, j)),
{
    assert(((a | b) >> j) & 1 == 1 <==> ((a >> j) & 1 == 1 || (b >> j) & 1 == 1)) by (bit_vector)
        requires j < 64;
}

proof fn lemma_and_bit(a: u64, b: u64, j: u64)
    requires
        j < 64,
    ensures
        bit(a & b, j) == (bit(a, j) && bit(b, j)),
{
    assert(((a & b) >> j) & 1 == 1 <==> ((a >> j) & 1 == 1 && (b >> j) & 1 == 1)) by (bit_vector)
        requires j < 64;
}

proof fn lemma_zero_bit(j: u64)
    requires
        j < 64,
    ensures
        !bit(0, j),
{
    assert((0u64 >> j) & 1 != 1) by (bit_vector)
        requires j < 64;
}


/// A word with none of its 64 bits set is zero.
proof fn lemma_zero_word(x: u64)
    requires
        (x >> 0u64) & 1 != 1,
        (x >> 1u64) & 1 != 1,
        (x >> 2u64) & 1 != 1,
        (x >> 3u64) & 1 != 1,
        (x >> 4u64) & 1 != 1,
        (x >> 5u64) & 1 != 1,
        (x >> 6u64) & 1 != 1,
        (x >> 7u64) & 1 != 1,
        (x >> 8u64) & 1 != 1,
        (x >> 9u64) & 1 != 1,
        (x >> 10u64) & 1 != 1,
        (x >> 11u64) & 1 != 1,
        (x >> 12u64) & 1 != 1,
        (x >> 13u64) & 1 != 1,
        (x >> 14u64) & 1 != 1,
        (x >> 15u64) & 1 != 1,
        (x >> 16u64) & 1 != 1,
        (x >> 17u64) & 1 != 1,
        (x >> 18u64) & 1 != 1,
        (x >> 19u64) & 1 != 1,
        (x >> 20u64) & 1 != 1,
        (x >> 21u64) & 1 != 1,
        (x >> 22u64) & 1 != 1,
        (x >> 23u64) & 1 != 1,
        (x >> 24u64) & 1 != 1,
        (x >> 25u64) & 1 != 1,
        (x >> 26u64) & 1 != 1,
        (x >> 27u64) & 1 != 1,
        (x >> 28u64) & 1 != 1,
        (x >> 29u64) & 1 != 1,
        (x >> 30u64) & 1 != 1,
        (x >> 31u64) & 1 != 1,
        (x >> 32u64) & 1 != 1,
        (x >> 33u64) & 1 != 1,
        (x >> 34u64) & 1 != 1,
        (x >> 35u64) & 1 != 1,
        (x >> 36u64) & 1 != 1,
        (x >> 37u64) & 1 != 1,
        (x >> 38u64) & 1 != 1,
        (x >> 39u64) & 1 != 1,
        (x >> 40u64) & 1 != 1,
        (x >> 41u64) & 1 != 1,
        (x >> 42u64) & 1 != 1,
        (x >> 43u64) & 1 != 1,
        (x >> 44u64) & 1 != 1,
        (x >> 45u64) & 1 != 1,
        (x >> 46u64) & 1 != 1,
        (x >> 47u64) & 1 != 1,
        (x >> 48u64) & 1 != 1,
        (x >> 49u64) & 1 != 1,
        (x >> 50u64) & 1 != 1,
        (x >> 51u64) & 1 != 1,
        (x >> 52u64) & 1 != 1,
        (x >> 53u64) & 1 != 1,
        (x >> 54u64) & 1 != 1,
        (x >> 55u64) & 1 != 1,
        (x >> 56u64) & 1 != 1,
        (x >> 57u64) & 1 != 1,
        (x >> 58u64) & 1 != 1,
        (x >> 59u64) & 1 != 1,
        (x >> 60u64) & 1 != 1,
        (x >> 61u64) & 1 != 1,
        (x >> 62u64) & 1 != 1,
        (x >> 63u64) & 1 != 1,
    ensures
        x == 0,
{
    assert(x == 0) by (bit_vector)
        requires
        (x >> 0u64) & 1 != 1,
        (x >> 1u64) & 1 != 1,
        (x >> 2u64) & 1 != 1,
        (x >> 3u64) & 1 != 1,
        (x >> 4u64) & 1 != 1,
        (x >> 5u64) & 1 != 1,
        (x >> 6u64) & 1 != 1,
        (x >> 7u64) & 1 != 1,
        (x >> 8u64) & 1 != 1,
        (x >> 9u64) & 1 != 1,
        (x >> 10u64) & 1 != 1,
        (x >> 11u64) & 1 != 1,
        (x >> 12u64) & 1 != 1,
        (x >> 13u64) & 1 != 1,
        (x >> 14u64) & 1 != 1,
        (x >> 15u64) & 1 != 1,
        (x >> 16u64) & 1 != 1,
        (x >> 17u64) & 1 != 1,
        (x >> 18u64) & 1 != 1,
        (x >> 19u64) & 1 != 1,
        (x >> 20u64) & 1 != 1,
        (x >> 21u64) & 1 != 1,
        (x >> 22u64) & 1 != 1,
        (x >> 23u64) & 1 != 1,
        (x >> 24u64) & 1 != 1,
        (x >> 25u64) & 1 != 1,
        (x >> 26u64) & 1 != 1,
        (x >> 27u64) & 1 != 1,
        (x >> 28u64) & 1 != 1,
        (x >> 29u64) & 1 != 1,
        (x >> 30u64) & 1 != 1,
        (x >> 31u64) & 1 != 1,
        (x >> 32u64) & 1 != 1,
        (x >> 33u64) & 1 != 1,
        (x >> 34u64) & 1 != 1,
        (x >> 35u64) & 1 != 1,
        (x >> 36u64) & 1 != 1,
        (x >> 37u64) & 1 != 1,
        (x >> 38u64) & 1 != 1,
        (x >> 39u64) & 1 != 1,
        (x >> 40u64) & 1 != 1,
        (x >> 41u64) & 1 != 1,
        (x >> 42u64) & 1 != 1,
        (x >> 43u64) & 1 != 1,
        (x >> 44u64) & 1 != 1,
        (x >> 45u64) & 1 != 1,
        (x >> 46u64) & 1 != 1,
        (x >> 47u64) & 1 != 1,
        (x >> 48u64) & 1 != 1,
        (x >> 49u64) & 1 != 1,
        (x >> 50u64) & 1 != 1,
        (x >> 51u64) & 1 != 1,
        (x >> 52u64) & 1 != 1,
        (x >> 53u64) & 1 != 1,
        (x >> 54u64) & 1 != 1,
        (x >> 55u64) & 1 != 1,
        (x >> 56u64) & 1 != 1,
        (x >> 57u64) & 1 != 1,
        (x >> 58u64) & 1 != 1,
        (x >> 59u64) & 1 != 1,
        (x >> 60u64) & 1 != 1,
        (x >> 61u64) & 1 != 1,
        (x >> 62u64) & 1 != 1,
        (x >> 63u64) & 1 != 1;
}

/// Some bit at or after `k` is set in a nonzero word whose lower bits are clear.
proof fn lemma_find_bit(x: u64, k: u64) -> (r: u64)
    requires
        x != 0,
        k <= 64,
        forall|k2: u64| k2 < k ==> !#[trigger] bit(x, k2),
    ensures
        r < 64,
        bit(x, r),
    decreases 64 - k,
{
    if k == 64 {
        assert(!bit(x, 0u64));
        assert(!bit(x, 1u64));
        assert(!bit(x, 2u64));
        assert(!bit(x, 3u64));
        assert(!bit(x, 4u64));
        assert(!bit(x, 5u64));
        assert(!bit(x, 6u64));
        assert(!bit(x, 7u64));
        assert(!bit(x, 8u64));
        assert(!bit(x, 9u64));
        assert(!bit(x, 10u64));
        assert(!bit(x, 11u64));
        assert(!bit(x, 12u64));
        assert(!bit(x, 13u64));
        assert(!bit(x, 14u64));
        assert(!bit(x, 15u64));
        assert(!bit(x, 16u64));
        assert(!bit(x, 17u64));
        assert(!bit(x, 18u64));
        assert(!bit(x, 19u64));
        assert(!bit(x, 20u64));
        assert(!bit(x, 21u64));
        assert(!bit(x, 22u64));
        assert(!bit(x, 23u64));
        assert(!bit(x, 24u64));
        assert(!bit(x, 25u64));
        assert(!bit(x, 26u64));
        assert(!bit(x, 27u64));
        assert(!bit(x, 28u64));
        assert(!bit(x, 29u64));
        assert(!bit(x, 30u64));
        assert(!bit(x, 31u64));
        assert(!bit(x, 32u64));
        assert(!bit(x, 33u64));
        assert(!bit(x, 34u64));
        assert(!bit(x, 35u64));
        assert(!bit(x, 36u64));
        assert(!bit(x, 37u64));
        assert(!bit(x, 38u64));
        assert(!bit(x, 39u64));
        assert(!bit(x, 40u64));
        assert(!bit(x, 41u64));
        assert(!bit(x, 42u64));
        assert(!bit(x, 43u64));
        assert(!bit(x, 44u64));
        assert(!bit(x, 45u64));
        assert(!bit(x, 46u64));
        assert(!bit(x, 47u64));
        assert(!bit(x, 48u64));
        assert(!bit(x, 49u64));
        assert(!bit(x, 50u64));
        assert(!bit(x, 51u64));
        assert(!bit(x, 52u64));
        assert(!bit(x, 53u64));
        assert(!bit(x, 54u64));
        assert(!bit(x, 55u64));
        assert(!bit(x, 56u64));
        assert(!bit(x, 57u64));
        assert(!bit(x, 58u64));
        assert(!bit(x, 59u64));
        assert(!bit(x, 60u64));
        assert(!bit(x, 61u64));
        assert(!bit(x, 62u64));
        assert(!bit(x, 63u64));
        lemma_zero_word(x);
        0
    } else if bit(x, k) {
        k
    } else {
        lemma_find_bit(x, (k + 1) as u64)
    }
}

proof fn lemma_or_gain(w: u64, o: u64)
    requires
        (w | o) != w,
    ensures
        (o & !w) != 0,
{
    assert((o & !w) != 0) by (bit_vector)
        requires (w | o) != w;
}

proof fn lemma_or_new_bit(w: u64, o: u64, k: u64)
    requires
        k < 64,
        bit(o & !w, k),
    ensures
        bit(w | o, k),
        !bit(w, k),
{
    assert(((w | o) >> k) & 1 == 1 && (w >> k) & 1 != 1) by (bit_vector)
        requires k < 64, ((o & !w) >> k) & 1 == 1;
}

proof fn lemma_set_already(w: u64, k: u64)
    requires
        k < 64,
        bit(w, k),
    ensures
        (w | (1u64 << k)) == w,
{
    assert((w | (1u64 << k)) == w) by (bit_vector)
        requires k < 64, (w >> k) & 1 == 1;
}

impl Bits {
    pub open spec fn has(&self, i: nat) -> bool {
        &&& i / 64 < self.words.len()
        &&& bit(self.words[(i / 64) as int], (i % 64) as u64)
    }

    pub fn new(n: usize) -> (r: Bits)
        requires
            n + 63 <= usize::MAX,
        ensures
            r.words.len() == words_for(n as nat),
            forall|i: nat| !r.has(i),
    {
        let w = (n + 63) / 64;
        let mut words: Vec<u64> = Vec::with_capacity(w);
        while words.len() < w
            invariant
                words.len() <= w,
                forall|k: int| 0 <= k < words.len() ==> words[k] == 0,
            decreases w - words.len(),
        {
            words.push(0);
        }
        let r = Bits { words };
        assert forall|i: nat| !r.has(i) by {
            if i / 64 < r.words.len() {
                lemma_zero_bit((i % 64) as u64);
            }
        }
        r
    }

    pub fn get(&self, i: usize) -> (r: bool)
        ensures
            r == self.has(i as nat),
    {
        let k = i / 64;
        if k >= self.words.len() {
            false
        } else {
            (self.words[k] >> ((i % 64) as u64)) & 1 == 1
        }
    }

    /// Adds `i`; returns whether the set changed.
    pub fn set(&mut self, i: usize) -> (changed: bool)
        requires
            i / 64 < old(self).words.len(),
        ensures
            final(self).words.len() == old(self).words.len(),
            forall|j: nat| #[trigger] final(self).has(j) == (j == i || old(self).has(j)),
            !changed ==> final(self).words@ == old(self).words@,
            changed ==> !old(self).has(i as nat),
    {
        let k = i / 64;
        let old_w = self.words[k];
        let w = old_w | (1u64 << ((i % 64) as u64));
        self.words.set(k, w);
        assert forall|j: nat| #[trigger] self.has(j) == (j == i || old(self).has(j)) by {
            if j / 64 < self.words.len() {
                if j / 64 == k {
                    lemma_set_bit(old(self).words[k as int], (i % 64) as u64, (j % 64) as u64);
                    assert((j % 64 == i % 64 && j / 64 == i / 64) ==> j == i) by (nonlinear_arith);
                }
            }
        }
        proof {
            if w == old_w {
                assert(self.words@ =~= old(self).words@);
            } else if old(self).has(i as nat) {
                lemma_set_already(old_w, (i % 64) as u64);
            }
        }
        w != old_w
    }

    /// Adds every member of `other`; returns whether the set changed.
    pub fn union(&mut self, other: &Bits) -> (changed: bool)
        requires
            other.words.len() == old(self).words.len(),
        ensures
            final(self).words.len() == old(self).words.len(),
            forall|j: nat| #[trigger] final(self).has(j) == (old(self).has(j) || other.has(j)),
            !changed ==> final(self).words@ == old(self).words@,
            changed ==> exists|j: nat| final(self).has(j) && !old(self).has(j),
    {
        let mut changed = false;
        let ghost mut wit: nat = 0;
        let mut k: usize = 0;
        while k < self.words.len()
            invariant
                self.words.len() == old(self).words.len(),
                other.words.len() == self.words.len(),
                k <= self.words.len(),
                forall|m: int| 0 <= m < k ==> self.words[m] == (old(self).words[m] | other.words[m]),
                forall|m: int| k <= m < self.words.len() ==> self.words[m] == old(self).words[m],
                !changed ==> self.words@ == old(self).words@,
                changed ==> wit / 64 < k && bit(old(self).words[(wit / 64) as int] | other.words[(wit / 64) as int], (wit % 64) as u64)
                    && !bit(old(self).words[(wit / 64) as int], (wit % 64) as u64),
            decreases self.words.len() - k,
        {
            let old_w = self.words[k];
            let w = old_w | other.words[k];
            if w != old_w && !changed {
                proof {
                    lemma_or_gain(old_w, other.words[k as int]);
                    let b = lemma_find_bit(other.words[k as int] & !old_w, 0);
                    lemma_or_new_bit(old_w, other.words[k as int], b);
                    wit = (k * 64 + b) as nat;
                    assert(wit / 64 == k && wit % 64 == b) by (nonlinear_arith)
                        requires wit == k * 64 + b, b < 64;
                }
                changed = true;
            }
            self.words.set(k, w);
            if !changed {
                assert(self.words@ =~= old(self).words@);
            }
            k = k + 1;
        }
        assert forall|j: nat| #[trigger] self.has(j) == (old(self).has(j) || other.has(j)) by {
            if j / 64 < self.words.len() {
                lemma_or_bit(old(self).words[(j / 64) as int], other.words[(j / 64) as int], (j % 64) as u64);
            }
        }
        if changed {
            assert(self.has(wit) && !old(self).has(wit));
        }
        changed
    }

    /// Whether the two sets share a member.
    pub fn intersects(&self, other: &Bits) -> (r: bool)
        requires
            other.words.len() == self.words.len(),
        ensures
            r == exists|j: nat| self.has(j) && #[trigger] other.has(j),
    {
        let mut k: usize = 0;
        while k < self.words.len()
            invariant
                k <= self.words.len(),
                other.words.len() == self.words.len(),
                forall|j: nat| j / 64 < k ==> !(self.has(j) && #[trigger] other.has(j)),
            decreases self.words.len() - k,
        {
            let w = self.words[k] & other.words[k];
            if w != 0 {
                proof {
                    let b = lemma_find_bit(w, 0);
                    lemma_and_bit(self.words[k as int], other.words[k as int], b);
                    let j = (k * 64 + b) as nat;
                    assert(j / 64 == k && j % 64 == b) by (nonlinear_arith)
                        requires j == k * 64 + b, b < 64;
                    assert(self.has(j) && other.has(j));
                }
                return true;
            }
            proof {
                assert forall|j: nat| j / 64 < k + 1 implies !(self.has(j) && #[trigger] other.has(j)) by {
                    if j / 64 == k {
                        lemma_and_bit(self.words[k as int], other.words[k as int], (j % 64) as u64);
                        lemma_zero_bit((j % 64) as u64);
                    }
                }
            }
            k = k + 1;
        }
        proof {
            assert forall|j: nat| !(self.has(j) && #[trigger] other.has(j)) by {
                if j / 64 >= k {
                    assert(!self.has(j));
                }
            }
        }
        false
    }

    pub fn clone_bits(&self) -> (r: Bits)
        ensures
            r.words@ == self.words@,
    {
        let mut words: Vec<u64> = Vec::new();
        let mut k: usize = 0;
        while k < self.words.len()
            invariant
                k <= self.words.len(),
                words@ == self.words@.subrange(0, k as int),
            decreases self.words.len() - k,
        {
            words.push(self.words[k]);
            k = k + 1;
        }
        assert(words@ =~= self.words@);
        Bits { words }
    }

    /// The smallest member at or after `from`, skipping empty words.
    pub fn next_set(&self, from: usize) -> (r: Option<usize>)
        requires
            self.words.len() <= 0x100_0000,
        ensures
            r matches Some(x) ==> from <= x && self.has(x as nat) && forall|j: nat| from <= j < x ==> !self.has(j),
            r is None ==> forall|j: nat| from <= j ==> !#[trigger] self.has(j),
    {
        let total: usize = self.words.len() * 64;
        let mut j: usize = from;
        while j < total
            invariant
                total == self.words.len() * 64,
                from <= j,
                forall|k: nat| from <= k < j ==> !self.has(k),
            decreases total - j,
        {
            let wi = j / 64;
            let w = self.words[wi];
            if w == 0 {
                let next = (wi + 1) * 64;
                assert forall|k: nat| j <= k < next implies !self.has(k) by {
                    assert(k / 64 == wi) by (nonlinear_arith)
                        requires j <= k, k < (wi + 1) * 64, wi == j / 64;
                    lemma_zero_bit((k % 64) as u64);
                }
                assert(next > j) by (nonlinear_arith) requires wi == j / 64, next == (wi + 1) * 64;
                j = next;
            } else {
                if (w >> ((j % 64) as u64)) & 1 == 1 {
                    return Some(j);
                }
                j = j + 1;
            }
        }
        assert forall|k: nat| from <= k implies !#[trigger] self.has(k) by {
            if k >= j {
                assert(k / 64 >= self.words.len()) by (nonlinear_arith)
                    requires k >= j, j >= total, total == self.words.len() * 64;
            }
        }
        None
    }
}

} // verus!
