//! The heads of a log: what a new change lists in `prev` (section 5.1). The aza app never lists
//! a change it can't read (section 13), and after a theft it leaves out the changes the person
//! disowns and everything descending from them (section 4).
use crate::bits::*;
use crate::dag::*;
use crate::log::*;
use vstd::prelude::*;

verus! {

/// Change `i` is left out: it is excluded itself, or one of its ancestors is.
pub open spec fn tainted(cs: Seq<Change>, ex: Seq<bool>, i: int) -> bool {
    ex[i] || exists|j: int| 0 <= j < cs.len() && ancestor(cs, i, j) && #[trigger] ex[j]
}

/// Change `i` is a head: not left out, and no change that isn't left out lists it in `prev`.
pub open spec fn head(cs: Seq<Change>, ex: Seq<bool>, i: int) -> bool {
    &&& !tainted(cs, ex, i)
    &&& forall|j: int| 0 <= j < cs.len() && !tainted(cs, ex, j) ==> !(#[trigger] cs[j].prev@).contains(i as usize)
}

/// Which changes are heads once the `excluded` ones and their descendants are left out.
pub fn heads(cs: &Vec<Change>, anc: &Vec<Bits>, excluded: &Vec<bool>) -> (h: Vec<bool>)
    requires
        valid(cs@),
        anc_exact(cs@, anc@),
        excluded.len() == cs.len(),
    ensures
        h.len() == cs.len(),
        forall|i: int| 0 <= i < cs.len() ==> #[trigger] h[i] == head(cs@, excluded@, i),
{
    let n = cs.len();
    let mut ex = Bits::new(n);
    let mut i: usize = 0;
    while i < n
        invariant
            i <= n == cs.len() == excluded.len() <= MAX_CHANGES,
            ex.words.len() == words_for(n as nat),
            forall|j: nat| #[trigger] ex.has(j) <==> (j < i && excluded[j as int]),
        decreases n - i,
    {
        if excluded[i] {
            proof { lemma_index_fits(i as nat, n as nat); }
            ex.set(i);
        }
        i = i + 1;
    }
    let mut tainted_v: Vec<bool> = Vec::new();
    let mut i: usize = 0;
    while i < n
        invariant
            i <= n == cs.len() == excluded.len() == anc.len(),
            valid(cs@),
            anc_exact(cs@, anc@),
            ex.words.len() == words_for(n as nat),
            forall|j: nat| #[trigger] ex.has(j) <==> (j < n && excluded[j as int]),
            tainted_v.len() == i,
            forall|k: int| 0 <= k < i ==> #[trigger] tainted_v[k] == tainted(cs@, excluded@, k),
        decreases n - i,
    {
        let t = excluded[i] || anc[i].intersects(&ex);
        proof {
            if t && !excluded[i as int] {
                let j = choose|j: nat| anc[i as int].has(j) && #[trigger] ex.has(j);
                lemma_ancestor_in_range(cs@, i as int, j as int);
                assert(ancestor(cs@, i as int, j as int) && excluded[j as int]);
            }
            if !t {
                assert forall|j: int| 0 <= j < n && ancestor(cs@, i as int, j) implies !#[trigger] excluded@[j] by {
                    assert(anc[i as int].has(j as nat));
                    if excluded@[j] {
                        assert(ex.has(j as nat));
                    }
                }
            }
        }
        tainted_v.push(t);
        i = i + 1;
    }
    // referenced[x]: some change that isn't left out lists x in prev.
    let mut referenced: Vec<bool> = Vec::new();
    while referenced.len() < n
        invariant
            referenced.len() <= n,
            forall|k: int| 0 <= k < referenced.len() ==> !referenced[k],
        decreases n - referenced.len(),
    {
        referenced.push(false);
    }
    let mut j: usize = 0;
    while j < n
        invariant
            j <= n == cs.len() == tainted_v.len(),
            referenced.len() == n,
            valid(cs@),
            forall|k: int| 0 <= k < n ==> #[trigger] tainted_v[k] == tainted(cs@, excluded@, k),
            forall|x: int| 0 <= x < n ==> (#[trigger] referenced[x] <==> exists|m: int| 0 <= m < j && !tainted_v[m] && #[trigger] cs@[m].prev@.contains(x as usize)),
        decreases n - j,
    {
        if !tainted_v[j] {
            let ghost before = referenced@;
            let mut q: usize = 0;
            while q < cs[j].prev.len()
                invariant
                    j < n == cs.len() == tainted_v.len(),
                    referenced.len() == n,
                    valid(cs@),
                    !tainted_v[j as int],
                    q <= cs[j as int].prev.len(),
                    forall|x: int| 0 <= x < n ==> (#[trigger] referenced[x] <==> (before[x]
                        || exists|r: int| 0 <= r < q && cs@[j as int].prev@[r] == x as usize)),
                decreases cs[j as int].prev.len() - q,
            {
                let x = cs[j].prev[q];
                assert(change_ok(cs@[j as int], n as nat));
                referenced.set(x, true);
                q = q + 1;
            }
            proof {
                assert forall|x: int| 0 <= x < n implies (#[trigger] referenced[x] <==> exists|m: int| 0 <= m < j + 1 && !tainted_v[m] && #[trigger] cs@[m].prev@.contains(x as usize)) by {
                    if referenced[x] && !before[x] {
                        let r = choose|r: int| 0 <= r < cs@[j as int].prev.len() && cs@[j as int].prev@[r] == x as usize;
                        assert(cs@[j as int].prev@.contains(x as usize));
                    }
                    if exists|m: int| 0 <= m < j + 1 && !tainted_v[m] && #[trigger] cs@[m].prev@.contains(x as usize) {
                        let m = choose|m: int| 0 <= m < j + 1 && !tainted_v[m] && #[trigger] cs@[m].prev@.contains(x as usize);
                        if m == j {
                            let r = choose|r: int| 0 <= r < cs@[j as int].prev.len() && cs@[j as int].prev@[r] == x as usize;
                        }
                    }
                }
            }
        } else {
            proof {
                assert forall|x: int| 0 <= x < n implies (#[trigger] referenced[x] <==> exists|m: int| 0 <= m < j + 1 && !tainted_v[m] && #[trigger] cs@[m].prev@.contains(x as usize)) by {
                    if exists|m: int| 0 <= m < j + 1 && !tainted_v[m] && #[trigger] cs@[m].prev@.contains(x as usize) {
                        let m = choose|m: int| 0 <= m < j + 1 && !tainted_v[m] && #[trigger] cs@[m].prev@.contains(x as usize);
                        assert(m != j);
                    }
                }
            }
        }
        j = j + 1;
    }
    let mut h: Vec<bool> = Vec::new();
    let mut i: usize = 0;
    while i < n
        invariant
            i <= n == cs.len() == tainted_v.len() == referenced.len(),
            forall|k: int| 0 <= k < n ==> #[trigger] tainted_v[k] == tainted(cs@, excluded@, k),
            forall|x: int| 0 <= x < n ==> (#[trigger] referenced[x] <==> exists|m: int| 0 <= m < n && !tainted_v[m] && #[trigger] cs@[m].prev@.contains(x as usize)),
            h.len() == i,
            forall|k: int| 0 <= k < i ==> #[trigger] h[k] == head(cs@, excluded@, k),
        decreases n - i,
    {
        let is_head = !tainted_v[i] && !referenced[i];
        proof {
            if !referenced[i as int] {
                assert forall|m: int| 0 <= m < n && !tainted(cs@, excluded@, m) implies !(#[trigger] cs@[m].prev@).contains(i as usize) by {
                    assert(!tainted_v[m]);
                }
            }
            if referenced[i as int] {
                let m = choose|m: int| 0 <= m < n && !tainted_v[m] && #[trigger] cs@[m].prev@.contains(i as usize);
                assert(!tainted(cs@, excluded@, m));
            }
        }
        h.push(is_head);
        i = i + 1;
    }
    h
}

/// The number of zero bits `b` starts with, most significant bit first.
pub open spec fn byte_zeros(b: nat) -> nat
    decreases 256 - b,
{
    if b == 0 || b >= 128 { if b == 0 { 8 } else { 0 } } else { 1 + byte_zeros(b * 2) }
}

proof fn lemma_byte_zeros(b: nat)
    requires
        1 <= b < 256,
    ensures
        byte_zeros(b) <= 7,
        b >= 2 ==> byte_zeros(b) <= 6,
        b >= 4 ==> byte_zeros(b) <= 5,
        b >= 8 ==> byte_zeros(b) <= 4,
        b >= 16 ==> byte_zeros(b) <= 3,
        b >= 32 ==> byte_zeros(b) <= 2,
        b >= 64 ==> byte_zeros(b) <= 1,
        b >= 128 ==> byte_zeros(b) == 0,
    decreases 256 - b,
{
    if b < 128 {
        lemma_byte_zeros(b * 2);
    }
}

/// The number of zero bits `s` starts with (section 12).
pub open spec fn zero_bits(s: Seq<u8>) -> nat
    decreases s.len(),
{
    if s.len() == 0 { 0 } else if s[0] == 0 { 8 + zero_bits(s.drop_first()) } else { byte_zeros(s[0] as nat) }
}

pub fn leading_zero_bits(s: &[u8]) -> (r: u64)
    requires
        s.len() < 0x1000_0000,
    ensures
        r == zero_bits(s@),
{
    let mut i: usize = 0;
    let mut r: u64 = 0;
    proof { assert(s@.skip(0) =~= s@); }
    while i < s.len() && s[i] == 0
        invariant
            i <= s.len() < 0x1000_0000,
            r == 8 * i,
            zero_bits(s@) == r + zero_bits(s@.skip(i as int)),
        decreases s.len() - i,
    {
        assert(s@.skip(i as int).drop_first() =~= s@.skip(i + 1));
        i = i + 1;
        r = r + 8;
    }
    if i == s.len() {
        return r;
    }
    let mut b: u64 = s[i] as u64;
    let mut z: u64 = 0;
    proof { lemma_byte_zeros(s[i as int] as nat); }
    while b < 128
        invariant
            i < s.len(),
            1 <= b < 256,
            byte_zeros(s[i as int] as nat) <= 7,
            byte_zeros(s[i as int] as nat) == z + byte_zeros(b as nat),
        decreases 256 - b,
    {
        b = b * 2;
        z = z + 1;
    }
    proof {
        assert(s@.skip(i as int)[0] == s[i as int]);
    }
    r + z
}

} // verus!
