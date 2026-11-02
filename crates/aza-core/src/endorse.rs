//! Endorsements, section 10, rules 3 and 4: which changes may keep alive the records made through
//! a device's approvals once its certificate stops working, and whether a record's inclusion
//! proofs satisfy them. Stated over `log::read`'s outputs, which are proven to be section 5.4's.
use crate::log::*;
use vstd::prelude::*;

verus! {

/// The changes whose `endorse` can keep alive records made through device d's approvals.
pub enum Endorsing {
    /// The device has no master removal: an endorsement in any of its sign-outs counts.
    AnyOf(Vec<usize>),
    /// The device has master removals: the record must be endorsed by every one of them.
    AllOf(Vec<usize>),
    /// An outgoing master: its next link must endorse the record.
    NextLink(usize),
    /// Nothing ended the device.
    Nothing,
}

pub open spec fn reading_ok(rd: &Reading) -> bool {
    &&& rd.removal.len() == rd.link.len()
    &&& rd.sign_out.len() == rd.link.len()
    &&& forall|k: int| 0 <= k < rd.links.len() ==> (rd.links[k] as int) < rd.link.len()
}

pub open spec fn has_removal(rd: &Reading, d: int) -> bool {
    exists|r: int| 0 <= r < rd.removal.len() && #[trigger] rd.removal[r] == Some(d as usize)
}

/// Rule 3 and the first half of rule 4: an outgoing master's next link; or every master removal
/// of the device once it has any; or else its sign-outs.
pub fn endorsing(rd: &Reading, d: usize) -> (e: Endorsing)
    requires
        reading_ok(rd),
        (d as int) < rd.link.len(),
    ensures
        match e {
            Endorsing::NextLink(c) => rd.link[d as int] matches Some(k) && k + 1 < rd.links.len() && c == rd.links[k + 1],
            Endorsing::AllOf(v) => rd.link[d as int] is None && v.len() > 0
                && forall|c: usize| #[trigger] v@.contains(c) <==> ((c as int) < rd.removal.len() && rd.removal[c as int] == Some(d)),
            Endorsing::AnyOf(v) => rd.link[d as int] is None && !has_removal(rd, d as int) && v.len() > 0
                && forall|c: usize| #[trigger] v@.contains(c) <==> ((c as int) < rd.sign_out.len() && rd.sign_out[c as int] == Some(d)),
            Endorsing::Nothing => match rd.link[d as int] {
                Some(k) => k + 1 >= rd.links.len(),
                None => !has_removal(rd, d as int) && forall|s: int| 0 <= s < rd.sign_out.len() ==> #[trigger] rd.sign_out[s] != Some(d),
            },
        },
{
    if let Some(k) = rd.link[d] {
        if rd.links.len() > 0 && k < rd.links.len() - 1 {
            return Endorsing::NextLink(rd.links[k + 1]);
        }
        return Endorsing::Nothing;
    }
    let removals = indices_of(&rd.removal, d);
    if removals.len() > 0 {
        return Endorsing::AllOf(removals);
    }
    let outs = indices_of(&rd.sign_out, d);
    proof {
        assert forall|r: int| 0 <= r < rd.removal.len() implies #[trigger] rd.removal[r] != Some(d) by {
            if rd.removal[r] == Some(d) {
                assert(removals@.contains(r as usize));
            }
        }
    }
    if outs.len() > 0 {
        return Endorsing::AnyOf(outs);
    }
    proof {
        assert forall|s: int| 0 <= s < rd.sign_out.len() implies #[trigger] rd.sign_out[s] != Some(d) by {
            if rd.sign_out[s] == Some(d) {
                assert(outs@.contains(s as usize));
            }
        }
    }
    Endorsing::Nothing
}

fn indices_of(v: &Vec<Option<usize>>, d: usize) -> (out: Vec<usize>)
    ensures
        forall|c: usize| #[trigger] out@.contains(c) <==> ((c as int) < v.len() && v[c as int] == Some(d)),
{
    let mut out: Vec<usize> = Vec::new();
    let mut i: usize = 0;
    while i < v.len()
        invariant
            i <= v.len(),
            forall|c: usize| #[trigger] out@.contains(c) <==> (c < i && v[c as int] == Some(d)),
        decreases v.len() - i,
    {
        if v[i] == Some(d) {
            let ghost before = out@;
            out.push(i);
            proof {
                assert forall|c: usize| #[trigger] out@.contains(c) <==> (c < i + 1 && v[c as int] == Some(d)) by {
                    lemma_push_contains(before, i, c);
                }
            }
        }
        i = i + 1;
    }
    out
}

fn any_proven(v: &Vec<usize>, proven: &Vec<bool>) -> (ok: bool)
    requires
        forall|q: int| 0 <= q < v.len() ==> (v[q] as int) < proven.len(),
    ensures
        ok == exists|q: int| 0 <= q < v.len() && #[trigger] proven[v[q] as int],
{
    let mut q: usize = 0;
    while q < v.len()
        invariant
            q <= v.len(),
            forall|r: int| 0 <= r < v.len() ==> (v[r] as int) < proven.len(),
            forall|r: int| 0 <= r < q ==> !#[trigger] proven[v[r] as int],
        decreases v.len() - q,
    {
        if proven[v[q]] {
            assert(proven[v[q as int] as int]);
            return true;
        }
        q = q + 1;
    }
    false
}

fn all_proven(v: &Vec<usize>, proven: &Vec<bool>) -> (ok: bool)
    requires
        forall|q: int| 0 <= q < v.len() ==> (v[q] as int) < proven.len(),
    ensures
        ok == (v.len() > 0 && forall|q: int| 0 <= q < v.len() ==> #[trigger] proven[v[q] as int]),
{
    if v.len() == 0 {
        return false;
    }
    let mut q: usize = 0;
    while q < v.len()
        invariant
            q <= v.len(),
            forall|r: int| 0 <= r < v.len() ==> (v[r] as int) < proven.len(),
            forall|r: int| 0 <= r < q ==> #[trigger] proven[v[r] as int],
        decreases v.len() - q,
    {
        if !proven[v[q]] {
            assert(!proven[v[q as int] as int]);
            return false;
        }
        q = q + 1;
    }
    true
}

pub open spec fn indices_fit(e: Endorsing, n: nat) -> bool {
    match e {
        Endorsing::AnyOf(v) => forall|q: int| 0 <= q < v.len() ==> (v[q] as int) < n,
        Endorsing::AllOf(v) => forall|q: int| 0 <= q < v.len() ==> (v[q] as int) < n,
        Endorsing::NextLink(c) => (c as int) < n,
        Endorsing::Nothing => true,
    }
}

pub open spec fn counts(e: Endorsing, proven: Seq<bool>) -> bool {
    match e {
        Endorsing::AnyOf(v) => exists|q: int| 0 <= q < v.len() && #[trigger] proven[v[q] as int],
        Endorsing::AllOf(v) => v.len() > 0 && forall|q: int| 0 <= q < v.len() ==> #[trigger] proven[v[q] as int],
        Endorsing::NextLink(c) => proven[c as int],
        Endorsing::Nothing => false,
    }
}

/// Rule 4, second half: the endorsement counts. `proven[c]` says the record carries an inclusion
/// proof that rebuilds change c's `endorse` root (false if c endorses nothing).
pub fn endorsement_counts(e: Endorsing, proven: &Vec<bool>) -> (ok: bool)
    requires
        indices_fit(e, proven.len() as nat),
    ensures
        ok == counts(e, proven@),
{
    match e {
        Endorsing::AnyOf(v) => any_proven(&v, proven),
        Endorsing::AllOf(v) => all_proven(&v, proven),
        Endorsing::NextLink(c) => proven[c],
        Endorsing::Nothing => false,
    }
}

} // verus!
