//! An identity, read from its change log (section 5.4) by the verified core.
use crate::change::{Body, Change};
use crate::crypto::{Hash, fingerprint};
use crate::error::{Error, Result};
use crate::work::{MIN_WORK, cached_work};
use aza_core::log as core;
use std::collections::HashMap;

/// A device of an identity, as the log describes it.
#[derive(Clone, Debug)]
pub struct Device {
    pub id: Hash,
    pub key: Vec<u8>,
    pub enc: Vec<u8>,
    /// `add-device` label; masters have none.
    pub label: Option<String>,
    /// A link of the master chain.
    pub master: bool,
    /// Current at the end of the log.
    pub current: bool,
}

#[derive(Clone)]
pub struct Identity {
    pub id: Hash,
    changes: Vec<Change>,
    by_hash: HashMap<Hash, usize>,
    by_device: HashMap<Hash, usize>,
    reading: std::sync::Arc<core::Reading>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity({}, {} changes)", hex::encode(&self.id[..8]), self.changes.len())
    }
}

impl Identity {
    /// Reads an identity's log. Changes for other identities, and duplicates, are ignored.
    pub fn read(id: Hash, changes: impl IntoIterator<Item = Change>) -> Result<Identity> {
        Identity::read_with_work(id, changes, MIN_WORK)
    }

    /// Reads a log, requiring at least `min_work` (a node's admission price).
    pub fn read_with_work(id: Hash, changes: impl IntoIterator<Item = Change>, min_work: u32) -> Result<Identity> {
        let mut list: Vec<Change> = Vec::new();
        let mut by_hash = HashMap::new();
        for c in changes {
            let ours = match c.body {
                Body::Genesis { .. } => c.hash() == id,
                _ => c.identity == Some(id),
            };
            if ours && !by_hash.contains_key(&c.hash()) {
                by_hash.insert(c.hash(), list.len());
                list.push(c);
            }
        }
        let genesis = *by_hash.get(&id).ok_or(Error::NoIdentity)?;
        let mut by_device: HashMap<Hash, usize> = HashMap::new();
        for (i, c) in list.iter().enumerate() {
            if c.device_key().is_some() {
                by_device.entry(c.device_id()).or_insert(i);
            }
        }
        // The verified core resolves every hash to an index and names the key each change must be
        // signed with; it checks the two sort orders it is given rather than trusting them.
        use aza_core::resolve::{Raw, RawBody, Signer};
        let raws: Vec<Raw> = list
            .iter()
            .map(|c| Raw {
                hash: c.hash(),
                id: c.device_id(),
                prev: c.prev.clone(),
                by: c.by,
                body: match &c.body {
                    Body::Genesis { key, next, .. } => RawBody::Genesis {
                        key: fingerprint(key),
                        next: *next,
                        work_ok: c.hash() == id && cached_work(&id, &c.signing_bytes()) >= min_work.max(MIN_WORK),
                    },
                    Body::AddDevice { key, .. } => RawBody::AddDevice { key: fingerprint(key) },
                    Body::SignOut { device, .. } => RawBody::SignOut { device: *device },
                    Body::RemoveDevice { device, keep, .. } => RawBody::RemoveDevice { device: *device, keep: *keep },
                    Body::SetMaster { reveal, key, next, .. } => {
                        RawBody::SetMaster { reveal: fingerprint(reveal), key: fingerprint(key), next: *next }
                    }
                    Body::SetHandle { .. } => RawBody::SetHandle,
                    Body::SetHome { .. } => RawBody::SetHome,
                    Body::RevokeClient { .. } => RawBody::RevokeClient,
                    Body::NewSecret { .. } => RawBody::NewSecret,
                    Body::Future => RawBody::Future,
                    Body::Invalid => RawBody::Invalid,
                },
            })
            .collect();
        let mut sorted_hash: Vec<usize> = (0..list.len()).collect();
        sorted_hash.sort_by_key(|&i| list[i].hash());
        let mut sorted_id: Vec<usize> = (0..list.len()).filter(|&i| list[i].device_key().is_some()).collect();
        sorted_id.sort_by_key(|&i| (list[i].device_id(), i));
        let (mut input, signers) =
            aza_core::resolve::resolve(&raws, &sorted_hash, &sorted_id).ok_or(Error::NoIdentity)?;
        for (i, signer) in signers.iter().enumerate() {
            let key = match signer {
                Signer::Own => list[i].own_signer(),
                Signer::Device(j) => list[*j].device_key(),
                Signer::Nobody => None,
            };
            input[i].sig_ok = key.is_some_and(|k| list[i].verify_with(k));
        }
        let reading = core::read(&input, genesis).ok_or(Error::NoIdentity)?;
        Ok(Identity { id, changes: list, by_hash, by_device, reading: std::sync::Arc::new(reading) })
    }

    pub fn changes(&self) -> &[Change] {
        &self.changes
    }

    pub fn change(&self, hash: &Hash) -> Option<&Change> {
        self.by_hash.get(hash).map(|&i| &self.changes[i])
    }

    fn index(&self, hash: &Hash) -> Option<usize> {
        self.by_hash.get(hash).copied()
    }

    /// The log can be used for everything, not only for signing sign-outs and removals.
    pub fn readable(&self) -> bool {
        !self.reading.unreadable
    }

    pub fn require_readable(&self) -> Result<()> {
        if self.readable() { Ok(()) } else { Err(Error::Unreadable) }
    }

    pub fn has_master_conflict(&self) -> bool {
        self.reading.conflict
    }

    pub fn is_discarded(&self, hash: &Hash) -> bool {
        self.index(hash).is_some_and(|i| self.reading.discarded[i])
    }

    pub fn is_applied(&self, hash: &Hash) -> bool {
        self.index(hash).is_some_and(|i| self.reading.applied[i])
    }

    pub fn is_master_change(&self, hash: &Hash) -> bool {
        self.index(hash).is_some_and(|i| self.reading.master_change[i])
    }

    /// Changes in reading order (discarded changes left out).
    pub fn reading_order(&self) -> impl Iterator<Item = &Change> {
        self.reading.order.iter().map(|&i| &self.changes[i])
    }

    fn device_at(&self, i: usize) -> Option<Device> {
        let c = &self.changes[i];
        let (key, enc) = (c.device_key()?, c.device_enc()?);
        let master = self.reading.link[i].is_some();
        if !master && !matches!(c.body, Body::AddDevice { .. }) {
            return None;
        }
        Some(Device {
            id: c.device_id(),
            key: key.to_vec(),
            enc: enc.to_vec(),
            label: match &c.body {
                Body::AddDevice { label, .. } => Some(label.clone()),
                _ => None,
            },
            master,
            current: self.reading.current[i],
        })
    }

    /// A device of this identity, current or not, discarded or not.
    pub fn device(&self, id: &Hash) -> Option<Device> {
        self.device_at(*self.by_device.get(id)?)
    }

    /// Every device the log brings in, including ones no longer current.
    pub fn devices(&self) -> Vec<Device> {
        let mut seen = std::collections::HashSet::new();
        (0..self.changes.len()).filter_map(|i| self.device_at(i)).filter(|d| seen.insert(d.id)).collect()
    }

    pub fn current_devices(&self) -> Vec<Device> {
        self.devices().into_iter().filter(|d| d.current).collect()
    }

    pub fn current_ordinary_devices(&self) -> Vec<Device> {
        self.devices().into_iter().filter(|d| d.current && !d.master).collect()
    }

    pub fn is_current(&self, device: &Hash) -> bool {
        self.device(device).is_some_and(|d| d.current)
    }

    /// The current master, unless the chain ended in a master conflict.
    pub fn master(&self) -> Option<Device> {
        if self.reading.conflict {
            return None;
        }
        self.device_at(*self.reading.links.last()?)
    }

    /// The signing key of a device, taken from the change that brought it in even if that
    /// change is discarded.
    pub fn device_key_any(&self, id: &Hash) -> Option<&[u8]> {
        self.changes[*self.by_device.get(id)?].device_key()
    }

    pub fn handle(&self) -> Option<String> {
        match &self.changes[self.reading.handle?].body {
            Body::SetHandle { handle } => handle.clone(),
            _ => None,
        }
    }

    pub fn home(&self) -> Option<String> {
        match &self.changes[self.reading.home?].body {
            Body::SetHome { node } => Some(node.clone()),
            _ => None,
        }
    }

    /// The name of the current data secret.
    pub fn current_secret(&self) -> Hash {
        self.changes[self.reading.secret].hash()
    }

    /// The `check` of a data secret readers may open: the first one or one an applied
    /// `new-secret` change announced.
    pub fn secret_check(&self, name: &Hash) -> Option<Hash> {
        let i = self.index(name)?;
        if !self.reading.announced[i] {
            return None;
        }
        match &self.changes[i].body {
            Body::Genesis { check, .. } | Body::NewSecret { check } => Some(*check),
            _ => None,
        }
    }

    /// Every data secret readers may open, oldest first in reading order.
    pub fn announced_secrets(&self) -> Vec<Hash> {
        self.reading.order.iter().filter(|&&i| self.reading.announced[i]).map(|&i| self.changes[i].hash()).collect()
    }

    /// The log has a revocation of this client key fingerprint.
    pub fn is_revoked(&self, client: &Hash) -> bool {
        self.changes.iter().enumerate().any(|(i, c)| {
            self.reading.revocation[i] && matches!(&c.body, Body::RevokeClient { client: f } if f == client)
        })
    }

    /// Changes that no other change lists in `prev`, for the `prev` of a new change. Changes
    /// this software can't read are never listed (section 13).
    pub fn heads(&self) -> Vec<Hash> {
        self.heads_excluding(&[])
    }

    /// Heads of the log once `disowned` changes and everything descending from them are left
    /// out, for a handoff after a theft (section 4).
    pub fn heads_excluding(&self, disowned: &[Hash]) -> Vec<Hash> {
        let n = self.changes.len();
        let mut tainted = vec![false; n];
        for &i in self.topological().iter() {
            let c = &self.changes[i];
            tainted[i] = disowned.contains(&c.hash())
                || matches!(c.body, Body::Future)
                || c.prev.iter().any(|p| self.index(p).is_some_and(|j| tainted[j]));
        }
        let mut referenced = vec![false; n];
        for (i, c) in self.changes.iter().enumerate() {
            if !tainted[i] {
                for p in &c.prev {
                    if let Some(j) = self.index(p) {
                        referenced[j] = true;
                    }
                }
            }
        }
        let mut heads: Vec<Hash> =
            (0..n).filter(|&i| !tainted[i] && !referenced[i]).map(|i| self.changes[i].hash()).collect();
        heads.sort();
        heads
    }

    fn topological(&self) -> Vec<usize> {
        let n = self.changes.len();
        let mut done = vec![false; n];
        let mut out = Vec::with_capacity(n);
        fn visit(id: &Identity, i: usize, done: &mut [bool], out: &mut Vec<usize>, depth: usize) {
            if done[i] || depth > id.changes.len() {
                return;
            }
            done[i] = true;
            for p in &id.changes[i].prev {
                if let Some(j) = id.index(p) {
                    visit(id, j, done, out, depth + 1);
                }
            }
            out.push(i);
        }
        for i in 0..n {
            visit(self, i, &mut done, &mut out, 0);
        }
        out
    }

    /// Whether change `a` is an ancestor of change `b`.
    pub fn is_ancestor(&self, a: &Hash, b: &Hash) -> bool {
        let (Some(_), Some(bi)) = (self.index(a), self.index(b)) else { return false };
        let mut stack = vec![bi];
        let mut seen = vec![false; self.changes.len()];
        while let Some(i) = stack.pop() {
            for p in &self.changes[i].prev {
                if let Some(j) = self.index(p)
                    && !seen[j]
                {
                    if self.changes[j].hash() == *a {
                        return true;
                    }
                    seen[j] = true;
                    stack.push(j);
                }
            }
        }
        false
    }

    /// The `add-device` change of a device and every change it signed, newest last.
    pub fn changes_by(&self, device: &Hash) -> Vec<&Change> {
        self.changes.iter().filter(|c| c.by.as_ref() == Some(device)).collect()
    }

    /// Whether records made through device `device`'s approvals stay valid through endorsements
    /// (section 10, rules 3 and 4, decided by the verified `aza_core::endorse`). `proved` says
    /// whether the record has an inclusion proof for an endorsing change against its root.
    pub fn endorsement_holds(&self, device: &Hash, proved: impl Fn(&Hash, &Hash) -> bool) -> bool {
        let Some(&d) = self.by_device.get(device) else { return false };
        let endorsing = aza_core::endorse::endorsing(&self.reading, d);
        let proven: Vec<bool> = self
            .changes
            .iter()
            .map(|c| match &c.body {
                Body::SignOut { endorse: Some(root), .. }
                | Body::RemoveDevice { endorse: Some(root), .. }
                | Body::SetMaster { endorse: Some(root), .. } => proved(&c.hash(), root),
                _ => false,
            })
            .collect();
        aza_core::endorse::endorsement_counts(endorsing, &proven)
    }

    /// Sign-outs that count, as (sign-out change, signed-out device).
    pub fn sign_outs(&self) -> Vec<(Hash, Hash)> {
        (0..self.changes.len())
            .filter_map(|i| self.reading.sign_out[i].map(|d| (self.changes[i].hash(), self.changes[d].device_id())))
            .collect()
    }

    /// Master removals, as (removal change, removed device).
    pub fn removals(&self) -> Vec<(Hash, Hash)> {
        (0..self.changes.len())
            .filter_map(|i| self.reading.removal[i].map(|d| (self.changes[i].hash(), self.changes[d].device_id())))
            .collect()
    }

    /// The device IDs of every link of the master chain, oldest first.
    pub fn master_chain(&self) -> Vec<Hash> {
        self.reading.links.iter().map(|&i| self.changes[i].device_id()).collect()
    }

    /// The `next` of the current master's link, if there is a master.
    pub fn master_next(&self) -> Option<Hash> {
        let i = *self.reading.links.last()?;
        match &self.changes[i].body {
            Body::Genesis { next, .. } | Body::SetMaster { next, .. } => Some(*next),
            _ => None,
        }
    }
}
