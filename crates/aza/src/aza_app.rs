//! The aza app: the only program that handles device keys. It creates identities, adds devices,
//! approves sign-ins, and keeps envelopes, secrets and approvals in order.
use crate::Value;
use crate::backup::{self, Contents};
use crate::certificate::{self, AZA_APP, Certificate, Grant, PUBLISH, READ, RECEIVE, Request};
use crate::change::{Body, Change, Unsigned, now};
use crate::crypto::{self, EncKey, Hash, SigningKey, fingerprint, sha256};
use crate::data::{self, Envelope, Kind, SyncItem, app_key, contact_tag, secret_check};
use crate::error::{Error, Result};
use crate::identity::{Device, Identity};
use crate::message::{Acceptance, ContactRequest, InboxItem};
use crate::node::{Inbox, NodeClient, PairingKeys, PairingReply, Signer};
use crate::profile::{self, Picture, Profile};
use crate::record::{Endorsement, Record};
use crate::saved::{self, StorageKey};
use crate::work::{MIN_WORK, work};
use std::collections::{BTreeMap, HashMap};

/// The most certificates the aza app keeps in effect per identity.
pub const MAX_APPROVALS: usize = 64;
/// Sync item names the aza app keeps under its own app ID.
const APPROVALS: &str = "approvals";

/// The labels of approved clients' requests, by client fingerprint: kept beside the approvals,
/// which stay plain certificates so every version of the aza app can read them.
const APPROVAL_LABELS: &str = "approval-labels";

/// A certificate in effect, and the label of the request it answered.
#[derive(Clone, Debug)]
pub struct Approval {
    pub certificate: Certificate,
    pub label: Option<String>,
}

const CONTACT: &str = "contact";

/// A device's private keys and its device ID.
#[derive(Clone, Debug)]
pub struct Keys {
    pub id: Hash,
    pub key: SigningKey,
    pub enc: EncKey,
}

/// A contact secret and its generation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ContactSecret {
    pub secret: Hash,
    pub generation: u64,
}

/// Which records a sign-out, removal or handoff endorses.
#[derive(Clone, Debug, Default)]
pub enum Endorse {
    /// No endorsement.
    #[default]
    None,
    /// For each name, the newest version made through the ended device's approvals, leaving out
    /// the record hashes listed (so the version before shows again).
    AllExcept(Vec<Hash>),
}

/// Signs the handoff a provider makes when a person takes control (section 8.2).
pub trait HandoffSigner {
    /// The provider's next public key.
    fn next_public_key(&self, identity: &Hash) -> Result<Vec<u8>>;
    /// Signs exactly this `set-master` change with the next key.
    fn sign_handoff(&self, identity: &Hash, change: &Unsigned) -> Result<Change>;
}

/// The outcome of taking control from a provider.
#[derive(Debug)]
pub struct TookControl {
    /// The new master and next keys, to save into one backup file.
    pub master: Keys,
    pub next: SigningKey,
    /// Approvals the provider's master had signed, which stopped working.
    pub provider_approvals: Vec<Certificate>,
    /// Devices removed because the person didn't recognise them.
    pub removed: Vec<Hash>,
    /// Machines whose devices the provider's handoff left out; each joins again with new keys.
    pub lost: Vec<Device>,
    /// Master changes the published handoff treats differently from the one asked for.
    pub differing: Vec<Hash>,
}

/// A new device waiting to be added through pairing.
pub struct Pairing {
    pub url: String,
    pub qr: String,
    key: SigningKey,
    enc: EncKey,
}

/// What a new device shows before joining: it joins only once the person confirms.
pub struct Joined {
    pub identity: Hash,
    pub name: Option<String>,
    pub handle: Option<String>,
    app: AzaApp,
}

impl Joined {
    pub fn confirm(self) -> AzaApp {
        self.app
    }
}

impl Pairing {
    /// Makes this machine's keys and stores the public ones on a node for ten minutes; `qr` is
    /// what the QR code shows: the pairing URL and the keys' hash.
    pub async fn start(node: &str, label: &str) -> Result<Pairing> {
        let key = SigningKey::generate();
        let enc = EncKey::generate();
        let keys = PairingKeys { key: key.public().to_vec(), enc: enc.public().to_vec(), label: label.into() };
        let url = NodeClient::new(node)?.post_pairing(&keys).await?;
        let qr = certificate::qr_payload(&url, &keys.hash());
        Ok(Pairing { url, qr, key, enc })
    }

    /// Takes the approving device's reply, then checks the log and returns what to confirm.
    /// `NotFound` until another device has approved; ask again.
    pub async fn finish(&self) -> Result<Joined> {
        let sealed = NodeClient::get_pairing_reply(&self.url).await?.ok_or(Error::NotFound("pairing reply".into()))?;
        let plain = self.enc.open(&sealed).ok_or(Error::Malformed("pairing reply"))?;
        let reply = PairingReply::from_value(&Value::from_bytes(&plain).ok_or(Error::Malformed("pairing reply"))?)?;
        let node = NodeClient::new(&reply.node)?;
        let log = Identity::read(reply.identity, node.get_log(&reply.identity).await?)?;
        let device = log.device(&reply.device).ok_or(Error::NotFound("the add-device change".into()))?;
        if !device.current || device.key != self.key.public() || device.enc != self.enc.public() {
            return Err(Error::Refused("the log doesn't add this machine's keys".into()));
        }
        let keys = Keys { id: reply.device, key: self.key.clone(), enc: self.enc.clone() };
        let mut app = AzaApp::with(reply.identity, node, keys, log)?;
        app.hold_secrets().await?;
        let name = app.profile().await?.and_then(|p| p.name().map(str::to_string));
        let handle = app.log.handle();
        Ok(Joined { identity: reply.identity, name, handle, app })
    }
}

/// The aza app on one machine, for one identity.
pub struct AzaApp {
    pub identity: Hash,
    node: NodeClient,
    device: Keys,
    /// The current master's keys, while this session holds them.
    master: Option<Keys>,
    /// The master's next key, while this session holds it.
    next: Option<SigningKey>,
    log: Identity,
    secrets: HashMap<Hash, Hash>,
    /// The last profile record this app saw readers use, to sign again if its device stops
    /// being current.
    known_profile: Option<Profile>,
    /// The image of the picture in the profile this app uses, to upload again if it's missing.
    known_picture: Option<Vec<u8>>,
    /// The devices that were current when this app last looked, to notice one that stops being
    /// current (`upkeep`).
    known_current: Vec<Hash>,
}

impl AzaApp {
    fn with(identity: Hash, node: NodeClient, device: Keys, log: Identity) -> Result<AzaApp> {
        Ok(AzaApp {
            identity,
            node,
            device,
            master: None,
            next: None,
            log,
            secrets: HashMap::new(),
            known_profile: None,
            known_picture: None,
            known_current: Vec::new(),
        })
    }

    /// Creates an identity: the master and its next key, the first data secret, a contact secret,
    /// and a device for this machine. `min_work` is the home node's admission price.
    pub async fn create(node: &str, label: &str, min_work: u32) -> Result<AzaApp> {
        let mut app = AzaApp::create_inner(node, Some(label), min_work).await?;
        app.write_contact_secrets(&[ContactSecret { secret: crypto::random(), generation: 1 }]).await?;
        app.save_approvals(&[]).await?;
        Ok(app)
    }

    /// Creates an identity whose master a provider holds: the master is its only device until
    /// the person's phones are added (section 8.2).
    pub async fn create_hosted(node: &str, min_work: u32) -> Result<AzaApp> {
        let mut app = AzaApp::create_inner(node, None, min_work).await?;
        app.write_contact_secrets(&[ContactSecret { secret: crypto::random(), generation: 1 }]).await?;
        app.save_approvals(&[]).await?;
        Ok(app)
    }

    async fn create_inner(node_url: &str, label: Option<&str>, min_work: u32) -> Result<AzaApp> {
        let node = NodeClient::new(node_url)?;
        let master_key = SigningKey::generate();
        let master_enc = EncKey::generate();
        let next = SigningKey::generate();
        let secret: Hash = crypto::random();
        let mut counter: u64 = 0;
        let target = min_work.max(MIN_WORK);
        let genesis = loop {
            let unsigned = Unsigned {
                identity: None,
                prev: Vec::new(),
                time: now(),
                by: None,
                body: Body::Genesis {
                    key: master_key.public().to_vec(),
                    enc: master_enc.public().to_vec(),
                    next: next.fingerprint(),
                    counter,
                    check: secret_check(&secret),
                },
            };
            if work(&unsigned.signing_bytes()) >= target {
                break unsigned.sign(&master_key);
            }
            counter += 1;
        };
        let id = genesis.hash();
        let master = Keys { id, key: master_key, enc: master_enc };
        let mut changes = vec![genesis.clone()];
        let sign = |body: Body, changes: &mut Vec<Change>| {
            let c = Unsigned {
                identity: Some(id),
                prev: vec![changes.last().unwrap().hash()],
                time: now(),
                by: Some(id),
                body,
            }
            .sign(&master.key);
            changes.push(c);
        };
        let device = match label {
            Some(label) => {
                let key = SigningKey::generate();
                let enc = EncKey::generate();
                let body =
                    Body::AddDevice { key: key.public().to_vec(), enc: enc.public().to_vec(), label: label.into() };
                sign(body, &mut changes);
                Keys { id: changes.last().unwrap().hash(), key, enc }
            }
            None => master.clone(),
        };
        sign(Body::SetHome { node: node_url.into() }, &mut changes);
        node.post_log(&id, &changes).await?;
        let log = Identity::read(id, changes)?;
        let mut app = AzaApp::with(id, node, device, log)?;
        app.master = Some(master);
        app.next = Some(next);
        app.secrets.insert(id, secret);
        app.write_secret_envelopes(&id, &secret).await?;
        Ok(app)
    }

    pub fn device(&self) -> &Keys {
        &self.device
    }

    /// Everything this aza app keeps between launches: the device's private keys, the master's
    /// and next key if this session holds them, the data secrets it has opened and the change
    /// log, encrypted under `key`. Keep `key` apart from what it encrypts.
    pub fn seal(&self, key: &StorageKey) -> Vec<u8> {
        saved::seal(key, "aza saved app v1", &self.plain())
    }

    /// An aza app saved with `seal`. Works offline: the change log it kept is read again.
    pub fn open(sealed: &[u8], key: &StorageKey) -> Result<AzaApp> {
        AzaApp::from_plain(&saved::open(key, "aza saved app v1", sealed)?)
    }

    /// The same, unencrypted, only for the operating system's keychain, which keeps it where only
    /// the aza app can read it. Never write it anywhere else.
    #[cfg(feature = "keychain")]
    pub fn save_for_keychain(&self) -> Vec<u8> {
        self.plain()
    }

    /// An aza app saved with `save_for_keychain`.
    #[cfg(feature = "keychain")]
    pub fn load_from_keychain(bytes: &[u8]) -> Result<AzaApp> {
        AzaApp::from_plain(bytes)
    }

    fn plain(&self) -> Vec<u8> {
        let keys = |k: &Keys| {
            Value::map([
                ("id", k.id.into()),
                ("key", k.key.secret().to_vec().into()),
                ("enc", k.enc.secret().to_vec().into()),
            ])
        };
        let mut m: Vec<(&str, Value)> = vec![
            ("identity", self.identity.into()),
            ("node", self.node.url.as_str().into()),
            ("device", keys(&self.device)),
            ("log", Value::Array(self.log.changes().iter().map(|c| c.to_value().clone()).collect())),
            (
                "secrets",
                Value::Array(
                    self.secrets
                        .iter()
                        .map(|(n, s)| Value::map([("name", (*n).into()), ("secret", (*s).into())]))
                        .collect(),
                ),
            ),
        ];
        if let Some(master) = &self.master {
            m.push(("master", keys(master)));
        }
        if let Some(next) = &self.next {
            m.push(("next", next.secret().to_vec().into()));
        }
        if let Some(p) = &self.known_profile {
            m.push(("profile", p.to_value().clone()));
        }
        if let Some(p) = &self.known_picture {
            m.push(("picture", p.clone().into()));
        }
        m.push(("current", Value::Array(self.known_current.iter().map(|d| (*d).into()).collect())));
        Value::map(m).to_bytes()
    }

    fn from_plain(bytes: &[u8]) -> Result<AzaApp> {
        let bad = || Error::Malformed("saved aza app");
        let v = Value::from_bytes(bytes).ok_or_else(bad)?;
        let keys = |k: &Value| -> Option<Keys> {
            Some(Keys {
                id: k.get("id")?.as_hash()?,
                key: SigningKey::from_bytes(k.get("key")?.as_bytes()?)?,
                enc: EncKey::from_bytes(k.get("enc")?.as_bytes()?)?,
            })
        };
        let identity = v.get("identity").and_then(Value::as_hash).ok_or_else(bad)?;
        let changes = v
            .get("log")
            .and_then(Value::as_array)
            .ok_or_else(bad)?
            .iter()
            .map(|c| Change::from_value(c.clone()))
            .collect::<Result<Vec<_>>>()?;
        let node = NodeClient::new(v.get("node").and_then(Value::as_text).ok_or_else(bad)?)?;
        let device = v.get("device").and_then(keys).ok_or_else(bad)?;
        let mut app = AzaApp::with(identity, node, device, Identity::read(identity, changes)?)?;
        app.master = match v.get("master") {
            None => None,
            Some(m) => Some(keys(m).ok_or_else(bad)?),
        };
        app.next = match v.get("next") {
            None => None,
            Some(n) => Some(SigningKey::from_bytes(n.as_bytes().ok_or_else(bad)?).ok_or_else(bad)?),
        };
        for s in v.get("secrets").and_then(Value::as_array).ok_or_else(bad)? {
            app.secrets.insert(
                s.get("name").and_then(Value::as_hash).ok_or_else(bad)?,
                s.get("secret").and_then(Value::as_hash).ok_or_else(bad)?,
            );
        }
        app.known_profile = match v.get("profile") {
            None => None,
            Some(p) => Some(Profile::from_value(p.clone())?),
        };
        app.known_picture = v.get("picture").and_then(Value::as_bytes).map(<[u8]>::to_vec);
        app.known_current = match v.get("current") {
            None => app.log.current_devices().iter().map(|d| d.id).collect(),
            Some(c) => {
                c.as_array().ok_or_else(bad)?.iter().map(|d| d.as_hash().ok_or_else(bad)).collect::<Result<_>>()?
            }
        };
        Ok(app)
    }

    pub fn log(&self) -> &Identity {
        &self.log
    }

    pub fn node(&self) -> &NodeClient {
        &self.node
    }

    pub fn holds_master(&self) -> bool {
        self.master.is_some()
    }

    /// The keys this app acts with: its own device while it is current, otherwise the master's
    /// if this session holds them (to repair things after this device was signed out).
    fn active(&self) -> &Keys {
        if self.log.is_current(&self.device.id) {
            return &self.device;
        }
        match &self.master {
            Some(m) if self.log.is_current(&m.id) => m,
            _ => &self.device,
        }
    }

    fn signer(&self) -> Signer {
        let k = self.active();
        Signer { identity: self.identity, by: k.id, key: k.key.clone() }
    }

    fn master_keys(&self) -> Result<&Keys> {
        self.master.as_ref().ok_or(Error::Refused("this needs the master: open its backup file".into()))
    }

    /// Downloads the newest log from the home node, following any move to another home node.
    pub async fn refresh(&mut self) -> Result<&Identity> {
        for _ in 0..4 {
            let mut changes = self.node.get_log(&self.identity).await?;
            changes.extend(self.log.changes().iter().cloned());
            self.log = Identity::read(self.identity, changes)?;
            match self.log.home() {
                Some(home) if home != self.node.url => self.node = NodeClient::new(&home)?,
                _ => break,
            }
        }
        Ok(&self.log)
    }

    /// Signs and uploads a change, after downloading the newest log so as not to leave out
    /// legitimate changes it hadn't seen yet.
    async fn sign_change(&mut self, body: Body, as_master: bool) -> Result<Change> {
        self.refresh().await?;
        if !matches!(body, Body::SignOut { .. } | Body::RemoveDevice { .. }) {
            self.log.require_readable()?;
        }
        let keys = if as_master { self.master_keys()?.clone() } else { self.device.clone() };
        let change =
            Unsigned { identity: Some(self.identity), prev: self.log.heads(), time: now(), by: Some(keys.id), body }
                .sign(&keys.key);
        self.upload(std::slice::from_ref(&change)).await?;
        Ok(change)
    }

    async fn upload(&mut self, changes: &[Change]) -> Result<()> {
        self.node.post_log(&self.identity, changes).await?;
        self.refresh().await?;
        Ok(())
    }

    // Backups.

    /// The master's keys and its next key as one backup file.
    pub fn backup_master(&self, password: &str) -> Result<Vec<u8>> {
        let m = self.master_keys()?;
        backup::write(
            &Contents {
                identity: self.identity,
                key: m.key.clone(),
                enc: m.enc.clone(),
                next: self.next.clone(),
                node: self.node.url.clone(),
            },
            password,
        )
    }

    /// This device as a backup file.
    pub fn backup_device(&self, password: &str) -> Result<Vec<u8>> {
        let d = &self.device;
        backup::write(
            &Contents {
                identity: self.identity,
                key: d.key.clone(),
                enc: d.enc.clone(),
                next: None,
                node: self.node.url.clone(),
            },
            password,
        )
    }

    /// Deletes the master's keys and next key from this machine, once they are backed up.
    pub fn forget_master(&mut self) {
        self.master = None;
        self.next = None;
    }

    /// Opens the master's backup file for this session, with its next key.
    pub async fn open_master(&mut self, file: &[u8], password: &str) -> Result<()> {
        let c = backup::open(file, password)?;
        self.refresh().await?;
        let master = self.log.master().ok_or(Error::Refused("the identity has no master".into()))?;
        if c.identity != self.identity || master.key != c.key.public() {
            return Err(Error::Refused("that backup file isn't this identity's current master".into()));
        }
        self.master = Some(Keys { id: master.id, key: c.key, enc: c.enc });
        self.next = c.next;
        Ok(())
    }

    /// Opens a master's backup file on a machine with no device, and adds the machine as a new
    /// device; the master's keys are forgotten afterwards.
    pub async fn restore(file: &[u8], password: &str, label: &str) -> Result<AzaApp> {
        let c = backup::open(file, password)?;
        let node = NodeClient::new(&c.node)?;
        let log = Identity::read(c.identity, node.get_log(&c.identity).await?)?;
        let master = log.master().ok_or(Error::Refused("the identity has no master".into()))?;
        if master.key != c.key.public() {
            return Err(Error::Refused("that backup file isn't the current master".into()));
        }
        let mkeys = Keys { id: master.id, key: c.key, enc: c.enc };
        let mut app = AzaApp::with(c.identity, node, mkeys.clone(), log)?;
        app.master = Some(mkeys);
        app.next = c.next;
        app.refresh().await?;
        let key = SigningKey::generate();
        let enc = EncKey::generate();
        let id = app.add_device_keys(key.public(), enc.public(), label, true).await?;
        app.device = Keys { id, key, enc };
        app.forget_master();
        Ok(app)
    }

    // Devices.

    async fn add_device_keys(&mut self, key: &[u8], enc: &[u8], label: &str, as_master: bool) -> Result<Hash> {
        let body = Body::AddDevice { key: key.to_vec(), enc: enc.to_vec(), label: label.into() };
        let change = self.sign_change(body, as_master).await?;
        let id = change.hash();
        if !self.log.is_current(&id) {
            return Err(Error::Refused("the new device isn't current; is the identity at 64 devices?".into()));
        }
        for name in self.log.announced_secrets() {
            if let Ok(secret) = self.data_secret(&name).await {
                let env = self.envelope(Kind::DataSecret, name, id, enc, &secret, None)?;
                self.node.post_envelopes(&self.identity, &[env], &self.signer()).await?;
            }
        }
        Ok(id)
    }

    /// Approves a new device from its pairing QR code: signs its `add-device`, seals it an
    /// envelope of the data secret, and replies telling it which identity it joined.
    pub async fn approve_pairing(&mut self, qr: &str) -> Result<Hash> {
        let (url, hash) = certificate::parse_qr_payload(qr)?;
        let keys = NodeClient::fetch_pairing(&url, &hash).await?;
        let as_master = self.device.id == self.master.as_ref().map_or([0; 32], |m| m.id);
        let id = self.add_device_keys(&keys.key, &keys.enc, &keys.label, as_master).await?;
        let reply = PairingReply { identity: self.identity, node: self.node.url.clone(), device: id };
        let sealed = crypto::seal(&keys.enc, &reply.to_value().to_bytes()).ok_or(Error::Malformed("pairing keys"))?;
        NodeClient::put_pairing_reply(&url, &sealed).await?;
        Ok(id)
    }

    /// Signs out an ordinary device; everything it signed that this device hadn't seen stops
    /// counting. Its envelopes are replaced and its tags bound again.
    ///
    /// A device may sign itself out. It can't sign anything afterwards, so the other devices
    /// replace its envelopes, tags and profile record when they next see the log (`upkeep`), and
    /// this app should then delete its keys.
    ///
    /// While this session holds the master, a device signing itself out does that work itself,
    /// as the master, so it can be the last device to leave and the master's backup file still
    /// brings everything back.
    pub async fn sign_out(&mut self, device: &Hash, endorse: Endorse) -> Result<Change> {
        self.hold_secrets().await?;
        let leaving = *device == self.device.id;
        if leaving {
            self.profile().await?;
        }
        let (root, endorsement) = self.endorsement_for(device, &endorse).await?;
        let change = self.sign_change(Body::SignOut { device: *device, endorse: root }, false).await?;
        self.attach_endorsements(&change, endorsement).await?;
        if !leaving {
            self.after_device_ended().await?;
        } else if self.master.is_some() {
            self.after_device_ended().await?;
            self.keep_profile_current().await?;
        }
        Ok(change)
    }

    /// Keeps this identity's shared state in order after changes other devices made: when a
    /// device stopped being current since this app last looked (one that signed itself out, say),
    /// writes envelopes again, binds tags again and signs the profile record again if it was
    /// that device's. Run it after `refresh` from time to time.
    pub async fn upkeep(&mut self) -> Result<()> {
        self.refresh().await?;
        if !self.log.is_current(&self.device.id) {
            return Ok(());
        }
        // The profile record readers use now, to sign again should its device leave.
        self.profile().await?;
        let current: Vec<Hash> = self.log.current_devices().iter().map(|d| d.id).collect();
        if self.known_current.iter().any(|d| !current.contains(d)) {
            self.after_device_ended().await?;
        }
        self.keep_profile_current().await?;
        self.known_current = current;
        Ok(())
    }

    /// Removes an ordinary device for good with the master, keeping its changes up to `keep`,
    /// then replaces the data secret.
    pub async fn remove_device(&mut self, device: &Hash, keep: Option<Hash>, endorse: Endorse) -> Result<Change> {
        self.master_keys()?;
        self.hold_secrets().await?;
        let (root, endorsement) = self.endorsement_for(device, &endorse).await?;
        self.refresh().await?;
        let add = self.log.change(device).ok_or(Error::NotFound("that device's add-device change".into()))?.hash();
        let mut prev = self.log.heads();
        if !prev.contains(&add) && !prev.iter().any(|h| self.log.is_ancestor(&add, h)) {
            prev.push(add);
        }
        let master = self.master_keys()?.clone();
        let change = Unsigned {
            identity: Some(self.identity),
            prev,
            time: now(),
            by: Some(master.id),
            body: Body::RemoveDevice { device: *device, keep, endorse: root },
        }
        .sign(&master.key);
        self.upload(std::slice::from_ref(&change)).await?;
        self.attach_endorsements(&change, endorsement).await?;
        self.replace_data_secret().await?;
        self.after_device_ended().await?;
        Ok(change)
    }

    /// The changes an ordinary device signed, for picking `keep` before a removal.
    pub fn changes_by(&self, device: &Hash) -> Vec<&Change> {
        self.log.changes_by(device)
    }

    /// After a device stops being current: new envelopes from secrets this device holds, and
    /// every tag bound again.
    async fn after_device_ended(&mut self) -> Result<()> {
        self.reseal().await?;
        self.bind_tags().await
    }

    pub async fn set_handle(&mut self, handle: Option<&str>) -> Result<Change> {
        if let Some(h) = handle
            && !crate::handle::is_handle(h)
        {
            return Err(Error::Malformed("handle"));
        }
        self.sign_change(Body::SetHandle { handle: handle.map(str::to_string) }, false).await
    }

    pub async fn revoke_client(&mut self, client: &Hash) -> Result<Change> {
        let change = self.sign_change(Body::RevokeClient { client: *client }, false).await?;
        let approvals: Vec<Approval> =
            self.approval_list().await?.into_iter().filter(|a| a.certificate.client_fp() != *client).collect();
        self.save_approvals(&approvals).await?;
        Ok(change)
    }

    // Data secrets and envelopes.

    fn envelope(
        &self,
        kind: Kind,
        secret: Hash,
        holder: Hash,
        enc: &[u8],
        contents: &Hash,
        generation: Option<u64>,
    ) -> Result<Envelope> {
        let k = self.active();
        Envelope::make(self.identity, kind, secret, holder, enc, contents, generation, k.id, &k.key)
    }

    /// Opens every data secret this device can, while the envelopes' signers are still current,
    /// so it can seal them again after a sign-out, removal or handoff.
    pub async fn hold_secrets(&mut self) -> Result<()> {
        self.refresh().await?;
        for name in self.log.announced_secrets() {
            let _ = self.data_secret(&name).await;
        }
        Ok(())
    }

    /// Opens a data secret from this device's envelope.
    pub async fn data_secret(&mut self, name: &Hash) -> Result<Hash> {
        if let Some(s) = self.secrets.get(name)
            && self.log.secret_check(name) == Some(secret_check(s))
        {
            return Ok(*s);
        }
        let k = self.active().clone();
        let envs = self.node.get_envelopes(&self.identity, &k.id, &self.signer()).await?;
        let s = data::open_data_secret(&envs, &self.log, &k.id, &k.enc, name)?;
        self.secrets.insert(*name, s);
        Ok(s)
    }

    async fn write_secret_envelopes(&mut self, name: &Hash, secret: &Hash) -> Result<()> {
        let mut envs = Vec::new();
        for d in self.log.current_devices() {
            envs.push(self.envelope(Kind::DataSecret, *name, d.id, &d.enc, secret, None)?);
        }
        self.node.post_envelopes(&self.identity, &envs, &self.signer()).await
    }

    /// Writes envelopes again for every current device and approved client, from the secrets
    /// this device holds, replacing any signed by devices that stopped being current.
    pub async fn reseal(&mut self) -> Result<()> {
        self.refresh().await?;
        let mut envs = Vec::new();
        let mut secrets = Vec::new();
        for name in self.log.announced_secrets() {
            if let Ok(s) = self.data_secret(&name).await {
                secrets.push((name, s));
            }
        }
        for d in self.log.current_devices() {
            for (name, s) in &secrets {
                envs.push(self.envelope(Kind::DataSecret, *name, d.id, &d.enc, s, None)?);
            }
        }
        let contacts = self.contact_secrets().await.unwrap_or_default();
        for cert in self.approvals().await? {
            if cert.check(&self.log).is_err() {
                continue;
            }
            envs.extend(self.client_envelopes(&cert, &secrets, &contacts)?);
        }
        if !envs.is_empty() {
            self.node.post_envelopes(&self.identity, &envs, &self.signer()).await?;
        }
        Ok(())
    }

    fn client_envelopes(
        &self,
        cert: &Certificate,
        secrets: &[(Hash, Hash)],
        contacts: &[ContactSecret],
    ) -> Result<Vec<Envelope>> {
        let mut envs = Vec::new();
        let Some(enc) = &cert.enc else { return Ok(envs) };
        if cert.has(READ) {
            for (name, s) in secrets {
                envs.push(self.envelope(Kind::AppKey, *name, cert.client_fp(), enc, &app_key(s, &cert.app), None)?);
            }
        }
        if cert.has(RECEIVE) {
            for c in contacts {
                let tag = contact_tag(&c.secret, &cert.app);
                envs.push(self.envelope(
                    Kind::ContactTag,
                    sha256(&c.secret),
                    cert.client_fp(),
                    enc,
                    &tag,
                    Some(c.generation),
                )?);
            }
        }
        Ok(envs)
    }

    /// Replaces the data secret with the master: announces a new one, writes envelopes for every
    /// current device and `read` client, and re-encrypts all sync data under the new app keys.
    pub async fn replace_data_secret(&mut self) -> Result<Hash> {
        let master = self.master_keys()?.clone();
        self.refresh().await?;
        let mut old = HashMap::new();
        for name in self.log.announced_secrets() {
            if let Ok(s) = self.data_secret(&name).await {
                old.insert(name, s);
            }
        }
        let secret: Hash = crypto::random();
        let change = Unsigned {
            identity: Some(self.identity),
            prev: self.log.heads(),
            time: now(),
            by: Some(master.id),
            body: Body::NewSecret { check: secret_check(&secret) },
        }
        .sign(&master.key);
        let name = change.hash();
        self.upload(&[change]).await?;
        if self.log.current_secret() != name {
            return Err(Error::Refused("the new secret wasn't applied".into()));
        }
        self.secrets.insert(name, secret);
        self.reseal().await?;
        let mut apps: Vec<String> =
            self.approvals().await?.iter().filter(|c| c.has(READ)).map(|c| c.app.clone()).collect();
        apps.push(AZA_APP.into());
        apps.sort();
        apps.dedup();
        for app in apps {
            self.reencrypt(&app, &old, &name, &secret).await?;
        }
        Ok(name)
    }

    /// Re-encrypts every item of an app's sync data still under an older secret.
    async fn reencrypt(&mut self, app: &str, old: &HashMap<Hash, Hash>, name: &Hash, secret: &Hash) -> Result<()> {
        let page = self.node.get_sync(&self.identity, app, 0, &self.signer()).await?;
        for item in latest(page.items) {
            if item.secret == *name {
                continue;
            }
            let Some(old_secret) = old.get(&item.secret) else { continue };
            let plain = item.open(&app_key(old_secret, app))?;
            let next =
                SyncItem::seal(self.identity, app, &item.name, item.version + 1, *name, &app_key(secret, app), &plain);
            self.node.put_sync(&next, &self.signer()).await?;
        }
        Ok(())
    }

    // The aza app's own sync data: approvals and contact secrets.

    async fn read_own(&mut self, name: &str) -> Result<Option<(u64, Value)>> {
        let page = self.node.get_sync(&self.identity, AZA_APP, 0, &self.signer()).await?;
        let Some(item) = latest(page.items).into_iter().find(|i| i.name == name) else { return Ok(None) };
        let secret = self.data_secret(&item.secret).await?;
        let plain = item.open(&app_key(&secret, AZA_APP))?;
        Ok(Some((item.version, Value::from_bytes(&plain).ok_or(Error::Malformed("aza app sync item"))?)))
    }

    async fn write_own(&mut self, name: &str, version: u64, value: &Value) -> Result<()> {
        let current = self.log.current_secret();
        let secret = self.data_secret(&current).await?;
        let item = SyncItem::seal(
            self.identity,
            AZA_APP,
            name,
            version,
            current,
            &app_key(&secret, AZA_APP),
            &value.to_bytes(),
        );
        self.node.put_sync(&item, &self.signer()).await
    }

    /// The certificates in effect, shared by every device through the aza app's sync data.
    pub async fn approvals(&mut self) -> Result<Vec<Certificate>> {
        Ok(self.approval_list().await?.into_iter().map(|a| a.certificate).collect())
    }

    /// The certificates in effect, each with the label its request carried.
    pub async fn approval_list(&mut self) -> Result<Vec<Approval>> {
        let certs = match self.read_own(APPROVALS).await? {
            None => Vec::new(),
            Some((_, v)) => v
                .as_array()
                .ok_or(Error::Malformed("approvals"))?
                .iter()
                .map(|c| Certificate::from_value(c.clone()))
                .collect::<Result<Vec<_>>>()?,
        };
        let labels = match self.read_own(APPROVAL_LABELS).await? {
            Some((_, Value::Map(m))) => m,
            _ => Vec::new(),
        };
        let label = |c: &Certificate| {
            let fp = c.client_fp();
            labels
                .iter()
                .find(|(k, _)| k.as_bytes() == Some(&fp[..]))
                .and_then(|(_, v)| v.as_text())
                .map(str::to_string)
        };
        Ok(certs.into_iter().map(|c| Approval { label: label(&c), certificate: c }).collect())
    }

    async fn save_approvals(&mut self, approvals: &[Approval]) -> Result<()> {
        let version = self.read_own(APPROVALS).await?.map_or(0, |(v, _)| v);
        let certs = Value::Array(approvals.iter().map(|a| a.certificate.to_value().clone()).collect());
        self.write_own(APPROVALS, version + 1, &certs).await?;
        let version = self.read_own(APPROVAL_LABELS).await?.map_or(0, |(v, _)| v);
        let labels = Value::Map(
            approvals
                .iter()
                .filter_map(|a| Some((a.certificate.client_fp().to_vec().into(), a.label.as_deref()?.into())))
                .collect(),
        )
        .sorted();
        self.write_own(APPROVAL_LABELS, version + 1, &labels).await
    }

    /// Every contact secret with its generation, oldest first.
    pub async fn contact_secrets(&mut self) -> Result<Vec<ContactSecret>> {
        let Some((_, v)) = self.read_own(CONTACT).await? else { return Ok(Vec::new()) };
        let mut list: Vec<ContactSecret> = v
            .as_array()
            .ok_or(Error::Malformed("contact secrets"))?
            .iter()
            .filter_map(|c| {
                Some(ContactSecret { secret: c.get("secret")?.as_hash()?, generation: c.get("generation")?.as_u64()? })
            })
            .collect();
        list.sort_by_key(|c| c.generation);
        Ok(list)
    }

    async fn write_contact_secrets(&mut self, list: &[ContactSecret]) -> Result<()> {
        let version = self.read_own(CONTACT).await?.map_or(0, |(v, _)| v);
        let value = Value::Array(
            list.iter()
                .map(|c| Value::map([("secret", c.secret.into()), ("generation", c.generation.into())]))
                .collect(),
        );
        self.write_own(CONTACT, version + 1, &value).await
    }

    /// The newest contact secret, to share as a QR code or link.
    pub async fn contact_secret(&mut self) -> Result<ContactSecret> {
        self.contact_secrets().await?.pop().ok_or(Error::NotFound("contact secret".into()))
    }

    /// Binds every tag of every app with a `receive` client to its app, marking each app's newest
    /// tag current, on the home node.
    pub async fn bind_tags(&mut self) -> Result<()> {
        let contacts = self.contact_secrets().await?;
        let apps = self.receive_apps().await?;
        for app in &apps {
            for c in &contacts {
                let newest = Some(c) == contacts.last();
                let tag = contact_tag(&c.secret, app);
                if !newest {
                    self.node.put_tag(&self.identity, &tag, app, false, &self.signer()).await?;
                }
            }
            if let Some(c) = contacts.last() {
                self.node.put_tag(&self.identity, &contact_tag(&c.secret, app), app, true, &self.signer()).await?;
            }
        }
        Ok(())
    }

    async fn receive_apps(&mut self) -> Result<Vec<String>> {
        let mut apps: Vec<String> =
            self.approvals().await?.iter().filter(|c| c.has(RECEIVE)).map(|c| c.app.clone()).collect();
        apps.sort();
        apps.dedup();
        Ok(apps)
    }

    /// Replaces the contact secret: commits a new one with the next generation, marks each app's
    /// new tag current, writes new tag envelopes and removes key packages under old tags.
    pub async fn replace_contact_secret(&mut self) -> Result<ContactSecret> {
        let mut list = self.contact_secrets().await?;
        let generation = list.last().map_or(1, |c| c.generation + 1);
        let new = ContactSecret { secret: crypto::random(), generation };
        list.push(new);
        self.write_contact_secrets(&list).await?;
        self.finish_contact_replacement().await?;
        Ok(new)
    }

    /// Finishes a contact secret replacement, also after one was interrupted.
    pub async fn finish_contact_replacement(&mut self) -> Result<()> {
        let list = self.contact_secrets().await?;
        self.bind_tags().await?;
        self.reseal().await?;
        let apps = self.receive_apps().await?;
        for app in &apps {
            for c in &list[..list.len().saturating_sub(1)] {
                self.node.delete_key_packages(&self.identity, &contact_tag(&c.secret, app), &self.signer()).await?;
            }
        }
        if let Some(p) = self.profile().await?
            && p.contact().is_some()
        {
            let newest = list.last().ok_or(Error::NotFound("contact secret".into()))?.secret;
            self.update_profile(|f| f.with("contact", newest.into())).await?;
        }
        Ok(())
    }

    // Certificates.

    /// Approves a certificate request: signs the certificate, adds it to the approvals, and
    /// writes the client's envelopes.
    pub async fn approve(&mut self, request: &Request) -> Result<Certificate> {
        request.validate()?;
        self.refresh().await?;
        self.log.require_readable()?;
        let mut approvals = self.approval_list().await?;
        approvals.retain(|a| a.certificate.check(&self.log).is_ok());
        if approvals.len() >= MAX_APPROVALS {
            return Err(Error::Refused("64 approvals are already in effect".into()));
        }
        let home = self.log.home().ok_or(Error::NotFound("home node".into()))?;
        let grant = Grant {
            identity: self.identity,
            node: home,
            app: request.app.clone(),
            client: request.client.clone(),
            enc: request.enc.clone(),
            scopes: request.scopes.clone(),
        };
        let cert = Certificate::sign(grant, now(), self.device.id, &self.device.key)?;
        approvals.push(Approval { certificate: cert.clone(), label: request.label.clone() });
        self.save_approvals(&approvals).await?;
        let mut secrets = Vec::new();
        for name in self.log.announced_secrets() {
            if let Ok(s) = self.data_secret(&name).await {
                secrets.push((name, s));
            }
        }
        let contacts = self.contact_secrets().await?;
        let envs = self.client_envelopes(&cert, &secrets, &contacts)?;
        if !envs.is_empty() {
            self.node.post_envelopes(&self.identity, &envs, &self.signer()).await?;
        }
        if cert.has(RECEIVE) {
            self.bind_tags().await?;
        }
        Ok(cert)
    }

    /// The same-machine path: approves `aza:approve#req=…` and returns the return URL with the
    /// certificate appended, for the operating system to open.
    pub async fn approve_url(&mut self, url: &str) -> Result<String> {
        let request = Request::from_approve_url(url)?;
        let cert = self.approve(&request).await?;
        Ok(certificate::return_with_certificate(&request.return_url, &cert))
    }

    /// The request a QR code from another machine names: fetched from the app's well-known URL
    /// and checked against the QR code's hash and the app it names.
    pub async fn qr_request(qr: &str) -> Result<Request> {
        let (url, hash) = certificate::parse_qr_payload(qr)?;
        let parsed = url::Url::parse(&url).map_err(|_| Error::Malformed("request URL"))?;
        if parsed.scheme() != "https" || !parsed.path().starts_with("/.well-known/aza/request/") {
            return Err(Error::Refused("request URL isn't an app's well-known request".into()));
        }
        let bytes = reqwest::get(&url).await?.error_for_status()?.bytes().await?;
        if sha256(&bytes) != hash {
            return Err(Error::Refused("request doesn't match the QR code".into()));
        }
        let request = Request::from_value(&Value::from_bytes(&bytes).ok_or(Error::Malformed("request"))?)?;
        if parsed.host_str() != Some(request.app.as_str()) {
            return Err(Error::Refused("request isn't hosted by its app".into()));
        }
        Ok(request)
    }

    /// The other-machine path: fetches the request the QR code names (`qr_request`), approves it
    /// and posts the certificate to its return URL.
    pub async fn approve_qr(&mut self, qr: &str) -> Result<Certificate> {
        let request = Self::qr_request(qr).await?;
        let cert = self.approve(&request).await?;
        reqwest::Client::new()
            .post(&request.return_url)
            .header("content-type", "application/cbor")
            .body(cert.to_bytes())
            .send()
            .await?
            .error_for_status()?;
        Ok(cert)
    }

    // Profile.

    /// The profile record readers use.
    pub async fn profile(&mut self) -> Result<Option<Profile>> {
        let records = self.node.get_profile(&self.identity).await?;
        let p = profile::choose(&records, &self.log).cloned();
        if p.is_some() {
            self.known_profile = p.clone();
        }
        Ok(p)
    }

    /// Signs a new profile version with this device, starting from the record readers use.
    pub async fn update_profile(&mut self, edit: impl FnOnce(Value) -> Value) -> Result<Profile> {
        self.refresh().await?;
        let records = self.node.get_profile(&self.identity).await?;
        let base = profile::choose(&records, &self.log).or(self.known_profile.as_ref());
        let fields = edit(base.map_or_else(|| Value::Map(Vec::new()), |p| p.fields.clone()));
        let version = records
            .iter()
            .filter(|p| p.signature_valid(&self.log) && self.log.is_current(&p.by))
            .map(|p| p.version)
            .chain(base.map(|p| p.version))
            .max()
            .unwrap_or(0)
            + 1;
        let k = self.active().clone();
        let p = Profile::sign(self.identity, version, fields, k.id, &k.key)?;
        self.node.put_profile(&p, &self.signer()).await?;
        self.known_profile = Some(p.clone());
        Ok(p)
    }

    pub async fn set_name(&mut self, name: &str) -> Result<Profile> {
        if name.chars().count() > 64 {
            return Err(Error::Refused("a name is at most 64 characters".into()));
        }
        self.update_profile(|f| f.with("name", name.into())).await
    }

    pub async fn set_picture(&mut self, image: &[u8], r#type: &str) -> Result<Profile> {
        if image.len() > profile::MAX_PICTURE || !profile::PICTURE_TYPES.contains(&r#type) {
            return Err(Error::Refused("pictures are PNG, JPEG, WebP or AVIF up to 256 KiB".into()));
        }
        let hash = self.node.put_blob(&self.identity, image, &self.signer()).await?;
        self.known_picture = Some(image.to_vec());
        let pic = Picture { hash, r#type: r#type.into(), size: image.len() as u64 };
        self.update_profile(|f| f.with("picture", pic.to_value())).await
    }

    /// Publishes (or withdraws) the contact secret in the profile.
    pub async fn publish_contact(&mut self, publish: bool) -> Result<Profile> {
        let secret = self.contact_secret().await?.secret;
        self.update_profile(|f| if publish { f.with("contact", secret.into()) } else { f.without("contact") }).await
    }

    /// If the record readers use was signed by a device that is no longer current, signs it again
    /// with this device.
    pub async fn keep_profile_current(&mut self) -> Result<()> {
        self.refresh().await?;
        let records = self.node.get_profile(&self.identity).await?;
        let in_use = profile::choose(&records, &self.log);
        let stale = match (&self.known_profile, in_use) {
            (Some(known), None) => !self.log.is_current(&known.by),
            (Some(known), Some(used)) => known.version > used.version,
            _ => false,
        };
        if stale {
            self.update_profile(|f| f).await?;
        }
        // Each device keeps a copy of the picture and uploads it again if it's missing.
        if let (Some(p), Some(image)) =
            (self.known_profile.as_ref().and_then(Profile::picture), self.known_picture.clone())
            && p.matches(&image, &p.r#type)
            && self.node.get_blob(&self.identity, &p.hash).await?.is_none()
        {
            self.node.put_blob(&self.identity, &image, &self.signer()).await?;
        }
        Ok(())
    }

    /// Re-encrypts any sync item still under an older data secret, for example after an
    /// interrupted replacement.
    pub async fn reencrypt_stale(&mut self) -> Result<()> {
        self.hold_secrets().await?;
        let current = self.log.current_secret();
        let secret = self.data_secret(&current).await?;
        let old: HashMap<Hash, Hash> = self.secrets.clone();
        let mut apps: Vec<String> =
            self.approvals().await?.iter().filter(|c| c.has(READ)).map(|c| c.app.clone()).collect();
        apps.push(AZA_APP.into());
        apps.sort();
        apps.dedup();
        for app in apps {
            self.reencrypt(&app, &old, &current, &secret).await?;
        }
        Ok(())
    }

    // Endorsements.

    /// Builds the endorsement for records made through `device`'s approvals.
    async fn endorsement_for(
        &mut self,
        device: &Hash,
        policy: &Endorse,
    ) -> Result<(Option<Hash>, Option<(Endorsement, Vec<Record>)>)> {
        let Endorse::AllExcept(leave_out) = policy else { return Ok((None, None)) };
        let mut apps: Vec<String> =
            self.approvals().await?.iter().filter(|c| c.has(PUBLISH)).map(|c| c.app.clone()).collect();
        apps.sort();
        apps.dedup();
        let mut kept: BTreeMap<(String, String), Record> = BTreeMap::new();
        for app in apps {
            let page = self.node.get_records(&self.identity, &app, 0).await?;
            for r in page.items {
                if r.certificate.by != *device || leave_out.contains(&r.leaf()) || r.identity != self.identity {
                    continue;
                }
                let key = (r.app.clone(), r.name.clone());
                if kept.get(&key).is_none_or(|k| k.version < r.version) {
                    kept.insert(key, r);
                }
            }
        }
        if kept.is_empty() {
            return Ok((None, None));
        }
        let records: Vec<Record> = kept.into_values().collect();
        let tree = Endorsement::new(records.iter().map(Record::leaf).collect());
        Ok((Some(tree.root()), Some((tree, records))))
    }

    async fn attach_endorsements(
        &mut self,
        change: &Change,
        endorsement: Option<(Endorsement, Vec<Record>)>,
    ) -> Result<()> {
        let Some((tree, records)) = endorsement else { return Ok(()) };
        for r in records {
            if let Some(proof) = tree.proof(&r.leaf(), change.hash()) {
                self.node.put_endorsed(&r, &proof, &self.signer()).await?;
            }
        }
        Ok(())
    }

    // The master role.

    /// Hands the master role on with the next key: brings in fresh master keys and a fresh next
    /// key. `disowned` lists changes signed with a stolen master key; everything descending from
    /// them is left out of `prev`. Replaces the data and contact secrets afterwards.
    pub async fn hand_off(&mut self, disowned: &[Hash], endorse: Endorse) -> Result<(Keys, SigningKey)> {
        let next = self.next.clone().ok_or(Error::Refused("this needs the next key: open its backup file".into()))?;
        self.hold_secrets().await?;
        if self.log.master_next() != Some(next.fingerprint()) {
            return Err(Error::Refused("that isn't the current master's next key".into()));
        }
        let old_master = self.log.master().ok_or(Error::Refused("the identity has no master".into()))?.id;
        let (root, endorsement) = self.endorsement_for(&old_master, &endorse).await?;
        let key = SigningKey::generate();
        let enc = EncKey::generate();
        let new_next = SigningKey::generate();
        let unsigned = Unsigned {
            identity: Some(self.identity),
            prev: self.log.heads_excluding(disowned),
            time: now(),
            by: None,
            body: Body::SetMaster {
                reveal: next.public().to_vec(),
                key: key.public().to_vec(),
                enc: enc.public().to_vec(),
                next: new_next.fingerprint(),
                endorse: root,
            },
        };
        let change = unsigned.sign(&next);
        self.upload(std::slice::from_ref(&change)).await?;
        let master = Keys { id: change.device_id(), key, enc };
        if self.log.master().map(|m| m.id) != Some(master.id) {
            return Err(Error::Conflict(
                "the handoff didn't become the next link; was the next key used before?".into(),
            ));
        }
        if self.device.id == old_master {
            self.device = master.clone();
        }
        self.master = Some(master.clone());
        self.next = Some(new_next.clone());
        self.attach_endorsements(&change, endorsement).await?;
        self.replace_data_secret().await?;
        self.replace_contact_secret().await?;
        Ok((master, new_next))
    }

    /// Takes control of an identity a provider hosts (section 8.2). `recognised` decides which
    /// current devices the person keeps; the rest are removed with the new master.
    pub async fn take_control(
        &mut self,
        provider: &impl HandoffSigner,
        recognised: impl Fn(&Device) -> bool,
    ) -> Result<TookControl> {
        self.hold_secrets().await?;
        let next_public = provider.next_public_key(&self.identity)?;
        if self.log.master_next() != Some(fingerprint(&next_public)) {
            return Err(Error::Refused("the provider's next key doesn't match the master's next".into()));
        }
        let provider_master = self.log.master().ok_or(Error::Refused("the identity has no master".into()))?.id;
        let before = self.log.current_ordinary_devices();
        let key = SigningKey::generate();
        let enc = EncKey::generate();
        let new_next = SigningKey::generate();
        let unsigned = Unsigned {
            identity: Some(self.identity),
            prev: self.log.heads(),
            time: now(),
            by: None,
            body: Body::SetMaster {
                reveal: next_public.clone(),
                key: key.public().to_vec(),
                enc: enc.public().to_vec(),
                next: new_next.fingerprint(),
                endorse: None,
            },
        };
        let change = provider.sign_handoff(&self.identity, &unsigned)?;
        if change.signing_bytes() != unsigned.signing_bytes() || !change.verify_with(&next_public) {
            return Err(Error::Refused("the provider signed a different handoff".into()));
        }
        // If the provider already published a handoff to these keys with a different prev, that
        // one is the link: uploading ours as well would be a master conflict.
        self.refresh().await?;
        if self.log.master().is_none_or(|m| m.key != key.public()) {
            self.upload(std::slice::from_ref(&change)).await?;
        }
        let link = self
            .log
            .master()
            .filter(|m| m.key == key.public())
            .ok_or(Error::Conflict("the handoff didn't become the next link".into()))?;
        let master = Keys { id: link.id, key, enc };
        self.master = Some(master.clone());
        self.next = Some(new_next.clone());
        let differing = if link.id == change.device_id() {
            Vec::new()
        } else {
            self.differing_master_changes(&provider_master, &unsigned.prev, &link.id)
        };
        // Devices whose additions the provider left out of the handoff's prev are discarded; the
        // new master removes each for good and this machine joins again with new keys.
        let mut lost = Vec::new();
        for d in &before {
            if !self.log.is_current(&d.id) {
                self.remove_with_add_in_prev(&d.id).await?;
                lost.push(d.clone());
            }
        }
        if !self.log.is_current(&self.device.id) {
            let label =
                before.iter().find(|d| d.id == self.device.id).and_then(|d| d.label.clone()).unwrap_or_default();
            let (key, enc) = (SigningKey::generate(), EncKey::generate());
            let id = self.add_device_keys(key.public(), enc.public(), &label, true).await?;
            self.device = Keys { id, key, enc };
            lost.retain(|d| d.label.as_deref() != Some(label.as_str()));
        }
        let mut removed = Vec::new();
        for d in self.log.current_ordinary_devices() {
            if d.id != self.device.id && !recognised(&d) {
                self.remove_with_add_in_prev(&d.id).await?;
                removed.push(d.id);
            }
        }
        self.replace_data_secret().await?;
        self.replace_contact_secret().await?;
        let provider_approvals = self.approvals().await?.into_iter().filter(|c| c.by == provider_master).collect();
        Ok(TookControl { master, next: new_next, provider_approvals, removed, lost, differing })
    }

    /// Removes a device with the master, with its `add-device` change in `prev`.
    async fn remove_with_add_in_prev(&mut self, device: &Hash) -> Result<()> {
        let master = self.master_keys()?.clone();
        let mut prev = self.log.heads();
        if self.log.change(device).is_some() && !prev.iter().any(|h| h == device || self.log.is_ancestor(device, h)) {
            prev.push(*device);
        }
        let change = Unsigned {
            identity: Some(self.identity),
            prev,
            time: now(),
            by: Some(master.id),
            body: Body::RemoveDevice { device: *device, keep: None, endorse: None },
        }
        .sign(&master.key);
        self.upload(&[change]).await
    }

    /// Master changes of the outgoing master that the published handoff treats differently from
    /// the one asked for: left out of its ancestors, or slipped in.
    fn differing_master_changes(&self, old_master: &Hash, asked_prev: &[Hash], link: &Hash) -> Vec<Hash> {
        let in_asked = |h: &Hash| asked_prev.iter().any(|p| p == h || self.log.is_ancestor(h, p));
        let link_change = self.log.changes().iter().find(|c| c.device_id() == *link).map(Change::hash);
        let in_link = |h: &Hash| link_change.is_some_and(|l| self.log.is_ancestor(h, &l));
        self.log
            .changes()
            .iter()
            .filter(|c| c.by.as_ref() == Some(old_master) || c.hash() == *old_master)
            .map(Change::hash)
            .filter(|h| in_asked(h) != in_link(h))
            .collect()
    }

    /// The current master's next public key, for a provider to hand to a person taking control.
    pub fn next_public_key(&self) -> Result<Vec<u8>> {
        Ok(self.next.as_ref().ok_or(Error::Refused("this session doesn't hold the next key".into()))?.public().to_vec())
    }

    /// Signs a handoff exactly as asked, revealing the next key. Each next key signs one handoff.
    pub fn sign_handoff(&mut self, unsigned: &Unsigned) -> Result<Change> {
        let next = self.next.take().ok_or(Error::Refused("this session doesn't hold the next key".into()))?;
        match &unsigned.body {
            Body::SetMaster { reveal, .. } if *reveal == next.public() && unsigned.identity == Some(self.identity) => {}
            _ => {
                self.next = Some(next);
                return Err(Error::Refused("that isn't a handoff revealing this next key".into()));
            }
        }
        self.master = None;
        Ok(unsigned.clone().sign(&next))
    }

    // Moving.

    /// Moves everything to a new home node, then signs a `set-home` and uploads it to both.
    pub async fn move_home(&mut self, new_node: &str) -> Result<Change> {
        let target = NodeClient::new(new_node)?;
        self.refresh().await?;
        let export = self.node.get_export(&self.identity, &self.signer()).await?;
        target.post_import(&self.identity, &export, &self.signer()).await?;
        let old = std::mem::replace(&mut self.node, target);
        self.bind_tags().await?;
        let change = Unsigned {
            identity: Some(self.identity),
            prev: self.log.heads(),
            time: now(),
            by: Some(self.device.id),
            body: Body::SetHome { node: new_node.into() },
        }
        .sign(&self.device.key);
        old.post_log(&self.identity, std::slice::from_ref(&change)).await?;
        self.upload(std::slice::from_ref(&change)).await?;
        Ok(change)
    }

    // Contact requests.

    /// Contact requests waiting in the requests inbox, checked against each sender's log.
    pub async fn contact_requests(&mut self) -> Result<Vec<(Hash, ContactRequest)>> {
        let page = self.node.get_inbox(&self.identity, Inbox::Requests, &self.device.id, 0, &self.signer()).await?;
        let mut out = Vec::new();
        for item in page.items {
            let Some(plain) = self.device.enc.open(&item.sealed) else { continue };
            let Some(v) = Value::from_bytes(&plain) else { continue };
            let Ok(req) = ContactRequest::from_value(v) else { continue };
            let Ok(sender_node) = NodeClient::new(&req.node) else { continue };
            let Ok(changes) = sender_node.get_log(&req.identity).await else { continue };
            let Ok(sender) = Identity::read(req.identity, changes) else { continue };
            if req.check(&sender, &self.identity, now()).is_ok() {
                out.push((item.hash(), req));
            }
        }
        Ok(out)
    }

    /// Accepts a contact request: sends the requesting client this identity's newest tag for the
    /// app, sealed to its encryption key, through the sender's own inbox.
    pub async fn accept_contact_request(&mut self, item: &Hash, req: &ContactRequest) -> Result<()> {
        let c = self.contact_secret().await?;
        let tag = contact_tag(&c.secret, &req.app);
        let acceptance =
            Acceptance::sign(self.identity, &req.app, tag, c.generation, req.time, self.device.id, &self.device.key)?;
        let enc = req.certificate.enc.as_ref().ok_or(Error::Malformed("contact request certificate"))?;
        let inbox_item = InboxItem::seal(req.certificate.client_fp(), enc, &acceptance.to_value().to_bytes())?;
        NodeClient::new(&req.node)?.post_inbox(&req.identity, Inbox::Tag(req.tag), &inbox_item).await?;
        self.node.delete_inbox(&self.identity, Inbox::Requests, &self.device.id, item, &self.signer()).await
    }

    pub async fn decline_contact_request(&mut self, item: &Hash) -> Result<()> {
        self.node.delete_inbox(&self.identity, Inbox::Requests, &self.device.id, item, &self.signer()).await
    }
}

/// Keeps only the newest version of each item name.
pub(crate) fn latest(items: Vec<SyncItem>) -> Vec<SyncItem> {
    let mut best: BTreeMap<String, SyncItem> = BTreeMap::new();
    for i in items {
        if best.get(&i.name).is_none_or(|b| b.version < i.version) {
            best.insert(i.name.clone(), i);
        }
    }
    best.into_values().collect()
}
