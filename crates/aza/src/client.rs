//! A client: one program acting for an identity inside an app (section 7). It holds its own
//! client key, never a device key, and gets permission through a certificate.
use crate::Value;
use crate::certificate::{self, Certificate, PUBLISH, READ, RECEIVE, Request, WRITE, sign_in_message};
use crate::change::now;
use crate::crypto::{EncKey, Hash, SigningKey};
use crate::data::{self, SyncItem};
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::message::{Acceptance, ContactRequest, Credential, InboxItem, KeyPackage};
use crate::node::{Inbox, NodeClient, Signer};
use crate::record::{self, Record};
use crate::saved::{self, StorageKey};

/// Fetches an identity's log starting from a node, then from the home node its latest `set-home`
/// names, if different.
pub async fn fetch_identity(node: &str, identity: &Hash) -> Result<(Identity, NodeClient)> {
    let mut client = NodeClient::new(node)?;
    let mut changes = Vec::new();
    for _ in 0..4 {
        changes.extend(client.get_log(identity).await?);
        let log = Identity::read(*identity, changes.clone())?;
        match log.home() {
            Some(home) if home != client.url => client = NodeClient::new(&home)?,
            _ => return Ok((log, client)),
        }
    }
    Err(Error::Refused("too many moves between home nodes".into()))
}

/// A sync item, decrypted.
#[derive(Clone, Debug, PartialEq)]
pub struct Item {
    pub name: String,
    pub version: u64,
    pub data: Vec<u8>,
}

/// A message in a client's inbox, decrypted.
#[derive(Clone, Debug)]
pub struct Message {
    pub inbox: Inbox,
    /// The hash of the stored item, for deleting it once handled.
    pub item: Hash,
    pub plaintext: Vec<u8>,
}

/// A contact request this client sent and hasn't seen accepted yet.
#[derive(Clone, Debug)]
pub struct SentRequest {
    pub recipient: Hash,
    pub app: String,
    pub time: u64,
}

pub struct Client {
    pub app: String,
    key: SigningKey,
    enc: Option<EncKey>,
    certificate: Option<Certificate>,
    node: Option<NodeClient>,
    log: Option<Identity>,
    sync_counter: u64,
    sent: Vec<SentRequest>,
}

impl Client {
    /// Makes a client key (and an encryption key if the scopes need one) and the request for a
    /// certificate. `return_url` must be on `https://<app>`.
    pub fn new(app: &str, scopes: &[&str], return_url: &str) -> Result<(Client, Request)> {
        Client::with_label(app, scopes, return_url, None)
    }

    /// `new`, with a name for this machine the aza app shows while approving (`Request::label`).
    pub fn with_label(app: &str, scopes: &[&str], return_url: &str, label: Option<&str>) -> Result<(Client, Request)> {
        let key = SigningKey::generate();
        let needs_enc = scopes.iter().any(|s| *s == READ || *s == RECEIVE);
        let enc = needs_enc.then(EncKey::generate);
        let request = Request {
            app: app.into(),
            client: key.public().to_vec(),
            enc: enc.as_ref().map(|e| e.public().to_vec()),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            return_url: return_url.into(),
            label: label.map(str::to_string),
        };
        request.validate()?;
        let client = Client {
            app: app.into(),
            key,
            enc,
            certificate: None,
            node: None,
            log: None,
            sync_counter: 0,
            sent: Vec::new(),
        };
        Ok((client, request))
    }

    pub fn fingerprint(&self) -> Hash {
        self.key.fingerprint()
    }

    /// Everything this client keeps between launches, its private keys and app key included,
    /// encrypted under `key`. Keep `key` apart from what it encrypts.
    pub fn seal(&self, key: &StorageKey) -> Vec<u8> {
        saved::seal(key, "aza saved client v1", &self.plain())
    }

    /// A client saved with `seal`. Works offline: the change log it kept is read again.
    pub fn open(sealed: &[u8], key: &StorageKey) -> Result<Client> {
        Client::from_plain(&saved::open(key, "aza saved client v1", sealed)?)
    }

    /// The same, unencrypted, only for the operating system's keychain, which keeps it where only
    /// this app can read it. Never write it anywhere else.
    #[cfg(feature = "keychain")]
    pub fn save_for_keychain(&self) -> Vec<u8> {
        self.plain()
    }

    /// A client saved with `save_for_keychain`.
    #[cfg(feature = "keychain")]
    pub fn load_from_keychain(bytes: &[u8]) -> Result<Client> {
        Client::from_plain(bytes)
    }

    fn plain(&self) -> Vec<u8> {
        let mut m: Vec<(&str, Value)> = vec![
            ("app", self.app.as_str().into()),
            ("key", self.key.secret().to_vec().into()),
            ("counter", self.sync_counter.into()),
            (
                "sent",
                Value::Array(
                    self.sent
                        .iter()
                        .map(|r| {
                            Value::map([
                                ("recipient", r.recipient.into()),
                                ("app", r.app.as_str().into()),
                                ("time", r.time.into()),
                            ])
                        })
                        .collect(),
                ),
            ),
        ];
        if let Some(enc) = &self.enc {
            m.push(("enc", enc.secret().to_vec().into()));
        }
        if let Some(cert) = &self.certificate {
            m.push(("certificate", cert.to_value().clone()));
        }
        if let Some(node) = &self.node {
            m.push(("node", node.url.as_str().into()));
        }
        if let Some(log) = &self.log {
            m.push(("log", Value::Array(log.changes().iter().map(|c| c.to_value().clone()).collect())));
        }
        Value::map(m).to_bytes()
    }

    fn from_plain(bytes: &[u8]) -> Result<Client> {
        let bad = || Error::Malformed("saved client");
        let v = Value::from_bytes(bytes).ok_or_else(bad)?;
        let certificate = match v.get("certificate") {
            None => None,
            Some(c) => Some(Certificate::from_value(c.clone())?),
        };
        let log = match (v.get("log"), &certificate) {
            (Some(l), Some(cert)) => {
                let changes = l
                    .as_array()
                    .ok_or_else(bad)?
                    .iter()
                    .map(|c| crate::change::Change::from_value(c.clone()))
                    .collect::<Result<Vec<_>>>()?;
                Some(Identity::read(cert.identity, changes)?)
            }
            _ => None,
        };
        Ok(Client {
            app: v.get("app").and_then(Value::as_text).ok_or_else(bad)?.to_string(),
            key: SigningKey::from_bytes(v.get("key").and_then(Value::as_bytes).ok_or_else(bad)?).ok_or_else(bad)?,
            enc: match v.get("enc") {
                None => None,
                Some(e) => Some(EncKey::from_bytes(e.as_bytes().ok_or_else(bad)?).ok_or_else(bad)?),
            },
            certificate,
            node: match v.get("node") {
                None => None,
                Some(n) => Some(NodeClient::new(n.as_text().ok_or_else(bad)?)?),
            },
            log,
            sync_counter: v.get("counter").and_then(Value::as_u64).ok_or_else(bad)?,
            sent: v
                .get("sent")
                .and_then(Value::as_array)
                .ok_or_else(bad)?
                .iter()
                .map(|r| {
                    Some(SentRequest {
                        recipient: r.get("recipient")?.as_hash()?,
                        app: r.get("app")?.as_text()?.to_string(),
                        time: r.get("time")?.as_u64()?,
                    })
                })
                .collect::<Option<Vec<_>>>()
                .ok_or_else(bad)?,
        })
    }

    /// The change log as this client last read it, if it has one.
    pub fn log(&self) -> Option<&Identity> {
        self.log.as_ref()
    }

    pub fn certificate(&self) -> Option<&Certificate> {
        self.certificate.as_ref()
    }

    pub fn identity(&self) -> Result<Hash> {
        Ok(self.cert()?.identity)
    }

    fn cert(&self) -> Result<&Certificate> {
        self.certificate.as_ref().ok_or(Error::Refused("this client has no certificate yet".into()))
    }

    fn node(&self) -> Result<&NodeClient> {
        self.node.as_ref().ok_or(Error::Refused("this client has no certificate yet".into()))
    }

    /// Signs this client's own requests to the identity's home node.
    pub fn signer(&self) -> Result<Signer> {
        Ok(Signer { identity: self.identity()?, by: self.fingerprint(), key: self.key.clone() })
    }

    /// Takes the certificate returned by the aza app (`#aza=…` on the return URL), checks it is
    /// for this client's key and app, and uploads it to the identity's home node.
    pub async fn receive_certificate_url(&mut self, url: &str) -> Result<()> {
        self.receive_certificate(certificate::certificate_from_return_url(url)?).await
    }

    pub async fn receive_certificate(&mut self, cert: Certificate) -> Result<()> {
        if cert.client != self.key.public() || cert.app != self.app {
            return Err(Error::Refused("certificate isn't for this client".into()));
        }
        let (log, node) = fetch_identity(&cert.node, &cert.identity).await?;
        cert.check(&log)?;
        let signer = Signer { identity: cert.identity, by: self.fingerprint(), key: self.key.clone() };
        node.post_certificate(&cert, &signer).await?;
        self.certificate = Some(cert);
        self.node = Some(node);
        self.log = Some(log);
        Ok(())
    }

    /// Reads the identity's newest log from its home node.
    pub async fn refresh(&mut self) -> Result<&Identity> {
        let cert = self.cert()?.clone();
        let (log, node) = fetch_identity(&self.node()?.url, &cert.identity).await?;
        self.node = Some(node);
        self.log = Some(log);
        Ok(self.log.as_ref().unwrap())
    }

    /// Signs a sign-in challenge from the app (check 5 of section 7).
    pub fn sign_in(&self, challenge: &[u8; 32]) -> Result<(Certificate, Vec<u8>)> {
        let cert = self.cert()?;
        Ok((cert.clone(), self.key.sign(&sign_in_message(&self.app, &cert.identity, challenge))))
    }

    // Sync data.

    async fn app_key_for(&mut self, secret: &Hash) -> Result<Hash> {
        let enc = self.enc.clone().ok_or(Error::Refused("this client can't read".into()))?;
        let id = self.identity()?;
        let fp = self.fingerprint();
        if self.log.is_none() {
            self.refresh().await?;
        }
        let envs = self.node()?.get_envelopes(&id, &fp, &self.signer()?).await?;
        let log = self.log.as_ref().ok_or(Error::Refused("no log".into()))?;
        data::open_app_key(&envs, log, &fp, &enc, secret)
    }

    /// Every item of this app's sync data, decrypted, newest version of each name.
    pub async fn read_all(&mut self) -> Result<Vec<Item>> {
        self.refresh().await?;
        let id = self.identity()?;
        let page = self.node()?.get_sync(&id, &self.app, 0, &self.signer()?).await?;
        self.sync_counter = page.counter;
        let mut out = Vec::new();
        for item in crate::aza_app::latest(page.items) {
            let key = self.app_key_for(&item.secret).await?;
            out.push(Item { name: item.name.clone(), version: item.version, data: item.open(&key)? });
        }
        Ok(out)
    }

    /// Items stored or changed since the last read.
    pub async fn read_changes(&mut self) -> Result<Vec<Item>> {
        let id = self.identity()?;
        let page = self.node()?.get_sync(&id, &self.app, self.sync_counter, &self.signer()?).await?;
        self.sync_counter = page.counter;
        let mut out = Vec::new();
        for item in page.items {
            let key = self.app_key_for(&item.secret).await?;
            out.push(Item { name: item.name.clone(), version: item.version, data: item.open(&key)? });
        }
        Ok(out)
    }

    /// Stores one item as `version`, which must be exactly one more than the stored version.
    pub async fn write(&mut self, name: &str, version: u64, data: &[u8]) -> Result<()> {
        if !self.cert()?.has(WRITE) {
            return Err(Error::Refused("this client can't write".into()));
        }
        self.refresh().await?;
        let secret = self.log.as_ref().unwrap().current_secret();
        let key = self.app_key_for(&secret).await?;
        let item = SyncItem::seal(self.identity()?, &self.app, name, version, secret, &key, data);
        self.node()?.put_sync(&item, &self.signer()?).await
    }

    /// Writes an item, merging with whatever another client stored first: `merge` gets the
    /// stored data (if any) and returns what to store.
    pub async fn update(&mut self, name: &str, merge: impl Fn(Option<&[u8]>) -> Vec<u8>) -> Result<u64> {
        for _ in 0..8 {
            let current = self.read_all().await?.into_iter().find(|i| i.name == name);
            let version = current.as_ref().map_or(1, |i| i.version + 1);
            let data = merge(current.as_ref().map(|i| i.data.as_slice()));
            match self.write(name, version, &data).await {
                Ok(()) => return Ok(version),
                Err(Error::Node { status: 409, .. }) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(Error::Conflict("too many concurrent writes".into()))
    }

    // Public records.

    /// Every version of this app's public records for the identity.
    pub async fn records(&mut self) -> Result<Vec<Record>> {
        let id = self.identity()?;
        Ok(self.node()?.get_records(&id, &self.app, 0).await?.items)
    }

    /// Publishes a record, or with `content` of `None`, a tombstone deleting it.
    pub async fn publish(&mut self, name: &str, content: Option<Value>) -> Result<Record> {
        let cert = self.cert()?.clone();
        if !cert.has(PUBLISH) {
            return Err(Error::Refused("this client can't publish".into()));
        }
        let version = self.records().await?.iter().filter(|r| r.name == name).map(|r| r.version).max().unwrap_or(0) + 1;
        let record = Record::sign(&cert, name, version, content, &self.key)?;
        self.node()?.put_record(&record, &self.signer()?).await?;
        Ok(record)
    }

    // Contact tags, registrations, key packages and the inbox.

    /// The contact tags this client holds for its app, newest generation first.
    pub async fn contact_tags(&mut self) -> Result<Vec<(Hash, u64)>> {
        let enc = self.enc.clone().ok_or(Error::Refused("this client can't receive".into()))?;
        self.refresh().await?;
        let id = self.identity()?;
        let fp = self.fingerprint();
        let envs = self.node()?.get_envelopes(&id, &fp, &self.signer()?).await?;
        Ok(data::open_contact_tags(&envs, self.log.as_ref().unwrap(), &fp, &enc))
    }

    /// Registers under every tag this client holds.
    pub async fn register(&mut self) -> Result<()> {
        let cert = self.cert()?.clone();
        for (tag, _) in self.contact_tags().await? {
            self.node()?.put_registration(&cert.identity, &tag, &cert, &self.signer()?).await?;
        }
        Ok(())
    }

    /// Publishes key packages under the newest tag. Each entry is an MLS signature key and the
    /// MLS key package that uses it.
    pub async fn publish_key_packages(&mut self, packages: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
        let cert = self.cert()?.clone();
        let (tag, _) = *self.contact_tags().await?.first().ok_or(Error::NotFound("contact tag".into()))?;
        let pkgs: Vec<KeyPackage> = packages
            .iter()
            .map(|(k, p)| KeyPackage { credential: Credential::sign(&cert, k, &self.key), package: p.clone() })
            .collect();
        self.node()?.post_key_packages(&cert.identity, &tag, &pkgs, &self.signer()?).await
    }

    /// Reads the inbox under every tag this client holds, registering again where a
    /// registration has gone.
    pub async fn inbox(&mut self) -> Result<Vec<Message>> {
        self.register().await?;
        let enc = self.enc.clone().ok_or(Error::Refused("this client can't receive".into()))?;
        let id = self.identity()?;
        let fp = self.fingerprint();
        let mut out = Vec::new();
        for (tag, _) in self.contact_tags().await? {
            let page = self.node()?.get_inbox(&id, Inbox::Tag(tag), &fp, 0, &self.signer()?).await?;
            for item in page.items {
                if let Some(plaintext) = enc.open(&item.sealed) {
                    out.push(Message { inbox: Inbox::Tag(tag), item: item.hash(), plaintext });
                }
            }
        }
        Ok(out)
    }

    pub async fn delete_message(&mut self, m: &Message) -> Result<()> {
        let id = self.identity()?;
        let fp = self.fingerprint();
        self.node()?.delete_inbox(&id, m.inbox, &fp, &m.item, &self.signer()?).await
    }

    /// Sends a contact request to an identity, sealed to one of its current ordinary devices
    /// (the master only if there are none).
    pub async fn send_contact_request(
        &mut self,
        recipient: &Hash,
        recipient_node: &str,
        note: Option<&str>,
    ) -> Result<()> {
        let cert = self.cert()?.clone();
        if !cert.has(RECEIVE) {
            return Err(Error::Refused("contact requests need a receive client".into()));
        }
        let (tag, _) = *self.contact_tags().await?.first().ok_or(Error::NotFound("contact tag".into()))?;
        self.register().await?;
        let home = self.log.as_ref().unwrap().home().ok_or(Error::NotFound("home node".into()))?;
        let (log, node) = fetch_identity(recipient_node, recipient).await?;
        let device = log
            .current_ordinary_devices()
            .into_iter()
            .next()
            .or_else(|| log.master())
            .ok_or(Error::NotFound("a current device".into()))?;
        let time = now();
        let req = ContactRequest::sign(&cert, &home, tag, note, *recipient, time, &self.key)?;
        let item = InboxItem::seal(device.id, &device.enc, &req.to_value().to_bytes())?;
        node.post_inbox(recipient, Inbox::Requests, &item).await?;
        self.sent.push(SentRequest { recipient: *recipient, app: self.app.clone(), time });
        Ok(())
    }

    /// Checks inbox messages for acceptances of contact requests this client sent, returning the
    /// accepted recipients and their tags.
    pub async fn acceptances(&mut self, recipient_node: &str) -> Result<Vec<(Hash, Hash)>> {
        let mut out = Vec::new();
        for m in self.inbox().await? {
            let Some(v) = Value::from_bytes(&m.plaintext) else { continue };
            let Ok(a) = Acceptance::from_value(v) else { continue };
            let Some(pos) =
                self.sent.iter().position(|s| s.recipient == a.identity && s.time == a.time && s.app == a.app)
            else {
                continue;
            };
            let (log, _) = fetch_identity(recipient_node, &a.identity).await?;
            if a.check(&log, &self.app, self.sent[pos].time).is_ok() {
                self.sent.remove(pos);
                out.push((a.identity, a.tag));
                self.delete_message(&m).await?;
            }
        }
        Ok(out)
    }
}

/// Someone sending to an identity's clients: fetches one key package per current client
/// registered under a tag, each checked against the recipient's log.
pub async fn fetch_key_packages(node: &str, recipient: &Hash, app: &str, tag: &Hash) -> Result<Vec<KeyPackage>> {
    let (log, client) = fetch_identity(node, recipient).await?;
    let packages = client.get_key_packages(recipient, tag).await?;
    Ok(packages.into_iter().filter(|k| k.credential.check(&log, app).is_ok()).collect())
}

/// Leaves a sealed message for a client in an identity's inbox under a tag.
pub async fn send_message(node: &str, recipient: &Hash, tag: &Hash, to: &Certificate, plaintext: &[u8]) -> Result<()> {
    let enc = to.enc.as_ref().ok_or(Error::Malformed("certificate without an encryption key"))?;
    let item = InboxItem::seal(to.client_fp(), enc, plaintext)?;
    let (_, client) = fetch_identity(node, recipient).await?;
    client.post_inbox(recipient, Inbox::Tag(*tag), &item).await
}

/// Reads an identity's public records for an app, keeping the version readers take for each
/// name (tombstones included).
pub async fn read_records(node: &str, identity: &Hash, app: &str) -> Result<Vec<Record>> {
    let (log, client) = fetch_identity(node, identity).await?;
    let page = client.get_records(identity, app, 0).await?;
    Ok(record::current_versions(&page.items, &log).into_iter().cloned().collect())
}
