//! Swift bindings for the aza client library. `scripts/build-swift.sh` builds them into the
//! `AzaKit` package under `swift/`.
//!
//! - `AzaClient`: one client of one app, such as Coach or Jarvis. Asks the aza app for a
//!   certificate, signs in, and reads and writes the app's sync data, records and messages.
//! - `AzaDevice`: the aza app's side, which holds a device's keys and approves requests.
//! - `AzaPairing`: a new machine joining an identity.
//!
//! Identity IDs, fingerprints and item hashes cross as lowercase hex. Saved state (`save`, `load`)
//! includes private keys: keep it in the Keychain.
use aza::Value;
use aza::aza_app::{AzaApp, Endorse, Pairing};
use aza::client::Client;
use std::sync::Arc;
use tokio::sync::Mutex;

uniffi::setup_scaffolding!("aza_kit");

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum AzaError {
    #[error("malformed: {message}")]
    Malformed { message: String },
    #[error("refused: {message}")]
    Refused { message: String },
    #[error("not found: {message}")]
    NotFound { message: String },
    /// Someone else wrote first: read again, merge, and write the next version.
    #[error("conflict: {message}")]
    Conflict { message: String },
    #[error("node error {status}: {message}")]
    Node { status: u16, message: String },
    #[error("network: {message}")]
    Network { message: String },
    #[error("wrong password or damaged backup file")]
    BadPassword,
    #[error("the change log has a change this version can't read; update the app")]
    Unreadable,
    #[error("no identity")]
    NoIdentity,
}

impl From<aza::Error> for AzaError {
    fn from(e: aza::Error) -> Self {
        use aza::Error as E;
        match e {
            E::Malformed(m) => AzaError::Malformed { message: m.into() },
            E::BadSignature(m) => AzaError::Refused { message: format!("invalid signature on {m}") },
            E::NoIdentity => AzaError::NoIdentity,
            E::Unreadable => AzaError::Unreadable,
            E::Refused(m) => AzaError::Refused { message: m },
            E::NotFound(m) => AzaError::NotFound { message: m },
            E::Conflict(m) => AzaError::Conflict { message: m },
            E::Node { status: 409, message } => AzaError::Conflict { message },
            E::Node { status, message } => AzaError::Node { status, message },
            E::Network(m) => AzaError::Network { message: m },
            E::BadPassword => AzaError::BadPassword,
        }
    }
}

type R<T> = Result<T, AzaError>;

fn hex32(s: &str) -> R<[u8; 32]> {
    hex::decode(s)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(AzaError::Malformed { message: "expected 64 hex digits".into() })
}

/// One item of an app's sync data, decrypted.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SyncItem {
    pub name: String,
    pub version: u64,
    pub data: Vec<u8>,
}

/// What others see of an identity (section 6). `handle` is set only once its DNS record checks out.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ProfileInfo {
    pub identity: String,
    pub name: Option<String>,
    pub handle: Option<String>,
    pub picture_hash: Option<String>,
    pub picture_type: Option<String>,
}

/// A signed sign-in: the certificate and the client's signature over the app's challenge.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SignIn {
    pub certificate: Vec<u8>,
    pub proof: Vec<u8>,
}

/// A public record's version readers take. `content` is its CBOR, or `None` for a tombstone.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RecordInfo {
    pub name: String,
    pub version: u64,
    pub content: Option<Vec<u8>>,
}

/// A message in a client's inbox.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MessageInfo {
    pub item: String,
    pub inbox: String,
    pub plaintext: Vec<u8>,
}

/// One device of an identity.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DeviceInfo {
    pub id: String,
    pub label: Option<String>,
    pub master: bool,
    pub current: bool,
}

/// An app approval: in effect, or asked for.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ApprovalInfo {
    pub app: String,
    pub client: String,
    pub scopes: Vec<String>,
}

/// A contact request waiting for the person to accept or decline.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ContactRequestInfo {
    pub item: String,
    pub sender: String,
    pub app: String,
    pub note: Option<String>,
}

async fn profile_of(node: &aza::node::NodeClient, log: &aza::identity::Identity) -> R<ProfileInfo> {
    let records = node.get_profile(&log.id).await?;
    let p = aza::profile::choose(&records, log);
    let handle = match log.handle() {
        Some(h) if aza::handle::verify(&aza::handle::DohResolver::default(), &h, &log.id).await => Some(h),
        _ => None,
    };
    let pic = p.and_then(|p| p.picture());
    Ok(ProfileInfo {
        identity: hex::encode(log.id),
        name: p.and_then(|p| p.name().map(str::to_string)),
        handle,
        picture_hash: pic.as_ref().map(|p| hex::encode(p.hash)),
        picture_type: pic.map(|p| p.r#type),
    })
}

/// One client of one app.
#[derive(uniffi::Object)]
pub struct AzaClient {
    inner: Mutex<Client>,
    request_url: Option<String>,
}

#[uniffi::export(async_runtime = "tokio")]
impl AzaClient {
    /// A new client of `app` asking for `scopes` (`sign-in`, `read`, `write`, `publish`,
    /// `receive`). `return_url` must be `https://<app>/…` and a verified app link to this app.
    #[uniffi::constructor]
    pub fn new(app: String, scopes: Vec<String>, return_url: String) -> R<Arc<Self>> {
        let scopes: Vec<&str> = scopes.iter().map(String::as_str).collect();
        let (client, request) = Client::new(&app, &scopes, &return_url)?;
        Ok(Arc::new(AzaClient { inner: Mutex::new(client), request_url: Some(request.approve_url()) }))
    }

    /// A client saved with `save`.
    #[uniffi::constructor]
    pub fn load(saved: Vec<u8>) -> R<Arc<Self>> {
        Ok(Arc::new(AzaClient { inner: Mutex::new(Client::load_from_keychain(&saved)?), request_url: None }))
    }

    /// `aza:approve#req=…`: open it so the aza app approves this client. Only on a new client.
    pub fn approve_url(&self) -> Option<String> {
        self.request_url.clone()
    }

    pub async fn save(&self) -> Vec<u8> {
        self.inner.lock().await.save_for_keychain()
    }

    pub async fn app(&self) -> String {
        self.inner.lock().await.app.clone()
    }

    /// The identity ID once signed in.
    pub async fn identity(&self) -> Option<String> {
        self.inner.lock().await.identity().ok().map(hex::encode)
    }

    pub async fn fingerprint(&self) -> String {
        hex::encode(self.inner.lock().await.fingerprint())
    }

    /// Takes the return URL the aza app opened (`…#aza=…`) and uploads the certificate.
    pub async fn receive(&self, url: String) -> R<()> {
        self.inner.lock().await.receive_certificate_url(&url).await?;
        Ok(())
    }

    /// Reads the newest change log.
    pub async fn refresh(&self) -> R<()> {
        self.inner.lock().await.refresh().await?;
        Ok(())
    }

    /// Signs an app server's 32-byte sign-in challenge.
    pub async fn sign_in(&self, challenge: Vec<u8>) -> R<SignIn> {
        let challenge: [u8; 32] =
            challenge.try_into().map_err(|_| AzaError::Malformed { message: "challenge must be 32 bytes".into() })?;
        let (cert, proof) = self.inner.lock().await.sign_in(&challenge)?;
        Ok(SignIn { certificate: cert.to_bytes(), proof })
    }

    /// The signed-in identity's profile.
    pub async fn profile(&self) -> R<ProfileInfo> {
        let mut c = self.inner.lock().await;
        let log = c.refresh().await?.clone();
        let node = aza::node::NodeClient::new(&log.home().ok_or(AzaError::NoIdentity)?)?;
        profile_of(&node, &log).await
    }

    /// The profile picture's image, checked against its hash.
    pub async fn picture(&self) -> R<Option<Vec<u8>>> {
        let mut c = self.inner.lock().await;
        let log = c.refresh().await?.clone();
        let node = aza::node::NodeClient::new(&log.home().ok_or(AzaError::NoIdentity)?)?;
        let records = node.get_profile(&log.id).await?;
        let Some(pic) = aza::profile::choose(&records, &log).and_then(|p| p.picture()) else { return Ok(None) };
        Ok(node.get_blob(&log.id, &pic.hash).await?)
    }

    /// Every item of this app's sync data, newest version of each name.
    pub async fn read_all(&self) -> R<Vec<SyncItem>> {
        let items = self.inner.lock().await.read_all().await?;
        Ok(items.into_iter().map(|i| SyncItem { name: i.name, version: i.version, data: i.data }).collect())
    }

    /// Items stored or changed since the last read.
    pub async fn read_changes(&self) -> R<Vec<SyncItem>> {
        let items = self.inner.lock().await.read_changes().await?;
        Ok(items.into_iter().map(|i| SyncItem { name: i.name, version: i.version, data: i.data }).collect())
    }

    /// Stores `data` as `version`: one more than the stored version, 1 for a new item. Fails with
    /// `Conflict` if another client wrote first: read, merge, and write the next version.
    pub async fn write(&self, name: String, version: u64, data: Vec<u8>) -> R<()> {
        self.inner.lock().await.write(&name, version, &data).await?;
        Ok(())
    }

    /// Publishes a public record (`content` is deterministic CBOR), or a tombstone with `None`.
    /// Returns its version.
    pub async fn publish(&self, name: String, content: Option<Vec<u8>>) -> R<u64> {
        let content = match content {
            None => None,
            Some(b) => Some(
                Value::from_bytes(&b)
                    .ok_or(AzaError::Malformed { message: "content must be deterministic CBOR".into() })?,
            ),
        };
        Ok(self.inner.lock().await.publish(&name, content).await?.version)
    }

    /// This app's public records for the signed-in identity: the version readers take of each name.
    pub async fn records(&self) -> R<Vec<RecordInfo>> {
        let mut c = self.inner.lock().await;
        let all = c.records().await?;
        let log = c.refresh().await?.clone();
        Ok(aza::record::current_versions(&all, &log)
            .into_iter()
            .map(|r| RecordInfo {
                name: r.name.clone(),
                version: r.version,
                content: r.content.as_ref().map(Value::to_bytes),
            })
            .collect())
    }

    /// Registers under every contact tag this client holds (a `receive` client).
    pub async fn register(&self) -> R<()> {
        self.inner.lock().await.register().await?;
        Ok(())
    }

    /// Publishes MLS key packages: `keys[i]` is the MLS signature key of `packages[i]`.
    pub async fn publish_key_packages(&self, keys: Vec<Vec<u8>>, packages: Vec<Vec<u8>>) -> R<()> {
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = keys.into_iter().zip(packages).collect();
        self.inner.lock().await.publish_key_packages(&pairs).await?;
        Ok(())
    }

    /// Messages under every tag this client holds.
    pub async fn inbox(&self) -> R<Vec<MessageInfo>> {
        Ok(self
            .inner
            .lock()
            .await
            .inbox()
            .await?
            .into_iter()
            .map(|m| MessageInfo { item: hex::encode(m.item), inbox: m.inbox.segment(), plaintext: m.plaintext })
            .collect())
    }

    pub async fn delete_message(&self, inbox: String, item: String) -> R<()> {
        let inbox = aza::node::Inbox::parse(&inbox).ok_or(AzaError::Malformed { message: "inbox".into() })?;
        let m = aza::client::Message { inbox, item: hex32(&item)?, plaintext: Vec::new() };
        self.inner.lock().await.delete_message(&m).await?;
        Ok(())
    }

    pub async fn send_contact_request(&self, recipient: String, recipient_node: String, note: Option<String>) -> R<()> {
        self.inner.lock().await.send_contact_request(&hex32(&recipient)?, &recipient_node, note.as_deref()).await?;
        Ok(())
    }
}

/// The aza app's side: one device of one identity.
#[derive(uniffi::Object)]
pub struct AzaDevice {
    inner: Mutex<AzaApp>,
}

impl AzaDevice {
    fn wrap(app: AzaApp) -> Arc<Self> {
        Arc::new(AzaDevice { inner: Mutex::new(app) })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl AzaDevice {
    /// Creates an identity on `node` with a device for this machine called `label`. The master
    /// and its next key stay in this session until `backup_master` and `forget_master`.
    #[uniffi::constructor]
    pub async fn create(node: String, label: String) -> R<Arc<Self>> {
        Ok(AzaDevice::wrap(AzaApp::create(&node, &label, aza::work::MIN_WORK).await?))
    }

    #[uniffi::constructor]
    pub fn load(saved: Vec<u8>) -> R<Arc<Self>> {
        Ok(AzaDevice::wrap(AzaApp::load_from_keychain(&saved)?))
    }

    /// Adds this machine as a new device by opening the master's backup file.
    #[uniffi::constructor]
    pub async fn restore(master_backup: Vec<u8>, password: String, label: String) -> R<Arc<Self>> {
        Ok(AzaDevice::wrap(AzaApp::restore(&master_backup, &password, &label).await?))
    }

    pub async fn save(&self) -> Vec<u8> {
        self.inner.lock().await.save_for_keychain()
    }

    pub async fn identity(&self) -> String {
        hex::encode(self.inner.lock().await.identity)
    }

    pub async fn device_id(&self) -> String {
        hex::encode(self.inner.lock().await.device().id)
    }

    pub async fn holds_master(&self) -> bool {
        self.inner.lock().await.holds_master()
    }

    /// Reads the newest log and keeps the identity in order (`upkeep`): after a device has
    /// signed itself out, its envelopes, tags and profile record are replaced.
    pub async fn refresh(&self) -> R<()> {
        self.inner.lock().await.upkeep().await?;
        Ok(())
    }

    pub async fn devices(&self) -> Vec<DeviceInfo> {
        self.inner
            .lock()
            .await
            .log()
            .devices()
            .into_iter()
            .map(|d| DeviceInfo { id: hex::encode(d.id), label: d.label, master: d.master, current: d.current })
            .collect()
    }

    /// The app and scopes an `aza:approve#req=…` asks for, to show before approving.
    pub fn describe_request(&self, url: String) -> R<ApprovalInfo> {
        let r = aza::certificate::Request::from_approve_url(&url)?;
        r.validate()?;
        Ok(ApprovalInfo { app: r.app, client: hex::encode(aza::crypto::fingerprint(&r.client)), scopes: r.scopes })
    }

    /// Approves `aza:approve#req=…`; returns the app's return URL with the certificate, to open.
    pub async fn approve_url(&self, url: String) -> R<String> {
        Ok(self.inner.lock().await.approve_url(&url).await?)
    }

    /// The app and scopes a request shown as a QR code on another machine asks for, to show
    /// before approving.
    pub async fn describe_qr(&self, qr: String) -> R<ApprovalInfo> {
        let r = AzaApp::qr_request(&qr).await?;
        r.validate()?;
        Ok(ApprovalInfo { app: r.app, client: hex::encode(aza::crypto::fingerprint(&r.client)), scopes: r.scopes })
    }

    /// Approves a request shown as a QR code on another machine.
    pub async fn approve_qr(&self, qr: String) -> R<()> {
        self.inner.lock().await.approve_qr(&qr).await?;
        Ok(())
    }

    pub async fn approvals(&self) -> R<Vec<ApprovalInfo>> {
        Ok(self
            .inner
            .lock()
            .await
            .approvals()
            .await?
            .into_iter()
            .map(|c| ApprovalInfo { app: c.app.clone(), client: hex::encode(c.client_fp()), scopes: c.scopes.clone() })
            .collect())
    }

    pub async fn revoke_client(&self, client: String) -> R<()> {
        self.inner.lock().await.revoke_client(&hex32(&client)?).await?;
        Ok(())
    }

    /// Approves a new device from its pairing QR code; returns its device ID.
    pub async fn approve_pairing(&self, qr: String) -> R<String> {
        Ok(hex::encode(self.inner.lock().await.approve_pairing(&qr).await?))
    }

    /// Signs out a device, endorsing every post made through its approvals.
    pub async fn sign_out(&self, device: String) -> R<()> {
        self.inner.lock().await.sign_out(&hex32(&device)?, Endorse::AllExcept(Vec::new())).await?;
        Ok(())
    }

    pub async fn profile(&self) -> R<ProfileInfo> {
        let mut a = self.inner.lock().await;
        a.refresh().await?;
        let log = a.log().clone();
        profile_of(a.node(), &log).await
    }

    /// The profile picture's image, checked against its hash.
    pub async fn picture(&self) -> R<Option<Vec<u8>>> {
        let a = self.inner.lock().await;
        let records = a.node().get_profile(&a.identity).await?;
        let Some(pic) = aza::profile::choose(&records, a.log()).and_then(|p| p.picture()) else { return Ok(None) };
        Ok(a.node().get_blob(&a.identity, &pic.hash).await?)
    }

    pub async fn set_name(&self, name: String) -> R<()> {
        self.inner.lock().await.set_name(&name).await?;
        Ok(())
    }

    pub async fn set_picture(&self, image: Vec<u8>, image_type: String) -> R<()> {
        self.inner.lock().await.set_picture(&image, &image_type).await?;
        Ok(())
    }

    pub async fn set_handle(&self, handle: Option<String>) -> R<()> {
        self.inner.lock().await.set_handle(handle.as_deref()).await?;
        Ok(())
    }

    /// The master's keys and its next key as one password-protected backup file.
    pub async fn backup_master(&self, password: String) -> R<Vec<u8>> {
        Ok(self.inner.lock().await.backup_master(&password)?)
    }

    /// Deletes the master's keys from this machine, once its backup file is saved.
    pub async fn forget_master(&self) {
        self.inner.lock().await.forget_master();
    }

    /// Opens the master's backup file for this session, to make repairs.
    pub async fn open_master(&self, file: Vec<u8>, password: String) -> R<()> {
        self.inner.lock().await.open_master(&file, &password).await?;
        Ok(())
    }

    /// Removes a device for good with the master, keeping its changes up to `keep`.
    pub async fn remove_device(&self, device: String, keep: Option<String>) -> R<()> {
        let keep = match keep {
            Some(k) => Some(hex32(&k)?),
            None => None,
        };
        self.inner.lock().await.remove_device(&hex32(&device)?, keep, Endorse::AllExcept(Vec::new())).await?;
        Ok(())
    }

    pub async fn contact_requests(&self) -> R<Vec<ContactRequestInfo>> {
        Ok(self
            .inner
            .lock()
            .await
            .contact_requests()
            .await?
            .into_iter()
            .map(|(item, r)| ContactRequestInfo {
                item: hex::encode(item),
                sender: hex::encode(r.identity),
                app: r.app,
                note: r.note,
            })
            .collect())
    }

    pub async fn accept_contact_request(&self, item: String) -> R<()> {
        let mut a = self.inner.lock().await;
        let item = hex32(&item)?;
        let (_, req) = a
            .contact_requests()
            .await?
            .into_iter()
            .find(|(i, _)| *i == item)
            .ok_or(AzaError::NotFound { message: "contact request".into() })?;
        a.accept_contact_request(&item, &req).await?;
        Ok(())
    }
}

/// A new machine joining an identity: show `qr`, then call `finish` until another device has
/// approved it.
#[derive(uniffi::Object)]
pub struct AzaPairing {
    inner: Pairing,
}

#[uniffi::export(async_runtime = "tokio")]
impl AzaPairing {
    #[uniffi::constructor]
    pub async fn start(node: String, label: String) -> R<Arc<Self>> {
        Ok(Arc::new(AzaPairing { inner: Pairing::start(&node, &label).await? }))
    }

    pub fn qr(&self) -> String {
        self.inner.qr.clone()
    }

    /// The joined device once another device has approved; `NotFound` until then. Show its
    /// profile and keep the device only if the person confirms it's theirs.
    pub async fn finish(&self) -> R<Arc<AzaDevice>> {
        Ok(AzaDevice::wrap(self.inner.finish().await?.confirm()))
    }
}

/// Whether a handle's `_aza` DNS record names this identity.
#[uniffi::export(async_runtime = "tokio")]
pub async fn verify_handle(handle: String, identity: String) -> bool {
    let Ok(id) = hex32(&identity) else { return false };
    aza::handle::verify(&aza::handle::DohResolver::default(), &handle, &id).await
}
