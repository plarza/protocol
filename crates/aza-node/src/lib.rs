//! An aza node (section 11): stores change logs, sync data, envelopes, certificates, profile
//! records, public records, blobs, tag bindings, registrations, inbox items and key packages,
//! and answers the node API under `/aza/v1/`.
pub mod store;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use aza::Value;
use aza::aza_core::access::{Request, Who};
use aza::certificate::{Certificate, PUBLISH, READ, RECEIVE, WRITE};
use aza::change::CLOCK_SKEW;
use aza::change::{Body, Change};
use aza::crypto::{self, Hash, sha256};
use aza::data::{Envelope, SyncItem};
use aza::identity::Identity;
use aza::message::{InboxItem, KeyPackage};
use aza::node::{Auth, Export, Inbox, PairingKeys, TagBinding, decode_name, error_body, parse_hex32};
use aza::profile::Profile;
use aza::record::{InclusionProof, Record};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use store::{Binding, Store};

pub fn now() -> u64 {
    aza::change::now()
}

#[derive(Clone, Debug)]
pub struct Config {
    /// The node's own URL, such as `https://node.example`; its host is what `aza-auth` must name.
    pub url: String,
    /// The SQLite database file; in memory if `None`.
    pub db: Option<String>,
    /// The admission price: the least work a new identity needs (section 12).
    pub min_work: u32,
    /// Bytes of sync data, envelopes, profile records, public records and blobs per identity.
    /// The change log never counts.
    pub quota: u64,
    /// The most items one holder's inbox may hold.
    pub max_inbox: u64,
    /// The most bytes the whole database may take: past it the node refuses anything that
    /// stores more, from anyone, and keeps serving reads and deletes.
    pub max_total: Option<u64>,
}

impl Config {
    pub fn new(url: &str) -> Config {
        Config {
            url: url.into(),
            db: None,
            min_work: aza::work::MIN_WORK,
            quota: 100_000_000,
            max_inbox: 10_000,
            max_total: None,
        }
    }
}

pub struct Node {
    config: Config,
    host: String,
    store: Mutex<Store>,
    nonces: Mutex<HashMap<[u8; 16], u64>>,
    logs: Mutex<HashMap<Hash, (u64, Identity)>>,
}

/// Why a request failed.
#[derive(Debug)]
pub enum Fail {
    Bad(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound,
    Conflict(String),
    TooLarge(String),
    Internal(String),
}

type R<T> = Result<T, Fail>;

impl From<rusqlite::Error> for Fail {
    fn from(e: rusqlite::Error) -> Self {
        Fail::Internal(e.to_string())
    }
}

impl From<aza::Error> for Fail {
    fn from(e: aza::Error) -> Self {
        match e {
            aza::Error::NoIdentity => Fail::NotFound,
            aza::Error::Refused(m) => Fail::Forbidden(m),
            e => Fail::Bad(e.to_string()),
        }
    }
}

fn bad(what: &str) -> Fail {
    Fail::Bad(format!("malformed {what}"))
}

fn forbidden(why: &str) -> Fail {
    Fail::Forbidden(why.into())
}

/// Who made a request.
enum Principal {
    Device { id: Hash, current: bool },
    Client { fp: Hash, certs: Vec<Certificate> },
}

impl Principal {
    fn by(&self) -> Hash {
        match self {
            Principal::Device { id, .. } => *id,
            Principal::Client { fp, .. } => *fp,
        }
    }
}

/// What a request names that decides who may make it (section 11.1).
#[derive(Default)]
struct Scope<'a> {
    /// The request's app, and the scope a client's certificate needs for it.
    app: Option<(&'a str, &'a str)>,
    /// `GET envelopes`: a certificate with `read` or `receive`, for any app.
    envelopes: bool,
    holder: Option<&'a Hash>,
    tag: Option<&'a Hash>,
    /// `PUT …/endorsed`: the device that signed the endorsing change.
    ended: Option<&'a Hash>,
}

struct Req {
    method: Method,
    segs: Vec<String>,
    path: String,
    query: HashMap<String, String>,
    auth: Option<String>,
    body: Bytes,
}

impl Req {
    fn since(&self) -> R<u64> {
        match self.query.get("since") {
            None => Ok(0),
            Some(s) => s.parse().map_err(|_| bad("since")),
        }
    }

    fn value(&self) -> R<Value> {
        Value::from_bytes(&self.body).ok_or_else(|| bad("CBOR body"))
    }
}

fn hex_seg(s: &str) -> R<Hash> {
    parse_hex32(s).ok_or_else(|| bad("hex in path"))
}

fn app_seg(s: &str) -> R<String> {
    if aza::certificate::is_app_id(s) { Ok(s.into()) } else { Err(bad("app ID")) }
}

fn values(rows: Vec<Vec<u8>>) -> Value {
    Value::Array(rows.iter().filter_map(|r| Value::from_bytes(r)).collect())
}

fn page(rows: Vec<Vec<u8>>, counter: u64) -> Value {
    Value::map([("items", values(rows)), ("counter", counter.into())])
}

impl Node {
    pub fn new(config: Config) -> Result<Arc<Node>, String> {
        let host = aza::node::host_of(&config.url).map_err(|e| e.to_string())?;
        let store = Store::open(config.db.as_deref()).map_err(|e| e.to_string())?;
        Ok(Arc::new(Node {
            config,
            host,
            store: Mutex::new(store),
            nonces: Default::default(),
            logs: Default::default(),
        }))
    }

    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The identity's log as this node holds it, read once per change.
    fn identity(&self, id: &Hash) -> R<Identity> {
        let (count, rows) = {
            let s = self.store();
            (s.change_count(id)?, s.changes(id)?)
        };
        if count == 0 {
            return Err(Fail::NotFound);
        }
        if let Some((n, log)) = self.logs.lock().unwrap().get(id)
            && *n == count
        {
            return Ok(log.clone());
        }
        let changes: Vec<Change> = rows.iter().filter_map(|r| Change::from_bytes(r).ok()).collect();
        let log = Identity::read(*id, changes)?;
        self.logs.lock().unwrap().insert(*id, (count, log.clone()));
        Ok(log)
    }

    /// Checks the `aza-auth` header: its identity, time, nonce and signature, by a device of the
    /// identity or a client whose certificate the node holds (or whose key is `client_key`).
    fn authenticate(&self, req: &Req, identity: &Identity, client_key: Option<&[u8]>) -> R<Principal> {
        let header = req.auth.as_deref().ok_or_else(|| Fail::Unauthorized("aza-auth header required".into()))?;
        let a = Auth::parse(header).map_err(|_| Fail::Unauthorized("malformed aza-auth header".into()))?;
        if a.identity != identity.id {
            return Err(Fail::Unauthorized("aza-auth names another identity".into()));
        }
        let t = now();
        if a.time.abs_diff(t) > CLOCK_SKEW {
            return Err(Fail::Unauthorized("aza-auth time is off".into()));
        }
        let verify = |key: &[u8]| a.verify(key, &self.host, req.method.as_str(), &req.path, &req.body);
        let principal = if let Some(key) = client_key {
            if crypto::fingerprint(key) != a.by || !verify(key) {
                return Err(Fail::Unauthorized("aza-auth signature".into()));
            }
            Principal::Client { fp: a.by, certs: Vec::new() }
        } else if let Some(device) = identity.device(&a.by) {
            if !verify(&device.key) {
                return Err(Fail::Unauthorized("aza-auth signature".into()));
            }
            Principal::Device { id: a.by, current: device.current }
        } else {
            let certs: Vec<Certificate> = self
                .store()
                .certificates_of(&identity.id, &a.by)?
                .iter()
                .filter_map(|c| Certificate::from_bytes(c).ok())
                .collect();
            let first = certs.first().ok_or_else(|| Fail::Unauthorized("unknown device or client".into()))?;
            if !verify(&first.client) {
                return Err(Fail::Unauthorized("aza-auth signature".into()));
            }
            Principal::Client { fp: a.by, certs }
        };
        let mut nonces = self.nonces.lock().unwrap();
        nonces.retain(|_, exp| *exp >= t);
        if nonces.insert(a.nonce, t + 2 * CLOCK_SKEW).is_some() {
            return Err(Fail::Unauthorized("aza-auth nonce reused".into()));
        }
        Ok(principal)
    }

    /// Authenticates a request and checks whoever signed it may make it, by section 11.1's
    /// table (decided by the verified `aza_core::access`).
    fn permit(&self, request: Request, req: &Req, identity: &Identity, scope: Scope) -> R<Principal> {
        let p = self.authenticate(req, identity, None)?;
        let who = match &p {
            Principal::Device { id, current } => {
                Who::Device { current: *current, ended: scope.ended == Some(id), holder: scope.holder == Some(id) }
            }
            Principal::Client { fp, certs } => {
                let works = |c: &&Certificate| c.check(identity).is_ok();
                let has = match scope.app {
                    Some((app, needed)) => certs.iter().filter(works).any(|c| c.app == app && c.has(needed)),
                    None => scope.envelopes && certs.iter().filter(works).any(|c| c.has(READ) || c.has(RECEIVE)),
                };
                let registered = match scope.tag {
                    Some(tag) => match self.tag_state(identity, tag)? {
                        Some((app, _)) => self.registered(identity, tag, &app, fp)?.is_some(),
                        None => false,
                    },
                    None => false,
                };
                Who::Client {
                    revoked: identity.is_revoked(fp),
                    scope: has,
                    registered,
                    holder: scope.holder == Some(fp),
                }
            }
        };
        if !aza::aza_core::access::allowed(&request, &who) {
            return Err(forbidden("whoever signed this request may not make it (section 11.1)"));
        }
        Ok(p)
    }

    fn check_quota(&self, identity: &Hash, removing: u64, adding: u64) -> R<()> {
        let used = self.store().usage(identity)?;
        if used.saturating_sub(removing) + adding > self.config.quota {
            return Err(Fail::TooLarge("storage limit reached".into()));
        }
        Ok(())
    }

    /// Tag bindings that count: those made by a device that is still current.
    fn live_bindings(&self, identity: &Identity) -> R<Vec<Binding>> {
        Ok(self.store().tags(&identity.id)?.into_iter().filter(|b| identity.is_current(&b.by)).collect())
    }

    /// The app a tag is bound to, and whether it is that app's current tag.
    fn tag_state(&self, identity: &Identity, tag: &Hash) -> R<Option<(String, bool)>> {
        let live = self.live_bindings(identity)?;
        let Some(b) = live.iter().find(|b| b.tag == *tag) else { return Ok(None) };
        let current = live.iter().filter(|x| x.app == b.app && x.current).max_by_key(|x| x.seq).map(|x| x.tag);
        Ok(Some((b.app.clone(), current == Some(*tag))))
    }

    /// The certificate of a client registered under a tag, if it still passes checks for the app
    /// the tag is bound to.
    fn registered(&self, identity: &Identity, tag: &Hash, app: &str, client: &Hash) -> R<Option<Certificate>> {
        let regs = self.store().registrations(&identity.id, tag)?;
        Ok(regs
            .into_iter()
            .filter(|(c, _)| c == client)
            .filter_map(|(_, d)| Certificate::from_bytes(&d).ok())
            .find(|c| c.app == app && c.has(RECEIVE) && c.check(identity).is_ok()))
    }

    fn dispatch(&self, req: Req) -> R<Value> {
        if let Some(max) = self.config.max_total
            && matches!(req.method, Method::POST | Method::PUT)
            && self.store().size()? >= max
        {
            return Err(Fail::TooLarge("this node is full".into()));
        }
        let segs: Vec<&str> = req.segs.iter().map(String::as_str).collect();
        let m = req.method.clone();
        match (m, segs.as_slice()) {
            (Method::GET, ["log", id]) => self.get_log(&hex_seg(id)?),
            (Method::POST, ["log", id]) => self.post_log(&hex_seg(id)?, &req),
            (Method::GET, ["export", id]) => self.get_export(&hex_seg(id)?, &req),
            (Method::POST, ["import", id]) => self.post_import(&hex_seg(id)?, &req),
            (Method::GET, ["sync", id, app]) => self.get_sync(&hex_seg(id)?, &app_seg(app)?, &req),
            (Method::PUT, ["sync", id, app, name]) => self.put_sync(&hex_seg(id)?, &app_seg(app)?, name, &req),
            (Method::POST, ["certificates", id]) => self.post_certificate(&hex_seg(id)?, &req),
            (Method::GET, ["envelopes", id, holder]) => self.get_envelopes(&hex_seg(id)?, &hex_seg(holder)?, &req),
            (Method::POST, ["envelopes", id]) => self.post_envelopes(&hex_seg(id)?, &req),
            (Method::GET, ["records", id, app]) => self.get_records(&hex_seg(id)?, &app_seg(app)?, &req),
            (Method::PUT, ["records", id, app, name]) => self.put_record(&hex_seg(id)?, &app_seg(app)?, name, &req),
            (Method::PUT, ["records", id, app, name, version, "endorsed"]) => {
                let version = version.parse().map_err(|_| bad("version"))?;
                self.put_endorsed(&hex_seg(id)?, &app_seg(app)?, name, version, &req)
            }
            (Method::POST, ["inbox", id, inbox]) => self.post_inbox(&hex_seg(id)?, inbox, &req),
            (Method::GET, ["inbox", id, inbox, holder]) => {
                self.get_inbox(&hex_seg(id)?, inbox, &hex_seg(holder)?, &req)
            }
            (Method::DELETE, ["inbox", id, inbox, holder, item]) => {
                self.delete_inbox(&hex_seg(id)?, inbox, &hex_seg(holder)?, &hex_seg(item)?, &req)
            }
            (Method::PUT, ["registrations", id, tag]) => self.put_registration(&hex_seg(id)?, &hex_seg(tag)?, &req),
            (Method::DELETE, ["registrations", id, tag, client]) => {
                self.delete_registration(&hex_seg(id)?, &hex_seg(tag)?, &hex_seg(client)?, &req)
            }
            (Method::POST, ["keypackages", id, tag]) => self.post_key_packages(&hex_seg(id)?, &hex_seg(tag)?, &req),
            (Method::GET, ["keypackages", id, tag]) => self.get_key_packages(&hex_seg(id)?, &hex_seg(tag)?),
            (Method::DELETE, ["keypackages", id, tag]) => self.delete_key_packages(&hex_seg(id)?, &hex_seg(tag)?, &req),
            (Method::GET, ["profile", id]) => self.get_profile(&hex_seg(id)?),
            (Method::PUT, ["profile", id]) => self.put_profile(&hex_seg(id)?, &req),
            (Method::PUT, ["blobs", id, hash]) => self.put_blob(&hex_seg(id)?, &hex_seg(hash)?, &req),
            (Method::GET, ["blobs", _, hash]) => self.get_blob(&hex_seg(hash)?),
            (Method::DELETE, ["blobs", id, hash]) => self.delete_blob(&hex_seg(id)?, &hex_seg(hash)?, &req),
            (Method::POST, ["pairing"]) => self.post_pairing(&req),
            (Method::GET, ["pairing", pid]) => self.get_pairing(pid),
            (Method::PUT, ["pairing", pid, "reply"]) => self.put_pairing_reply(pid, &req),
            (Method::GET, ["pairing", pid, "reply"]) => self.get_pairing_reply(pid),
            (Method::PUT, ["tags", id, tag]) => self.put_tag(&hex_seg(id)?, &hex_seg(tag)?, &req),
            _ => Err(Fail::NotFound),
        }
    }

    // Change logs.

    fn get_log(&self, id: &Hash) -> R<Value> {
        let rows = self.store().changes(id)?;
        if rows.is_empty() {
            return Err(Fail::NotFound);
        }
        Ok(values(rows))
    }

    /// Keeps the uploaded changes with valid signatures; a new identity's work must meet the
    /// admission price.
    fn store_changes(&self, id: &Hash, uploaded: Vec<Change>) -> R<u64> {
        let existing: Vec<Change> =
            self.store().changes(id)?.iter().filter_map(|r| Change::from_bytes(r).ok()).collect();
        let new_identity = existing.is_empty();
        let mut all = existing.clone();
        all.extend(uploaded.iter().cloned());
        let min = if new_identity { self.config.min_work } else { aza::work::MIN_WORK };
        let log = Identity::read_with_work(*id, all, min)
            .map_err(|_| forbidden("no valid genesis change, or too little work"))?;
        let held: std::collections::HashSet<Hash> = existing.iter().map(Change::hash).collect();
        let mut fresh = std::collections::HashSet::new();
        for c in &uploaded {
            if held.contains(&c.hash()) || log.change(&c.hash()).is_none() {
                continue;
            }
            let key = match c.own_signer() {
                Some(k) => Some(k.to_vec()),
                None => c.by.and_then(|b| log.device_key_any(&b).map(<[u8]>::to_vec)),
            };
            if key.is_some_and(|k| c.verify_with(&k)) {
                fresh.insert(c.hash());
            }
        }
        // The node limits a log only as section 11 allows: per signing device.
        let kept: std::collections::HashSet<Hash> = log.admit(&held, &fresh).into_iter().collect();
        let s = self.store();
        // The copy the reading keeps, whose signature is valid.
        for c in log.changes().iter().filter(|c| kept.contains(&c.hash())) {
            s.add_change(id, &c.hash(), &c.to_bytes())?;
        }
        if kept.len() < fresh.len() {
            return Err(Fail::TooLarge("the node keeps no more of these changes (section 11)".into()));
        }
        Ok(kept.len() as u64)
    }

    fn post_log(&self, id: &Hash, req: &Req) -> R<Value> {
        let v = req.value()?;
        let changes = v
            .as_array()
            .ok_or_else(|| bad("change list"))?
            .iter()
            .map(|c| Change::from_value(c.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Fail::Bad(e.to_string()))?;
        let stored = self.store_changes(id, changes)?;
        Ok(Value::map([("stored", stored.into())]))
    }

    fn export(&self, id: &Hash) -> R<Export> {
        let s = self.store();
        let parse = |rows: Vec<Vec<u8>>| rows.into_iter().filter_map(|r| Value::from_bytes(&r)).collect::<Vec<_>>();
        Ok(Export {
            log: parse(s.changes(id)?).into_iter().filter_map(|v| Change::from_value(v).ok()).collect(),
            sync: parse(s.all_sync(id)?).iter().filter_map(|v| SyncItem::from_value(v).ok()).collect(),
            envelopes: parse(s.all_envelopes(id)?).into_iter().filter_map(|v| Envelope::from_value(v).ok()).collect(),
            certificates: parse(s.all_certificates(id)?)
                .into_iter()
                .filter_map(|v| Certificate::from_value(v).ok())
                .collect(),
            profiles: s
                .profiles(id)?
                .into_iter()
                .filter_map(|(_, d)| Profile::from_value(Value::from_bytes(&d)?).ok())
                .collect(),
            records: parse(s.all_records(id)?).into_iter().filter_map(|v| Record::from_value(v).ok()).collect(),
            blobs: s.all_blobs(id)?,
            tags: s
                .tags(id)?
                .into_iter()
                .map(|b| TagBinding { tag: b.tag, app: b.app, current: b.current, by: b.by })
                .collect(),
            registrations: s
                .all_registrations(id)?
                .into_iter()
                .filter_map(|(t, d)| Some((t, Certificate::from_bytes(&d).ok()?)))
                .collect(),
            inbox: s
                .all_inbox(id)?
                .into_iter()
                .filter_map(|(b, d)| Some((Inbox::parse(&b)?, InboxItem::from_value(&Value::from_bytes(&d)?).ok()?)))
                .collect(),
            key_packages: s
                .all_key_packages(id)?
                .into_iter()
                .filter_map(|(t, c, d)| Some((t, c, KeyPackage::from_value(&Value::from_bytes(&d)?).ok()?)))
                .collect(),
        })
    }

    fn get_export(&self, id: &Hash, req: &Req) -> R<Value> {
        let identity = self.identity(id)?;
        self.permit(Request::GetExport, req, &identity, Scope::default())?;
        Ok(self.export(id)?.to_value())
    }

    /// Stores an export from another node. Permission is judged with the log inside it; sync
    /// data, blobs, tag bindings, registrations, inbox items and key packages are kept as they
    /// were, without the usual version and client checks.
    fn post_import(&self, id: &Hash, req: &Req) -> R<Value> {
        let export = Export::from_value(&req.value()?).map_err(|e| Fail::Bad(e.to_string()))?;
        let existing: Vec<Change> =
            self.store().changes(id)?.iter().filter_map(|r| Change::from_bytes(r).ok()).collect();
        let mut all = existing;
        all.extend(export.log.iter().cloned());
        let log = Identity::read_with_work(*id, all, self.config.min_work)?;
        self.permit(Request::PostImport, req, &log, Scope::default())?;
        self.store_changes(id, export.log.clone())?;
        let log = self.identity(id)?;
        let size: u64 = export.sync.iter().map(|i| i.to_value().to_bytes().len() as u64).sum::<u64>()
            + export.envelopes.iter().map(|e| e.to_value().to_bytes().len() as u64).sum::<u64>()
            + export.profiles.iter().map(|p| p.to_value().to_bytes().len() as u64).sum::<u64>()
            + export.records.iter().map(|r| r.to_value().to_bytes().len() as u64).sum::<u64>()
            + export.blobs.iter().map(|(_, d)| d.len() as u64).sum::<u64>();
        self.check_quota(id, 0, size)?;
        let mut s = self.store();
        s.transaction(|s| {
            for item in &export.sync {
                if item.identity == *id {
                    s.put_sync(id, &item.app, &item.name, item.version, &item.secret, &item.to_value().to_bytes())?;
                }
            }
            for e in export.envelopes.iter().filter(|e| e.signature_valid(&log)) {
                s.add_envelope(id, &e.holder, &e.to_value().to_bytes())?;
            }
            for c in export.certificates.iter().filter(|c| c.signed_by_device_key(&log)) {
                s.add_certificate(id, &c.client_fp(), &c.to_bytes())?;
            }
            for p in export.profiles.iter().filter(|p| p.signature_valid(&log)) {
                s.put_profile(id, &p.by, &p.to_value().to_bytes())?;
            }
            for r in export.records.iter().filter(|r| r.authentic(&log)) {
                s.put_record(id, &r.app, &r.name, r.version, &r.to_value().to_bytes())?;
            }
            for (h, d) in export.blobs.iter().filter(|(h, d)| sha256(d) == *h) {
                s.put_blob(id, h, d)?;
            }
            for t in &export.tags {
                s.put_tag(id, &t.tag, &t.app, t.current, &t.by)?;
            }
            for (tag, c) in &export.registrations {
                s.put_registration(id, tag, &c.client_fp(), &c.to_bytes())?;
            }
            for (inbox, item) in &export.inbox {
                s.add_inbox(id, &inbox.segment(), &item.to, &item.hash(), &item.to_value().to_bytes())?;
            }
            for (tag, client, k) in &export.key_packages {
                s.add_key_package(id, tag, client, &k.to_value().to_bytes())?;
            }
            Ok(())
        })?;
        Ok(Value::null())
    }

    // Sync data.

    fn get_sync(&self, id: &Hash, app: &str, req: &Req) -> R<Value> {
        let identity = self.identity(id)?;
        self.permit(Request::GetSync, req, &identity, Scope { app: Some((app, READ)), ..Default::default() })?;
        let s = self.store();
        Ok(page(s.sync_since(id, app, req.since()?)?, s.counter(id)?))
    }

    fn put_sync(&self, id: &Hash, app: &str, name: &str, req: &Req) -> R<Value> {
        let identity = self.identity(id)?;
        self.permit(Request::PutSync, req, &identity, Scope { app: Some((app, WRITE)), ..Default::default() })?;
        let name = decode_name(name).ok_or_else(|| bad("item name"))?;
        let item = SyncItem::from_value(&req.value()?).map_err(|e| Fail::Bad(e.to_string()))?;
        if item.identity != *id || item.app != app || item.name != name {
            return Err(Fail::Bad("item doesn't match its path".into()));
        }
        let stored = self.store().sync_item(id, app, &name)?;
        let expected = stored.as_ref().map_or(1, |(v, _)| v + 1);
        if item.version != expected {
            return Err(Fail::Conflict(format!("version must be {expected}")));
        }
        if item.secret != identity.current_secret() {
            return Err(Fail::Conflict("not the current data secret".into()));
        }
        let data = item.to_value().to_bytes();
        self.check_quota(id, stored.map_or(0, |(_, d)| d.len() as u64), data.len() as u64)?;
        self.store().put_sync(id, app, &name, item.version, &item.secret, &data)?;
        Ok(Value::null())
    }

    // Certificates and envelopes.

    fn post_certificate(&self, id: &Hash, req: &Req) -> R<Value> {
        let identity = self.identity(id)?;
        let cert = Certificate::from_value(req.value()?).map_err(|e| Fail::Bad(e.to_string()))?;
        self.authenticate(req, &identity, Some(&cert.client))?;
        cert.check(&identity)?;
        self.store().add_certificate(id, &cert.client_fp(), &cert.to_bytes())?;
        Ok(Value::null())
    }

    fn get_envelopes(&self, id: &Hash, holder: &Hash, req: &Req) -> R<Value> {
        let identity = self.identity(id)?;
        let scope = Scope { envelopes: true, holder: Some(holder), ..Default::default() };
        self.permit(Request::GetEnvelopes, req, &identity, scope)?;
        Ok(values(self.store().envelopes_for(id, holder)?))
    }

    fn post_envelopes(&self, id: &Hash, req: &Req) -> R<Value> {
        let identity = self.identity(id)?;
        self.permit(Request::PostEnvelopes, req, &identity, Scope::default())?;
        let v = req.value()?;
        let envs: Vec<Envelope> = v
            .as_array()
            .ok_or_else(|| bad("envelope list"))?
            .iter()
            .map(|e| Envelope::from_value(e.clone()))
            .collect::<Result<_, _>>()
            .map_err(|e| Fail::Bad(e.to_string()))?;
        let valid: Vec<&Envelope> = envs.iter().filter(|e| e.signature_valid(&identity)).collect();
        self.check_quota(id, 0, valid.iter().map(|e| e.to_value().to_bytes().len() as u64).sum())?;
        let mut s = self.store();
        s.transaction(|s| {
            for e in valid {
                s.add_envelope(id, &e.holder, &e.to_value().to_bytes())?;
            }
            Ok(())
        })?;
        Ok(Value::null())
    }

    // Public records.

    fn get_records(&self, id: &Hash, app: &str, req: &Req) -> R<Value> {
        let s = self.store();
        Ok(page(s.records_since(id, app, req.since()?)?, s.counter(id)?))
    }

    fn put_record(&self, id: &Hash, app: &str, name: &str, req: &Req) -> R<Value> {
        let identity = self.identity(id)?;
        let p =
            self.permit(Request::PutRecord, req, &identity, Scope { app: Some((app, PUBLISH)), ..Default::default() })?;
        let name = decode_name(name).ok_or_else(|| bad("record name"))?;
        let record = Record::from_value(req.value()?).map_err(|e| Fail::Bad(e.to_string()))?;
        if record.identity != *id || record.app != app || record.name != name || !record.endorsed.is_empty() {
            return Err(Fail::Bad("record doesn't match its path".into()));
        }
        if record.certificate.client_fp() != p.by() {
            return Err(forbidden("a record must be signed by the client storing it"));
        }
        if !record.is_valid(&identity) {
            return Err(forbidden("record isn't valid"));
        }
        let expected = self.store().record_max_version(id, app, &name)? + 1;
        if record.version != expected {
            return Err(Fail::Conflict(format!("version must be {expected}")));
        }
        let data = record.to_value().to_bytes();
        self.check_quota(id, 0, data.len() as u64)?;
        self.store().put_record(id, app, &name, record.version, &data)?;
        Ok(Value::null())
    }

    /// A device that signed itself out attaches its sign-out's proofs after it stopped being
    /// current, so the device that signed the endorsing change may do so. The proof checks itself
    /// against the change's root either way.
    fn put_endorsed(&self, id: &Hash, app: &str, name: &str, version: u64, req: &Req) -> R<Value> {
        let identity = self.identity(id)?;
        let proof = InclusionProof::from_value(&req.value()?).map_err(|e| Fail::Bad(e.to_string()))?;
        let change = identity.change(&proof.change).ok_or_else(|| Fail::Bad("unknown endorsing change".into()))?;
        self.permit(Request::PutEndorsed, req, &identity, Scope { ended: change.by.as_ref(), ..Default::default() })?;
        let name = decode_name(name).ok_or_else(|| bad("record name"))?;
        let stored = self.store().record(id, app, &name, version)?.ok_or(Fail::NotFound)?;
        let record = Record::from_value(Value::from_bytes(&stored).ok_or_else(|| bad("stored record"))?)
            .map_err(|e| Fail::Bad(e.to_string()))?;
        let root = match &change.body {
            Body::SignOut { endorse: Some(r), .. }
            | Body::RemoveDevice { endorse: Some(r), .. }
            | Body::SetMaster { endorse: Some(r), .. } => *r,
            _ => return Err(Fail::Bad("that change endorses nothing".into())),
        };
        if !proof.verifies(&record.leaf(), &root) {
            return Err(Fail::Bad("the proof doesn't rebuild the endorsement".into()));
        }
        let updated = record.with_proof(proof);
        self.store().put_record(id, app, &name, version, &updated.to_value().to_bytes())?;
        Ok(Value::null())
    }

    // Inboxes.

    fn post_inbox(&self, id: &Hash, inbox: &str, req: &Req) -> R<Value> {
        let identity = self.identity(id)?;
        let inbox = Inbox::parse(inbox).ok_or_else(|| bad("inbox"))?;
        let item = InboxItem::from_value(&req.value()?).map_err(|e| Fail::Bad(e.to_string()))?;
        match inbox {
            Inbox::Requests => {
                let devices = identity.current_ordinary_devices();
                let ok = if devices.is_empty() {
                    identity.master().is_some_and(|m| m.id == item.to)
                } else {
                    devices.iter().any(|d| d.id == item.to)
                };
                if !ok {
                    return Err(forbidden("requests go to a current ordinary device"));
                }
            }
            Inbox::Tag(tag) => {
                let (app, _) = self.tag_state(&identity, &tag)?.ok_or(Fail::NotFound)?;
                if self.registered(&identity, &tag, &app, &item.to)?.is_none() {
                    return Err(forbidden("no receive client registered under this tag has that fingerprint"));
                }
            }
        }
        let seg = inbox.segment();
        if self.store().inbox_count(id, &seg, &item.to)? >= self.config.max_inbox {
            return Err(Fail::TooLarge("inbox is full".into()));
        }
        self.store().add_inbox(id, &seg, &item.to, &item.hash(), &item.to_value().to_bytes())?;
        Ok(Value::null())
    }

    fn inbox_scope<'a>(inbox: &'a Inbox, holder: &'a Hash) -> Scope<'a> {
        let tag = match inbox {
            Inbox::Tag(t) => Some(t),
            Inbox::Requests => None,
        };
        Scope { holder: Some(holder), tag, ..Default::default() }
    }

    fn get_inbox(&self, id: &Hash, inbox: &str, holder: &Hash, req: &Req) -> R<Value> {
        let identity = self.identity(id)?;
        let inbox = Inbox::parse(inbox).ok_or_else(|| bad("inbox"))?;
        self.permit(Request::GetInbox, req, &identity, Self::inbox_scope(&inbox, holder))?;
        let s = self.store();
        Ok(page(s.inbox_since(id, &inbox.segment(), holder, req.since()?)?, s.counter(id)?))
    }

    fn delete_inbox(&self, id: &Hash, inbox: &str, holder: &Hash, item: &Hash, req: &Req) -> R<Value> {
        let identity = self.identity(id)?;
        let inbox = Inbox::parse(inbox).ok_or_else(|| bad("inbox"))?;
        self.permit(Request::DeleteInbox, req, &identity, Self::inbox_scope(&inbox, holder))?;
        if self.store().delete_inbox(id, &inbox.segment(), holder, item)? == 0 {
            return Err(Fail::NotFound);
        }
        Ok(Value::null())
    }

    // Registrations and key packages.

    fn put_registration(&self, id: &Hash, tag: &Hash, req: &Req) -> R<Value> {
        let identity = self.identity(id)?;
        let (app, _) = self.tag_state(&identity, tag)?.ok_or_else(|| forbidden("tag isn't bound to an app"))?;
        let p = self.permit(
            Request::PutRegistration,
            req,
            &identity,
            Scope { app: Some((&app, RECEIVE)), ..Default::default() },
        )?;
        let cert = Certificate::from_value(req.value()?).map_err(|e| Fail::Bad(e.to_string()))?;
        if cert.client_fp() != p.by() || cert.app != app || !cert.has(RECEIVE) || cert.check(&identity).is_err() {
            return Err(forbidden("a client registers with its own receive certificate for the tag's app"));
        }
        self.store().put_registration(id, tag, &cert.client_fp(), &cert.to_bytes())?;
        Ok(Value::null())
    }

    fn delete_registration(&self, id: &Hash, tag: &Hash, client: &Hash, req: &Req) -> R<Value> {
        let identity = self.identity(id)?;
        self.permit(Request::DeleteRegistration, req, &identity, Scope::default())?;
        self.store().delete_registration(id, tag, client)?;
        Ok(Value::null())
    }

    fn post_key_packages(&self, id: &Hash, tag: &Hash, req: &Req) -> R<Value> {
        let identity = self.identity(id)?;
        let (app, current) = self.tag_state(&identity, tag)?.ok_or_else(|| forbidden("tag isn't bound to an app"))?;
        if !current {
            return Err(forbidden("tag is marked old"));
        }
        let p =
            self.permit(Request::PostKeyPackages, req, &identity, Scope { tag: Some(tag), ..Default::default() })?;
        let v = req.value()?;
        let pkgs: Vec<KeyPackage> = v
            .as_array()
            .ok_or_else(|| bad("key package list"))?
            .iter()
            .map(KeyPackage::from_value)
            .collect::<Result<_, _>>()
            .map_err(|e| Fail::Bad(e.to_string()))?;
        for k in &pkgs {
            if k.credential.certificate.client_fp() != p.by() || k.credential.check(&identity, &app).is_err() {
                return Err(forbidden("key package credential doesn't check out"));
            }
        }
        let mut s = self.store();
        s.transaction(|s| {
            for k in &pkgs {
                s.add_key_package(id, tag, &p.by(), &k.to_value().to_bytes())?;
            }
            Ok(())
        })?;
        Ok(Value::null())
    }

    fn get_key_packages(&self, id: &Hash, tag: &Hash) -> R<Value> {
        let identity = self.identity(id)?;
        let Some((app, _)) = self.tag_state(&identity, tag)? else { return Ok(Value::Array(Vec::new())) };
        let regs = self.store().registrations(id, tag)?;
        let mut out = Vec::new();
        for (client, _) in regs {
            if self.registered(&identity, tag, &app, &client)?.is_none() {
                continue;
            }
            if let Some(k) = self.store().take_key_package(id, tag, &client)? {
                out.extend(Value::from_bytes(&k));
            }
        }
        Ok(Value::Array(out))
    }

    fn delete_key_packages(&self, id: &Hash, tag: &Hash, req: &Req) -> R<Value> {
        let identity = self.identity(id)?;
        self.permit(Request::DeleteKeyPackages, req, &identity, Scope::default())?;
        self.store().delete_key_packages(id, tag)?;
        Ok(Value::null())
    }

    // Profiles and blobs.

    /// The newest profile record from each current device; records from devices no longer
    /// current are dropped.
    fn current_profiles(&self, identity: &Identity) -> R<Vec<Profile>> {
        let rows = self.store().profiles(&identity.id)?;
        let mut out = Vec::new();
        for (device, data) in rows {
            let p = Value::from_bytes(&data).and_then(|v| Profile::from_value(v).ok());
            match p {
                Some(p) if identity.is_current(&device) && p.signature_valid(identity) => out.push(p),
                _ => self.store().delete_profile(&identity.id, &device)?,
            }
        }
        Ok(out)
    }

    fn get_profile(&self, id: &Hash) -> R<Value> {
        let identity = self.identity(id)?;
        Ok(Value::Array(self.current_profiles(&identity)?.iter().map(|p| p.to_value().clone()).collect()))
    }

    fn put_profile(&self, id: &Hash, req: &Req) -> R<Value> {
        let identity = self.identity(id)?;
        self.permit(Request::PutProfile, req, &identity, Scope::default())?;
        let p = Profile::from_value(req.value()?).map_err(|e| Fail::Bad(e.to_string()))?;
        if p.identity != *id || !p.signature_valid(&identity) || !identity.is_current(&p.by) {
            return Err(forbidden("profile record must be signed by a current device"));
        }
        let held = self.current_profiles(&identity)?;
        if held.iter().any(|h| h.version >= p.version) {
            return Err(Fail::Conflict("version must be higher than any held from a current device".into()));
        }
        let data = p.to_value().to_bytes();
        let old = held.iter().find(|h| h.by == p.by).map_or(0, |h| h.to_value().to_bytes().len() as u64);
        self.check_quota(id, old, data.len() as u64)?;
        self.store().put_profile(id, &p.by, &data)?;
        Ok(Value::null())
    }

    fn put_blob(&self, id: &Hash, hash: &Hash, req: &Req) -> R<Value> {
        let identity = self.identity(id)?;
        self.permit(Request::PutBlob, req, &identity, Scope::default())?;
        let v = req.value()?;
        let data = v.as_bytes().ok_or_else(|| bad("blob"))?;
        if sha256(data) != *hash {
            return Err(Fail::Bad("blob doesn't match its hash".into()));
        }
        self.check_quota(id, 0, data.len() as u64)?;
        self.store().put_blob(id, hash, data)?;
        Ok(Value::null())
    }

    fn get_blob(&self, hash: &Hash) -> R<Value> {
        Ok(Value::Bytes(self.store().blob(hash)?.ok_or(Fail::NotFound)?))
    }

    fn delete_blob(&self, id: &Hash, hash: &Hash, req: &Req) -> R<Value> {
        let identity = self.identity(id)?;
        self.permit(Request::DeleteBlob, req, &identity, Scope::default())?;
        self.store().delete_blob(id, hash)?;
        Ok(Value::null())
    }

    // Pairing.

    fn post_pairing(&self, req: &Req) -> R<Value> {
        let keys = PairingKeys::from_value(&req.value()?).map_err(|e| Fail::Bad(e.to_string()))?;
        let id = hex::encode(crypto::random::<16>());
        self.store().add_pairing(&id, &keys.to_value().to_bytes(), now() + 600)?;
        Ok(Value::map([("url", format!("{}/aza/v1/pairing/{id}", self.config.url).into())]))
    }

    fn get_pairing(&self, pid: &str) -> R<Value> {
        let (keys, _) = self.store().pairing(pid)?.ok_or(Fail::NotFound)?;
        Value::from_bytes(&keys).ok_or_else(|| Fail::Internal("stored pairing keys".into()))
    }

    fn put_pairing_reply(&self, pid: &str, req: &Req) -> R<Value> {
        let v = req.value()?;
        v.get("sealed").and_then(Value::as_bytes).ok_or_else(|| bad("pairing reply"))?;
        self.store().pairing(pid)?.ok_or(Fail::NotFound)?;
        if self.store().set_pairing_reply(pid, &v.to_bytes())? == 0 {
            return Err(Fail::Conflict("this pairing already has a reply".into()));
        }
        Ok(Value::null())
    }

    fn get_pairing_reply(&self, pid: &str) -> R<Value> {
        let (_, reply) = self.store().pairing(pid)?.ok_or(Fail::NotFound)?;
        Value::from_bytes(&reply.ok_or(Fail::NotFound)?).ok_or_else(|| Fail::Internal("stored pairing reply".into()))
    }

    // Tags.

    fn put_tag(&self, id: &Hash, tag: &Hash, req: &Req) -> R<Value> {
        let identity = self.identity(id)?;
        let device = self.permit(Request::PutTag, req, &identity, Scope::default())?.by();
        let v = req.value()?;
        let app = v
            .get("app")
            .and_then(Value::as_text)
            .filter(|a| aza::certificate::is_app_id(a))
            .ok_or_else(|| bad("tag binding"))?;
        let current = v.get("current").and_then(Value::as_bool).ok_or_else(|| bad("tag binding"))?;
        self.store().put_tag(id, tag, app, current, &device)?;
        Ok(Value::null())
    }
}

fn respond(result: R<Value>) -> Response {
    let (status, body) = match result {
        Ok(v) => (StatusCode::OK, v.to_bytes()),
        Err(f) => {
            let (status, msg) = match f {
                Fail::Bad(m) => (StatusCode::BAD_REQUEST, m),
                Fail::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m),
                Fail::Forbidden(m) => (StatusCode::FORBIDDEN, m),
                Fail::NotFound => (StatusCode::NOT_FOUND, "not found".into()),
                Fail::Conflict(m) => (StatusCode::CONFLICT, m),
                Fail::TooLarge(m) => (StatusCode::PAYLOAD_TOO_LARGE, m),
                Fail::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
            };
            (status, error_body(&msg))
        }
    };
    (status, [("content-type", "application/cbor")], body).into_response()
}

async fn handle(State(node): State<Arc<Node>>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let Some(rest) = uri.path().strip_prefix(aza::node::API) else { return respond(Err(Fail::NotFound)) };
    let req = Req {
        method,
        segs: rest.split('/').map(str::to_string).collect(),
        path: uri.path_and_query().map_or_else(|| uri.path().to_string(), |p| p.as_str().to_string()),
        query: uri
            .query()
            .unwrap_or("")
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        auth: headers.get("aza-auth").and_then(|h| h.to_str().ok()).map(str::to_string),
        body,
    };
    let result = tokio::task::spawn_blocking(move || node.dispatch(req))
        .await
        .unwrap_or_else(|e| Err(Fail::Internal(e.to_string())));
    respond(result)
}

/// For health checks: 200 while the database answers, 503 otherwise.
async fn healthz(State(node): State<Arc<Node>>) -> StatusCode {
    match tokio::task::spawn_blocking(move || node.store().ping()).await {
        Ok(Ok(())) => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// The node's HTTP routes: the node API, and `/healthz` for health checks.
pub fn router(node: Arc<Node>) -> axum::Router {
    axum::Router::new()
        .route("/healthz", axum::routing::get(healthz))
        .fallback(handle)
        .layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024))
        .with_state(node)
}

/// Serves a node on a listener until the process ends.
pub async fn serve(config: Config, listener: tokio::net::TcpListener) -> std::io::Result<()> {
    let node = Node::new(config).map_err(std::io::Error::other)?;
    axum::serve(listener, router(node)).await
}
