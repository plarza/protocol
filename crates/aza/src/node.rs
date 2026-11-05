//! Talking to nodes, section 11: URLs, the `aza-auth` header, request bodies, and an HTTP client
//! for every request of the node API.
use crate::Value;
use crate::certificate::{Certificate, b64, unb64};
use crate::change::Change;
use crate::crypto::{self, Hash, SigningKey, sha256};
use crate::data::{Envelope, SyncItem};
use crate::error::{Error, Result};
use crate::message::{InboxItem, KeyPackage};
use crate::profile::Profile;
use crate::record::{InclusionProof, Record};

pub const API: &str = "/aza/v1/";

/// Whether `s` is a node URL: `https` with a host, or `http` on a loopback host for local
/// testing, with no path, query or fragment.
pub fn is_node_url(s: &str) -> bool {
    let Ok(u) = url::Url::parse(s) else { return false };
    let loopback = matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    let scheme_ok = u.scheme() == "https" || (u.scheme() == "http" && loopback);
    scheme_ok
        && u.host_str().is_some_and(|h| !h.is_empty())
        && (u.path() == "/" || u.path().is_empty())
        && !s.ends_with('/')
        && u.query().is_none()
        && u.fragment().is_none()
        && u.username().is_empty()
}

/// The host (and port) the `aza-auth` header names for a node URL.
pub fn host_of(node: &str) -> Result<String> {
    let u = url::Url::parse(node).map_err(|_| Error::Malformed("node URL"))?;
    let host = u.host_str().ok_or(Error::Malformed("node URL"))?;
    Ok(match u.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    })
}

/// An item `name` as a single path segment: every byte other than letters, digits, `-`, `.`,
/// `_` and `~` percent-encoded (verified in `aza_core::names`).
pub fn encode_name(name: &str) -> String {
    String::from_utf8(aza_core::names::encode_name(name.as_bytes())).expect("percent-encoding is ASCII")
}

/// The name a path segment encodes, only if `segment` is exactly its `encode_name`.
pub fn decode_name(segment: &str) -> Option<String> {
    String::from_utf8(aza_core::names::decode_name(segment.as_bytes())?).ok()
}

/// A hash as lowercase hex.
pub fn hex32(h: &Hash) -> String {
    String::from_utf8(aza_core::names::encode_hex(h)).expect("hex is ASCII")
}

/// The hash whose lowercase hex is `s` (verified in `aza_core::names`).
pub fn parse_hex32(s: &str) -> Option<Hash> {
    aza_core::names::decode_hex32(s.as_bytes())
}

/// Who signs a request: a device, or a client by its key fingerprint.
#[derive(Clone, Debug)]
pub struct Signer {
    pub identity: Hash,
    /// A device ID or client key fingerprint.
    pub by: Hash,
    pub key: SigningKey,
}

/// The array an `aza-auth` signature covers.
pub fn auth_message(host: &str, method: &str, path: &str, time: u64, nonce: &[u8], body: &[u8]) -> Vec<u8> {
    Value::Array(vec![
        "aza auth v1".into(),
        host.into(),
        method.into(),
        path.into(),
        time.into(),
        nonce.to_vec().into(),
        sha256(body).into(),
    ])
    .to_bytes()
}

/// A parsed `aza-auth` header.
#[derive(Clone, Debug)]
pub struct Auth {
    pub identity: Hash,
    pub by: Hash,
    pub time: u64,
    pub nonce: [u8; 16],
    pub sig: Vec<u8>,
}

impl Auth {
    pub fn header(signer: &Signer, host: &str, method: &str, path: &str, body: &[u8]) -> String {
        let time = crate::change::now();
        let nonce = crypto::random::<16>();
        let sig = signer.key.sign(&auth_message(host, method, path, time, &nonce, body));
        let v = Value::map([
            ("identity", signer.identity.into()),
            ("by", signer.by.into()),
            ("time", time.into()),
            ("nonce", nonce.to_vec().into()),
            ("sig", sig.into()),
        ]);
        b64(&v.to_bytes())
    }

    pub fn parse(header: &str) -> Result<Auth> {
        let bad = || Error::Malformed("aza-auth header");
        let v = Value::from_bytes(&unb64(header).ok_or_else(bad)?).ok_or_else(bad)?;
        Ok(Auth {
            identity: v.get("identity").and_then(Value::as_hash).ok_or_else(bad)?,
            by: v.get("by").and_then(Value::as_hash).ok_or_else(bad)?,
            time: v.get("time").and_then(Value::as_u64).ok_or_else(bad)?,
            nonce: v.get("nonce").and_then(Value::as_bytes).and_then(|n| n.try_into().ok()).ok_or_else(bad)?,
            sig: v.get("sig").and_then(Value::as_bytes).ok_or_else(bad)?.to_vec(),
        })
    }

    pub fn verify(&self, key: &[u8], host: &str, method: &str, path: &str, body: &[u8]) -> bool {
        crypto::verify(key, &auth_message(host, method, path, self.time, &self.nonce, body), &self.sig)
    }
}

/// A tag binding as a node keeps it (`PUT tags`).
#[derive(Clone, Debug, PartialEq)]
pub struct TagBinding {
    pub tag: Hash,
    pub app: String,
    pub current: bool,
    /// The device that made the mark.
    pub by: Hash,
}

impl TagBinding {
    pub fn to_value(&self) -> Value {
        Value::map([
            ("tag", self.tag.into()),
            ("app", self.app.as_str().into()),
            ("current", self.current.into()),
            ("by", self.by.into()),
        ])
    }

    pub fn from_value(v: &Value) -> Result<TagBinding> {
        let bad = || Error::Malformed("tag binding");
        Ok(TagBinding {
            tag: v.get("tag").and_then(Value::as_hash).ok_or_else(bad)?,
            app: v.get("app").and_then(Value::as_text).ok_or_else(bad)?.into(),
            current: v.get("current").and_then(Value::as_bool).ok_or_else(bad)?,
            by: v.get("by").and_then(Value::as_hash).ok_or_else(bad)?,
        })
    }
}

/// Which inbox: an app's contact tag, or the requests inbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Inbox {
    Tag(Hash),
    Requests,
}

impl Inbox {
    pub fn segment(&self) -> String {
        match self {
            Inbox::Tag(t) => hex32(t),
            Inbox::Requests => "requests".into(),
        }
    }

    pub fn parse(s: &str) -> Option<Inbox> {
        if s == "requests" { Some(Inbox::Requests) } else { parse_hex32(s).map(Inbox::Tag) }
    }

    fn to_value(self) -> Value {
        match self {
            Inbox::Tag(t) => t.into(),
            Inbox::Requests => "requests".into(),
        }
    }

    fn from_value(v: &Value) -> Option<Inbox> {
        match v.as_text() {
            Some("requests") => Some(Inbox::Requests),
            _ => v.as_hash().map(Inbox::Tag),
        }
    }
}

/// Everything a node holds for an identity, for moving (`GET export`, `POST import`).
#[derive(Clone, Debug, Default)]
pub struct Export {
    pub log: Vec<Change>,
    pub sync: Vec<SyncItem>,
    pub envelopes: Vec<Envelope>,
    pub certificates: Vec<Certificate>,
    pub profiles: Vec<Profile>,
    pub records: Vec<Record>,
    pub blobs: Vec<(Hash, Vec<u8>)>,
    pub tags: Vec<TagBinding>,
    pub registrations: Vec<(Hash, Certificate)>,
    pub inbox: Vec<(Inbox, InboxItem)>,
    /// (tag, client key fingerprint, key package)
    pub key_packages: Vec<(Hash, Hash, KeyPackage)>,
}

impl Export {
    pub fn to_value(&self) -> Value {
        let arr = |v: Vec<Value>| Value::Array(v);
        Value::map([
            ("log", arr(self.log.iter().map(|c| c.to_value().clone()).collect())),
            ("sync", arr(self.sync.iter().map(SyncItem::to_value).collect())),
            ("envelopes", arr(self.envelopes.iter().map(|e| e.to_value().clone()).collect())),
            ("certificates", arr(self.certificates.iter().map(|c| c.to_value().clone()).collect())),
            ("profiles", arr(self.profiles.iter().map(|p| p.to_value().clone()).collect())),
            ("records", arr(self.records.iter().map(|r| r.to_value().clone()).collect())),
            (
                "blobs",
                arr(self
                    .blobs
                    .iter()
                    .map(|(h, d)| Value::map([("hash", (*h).into()), ("data", d.clone().into())]))
                    .collect()),
            ),
            ("tags", arr(self.tags.iter().map(TagBinding::to_value).collect())),
            (
                "registrations",
                arr(self
                    .registrations
                    .iter()
                    .map(|(t, c)| Value::map([("tag", (*t).into()), ("certificate", c.to_value().clone())]))
                    .collect()),
            ),
            (
                "inbox",
                arr(self
                    .inbox
                    .iter()
                    .map(|(b, i)| Value::map([("box", b.to_value()), ("item", i.to_value())]))
                    .collect()),
            ),
            (
                "keypackages",
                arr(self
                    .key_packages
                    .iter()
                    .map(|(t, c, k)| {
                        Value::map([("tag", (*t).into()), ("client", (*c).into()), ("package", k.to_value())])
                    })
                    .collect()),
            ),
        ])
    }

    pub fn from_value(v: &Value) -> Result<Export> {
        let bad = || Error::Malformed("export");
        let list = |k: &str| v.get(k).and_then(Value::as_array).ok_or_else(bad);
        Ok(Export {
            log: list("log")?.iter().map(|c| Change::from_value(c.clone())).collect::<Result<_>>()?,
            sync: list("sync")?.iter().map(SyncItem::from_value).collect::<Result<_>>()?,
            envelopes: list("envelopes")?.iter().map(|e| Envelope::from_value(e.clone())).collect::<Result<_>>()?,
            certificates: list("certificates")?
                .iter()
                .map(|c| Certificate::from_value(c.clone()))
                .collect::<Result<_>>()?,
            profiles: list("profiles")?.iter().map(|p| Profile::from_value(p.clone())).collect::<Result<_>>()?,
            records: list("records")?.iter().map(|r| Record::from_value(r.clone())).collect::<Result<_>>()?,
            blobs: list("blobs")?
                .iter()
                .map(|b| {
                    let blob = || Some((b.get("hash")?.as_hash()?, b.get("data")?.as_bytes()?.to_vec()));
                    blob().ok_or_else(bad)
                })
                .collect::<Result<_>>()?,
            tags: list("tags")?.iter().map(TagBinding::from_value).collect::<Result<_>>()?,
            registrations: list("registrations")?
                .iter()
                .map(|r| {
                    Ok((
                        r.get("tag").and_then(Value::as_hash).ok_or_else(bad)?,
                        Certificate::from_value(r.get("certificate").ok_or_else(bad)?.clone())?,
                    ))
                })
                .collect::<Result<_>>()?,
            inbox: list("inbox")?
                .iter()
                .map(|i| {
                    Ok((
                        i.get("box").and_then(Inbox::from_value).ok_or_else(bad)?,
                        InboxItem::from_value(i.get("item").ok_or_else(bad)?)?,
                    ))
                })
                .collect::<Result<_>>()?,
            key_packages: list("keypackages")?
                .iter()
                .map(|k| {
                    Ok((
                        k.get("tag").and_then(Value::as_hash).ok_or_else(bad)?,
                        k.get("client").and_then(Value::as_hash).ok_or_else(bad)?,
                        KeyPackage::from_value(k.get("package").ok_or_else(bad)?)?,
                    ))
                })
                .collect::<Result<_>>()?,
        })
    }
}

/// A page of items stored or changed since a counter, and the node's new counter.
#[derive(Clone, Debug)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub counter: u64,
}

/// The public keys a new device stores with `POST pairing`.
#[derive(Clone, Debug, PartialEq)]
pub struct PairingKeys {
    pub key: Vec<u8>,
    pub enc: Vec<u8>,
    pub label: String,
}

impl PairingKeys {
    pub fn to_value(&self) -> Value {
        Value::map([
            ("key", self.key.clone().into()),
            ("enc", self.enc.clone().into()),
            ("label", self.label.as_str().into()),
        ])
    }

    pub fn from_value(v: &Value) -> Result<PairingKeys> {
        let bad = || Error::Malformed("pairing keys");
        Ok(PairingKeys {
            key: v
                .get("key")
                .and_then(Value::as_bytes)
                .filter(|k| k.len() == crypto::PUBLIC_KEY_LEN)
                .ok_or_else(bad)?
                .to_vec(),
            enc: v
                .get("enc")
                .and_then(Value::as_bytes)
                .filter(|e| crypto::is_enc_public_key(e))
                .ok_or_else(bad)?
                .to_vec(),
            label: v.get("label").and_then(Value::as_text).ok_or_else(bad)?.into(),
        })
    }

    /// The hash shown in the QR code next to the pairing URL.
    pub fn hash(&self) -> Hash {
        sha256(&self.to_value().to_bytes())
    }
}

/// What the approving device tells the new one, sealed to its encryption key.
#[derive(Clone, Debug, PartialEq)]
pub struct PairingReply {
    pub identity: Hash,
    pub node: String,
    pub device: Hash,
}

impl PairingReply {
    pub fn to_value(&self) -> Value {
        Value::map([
            ("identity", self.identity.into()),
            ("node", self.node.as_str().into()),
            ("device", self.device.into()),
        ])
    }

    pub fn from_value(v: &Value) -> Result<PairingReply> {
        let bad = || Error::Malformed("pairing reply");
        Ok(PairingReply {
            identity: v.get("identity").and_then(Value::as_hash).ok_or_else(bad)?,
            node: v.get("node").and_then(Value::as_text).ok_or_else(bad)?.into(),
            device: v.get("device").and_then(Value::as_hash).ok_or_else(bad)?,
        })
    }
}

/// A CBOR body for an error response.
pub fn error_body(message: &str) -> Vec<u8> {
    Value::map([("error", message.into())]).to_bytes()
}

/// An HTTP client for one node.
#[derive(Clone, Debug)]
pub struct NodeClient {
    pub url: String,
    host: String,
    http: reqwest::Client,
}

impl NodeClient {
    pub fn new(url: &str) -> Result<NodeClient> {
        if !is_node_url(url) {
            return Err(Error::Malformed("node URL"));
        }
        Ok(NodeClient { url: url.to_string(), host: host_of(url)?, http: reqwest::Client::new() })
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: String,
        body: Option<Value>,
        signer: Option<&Signer>,
    ) -> Result<Option<Value>> {
        let full = format!("{API}{path}");
        let body = body.map(|b| b.to_bytes()).unwrap_or_default();
        let mut req = self.http.request(method.clone(), format!("{}{full}", self.url));
        if !body.is_empty() {
            req = req.header("content-type", "application/cbor").body(body.clone());
        }
        if let Some(s) = signer {
            req = req.header("aza-auth", Auth::header(s, &self.host, method.as_str(), &full, &body));
        }
        let resp = req.send().await?;
        let status = resp.status();
        let bytes = resp.bytes().await?;
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            let message = Value::from_bytes(&bytes)
                .and_then(|v| v.get("error").and_then(Value::as_text).map(str::to_string))
                .unwrap_or_else(|| String::from_utf8_lossy(&bytes).into_owned());
            return Err(Error::Node { status: status.as_u16(), message });
        }
        if bytes.is_empty() {
            return Ok(Some(Value::null()));
        }
        Ok(Some(Value::from_bytes(&bytes).ok_or(Error::Malformed("node response"))?))
    }

    async fn get(&self, path: String, signer: Option<&Signer>) -> Result<Option<Value>> {
        self.call(reqwest::Method::GET, path, None, signer).await
    }

    async fn send(&self, method: reqwest::Method, path: String, body: Value, signer: Option<&Signer>) -> Result<Value> {
        self.call(method, path.clone(), Some(body), signer).await?.ok_or(Error::NotFound(path))
    }

    async fn delete(&self, path: String, signer: &Signer) -> Result<()> {
        self.call(reqwest::Method::DELETE, path.clone(), None, Some(signer)).await?.ok_or(Error::NotFound(path))?;
        Ok(())
    }

    fn page<T>(v: Option<Value>, parse: impl Fn(&Value) -> Result<T>) -> Result<Page<T>> {
        let Some(v) = v else { return Ok(Page { items: Vec::new(), counter: 0 }) };
        let bad = || Error::Malformed("page");
        Ok(Page {
            items: v
                .get("items")
                .and_then(Value::as_array)
                .ok_or_else(bad)?
                .iter()
                .map(parse)
                .collect::<Result<_>>()?,
            counter: v.get("counter").and_then(Value::as_u64).ok_or_else(bad)?,
        })
    }

    fn list<T>(v: Option<Value>, parse: impl Fn(&Value) -> Result<T>) -> Result<Vec<T>> {
        match v {
            None => Ok(Vec::new()),
            Some(v) => v.as_array().ok_or(Error::Malformed("list"))?.iter().map(parse).collect(),
        }
    }

    // Change logs.

    pub async fn get_log(&self, identity: &Hash) -> Result<Vec<Change>> {
        Self::list(self.get(format!("log/{}", hex32(identity)), None).await?, |c| Change::from_value(c.clone()))
    }

    pub async fn post_log(&self, identity: &Hash, changes: &[Change]) -> Result<()> {
        let body = Value::Array(changes.iter().map(|c| c.to_value().clone()).collect());
        self.send(reqwest::Method::POST, format!("log/{}", hex32(identity)), body, None).await?;
        Ok(())
    }

    pub async fn get_export(&self, identity: &Hash, signer: &Signer) -> Result<Export> {
        let v = self
            .get(format!("export/{}", hex32(identity)), Some(signer))
            .await?
            .ok_or(Error::NotFound("export".into()))?;
        Export::from_value(&v)
    }

    pub async fn post_import(&self, identity: &Hash, export: &Export, signer: &Signer) -> Result<()> {
        self.send(reqwest::Method::POST, format!("import/{}", hex32(identity)), export.to_value(), Some(signer))
            .await?;
        Ok(())
    }

    // Sync data.

    pub async fn get_sync(&self, identity: &Hash, app: &str, since: u64, signer: &Signer) -> Result<Page<SyncItem>> {
        let v = self.get(format!("sync/{}/{}?since={since}", hex32(identity), app), Some(signer)).await?;
        Self::page(v, SyncItem::from_value)
    }

    pub async fn put_sync(&self, item: &SyncItem, signer: &Signer) -> Result<()> {
        let path = format!("sync/{}/{}/{}", hex32(&item.identity), item.app, encode_name(&item.name));
        self.send(reqwest::Method::PUT, path, item.to_value(), Some(signer)).await?;
        Ok(())
    }

    // Certificates and envelopes.

    pub async fn post_certificate(&self, cert: &Certificate, signer: &Signer) -> Result<()> {
        self.send(
            reqwest::Method::POST,
            format!("certificates/{}", hex32(&cert.identity)),
            cert.to_value().clone(),
            Some(signer),
        )
        .await?;
        Ok(())
    }

    pub async fn get_envelopes(&self, identity: &Hash, holder: &Hash, signer: &Signer) -> Result<Vec<Envelope>> {
        let v = self.get(format!("envelopes/{}/{}", hex32(identity), hex32(holder)), Some(signer)).await?;
        Self::list(v, |e| Envelope::from_value(e.clone()))
    }

    pub async fn post_envelopes(&self, identity: &Hash, envelopes: &[Envelope], signer: &Signer) -> Result<()> {
        let body = Value::Array(envelopes.iter().map(|e| e.to_value().clone()).collect());
        self.send(reqwest::Method::POST, format!("envelopes/{}", hex32(identity)), body, Some(signer)).await?;
        Ok(())
    }

    // Public records.

    pub async fn get_records(&self, identity: &Hash, app: &str, since: u64) -> Result<Page<Record>> {
        let v = self.get(format!("records/{}/{}?since={since}", hex32(identity), app), None).await?;
        Self::page(v, |r| Record::from_value(r.clone()))
    }

    pub async fn put_record(&self, record: &Record, signer: &Signer) -> Result<()> {
        let path = format!("records/{}/{}/{}", hex32(&record.identity), record.app, encode_name(&record.name));
        self.send(reqwest::Method::PUT, path, record.to_value().clone(), Some(signer)).await?;
        Ok(())
    }

    pub async fn put_endorsed(&self, record: &Record, proof: &InclusionProof, signer: &Signer) -> Result<()> {
        let path = format!(
            "records/{}/{}/{}/{}/endorsed",
            hex32(&record.identity),
            record.app,
            encode_name(&record.name),
            record.version
        );
        self.send(reqwest::Method::PUT, path, proof.to_value(), Some(signer)).await?;
        Ok(())
    }

    // Inboxes.

    pub async fn post_inbox(&self, identity: &Hash, inbox: Inbox, item: &InboxItem) -> Result<()> {
        self.send(
            reqwest::Method::POST,
            format!("inbox/{}/{}", hex32(identity), inbox.segment()),
            item.to_value(),
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn get_inbox(
        &self,
        identity: &Hash,
        inbox: Inbox,
        holder: &Hash,
        since: u64,
        signer: &Signer,
    ) -> Result<Page<InboxItem>> {
        let path = format!("inbox/{}/{}/{}?since={since}", hex32(identity), inbox.segment(), hex32(holder));
        Self::page(self.get(path, Some(signer)).await?, InboxItem::from_value)
    }

    pub async fn delete_inbox(
        &self,
        identity: &Hash,
        inbox: Inbox,
        holder: &Hash,
        item: &Hash,
        signer: &Signer,
    ) -> Result<()> {
        self.delete(format!("inbox/{}/{}/{}/{}", hex32(identity), inbox.segment(), hex32(holder), hex32(item)), signer)
            .await
    }

    // Registrations, key packages and tags.

    pub async fn put_registration(
        &self,
        identity: &Hash,
        tag: &Hash,
        cert: &Certificate,
        signer: &Signer,
    ) -> Result<()> {
        let path = format!("registrations/{}/{}", hex32(identity), hex32(tag));
        self.send(reqwest::Method::PUT, path, cert.to_value().clone(), Some(signer)).await?;
        Ok(())
    }

    pub async fn delete_registration(&self, identity: &Hash, tag: &Hash, client: &Hash, signer: &Signer) -> Result<()> {
        self.delete(format!("registrations/{}/{}/{}", hex32(identity), hex32(tag), hex32(client)), signer).await
    }

    pub async fn post_key_packages(
        &self,
        identity: &Hash,
        tag: &Hash,
        packages: &[KeyPackage],
        signer: &Signer,
    ) -> Result<()> {
        let body = Value::Array(packages.iter().map(KeyPackage::to_value).collect());
        self.send(reqwest::Method::POST, format!("keypackages/{}/{}", hex32(identity), hex32(tag)), body, Some(signer))
            .await?;
        Ok(())
    }

    pub async fn get_key_packages(&self, identity: &Hash, tag: &Hash) -> Result<Vec<KeyPackage>> {
        let v = self.get(format!("keypackages/{}/{}", hex32(identity), hex32(tag)), None).await?;
        Self::list(v, KeyPackage::from_value)
    }

    pub async fn delete_key_packages(&self, identity: &Hash, tag: &Hash, signer: &Signer) -> Result<()> {
        self.delete(format!("keypackages/{}/{}", hex32(identity), hex32(tag)), signer).await
    }

    pub async fn put_tag(&self, identity: &Hash, tag: &Hash, app: &str, current: bool, signer: &Signer) -> Result<()> {
        let body = Value::map([("app", app.into()), ("current", current.into())]);
        self.send(reqwest::Method::PUT, format!("tags/{}/{}", hex32(identity), hex32(tag)), body, Some(signer)).await?;
        Ok(())
    }

    // Profiles and blobs.

    pub async fn get_profile(&self, identity: &Hash) -> Result<Vec<Profile>> {
        let v = self.get(format!("profile/{}", hex32(identity)), None).await?;
        Self::list(v, |p| Profile::from_value(p.clone()))
    }

    pub async fn put_profile(&self, profile: &Profile, signer: &Signer) -> Result<()> {
        self.send(
            reqwest::Method::PUT,
            format!("profile/{}", hex32(&profile.identity)),
            profile.to_value().clone(),
            Some(signer),
        )
        .await?;
        Ok(())
    }

    pub async fn put_blob(&self, identity: &Hash, data: &[u8], signer: &Signer) -> Result<Hash> {
        let hash = sha256(data);
        self.send(
            reqwest::Method::PUT,
            format!("blobs/{}/{}", hex32(identity), hex32(&hash)),
            data.to_vec().into(),
            Some(signer),
        )
        .await?;
        Ok(hash)
    }

    pub async fn get_blob(&self, identity: &Hash, hash: &Hash) -> Result<Option<Vec<u8>>> {
        let v = self.get(format!("blobs/{}/{}", hex32(identity), hex32(hash)), None).await?;
        Ok(match v {
            None => None,
            Some(v) => Some(v.as_bytes().ok_or(Error::Malformed("blob"))?.to_vec()).filter(|d| sha256(d) == *hash),
        })
    }

    pub async fn delete_blob(&self, identity: &Hash, hash: &Hash, signer: &Signer) -> Result<()> {
        self.delete(format!("blobs/{}/{}", hex32(identity), hex32(hash)), signer).await
    }

    // Pairing.

    /// Stores a new device's public keys; returns the pairing URL.
    pub async fn post_pairing(&self, keys: &PairingKeys) -> Result<String> {
        let v = self.send(reqwest::Method::POST, "pairing".into(), keys.to_value(), None).await?;
        Ok(v.get("url").and_then(Value::as_text).ok_or(Error::Malformed("pairing response"))?.to_string())
    }

    /// Fetches the keys behind a pairing URL and checks them against the QR code's hash.
    pub async fn fetch_pairing(pairing_url: &str, hash: &Hash) -> Result<PairingKeys> {
        let bytes = reqwest::get(pairing_url).await?.error_for_status()?.bytes().await?;
        let keys = PairingKeys::from_value(&Value::from_bytes(&bytes).ok_or(Error::Malformed("pairing keys"))?)?;
        if keys.hash() != *hash {
            return Err(Error::Refused("pairing keys don't match the QR code".into()));
        }
        Ok(keys)
    }

    pub async fn put_pairing_reply(pairing_url: &str, sealed: &[u8]) -> Result<()> {
        let body = Value::map([("sealed", sealed.to_vec().into())]).to_bytes();
        let resp = reqwest::Client::new()
            .put(format!("{pairing_url}/reply"))
            .header("content-type", "application/cbor")
            .body(body)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Error::Node { status: resp.status().as_u16(), message: "pairing reply refused".into() });
        }
        Ok(())
    }

    pub async fn get_pairing_reply(pairing_url: &str) -> Result<Option<Vec<u8>>> {
        let resp = reqwest::get(format!("{pairing_url}/reply")).await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let bytes = resp.error_for_status()?.bytes().await?;
        let v = Value::from_bytes(&bytes).ok_or(Error::Malformed("pairing reply"))?;
        Ok(Some(v.get("sealed").and_then(Value::as_bytes).ok_or(Error::Malformed("pairing reply"))?.to_vec()))
    }
}
