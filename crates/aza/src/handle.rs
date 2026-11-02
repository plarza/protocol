//! Handles, section 6: a registrable domain proven with a DNS record.
use crate::crypto::Hash;
use crate::error::{Error, Result};

/// Whether `s` is a registrable domain, like `sidny.me` or `example.com.au`, but never a
/// subdomain like `blog.sidny.me`.
pub fn is_handle(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && crate::certificate::is_app_id(s)
        && psl::domain_str(s) == Some(s)
}

/// The TXT record a handle's owner adds at `_aza.<handle>`.
pub fn txt_record(identity: &Hash, node: &str) -> String {
    format!("aza={} node={}", hex::encode(identity), node)
}

/// What a `_aza` TXT record says: the identity ID and home node URL.
pub fn parse_txt(txt: &str) -> Option<(Hash, String)> {
    let mut id = None;
    let mut node = None;
    for part in txt.split_whitespace() {
        if let Some(v) = part.strip_prefix("aza=") {
            id = hex::decode(v).ok().and_then(|b| b.try_into().ok());
        } else if let Some(v) = part.strip_prefix("node=") {
            node = Some(v.to_string());
        }
    }
    Some((id?, node?))
}

/// Looks up TXT records through a public DNS-over-HTTPS resolver.
pub trait Resolver: Send + Sync {
    fn txt(&self, name: &str) -> impl std::future::Future<Output = Result<Vec<String>>> + Send;
}

/// A DNS-over-HTTPS resolver speaking the JSON API, such as `https://cloudflare-dns.com/dns-query`.
pub struct DohResolver {
    pub url: String,
    http: reqwest::Client,
}

impl Default for DohResolver {
    fn default() -> Self {
        DohResolver { url: "https://cloudflare-dns.com/dns-query".into(), http: reqwest::Client::new() }
    }
}

impl Resolver for DohResolver {
    async fn txt(&self, name: &str) -> Result<Vec<String>> {
        let mut url = url::Url::parse(&self.url).map_err(|_| Error::Malformed("resolver URL"))?;
        url.query_pairs_mut().append_pair("name", name).append_pair("type", "TXT");
        let resp = self.http.get(url).header("accept", "application/dns-json").send().await?.error_for_status()?;
        let json: serde_json::Value =
            serde_json::from_slice(&resp.bytes().await?).map_err(|_| Error::Malformed("DNS answer"))?;
        Ok(json["Answer"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|r| r["type"].as_u64() == Some(16))
                    .filter_map(|r| r["data"].as_str())
                    .map(|d| d.split('"').enumerate().filter(|(i, _)| i % 2 == 1).map(|(_, s)| s).collect::<String>())
                    .collect()
            })
            .unwrap_or_default())
    }
}

/// Looks up a handle's record, returning the identity ID and node URL it names.
pub async fn lookup(resolver: &impl Resolver, handle: &str) -> Result<Vec<(Hash, String)>> {
    if !is_handle(handle) {
        return Err(Error::Malformed("handle"));
    }
    Ok(resolver.txt(&format!("_aza.{handle}")).await?.iter().filter_map(|t| parse_txt(t)).collect())
}

/// Whether the handle's DNS record names this identity; apps show a handle only if it does.
pub async fn verify(resolver: &impl Resolver, handle: &str, identity: &Hash) -> bool {
    lookup(resolver, handle).await.is_ok_and(|records| records.iter().any(|(id, _)| id == identity))
}
