//! Running real nodes for the end-to-end tests.
use aza::crypto::Hash;
use aza::handle::Resolver;
use aza_node::Config;
use std::collections::HashMap;
use std::sync::Mutex;

/// Starts a node on a free loopback port and returns its URL.
pub async fn node() -> String {
    node_with(|_| {}).await
}

pub async fn node_with(configure: impl FnOnce(&mut Config)) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let mut config = Config::new(&url);
    configure(&mut config);
    tokio::spawn(aza_node::serve(config, listener));
    url
}

/// A DNS resolver holding records the test sets, standing in for DNS-over-HTTPS.
#[derive(Default)]
pub struct FakeDns {
    records: Mutex<HashMap<String, Vec<String>>>,
}

impl FakeDns {
    pub fn set(&self, name: &str, txt: &str) {
        self.records.lock().unwrap().entry(name.into()).or_default().push(txt.into());
    }
}

impl Resolver for FakeDns {
    async fn txt(&self, name: &str) -> aza::Result<Vec<String>> {
        Ok(self.records.lock().unwrap().get(name).cloned().unwrap_or_default())
    }
}

pub fn short(h: &Hash) -> String {
    h[..4].iter().map(|b| format!("{b:02x}")).collect()
}
