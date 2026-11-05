//! An app's own server: hosting certificate requests for the other-machine path, receiving
//! certificates, and checking sign-ins (section 7).
use crate::certificate::{self, Certificate, Request};
use crate::client::fetch_identity;
use crate::crypto;
use crate::error::{Error, Result};
use crate::identity::Identity;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// The server side of one app.
pub struct App {
    pub id: String,
    /// Requests stored at `/.well-known/aza/request/<id>`.
    requests: Mutex<HashMap<String, Vec<u8>>>,
    /// Client keys this app's clients made; certificates for any other key are dropped.
    created: Mutex<HashSet<Vec<u8>>>,
    /// Certificates received at the return URL, waiting for the client that asked.
    received: Mutex<HashMap<Vec<u8>, Certificate>>,
    challenges: Mutex<HashSet<[u8; 32]>>,
}

impl App {
    pub fn new(id: &str) -> Result<App> {
        if !certificate::is_app_id(id) {
            return Err(Error::Malformed("app ID"));
        }
        Ok(App {
            id: id.into(),
            requests: Default::default(),
            created: Default::default(),
            received: Default::default(),
            challenges: Default::default(),
        })
    }

    /// Stores a client's request for the other-machine path. Returns the request's URL and the
    /// QR code payload (the URL and the request's hash).
    pub fn host_request(&self, request: &Request) -> Result<(String, String)> {
        if request.app != self.id {
            return Err(Error::Refused("request is for another app".into()));
        }
        request.validate()?;
        let id = hex::encode(crypto::random::<16>());
        let bytes = request.to_value().to_bytes();
        let url = Request::well_known_url(&self.id, &id);
        let qr = certificate::qr_payload(&url, &crypto::sha256(&bytes));
        self.requests.lock().unwrap().insert(id, bytes);
        self.created.lock().unwrap().insert(request.client.clone());
        Ok((url, qr))
    }

    /// Serves `GET /.well-known/aza/request/<id>`.
    pub fn request(&self, id: &str) -> Option<Vec<u8>> {
        self.requests.lock().unwrap().get(id).cloned()
    }

    /// Notes a client key this app's client made on the same machine.
    pub fn created_client(&self, client: &[u8]) {
        self.created.lock().unwrap().insert(client.to_vec());
    }

    /// Handles the aza app's `POST` to the return URL; drops certificates for client keys this
    /// app didn't create.
    pub fn receive_certificate(&self, body: &[u8]) -> Result<()> {
        let cert = Certificate::from_bytes(body)?;
        if cert.app != self.id || !self.created.lock().unwrap().contains(&cert.client) {
            return Err(Error::Refused("certificate for a client key this app didn't create".into()));
        }
        self.received.lock().unwrap().insert(cert.client.clone(), cert);
        Ok(())
    }

    /// Hands a received certificate to the client that asked.
    pub fn take_certificate(&self, client: &[u8]) -> Option<Certificate> {
        self.received.lock().unwrap().remove(client)
    }

    /// 32 fresh random bytes for a client to sign.
    pub fn challenge(&self) -> [u8; 32] {
        let c = crypto::random();
        self.challenges.lock().unwrap().insert(c);
        c
    }

    /// Checks a sign-in: fetches the change log from the certificate's node (then the home node),
    /// and runs checks 1 to 5. Each challenge works once.
    pub async fn check_sign_in(&self, cert: &Certificate, challenge: &[u8; 32], proof: &[u8]) -> Result<Identity> {
        if !self.challenges.lock().unwrap().remove(challenge) {
            return Err(Error::Refused("unknown or used challenge".into()));
        }
        let (log, _) = fetch_identity(&cert.node, &cert.identity).await?;
        cert.check_sign_in(&log, &self.id, challenge, proof)?;
        Ok(log)
    }
}
