//! Hosted masters, section 8.2: a provider holds the master and its next key for people who
//! sign up with a login of the provider's own, and hands off when they take control.
use crate::aza_app::{AzaApp, HandoffSigner};
use crate::change::{Change, Unsigned};
use crate::crypto::Hash;
use crate::error::{Error, Result};
use std::collections::HashMap;
use std::sync::Mutex;

/// A provider. Logins (an email address or anything else) are between the person and the
/// provider and never appear in the protocol.
pub struct Provider {
    pub node: String,
    pub min_work: u32,
    accounts: Mutex<HashMap<String, AzaApp>>,
    by_identity: Mutex<HashMap<Hash, String>>,
}

impl Provider {
    pub fn new(node: &str, min_work: u32) -> Provider {
        Provider { node: node.into(), min_work, accounts: Default::default(), by_identity: Default::default() }
    }

    /// Signs someone up: creates an identity whose master (and next key) the provider holds.
    pub async fn sign_up(&self, login: &str) -> Result<Hash> {
        if self.accounts.lock().unwrap().contains_key(login) {
            return Err(Error::Conflict("that login already has an identity".into()));
        }
        let app = AzaApp::create_hosted(&self.node, self.min_work).await?;
        let id = app.identity;
        self.by_identity.lock().unwrap().insert(id, login.into());
        self.accounts.lock().unwrap().insert(login.into(), app);
        Ok(id)
    }

    fn take(&self, login: &str) -> Result<AzaApp> {
        self.accounts.lock().unwrap().remove(login).ok_or(Error::NotFound("account".into()))
    }

    fn put(&self, login: &str, app: AzaApp) {
        self.accounts.lock().unwrap().insert(login.into(), app);
    }

    /// When the person logs in on a new phone, the provider uses the master to add it, from the
    /// phone's pairing QR code.
    pub async fn add_device(&self, login: &str, qr: &str) -> Result<Hash> {
        let mut app = self.take(login)?;
        let r = app.approve_pairing(qr).await;
        self.put(login, app);
        r
    }

    pub fn identity_of(&self, login: &str) -> Option<Hash> {
        self.accounts.lock().unwrap().get(login).map(|a| a.identity)
    }

    /// Runs `f` with the account's aza app, for anything else a master does.
    pub async fn with_account<T>(&self, login: &str, f: impl AsyncFnOnce(&mut AzaApp) -> Result<T>) -> Result<T> {
        let mut app = self.take(login)?;
        let r = f(&mut app).await;
        self.put(login, app);
        r
    }

    fn login_of(&self, identity: &Hash) -> Result<String> {
        self.by_identity.lock().unwrap().get(identity).cloned().ok_or(Error::NotFound("hosted identity".into()))
    }
}

impl HandoffSigner for Provider {
    fn next_public_key(&self, identity: &Hash) -> Result<Vec<u8>> {
        let login = self.login_of(identity)?;
        self.accounts.lock().unwrap().get(&login).ok_or(Error::NotFound("account".into()))?.next_public_key()
    }

    /// Signs exactly the `set-master` change the person's aza app built, then forgets the
    /// master: the provider can't take the identity back.
    fn sign_handoff(&self, identity: &Hash, change: &Unsigned) -> Result<Change> {
        let login = self.login_of(identity)?;
        let mut accounts = self.accounts.lock().unwrap();
        let app = accounts.get_mut(&login).ok_or(Error::NotFound("account".into()))?;
        app.sign_handoff(change)
    }
}
