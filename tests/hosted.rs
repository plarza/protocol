//! Hosted masters (section 8.2): taking control from a provider that misbehaves.
use aza::aza_app::{AzaApp, HandoffSigner, Pairing};
use aza::backup;
use aza::certificate::{PUBLISH, SIGN_IN};
use aza::change::{Change, Unsigned};
use aza::client::Client;
use aza::crypto::{Hash, SigningKey};
use aza::node::NodeClient;

/// A provider that publishes its own handoff to the person's keys, leaving the person's
/// devices out of `prev`, and secretly keeps its next key.
struct SneakyProvider {
    node: NodeClient,
    next: SigningKey,
}

impl HandoffSigner for SneakyProvider {
    fn next_public_key(&self, _: &Hash) -> aza::Result<Vec<u8>> {
        Ok(self.next.public().to_vec())
    }

    fn sign_handoff(&self, identity: &Hash, change: &Unsigned) -> aza::Result<Change> {
        let mut variant = change.clone();
        variant.prev = vec![*identity];
        let variant = variant.sign(&self.next);
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.node.post_log(identity, &[variant]))
        })?;
        Ok(change.clone().sign(&self.next))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn taking_control_survives_a_provider_that_publishes_its_own_handoff() {
    let node = aza_tests::node().await;
    let mut hosted = AzaApp::create_hosted(&node, 6).await.unwrap();
    let id = hosted.identity;
    let next = backup::open(&hosted.backup_master("pw").unwrap(), "pw").unwrap().next.unwrap();
    let provider_master = hosted.log().master().unwrap().id;

    // The person logs in on a phone; the provider's master adds it and approves an app.
    let pairing = Pairing::start(&node, "Phone").await.unwrap();
    let old_phone = hosted.approve_pairing(&pairing.qr).await.unwrap();
    let mut phone = pairing.finish().await.unwrap().confirm();
    let (mut plarza, req) = Client::new("plarza.com", &[SIGN_IN, PUBLISH], "https://plarza.com/aza").unwrap();
    let returned = hosted.approve_url(&req.approve_url()).await.unwrap();
    plarza.receive_certificate_url(&returned).await.unwrap();

    let sneaky = SneakyProvider { node: NodeClient::new(&node).unwrap(), next: next.clone() };
    let took = phone.take_control(&sneaky, |_| true).await.unwrap();
    let log = phone.refresh().await.unwrap().clone();
    assert!(!log.has_master_conflict(), "the aza app didn't upload a competing handoff");
    assert_eq!(log.master().unwrap().id, took.master.id, "the person is the master anyway");
    assert!(log.is_current(&took.master.id));
    assert!(!log.is_current(&provider_master));
    assert!(took.differing.contains(&old_phone), "the left-out addition is shown");
    assert!(!log.is_current(&old_phone), "the phone's old device was discarded and removed");
    assert_ne!(phone.device().id, old_phone);
    assert!(log.is_current(&phone.device().id), "this machine joined again with new keys");
    assert_eq!(took.provider_approvals.len(), 1, "approvals the provider's master signed are listed");
    assert!(took.provider_approvals[0].check(&log).is_err());
    // The data secret is the person's own now.
    let current = log.current_secret();
    phone.data_secret(&current).await.unwrap();
    assert!(hosted.data_secret(&current).await.is_err());

    // The provider can never take the identity back, but its old next key can still break it.
    let competing = Unsigned {
        identity: Some(id),
        prev: vec![id],
        time: aza::change::now(),
        by: None,
        body: aza::change::Body::SetMaster {
            reveal: next.public().to_vec(),
            key: SigningKey::generate().public().to_vec(),
            enc: aza::crypto::EncKey::generate().public().to_vec(),
            next: SigningKey::generate().fingerprint(),
            endorse: None,
        },
    }
    .sign(&next);
    NodeClient::new(&node).unwrap().post_log(&id, &[competing]).await.unwrap();
    let log = phone.refresh().await.unwrap();
    assert!(log.has_master_conflict());
    assert!(log.master().is_none());
}
