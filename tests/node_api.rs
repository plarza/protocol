//! The node API (section 11.1) and the rules around it, against real nodes.
use aza::aza_app::{AzaApp, Endorse, Pairing};
use aza::certificate::{PUBLISH, READ, RECEIVE, SIGN_IN, WRITE};
use aza::client::{self, Client};
use aza::crypto::{Hash, SigningKey, sha256};
use aza::data::contact_tag;
use aza::message::InboxItem;
use aza::node::{Inbox, NodeClient, Signer, auth_message};
use aza::{Error, Value};

async fn client(app: &mut AzaApp, id: &str, scopes: &[&str]) -> Client {
    let (mut c, req) = Client::new(id, scopes, &format!("https://{id}/aza")).unwrap();
    let returned = app.approve_url(&req.approve_url()).await.unwrap();
    c.receive_certificate_url(&returned).await.unwrap();
    c
}

fn status(e: Error) -> u16 {
    match e {
        Error::Node { status, .. } => status,
        e => panic!("expected a node error, got {e:?}"),
    }
}

/// Sends a raw request with an `aza-auth` header built from the given parts.
#[allow(clippy::too_many_arguments)]
async fn raw(
    node: &str,
    method: &str,
    path: &str,
    identity: &Hash,
    by: &Hash,
    key: &SigningKey,
    host: &str,
    time: u64,
    nonce: [u8; 16],
) -> u16 {
    let sig = key.sign(&auth_message(host, method, path, time, &nonce, b""));
    let header = Value::map([
        ("identity", (*identity).into()),
        ("by", (*by).into()),
        ("time", time.into()),
        ("nonce", nonce.to_vec().into()),
        ("sig", sig.into()),
    ]);
    use base64::Engine;
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header.to_bytes());
    reqwest::Client::new()
        .request(method.parse().unwrap(), format!("{node}{path}"))
        .header("aza-auth", header)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test(flavor = "multi_thread")]
async fn aza_auth_rejects_wrong_host_stale_time_and_replays() {
    let node = aza_tests::node().await;
    let app = AzaApp::create(&node, "A", 6).await.unwrap();
    let (id, dev, key) = (app.identity, app.device().id, app.device().key.clone());
    let host = node.strip_prefix("http://").unwrap();
    let path = format!("/aza/v1/envelopes/{}/{}", hex(&id), hex(&dev));
    let now = aza::change::now();
    assert_eq!(raw(&node, "GET", &path, &id, &dev, &key, host, now, [1; 16]).await, 200);
    assert_eq!(raw(&node, "GET", &path, &id, &dev, &key, host, now, [1; 16]).await, 401, "nonce reused");
    assert_eq!(raw(&node, "GET", &path, &id, &dev, &key, "other.example", now, [2; 16]).await, 401, "another host");
    assert_eq!(raw(&node, "GET", &path, &id, &dev, &key, host, now - 600, [3; 16]).await, 401, "too old");
    assert_eq!(raw(&node, "GET", &path, &id, &dev, &key, host, now, [4; 16]).await, 200);
    let stranger = SigningKey::generate();
    assert_eq!(raw(&node, "GET", &path, &id, &dev, &stranger, host, now, [5; 16]).await, 401, "wrong key");
    // The header signs the exact path, query included.
    let other_path = format!("{path}?x=1");
    let sig = key.sign(&auth_message(host, "GET", &path, now, &[6; 16], b""));
    let header = Value::map([
        ("identity", id.into()),
        ("by", dev.into()),
        ("time", now.into()),
        ("nonce", vec![6u8; 16].into()),
        ("sig", sig.into()),
    ]);
    use base64::Engine;
    let resp = reqwest::Client::new()
        .get(format!("{node}{other_path}"))
        .header("aza-auth", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header.to_bytes()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn scopes_decide_what_clients_may_do() {
    let node = aza_tests::node().await;
    let mut app = AzaApp::create(&node, "A", 6).await.unwrap();
    let mut reader = client(&mut app, "notes.example", &[READ]).await;
    let mut writer = client(&mut app, "notes.example", &[READ, WRITE]).await;
    let mut other_app = client(&mut app, "other.example", &[READ, WRITE]).await;
    writer.write("a", 1, b"one").await.unwrap();
    assert_eq!(reader.read_all().await.unwrap()[0].data, b"one");
    assert!(matches!(reader.write("a", 2, b"two").await, Err(Error::Refused(_))));
    // The node refuses it too, whatever the client tries.
    let junk =
        aza::data::SyncItem::seal(app.identity, "notes.example", "a", 2, app.log().current_secret(), &[0; 32], b"two");
    assert_eq!(status(app.node().put_sync(&junk, &reader.signer().unwrap()).await.unwrap_err()), 403);
    assert!(other_app.read_all().await.unwrap().is_empty(), "a client sees only its own app");
    // A client can't publish without `publish`, and can't sign in without `sign-in`.
    assert!(writer.publish("x", Some("y".into())).await.is_err());
    // Write implies read: such a request is refused before it reaches the aza app.
    assert!(Client::new("notes.example", &[WRITE], "https://notes.example/aza").is_err());
    // Revoking a client stops it at once.
    let fp = writer.fingerprint();
    app.revoke_client(&fp).await.unwrap();
    let err = writer.read_all().await.unwrap_err();
    assert!(matches!(err, Error::Node { status: 403, .. }), "{err:?}");
    assert!(!app.approvals().await.unwrap().iter().any(|c| c.client_fp() == fp));
    // A signed-out device can't make requests either.
    let pairing = Pairing::start(&node, "B").await.unwrap();
    // The new device asks until another device has approved it.
    assert!(matches!(pairing.finish().await, Err(Error::NotFound(_))));
    let b = app.approve_pairing(&pairing.qr).await.unwrap();
    let mut b_app = pairing.finish().await.unwrap().confirm();
    app.sign_out(&b, Endorse::None).await.unwrap();
    assert!(b_app.approvals().await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn writes_need_the_current_secret_and_the_next_version() {
    let node = aza_tests::node().await;
    let mut app = AzaApp::create(&node, "A", 6).await.unwrap();
    let mut c = client(&mut app, "notes.example", &[READ, WRITE]).await;
    c.write("n", 1, b"v1").await.unwrap();
    assert_eq!(status(c.write("n", 3, b"v3").await.unwrap_err()), 409);
    // After the master replaces the data secret, the item is re-encrypted and old-secret writes
    // are refused.
    let old = app.log().current_secret();
    let old_secret = app.data_secret(&old).await.unwrap();
    let new = app.replace_data_secret().await.unwrap();
    assert_ne!(old, new);
    let items = c.read_all().await.unwrap();
    assert_eq!(items[0].data, b"v1");
    assert_eq!(items[0].version, 2);
    let stale = aza::data::SyncItem::seal(
        app.identity,
        "notes.example",
        "n",
        3,
        old,
        &aza::data::app_key(&old_secret, "notes.example"),
        b"x",
    );
    let signer = Signer { identity: app.identity, by: app.device().id, key: app.device().key.clone() };
    assert_eq!(status(app.node().put_sync(&stale, &signer).await.unwrap_err()), 409);
    c.write("n", 3, b"v3").await.unwrap();
    // A non-master can't replace the secret.
    app.forget_master();
    assert!(app.replace_data_secret().await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn storage_limits_never_block_the_change_log() {
    let node = aza_tests::node_with(|c| c.quota = 60_000).await;
    let mut app = AzaApp::create(&node, "A", 6).await.unwrap();
    let mut c = client(&mut app, "notes.example", &[READ, WRITE]).await;
    let big = vec![7u8; 30_000];
    c.write("big", 1, &big).await.unwrap();
    let err = c.write("bigger", 1, &big).await.unwrap_err();
    assert_eq!(status(err), 413);
    let pairing = Pairing::start(&node, "B").await.unwrap();
    let b = app.approve_pairing(&pairing.qr).await;
    let b = match b {
        Ok(b) => b,
        Err(_) => app.log().current_ordinary_devices().iter().find(|d| d.label.as_deref() == Some("B")).unwrap().id,
    };
    // The sign-out goes through even though storage is full.
    let out = aza::change::Unsigned {
        identity: Some(app.identity),
        prev: app.log().heads(),
        time: aza::change::now(),
        by: Some(app.device().id),
        body: aza::change::Body::SignOut { device: b, endorse: None },
    }
    .sign(&app.device().key);
    app.node().post_log(&app.identity, &[out]).await.unwrap();
    assert!(!app.refresh().await.unwrap().is_current(&b));
}

#[tokio::test(flavor = "multi_thread")]
async fn profiles_follow_the_version_rule_and_current_devices() {
    let node = aza_tests::node().await;
    let mut a = AzaApp::create(&node, "A", 6).await.unwrap();
    a.set_name("first").await.unwrap();
    let png = [0x89u8, b'P', b'N', b'G', 1, 2, 3];
    let p = a.set_picture(&png, "image/png").await.unwrap();
    let pic = p.picture().unwrap();
    let nc = NodeClient::new(&node).unwrap();
    let blob = nc.get_blob(&a.identity, &pic.hash).await.unwrap().unwrap();
    assert!(pic.matches(&blob, "image/png"));
    assert!(!pic.matches(&blob, "image/webp"));
    // Any node can serve a copy by hash, and readers check it.
    assert!(nc.get_blob(&[0; 32], &pic.hash).await.unwrap().is_some());
    // A lower version is refused.
    let signer = Signer { identity: a.identity, by: a.device().id, key: a.device().key.clone() };
    let low = aza::profile::Profile::sign(
        a.identity,
        1,
        Value::map([("name", "old".into())]),
        a.device().id,
        &a.device().key,
    )
    .unwrap();
    assert_eq!(status(nc.put_profile(&low, &signer).await.unwrap_err()), 409);
    // A stolen device's huge version disappears once it is signed out.
    let pairing = Pairing::start(&node, "B").await.unwrap();
    let b_id = a.approve_pairing(&pairing.qr).await.unwrap();
    let mut b = pairing.finish().await.unwrap().confirm();
    b.update_profile(|f| f.with("name", "thief".into())).await.unwrap();
    let huge = aza::profile::Profile::sign(
        a.identity,
        u64::MAX / 2,
        Value::map([("name", "frozen".into())]),
        b_id,
        &b.device().key,
    )
    .unwrap();
    nc.put_profile(&huge, &Signer { identity: a.identity, by: b_id, key: b.device().key.clone() }).await.unwrap();
    assert_eq!(a.profile().await.unwrap().unwrap().name(), Some("frozen"));
    a.sign_out(&b_id, Endorse::None).await.unwrap();
    let records = nc.get_profile(&a.identity).await.unwrap();
    assert!(records.iter().all(|r| r.by != b_id), "records from devices no longer current are dropped");
    a.set_name("back").await.unwrap();
    assert_eq!(a.profile().await.unwrap().unwrap().name(), Some("back"));
    // Contact publishing puts the secret in the profile.
    a.publish_contact(true).await.unwrap();
    let c = a.contact_secret().await.unwrap();
    assert_eq!(a.profile().await.unwrap().unwrap().contact(), Some(c.secret));
}

#[tokio::test(flavor = "multi_thread")]
async fn moving_home_keeps_everything_and_clients_follow() {
    let old = aza_tests::node().await;
    let new = aza_tests::node().await;
    let mut a = AzaApp::create(&old, "A", 6).await.unwrap();
    a.set_name("mover").await.unwrap();
    let mut notes = client(&mut a, "notes.example", &[READ, WRITE]).await;
    notes.write("todo", 1, b"move house").await.unwrap();
    let mut posts = client(&mut a, "plarza.com", &[SIGN_IN, PUBLISH]).await;
    posts.publish("posts/1", Some("before the move".into())).await.unwrap();
    let mut msgs = client(&mut a, "messenger.example", &[RECEIVE]).await;
    msgs.register().await.unwrap();
    a.move_home(&new).await.unwrap();
    assert_eq!(a.log().home().as_deref(), Some(new.as_str()));
    assert_eq!(a.node().url, new);
    // Clients whose certificate names the old node follow the latest set-home.
    assert_eq!(notes.read_all().await.unwrap()[0].data, b"move house");
    notes.write("todo", 2, b"done").await.unwrap();
    let new_nc = NodeClient::new(&new).unwrap();
    assert!(new_nc.get_profile(&a.identity).await.unwrap().iter().any(|p| p.name() == Some("mover")));
    let records = client::read_records(&old, &a.identity, "plarza.com").await.unwrap();
    assert_eq!(records[0].content.as_ref().unwrap().as_text(), Some("before the move"));
    // The old node keeps answering for the log, including the set-home.
    let old_log =
        aza::identity::Identity::read(a.identity, NodeClient::new(&old).unwrap().get_log(&a.identity).await.unwrap())
            .unwrap();
    assert_eq!(old_log.home().as_deref(), Some(new.as_str()));
    // Messages reach the new node: tags were bound again there.
    let c = a.contact_secret().await.unwrap();
    let tag = contact_tag(&c.secret, "messenger.example");
    client::send_message(&old, &a.identity, &tag, msgs.certificate().unwrap(), b"hello at the new place")
        .await
        .unwrap();
    assert_eq!(msgs.inbox().await.unwrap()[0].plaintext, b"hello at the new place");
}

#[tokio::test(flavor = "multi_thread")]
async fn old_tags_keep_conversations_but_take_no_new_key_packages() {
    let node = aza_tests::node().await;
    let mut a = AzaApp::create(&node, "A", 6).await.unwrap();
    let app = "messenger.example";
    let mut m = client(&mut a, app, &[RECEIVE]).await;
    m.register().await.unwrap();
    m.publish_key_packages(&[(b"k1".to_vec(), b"p1".to_vec())]).await.unwrap();
    let old = contact_tag(&a.contact_secret().await.unwrap().secret, app);
    a.replace_contact_secret().await.unwrap();
    let new = contact_tag(&a.contact_secret().await.unwrap().secret, app);
    assert_ne!(old, new);
    assert!(
        client::fetch_key_packages(&node, &a.identity, app, &old).await.unwrap().is_empty(),
        "old tags have no key packages"
    );
    let tags = m.contact_tags().await.unwrap();
    assert_eq!(tags.iter().map(|t| t.0).collect::<Vec<_>>(), vec![new, old], "newest generation first");
    m.register().await.unwrap();
    // Publishing under the old tag is refused; the client publishes under the newest.
    let refused = NodeClient::new(&node).unwrap().post_key_packages(&a.identity, &old, &[], &m.signer().unwrap()).await;
    assert_eq!(status(refused.unwrap_err()), 403);
    m.publish_key_packages(&[(b"k2".to_vec(), b"p2".to_vec())]).await.unwrap();
    assert_eq!(client::fetch_key_packages(&node, &a.identity, app, &new).await.unwrap().len(), 1);
    // People already in conversations still deliver under the old tag.
    client::send_message(&node, &a.identity, &old, m.certificate().unwrap(), b"still here").await.unwrap();
    assert!(m.inbox().await.unwrap().iter().any(|x| x.plaintext == b"still here"));
}

#[tokio::test(flavor = "multi_thread")]
async fn inboxes_accept_only_registered_holders() {
    let node = aza_tests::node().await;
    let mut a = AzaApp::create(&node, "A", 6).await.unwrap();
    let app = "messenger.example";
    let mut m = client(&mut a, app, &[RECEIVE]).await;
    m.register().await.unwrap();
    let tag = contact_tag(&a.contact_secret().await.unwrap().secret, app);
    let nc = NodeClient::new(&node).unwrap();
    let enc = m.certificate().unwrap().enc.clone().unwrap();
    let stray = InboxItem::seal([9; 32], &enc, b"to nobody").unwrap();
    assert_eq!(status(nc.post_inbox(&a.identity, Inbox::Tag(tag), &stray).await.unwrap_err()), 403);
    let unknown_tag = InboxItem::seal(m.fingerprint(), &enc, b"x").unwrap();
    let unbound = nc.post_inbox(&a.identity, Inbox::Tag([1; 32]), &unknown_tag).await;
    assert!(matches!(unbound, Err(Error::NotFound(_))), "a tag that isn't bound has no inbox");
    // Requests go only to a current ordinary device.
    let master = a.log().master().unwrap();
    let to_master = InboxItem::seal(master.id, &master.enc, b"hi").unwrap();
    assert_eq!(status(nc.post_inbox(&a.identity, Inbox::Requests, &to_master).await.unwrap_err()), 403);
    // A device deleting a registration only causes a short gap: the client registers again.
    let signer = Signer { identity: a.identity, by: a.device().id, key: a.device().key.clone() };
    nc.delete_registration(&a.identity, &tag, &m.fingerprint(), &signer).await.unwrap();
    let item = InboxItem::seal(m.fingerprint(), &enc, b"after").unwrap();
    assert_eq!(status(nc.post_inbox(&a.identity, Inbox::Tag(tag), &item).await.unwrap_err()), 403);
    assert!(m.inbox().await.unwrap().is_empty());
    nc.post_inbox(&a.identity, Inbox::Tag(tag), &item).await.unwrap();
    assert_eq!(m.inbox().await.unwrap()[0].plaintext, b"after");
    // Someone else can't read the client's inbox.
    let device = Signer { identity: a.identity, by: a.device().id, key: a.device().key.clone() };
    assert_eq!(
        status(nc.get_inbox(&a.identity, Inbox::Tag(tag), &m.fingerprint(), 0, &device).await.unwrap_err()),
        403
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn revoking_a_publishing_client_hides_its_records_for_good() {
    let node = aza_tests::node().await;
    let mut a = AzaApp::create(&node, "A", 6).await.unwrap();
    let mut p = client(&mut a, "plarza.com", &[PUBLISH]).await;
    let mut q = client(&mut a, "plarza.com", &[PUBLISH]).await;
    p.publish("posts/p", Some("from p".into())).await.unwrap();
    q.publish("posts/q", Some("from q".into())).await.unwrap();
    a.revoke_client(&p.fingerprint()).await.unwrap();
    let records = client::read_records(&node, &a.identity, "plarza.com").await.unwrap();
    assert_eq!(records.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["posts/q"]);
    assert!(p.publish("posts/p2", Some("x".into())).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn envelopes_are_read_only_by_their_holder() {
    let node = aza_tests::node().await;
    let mut a = AzaApp::create(&node, "A", 6).await.unwrap();
    let r1 = client(&mut a, "notes.example", &[READ]).await;
    let r2 = client(&mut a, "notes.example", &[READ]).await;
    let nc = NodeClient::new(&node).unwrap();
    let id = a.identity;
    assert_eq!(nc.get_envelopes(&id, &r2.fingerprint(), &r2.signer().unwrap()).await.unwrap().len(), 1);
    assert_eq!(status(nc.get_envelopes(&id, &r1.fingerprint(), &r2.signer().unwrap()).await.unwrap_err()), 403);
    let sign_in_only = client(&mut a, "game.example", &[SIGN_IN]).await;
    let s3 = sign_in_only.signer().unwrap();
    assert_eq!(status(nc.get_envelopes(&id, &sign_in_only.fingerprint(), &s3).await.unwrap_err()), 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_keeps_only_the_first_reply_and_checks_the_keys() {
    let node = aza_tests::node().await;
    let mut a = AzaApp::create(&node, "A", 6).await.unwrap();
    let pairing = Pairing::start(&node, "B").await.unwrap();
    let (url, _) = aza::certificate::parse_qr_payload(&pairing.qr).unwrap();
    // A QR code whose hash doesn't match the stored keys is refused.
    let tampered = aza::certificate::qr_payload(&url, &sha256(b"other keys"));
    assert!(a.approve_pairing(&tampered).await.is_err());
    a.approve_pairing(&pairing.qr).await.unwrap();
    assert!(NodeClient::put_pairing_reply(&url, b"second reply").await.is_err());
    let b = pairing.finish().await.unwrap();
    assert_eq!(b.identity, a.identity);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_master_backup_restores_an_identity_after_every_device_is_lost() {
    let node = aza_tests::node().await;
    let mut a = AzaApp::create(&node, "lost phone", 6).await.unwrap();
    let mut notes = client(&mut a, "notes.example", &[READ, WRITE]).await;
    notes.write("n", 1, b"keep me").await.unwrap();
    let file = a.backup_master("pw").unwrap();
    let id = a.identity;
    drop(a);
    let mut restored = AzaApp::restore(&file, "pw", "new phone").await.unwrap();
    assert_eq!(restored.identity, id);
    assert!(!restored.holds_master());
    let secret = restored.log().current_secret();
    restored.data_secret(&secret).await.unwrap();
    assert_eq!(restored.approvals().await.unwrap().len(), 1);
    assert!(AzaApp::restore(&file, "wrong", "x").await.is_err());
}

fn hex(h: &Hash) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn healthz_answers_outside_the_api() {
    let node = aza_tests::node().await;
    let res = reqwest::get(format!("{node}/healthz")).await.unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let res = reqwest::get(format!("{node}/aza/v1/nothing")).await.unwrap();
    assert_eq!(res.status().as_u16(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_signs_itself_out_and_the_others_take_over() {
    let node = aza_tests::node().await;
    let mut phone = AzaApp::create(&node, "iPhone", 6).await.unwrap();
    phone.set_name("aiden").await.unwrap();
    let phone_id = phone.device().id;
    // The Mac joins through the iPhone, so its envelope of the data secret is the iPhone's.
    let pairing = Pairing::start(&node, "Mac").await.unwrap();
    phone.approve_pairing(&pairing.qr).await.unwrap();
    let mut mac = pairing.finish().await.unwrap().confirm();
    mac.upkeep().await.unwrap();
    let mut plarza = client(&mut phone, "plarza.com", &[SIGN_IN, PUBLISH]).await;
    plarza.publish("posts/a", Some(Value::from("hello"))).await.unwrap();
    let mut notes = client(&mut mac, "notes.example", &[READ, WRITE]).await;
    notes.write("n", 1, b"kept").await.unwrap();

    // With the master backed up and off it, the iPhone signs itself out, endorsing the posts
    // made through its approvals.
    phone.backup_master("pw").unwrap();
    phone.forget_master();
    phone.sign_out(&phone_id, Endorse::AllExcept(Vec::new())).await.unwrap();
    let log = phone.refresh().await.unwrap().clone();
    assert!(!log.is_current(&phone_id));
    assert!(phone.set_name("gone").await.is_err(), "a signed-out device signs nothing more");
    assert!(plarza.publish("posts/b", Some(Value::from("late"))).await.is_err(), "its approvals end");
    let posts = client::read_records(&node, &mac.identity, "plarza.com").await.unwrap();
    assert!(posts.iter().any(|r| r.name == "posts/a" && r.content.is_some()), "endorsed posts stay");

    // The Mac notices on its next upkeep and takes over the iPhone's profile record and envelopes.
    mac.upkeep().await.unwrap();
    let profile = mac.profile().await.unwrap().unwrap();
    assert_eq!(profile.name(), Some("aiden"));
    assert_eq!(profile.by, mac.device().id);
    let secret = mac.log().current_secret();
    mac.data_secret(&secret).await.unwrap();
    assert_eq!(notes.read_all().await.unwrap()[0].data, b"kept");
    // And a fresh Mac session still opens the data secret.
    let mut again = AzaApp::load(&mac.save()).unwrap();
    again.refresh().await.unwrap();
    again.data_secret(&secret).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_last_device_signs_out_and_its_backup_brings_everything_back() {
    let node = aza_tests::node().await;
    let mut phone = AzaApp::create(&node, "iPhone", 6).await.unwrap();
    phone.set_name("aiden").await.unwrap();
    let mut notes = client(&mut phone, "notes.example", &[READ, WRITE]).await;
    notes.write("n", 1, b"kept").await.unwrap();
    let file = phone.backup_master("pw").unwrap();
    // Still holding the master, the iPhone signs itself out and hands its work to the master.
    let phone_id = phone.device().id;
    phone.sign_out(&phone_id, Endorse::AllExcept(Vec::new())).await.unwrap();
    phone.forget_master();
    assert!(phone.log().current_ordinary_devices().is_empty());

    let mut restored = AzaApp::restore(&file, "pw", "new iPhone").await.unwrap();
    assert_eq!(restored.profile().await.unwrap().unwrap().name(), Some("aiden"));
    let secret = restored.log().current_secret();
    restored.data_secret(&secret).await.unwrap();
    // Approvals the iPhone signed ended with it; signing in again reads the same data.
    assert!(notes.read_all().await.is_err());
    let mut notes = client(&mut restored, "notes.example", &[READ, WRITE]).await;
    assert_eq!(notes.read_all().await.unwrap()[0].data, b"kept");
}
