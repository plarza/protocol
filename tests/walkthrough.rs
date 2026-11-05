//! Section 14, end to end: aiden's identity from creation to messages, against a real node.
use aza::app::App;
use aza::aza_app::{AzaApp, Endorse, Pairing};
use aza::certificate::{PUBLISH, READ, RECEIVE, SIGN_IN, WRITE};
use aza::change::{Body, Unsigned, now};
use aza::client::{self, Client};
use aza::crypto::{EncKey, SigningKey};
use aza::data::contact_tag;
use aza::handle;
use aza::node::NodeClient;
use aza::provider::Provider;
use aza::{Error, Value};
use aza_tests::FakeDns;

#[tokio::test(flavor = "multi_thread")]
async fn walkthrough() {
    let node = aza_tests::node().await;
    let nc = NodeClient::new(&node).unwrap();

    // 1. Create: the master, a next key, the first data secret, a contact secret and the
    // iPhone's device; the iPhone signs a profile with aiden's name.
    let mut phone = AzaApp::create(&node, "iPhone", 6).await.unwrap();
    let id = phone.identity;
    phone.set_name("aiden").await.unwrap();
    let log = phone.log().clone();
    let master_id = log.master().unwrap().id;
    assert_eq!(master_id, id, "the first master's device ID is the identity ID");
    assert!(log.is_current(&phone.device().id));
    assert_eq!(log.current_ordinary_devices().len(), 1);

    // 2. Back up: the master's keys and its next key into one file, then off the iPhone.
    let master_file = phone.backup_master("correct horse").unwrap();
    phone.forget_master();
    assert!(!phone.holds_master());
    assert!(matches!(aza::backup::open(&master_file, "wrong"), Err(Error::BadPassword)));

    // 3. Laptop: the Mac pairs through the node; the iPhone approves it.
    let pairing = Pairing::start(&node, "MacBook").await.unwrap();
    let mac_id = phone.approve_pairing(&pairing.qr).await.unwrap();
    let joined = pairing.finish().await.unwrap();
    assert_eq!(joined.identity, id);
    assert_eq!(joined.name.as_deref(), Some("aiden"));
    let mut mac = joined.confirm();
    assert_eq!(mac.device().id, mac_id);
    let secret_name = mac.log().current_secret();
    let first_secret = mac.data_secret(&secret_name).await.unwrap();
    assert_eq!(first_secret, phone.data_secret(&secret_name).await.unwrap());
    mac.profile().await.unwrap();

    // 4. Handle: shown only once the DNS record names the identity.
    let dns = FakeDns::default();
    assert!(!handle::verify(&dns, "sidny.me", &id).await);
    dns.set("_aza.sidny.me", &handle::txt_record(&id, &node));
    mac.set_handle(Some("sidny.me")).await.unwrap();
    assert_eq!(mac.log().handle().as_deref(), Some("sidny.me"));
    assert!(handle::verify(&dns, "sidny.me", &id).await);
    assert!(handle::is_handle("example.com.au"));
    assert!(!handle::is_handle("blog.sidny.me"));
    assert!(mac.set_handle(Some("blog.sidny.me")).await.is_err());

    // 5. A game: coolgame signs in with a certificate from the Mac.
    let coolgame = App::new("coolgame.com").unwrap();
    let (mut game, req) = Client::new("coolgame.com", &[SIGN_IN], "https://coolgame.com/aza").unwrap();
    coolgame.created_client(&req.client);
    let returned = mac.approve_url(&req.approve_url()).await.unwrap();
    assert!(returned.starts_with("https://coolgame.com/aza#aza="));
    game.receive_certificate_url(&returned).await.unwrap();
    let challenge = coolgame.challenge();
    let (cert, proof) = game.sign_in(&challenge).unwrap();
    coolgame.check_sign_in(&cert, &challenge, &proof).await.unwrap();
    assert!(coolgame.check_sign_in(&cert, &challenge, &proof).await.is_err(), "a challenge works once");
    let fresh = coolgame.challenge();
    assert!(coolgame.check_sign_in(&cert, &fresh, &proof).await.is_err(), "a proof is bound to its challenge");
    let wrong_app = App::new("othergame.com").unwrap();
    let c = wrong_app.challenge();
    let (cert2, proof2) = game.sign_in(&c).unwrap();
    assert!(wrong_app.check_sign_in(&cert2, &c, &proof2).await.is_err(), "a certificate is for one app");
    let log_bytes: Vec<u8> = mac.log().changes().iter().flat_map(|c| c.to_bytes()).collect();
    assert!(!log_bytes.windows(12).any(|w| w == b"coolgame.com"), "nothing about coolgame is in the log");
    // A return URL that isn't on the app's own host is refused.
    let mut evil = req.clone();
    evil.return_url = "https://evil.example/aza".into();
    assert!(mac.approve(&evil).await.is_err());
    // A certificate is useless to someone who doesn't hold the client key.
    let (impostor, _) = Client::new("coolgame.com", &[SIGN_IN], "https://coolgame.com/aza").unwrap();
    let c = coolgame.challenge();
    let fake_proof = SigningKey::generate().sign(&aza::certificate::sign_in_message("coolgame.com", &id, &c));
    assert!(coolgame.check_sign_in(&cert, &c, &fake_proof).await.is_err());
    drop(impostor);

    // 7. Offline apps: Coach syncs encrypted workouts through the home node.
    let (mut coach, req) = Client::new("coach.aza.network", &[READ, WRITE], "https://coach.aza.network/aza").unwrap();
    let returned = mac.approve_url(&req.approve_url()).await.unwrap();
    coach.receive_certificate_url(&returned).await.unwrap();
    coach.write("workouts/2026-11-01", 1, b"squats 5x5").await.unwrap();
    let err = coach.write("workouts/2026-11-01", 1, b"deadlifts").await.unwrap_err();
    assert!(matches!(err, Error::Node { status: 409, .. }), "two writers can't both succeed: {err:?}");
    let v = coach.update("workouts/2026-11-01", |old| [old.unwrap(), b", deadlifts 1x5"].concat()).await.unwrap();
    assert_eq!(v, 2);
    let items = coach.read_all().await.unwrap();
    assert_eq!(
        items,
        vec![client::Item {
            name: "workouts/2026-11-01".into(),
            version: 2,
            data: b"squats 5x5, deadlifts 1x5".to_vec()
        }]
    );
    // The node only ever sees ciphertext.
    let raw = nc
        .get_sync(
            &id,
            "coach.aza.network",
            0,
            &aza::node::Signer { identity: id, by: mac_id, key: mac.device().key.clone() },
        )
        .await
        .unwrap();
    assert!(!raw.items[0].ciphertext.windows(6).any(|w| w == b"squats"));

    // 8. Plarza: posts are public records anyone can check came from @sidny.me. One client was
    // approved by the iPhone, one by the Mac.
    let (mut plarza_phone, req) = Client::new("plarza.com", &[SIGN_IN, PUBLISH], "https://plarza.com/aza").unwrap();
    let returned = phone.approve_url(&req.approve_url()).await.unwrap();
    plarza_phone.receive_certificate_url(&returned).await.unwrap();
    let (mut plarza_mac, req) = Client::new("plarza.com", &[SIGN_IN, PUBLISH], "https://plarza.com/aza").unwrap();
    let returned = mac.approve_url(&req.approve_url()).await.unwrap();
    plarza_mac.receive_certificate_url(&returned).await.unwrap();
    plarza_phone.publish("posts/2026-11-01-a", Some(Value::from("hello from my phone"))).await.unwrap();
    plarza_mac.publish("posts/2026-11-01-b", Some(Value::from("hello from my mac"))).await.unwrap();
    plarza_phone.publish("posts/2026-11-01-c", Some(Value::from("soon deleted"))).await.unwrap();
    plarza_phone.publish("posts/2026-11-01-c", None).await.unwrap();
    let posts = client::read_records(&node, &id, "plarza.com").await.unwrap();
    let live: Vec<&str> = posts.iter().filter(|r| r.content.is_some()).map(|r| r.name.as_str()).collect();
    assert_eq!(live, ["posts/2026-11-01-a", "posts/2026-11-01-b"]);
    assert!(posts.iter().any(|r| r.name == "posts/2026-11-01-c" && r.content.is_none()), "deleting stores a tombstone");

    // 6. Stolen phone. Before anyone notices, the thief edits the profile and posts.
    let trusted = phone.log().heads();
    let last_trusted_by_phone = mac_id; // the iPhone signed the Mac's add-device
    phone.set_name("pwned").await.unwrap();
    let defaced = plarza_phone.publish("posts/2026-11-01-a", Some(Value::from("defaced"))).await.unwrap();
    let spam = plarza_phone.publish("posts/2026-11-01-spam", Some(Value::from("buy now"))).await.unwrap();

    // The Mac, not having seen the thief's next moves, signs the iPhone out and endorses the
    // posts made through the iPhone's approvals that aiden still trusts.
    mac.sign_out(&phone.device().id, Endorse::AllExcept(vec![defaced.leaf(), spam.leaf()])).await.unwrap();
    assert!(!mac.log().is_current(&phone.device().id));

    // The thief adds a device and signs out the Mac, faking `prev` so both look older.
    let pk = phone.device().key.clone();
    let thief_key = SigningKey::generate();
    let thief_add = Unsigned {
        identity: Some(id),
        prev: trusted.clone(),
        time: now(),
        by: Some(phone.device().id),
        body: Body::AddDevice {
            key: thief_key.public().to_vec(),
            enc: EncKey::generate().public().to_vec(),
            label: "thief".into(),
        },
    }
    .sign(&pk);
    let thief_out = Unsigned {
        identity: Some(id),
        prev: trusted.clone(),
        time: now(),
        by: Some(phone.device().id),
        body: Body::SignOut { device: mac_id, endorse: None },
    }
    .sign(&pk);
    // Rule 4 ignores the thief's device, so the node doesn't even store its addition.
    assert!(matches!(
        nc.post_log(&id, std::slice::from_ref(&thief_add)).await,
        Err(aza::Error::Node { status: 413, .. })
    ));
    nc.post_log(&id, std::slice::from_ref(&thief_out)).await.unwrap();
    let log = mac.refresh().await.unwrap().clone();
    assert!(log.change(&thief_add.hash()).is_none());
    assert!(!log.is_current(&mac_id), "the faked sign-out counts until the master acts");
    assert!(!log.is_current(&phone.device().id));
    assert!(cert.check(&log).is_err(), "certificates the Mac signed stop working while it is signed out");
    assert!(plarza_phone.certificate().unwrap().check(&log).is_err(), "certificates the iPhone signed stop working");
    // The thief's profile edit disappears with the iPhone.
    assert!(aza::profile::choose(&nc.get_profile(&id).await.unwrap(), &log).is_none());

    // aiden opens the master's backup file on the Mac and removes the iPhone, keeping its changes
    // up to the last one aiden trusts.
    mac.open_master(&master_file, "correct horse").await.unwrap();
    let removal = mac
        .remove_device(
            &phone.device().id,
            Some(last_trusted_by_phone),
            Endorse::AllExcept(vec![defaced.leaf(), spam.leaf()]),
        )
        .await
        .unwrap();
    let log = mac.refresh().await.unwrap().clone();
    assert!(log.is_master_change(&removal.hash()));
    assert!(log.is_discarded(&thief_out.hash()));
    assert!(log.is_current(&mac_id), "the Mac is current again, with everything it did since");
    assert!(cert.check(&log).is_ok(), "coolgame's certificate works again");
    assert_eq!(log.handle().as_deref(), Some("sidny.me"));
    let new_secret = log.current_secret();
    assert_ne!(new_secret, secret_name, "removing a device replaces the data secret");
    assert!(phone.data_secret(&new_secret).await.is_err(), "the iPhone can't read the new data secret");
    // Coach's data was re-encrypted and is still readable.
    let items = coach.read_all().await.unwrap();
    assert_eq!(items[0].data, b"squats 5x5, deadlifts 1x5");
    assert_eq!(coach.refresh().await.unwrap().current_secret(), new_secret);
    // Endorsed posts survive, the thief's don't, and the defaced post shows its earlier version.
    let posts = client::read_records(&node, &id, "plarza.com").await.unwrap();
    let live: Vec<(&str, String)> =
        posts.iter().filter_map(|r| Some((r.name.as_str(), r.content.as_ref()?.as_text()?.to_string()))).collect();
    assert_eq!(
        live,
        [
            ("posts/2026-11-01-a", "hello from my phone".to_string()),
            ("posts/2026-11-01-b", "hello from my mac".to_string())
        ]
    );
    // The profile is signed again with the Mac, from the version aiden saw.
    mac.keep_profile_current().await.unwrap();
    assert_eq!(mac.profile().await.unwrap().unwrap().name(), Some("aiden"));
    // The contact secret is replaced, since the iPhone could read it.
    let old_contact = mac.contact_secrets().await.unwrap();
    let new_contact = mac.replace_contact_secret().await.unwrap();
    assert_eq!(new_contact.generation, old_contact.last().unwrap().generation + 1);
    mac.forget_master();

    // 9. A friend joins through a provider, then takes control a year later.
    let provider = Provider::new(&node, 6);
    let friend_id = provider.sign_up("friend@example.com").await.unwrap();
    let pairing = Pairing::start(&node, "Friend's phone").await.unwrap();
    provider.add_device("friend@example.com", &pairing.qr).await.unwrap();
    let mut friend = pairing.finish().await.unwrap().confirm();
    assert_eq!(friend.identity, friend_id);
    friend.set_name("friend").await.unwrap();
    let hosted_master = friend.log().master().unwrap().id;
    let took = friend.take_control(&provider, |_| true).await.unwrap();
    let flog = friend.refresh().await.unwrap().clone();
    assert_eq!(flog.id, friend_id, "same identity ID");
    assert_ne!(flog.master().unwrap().id, hosted_master);
    assert_eq!(flog.master().unwrap().id, took.master.id);
    assert!(flog.is_current(&friend.device().id));
    assert!(!flog.is_current(&hosted_master), "the provider's master stops being current");
    assert!(aza::identity::Identity::read(friend_id, flog.changes().to_vec()).unwrap().master_chain().len() == 2);
    use aza::aza_app::HandoffSigner;
    assert!(provider.next_public_key(&friend_id).is_err(), "the provider can't hand off again");

    // 10. Messages: a messenger on the Mac receives through its contact tag.
    let app = "messenger.example";
    let (mut messenger, req) = Client::new(app, &[RECEIVE], "https://messenger.example/aza").unwrap();
    let returned = mac.approve_url(&req.approve_url()).await.unwrap();
    messenger.receive_certificate_url(&returned).await.unwrap();
    messenger.register().await.unwrap();
    messenger.publish_key_packages(&[(b"mls-sig-key-1".to_vec(), b"mls-key-package-1".to_vec())]).await.unwrap();
    // A friend scans aiden's contact QR code and works out the tag.
    let contact = mac.contact_secret().await.unwrap();
    let tag = contact_tag(&contact.secret, app);
    let kps = client::fetch_key_packages(&node, &id, app, &tag).await.unwrap();
    assert_eq!(kps.len(), 1);
    assert_eq!(kps[0].package, b"mls-key-package-1");
    assert!(client::fetch_key_packages(&node, &id, app, &tag).await.unwrap().is_empty(), "key packages are single-use");
    client::send_message(&node, &id, &tag, &kps[0].credential.certificate, b"welcome to the group").await.unwrap();
    let inbox = messenger.inbox().await.unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].plaintext, b"welcome to the group");
    messenger.delete_message(&inbox[0]).await.unwrap();
    assert!(messenger.inbox().await.unwrap().is_empty());

    // Someone who doesn't know aiden sends a contact request, and aiden accepts it.
    let (mut stranger, req) = Client::new(app, &[RECEIVE], "https://messenger.example/aza").unwrap();
    let returned = friend.approve_url(&req.approve_url()).await.unwrap();
    stranger.receive_certificate_url(&returned).await.unwrap();
    stranger.send_contact_request(&id, &node, Some("hi, it's your friend")).await.unwrap();
    let requests = mac.contact_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1.note.as_deref(), Some("hi, it's your friend"));
    assert_eq!(requests[0].1.identity, friend_id);
    mac.accept_contact_request(&requests[0].0, &requests[0].1).await.unwrap();
    let accepted = stranger.acceptances(&node).await.unwrap();
    assert_eq!(accepted, vec![(id, tag)]);
    assert!(mac.contact_requests().await.unwrap().is_empty());

    // The backup file still opens, with the next key that hands the master role on.
    mac.open_master(&master_file, "correct horse").await.unwrap();
    assert!(mac.holds_master());
}
