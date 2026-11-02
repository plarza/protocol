//! Apps restart: the aza app and every client are saved, dropped, and loaded again.
use aza::aza_app::AzaApp;
use aza::certificate::{READ, SIGN_IN, WRITE};
use aza::client::Client;

#[tokio::test(flavor = "multi_thread")]
async fn saved_state_survives_a_restart() {
    let node = aza_tests::node().await;
    let mut phone = AzaApp::create(&node, "iPhone", 6).await.unwrap();
    phone.set_name("aiden").await.unwrap();
    let (mut coach, req) =
        Client::new("coach.aza.network", &[SIGN_IN, READ, WRITE], "https://coach.aza.network/aza").unwrap();
    let returned = phone.approve_url(&req.approve_url()).await.unwrap();
    coach.receive_certificate_url(&returned).await.unwrap();
    coach.write("workouts/2026-11-02", 1, b"bench 3x5").await.unwrap();

    // Both apps quit; only their saved bytes remain.
    let phone_saved = phone.save();
    let coach_saved = coach.save();
    let id = phone.identity;
    drop((phone, coach));

    let mut coach = Client::load(&coach_saved).unwrap();
    assert_eq!(coach.identity().unwrap(), id);
    assert!(coach.log().is_some(), "the log is there offline");
    assert_eq!(coach.read_all().await.unwrap()[0].data, b"bench 3x5");
    coach.write("workouts/2026-11-02", 2, b"bench 3x5, rows 3x8").await.unwrap();

    let mut phone = AzaApp::load(&phone_saved).unwrap();
    assert_eq!(phone.identity, id);
    assert!(phone.holds_master(), "a session that held the master still holds it");
    assert_eq!(phone.approvals().await.unwrap().len(), 1);
    assert_eq!(phone.profile().await.unwrap().unwrap().name(), Some("aiden"));
    // It still approves sign-ins and replaces the data secret, and the client keeps up.
    let (mut game, req) = Client::new("coolgame.com", &[SIGN_IN], "https://coolgame.com/aza").unwrap();
    game.receive_certificate_url(&phone.approve_url(&req.approve_url()).await.unwrap()).await.unwrap();
    phone.replace_data_secret().await.unwrap();
    assert_eq!(coach.read_all().await.unwrap()[0].data, b"bench 3x5, rows 3x8");

    // A saved client that never got its certificate loads too, ready to finish signing in.
    let (pending, _) = Client::new("coach.aza.network", &[SIGN_IN], "https://coach.aza.network/aza").unwrap();
    let pending = Client::load(&pending.save()).unwrap();
    assert!(pending.certificate().is_none());
    assert!(Client::load(b"not a client").is_err());
}
