//! Section 7: a request names the machine it comes from, and the list of approvals keeps that name.
use aza::aza_app::AzaApp;
use aza::certificate::{READ, Request, SIGN_IN, WRITE};
use aza::client::Client;

#[tokio::test(flavor = "multi_thread")]
async fn approvals_keep_the_label_of_their_request() {
    let node = aza_tests::node().await;
    let mut phone = AzaApp::create(&node, "iPhone", 6).await.unwrap();

    let (_, mac) =
        Client::with_label("coach.aza.network", &[READ, WRITE], "https://coach.aza.network/aza", Some("MacBook Pro"))
            .unwrap();
    let (_, plain) = Client::new("stream.aza.network", &[SIGN_IN], "https://stream.aza.network/aza").unwrap();
    // Labels of several clients, so their stored order matters.
    let iphones: Vec<_> = (0..4)
        .map(|i| {
            Client::with_label(
                "coach.aza.network",
                &[SIGN_IN],
                "https://coach.aza.network/aza",
                Some(&format!("iPhone {i}")),
            )
            .unwrap()
            .1
        })
        .collect();
    let opened = Request::from_approve_url(&mac.approve_url()).unwrap();
    assert_eq!(opened.label.as_deref(), Some("MacBook Pro"));

    phone.approve_url(&mac.approve_url()).await.unwrap();
    phone.approve_url(&plain.approve_url()).await.unwrap();
    for r in &iphones {
        phone.approve_url(&r.approve_url()).await.unwrap();
    }
    let list = phone.approval_list().await.unwrap();
    let labels: Vec<_> = list.iter().map(|a| a.label.as_deref()).collect();
    assert_eq!(
        labels,
        [Some("MacBook Pro"), None, Some("iPhone 0"), Some("iPhone 1"), Some("iPhone 2"), Some("iPhone 3")]
    );

    // Revoking one client keeps the others' labels.
    let stream = list[1].certificate.client_fp();
    phone.revoke_client(&stream).await.unwrap();
    let list = phone.approval_list().await.unwrap();
    assert_eq!(list.len(), 5);
    assert_eq!(list[0].label.as_deref(), Some("MacBook Pro"));

    // The approvals themselves stay plain certificates, which aza apps without labels can read.
    assert_eq!(phone.approvals().await.unwrap().len(), 5);

    // A label is a short, plain name: never empty, a paragraph, or text that reads backwards.
    for bad in ["", "  ", " Mac", "Mac\nmini", "\u{202E}orP kooBcaM", &"x".repeat(65)] {
        assert!(
            Client::with_label("coach.aza.network", &[SIGN_IN], "https://coach.aza.network/aza", Some(bad)).is_err()
        );
    }
}
