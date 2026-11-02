use aza::aza_app::AzaApp;

#[tokio::test(flavor = "multi_thread")]
async fn create_identity() {
    let node = aza_tests::node().await;
    let t = std::time::Instant::now();
    let mut phone = AzaApp::create(&node, "iPhone", 6).await.expect("create");
    eprintln!("created in {:?}", t.elapsed());
    let log = phone.refresh().await.unwrap().clone();
    assert!(log.master().is_some());
    assert!(log.is_current(&phone.device().id));
    assert_eq!(log.home().as_deref(), Some(node.as_str()));
    phone.set_name("aiden").await.expect("name");
    assert_eq!(phone.profile().await.unwrap().unwrap().name(), Some("aiden"));
}
