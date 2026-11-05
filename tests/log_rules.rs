//! Reading the change log (section 5.4), through a real node: changes are signed by hand,
//! uploaded, and the log is read back as every reader would.
use aza::aza_app::AzaApp;
use aza::backup;
use aza::change::{Body, Change, Unsigned, now};
use aza::crypto::{EncKey, Hash, SigningKey, fingerprint};
use aza::identity::Identity;
use aza::node::NodeClient;
use aza::{Error, Value};

/// An identity whose keys the test holds directly.
struct Lab {
    node: NodeClient,
    id: Hash,
    master: SigningKey,
    master_id: Hash,
    next: SigningKey,
    /// The first ordinary device, made by the aza app.
    a: (Hash, SigningKey),
}

impl Lab {
    async fn new(node: &str) -> Lab {
        let app = AzaApp::create(node, "A", 6).await.unwrap();
        let file = backup::open(&app.backup_master("pw").unwrap(), "pw").unwrap();
        let (master, next) = (file.key, file.next.unwrap());
        Lab {
            node: NodeClient::new(node).unwrap(),
            id: app.identity,
            master,
            master_id: app.identity,
            next,
            a: (app.device().id, app.device().key.clone()),
        }
    }

    async fn log(&self) -> Identity {
        Identity::read(self.id, self.node.get_log(&self.id).await.unwrap()).unwrap()
    }

    async fn heads(&self) -> Vec<Hash> {
        self.log().await.heads()
    }

    fn sign(&self, key: &SigningKey, by: Hash, prev: Vec<Hash>, body: Body) -> Change {
        Unsigned { identity: Some(self.id), prev, time: now(), by: Some(by), body }.sign(key)
    }

    async fn post(&self, changes: &[Change]) {
        self.node.post_log(&self.id, changes).await.unwrap();
    }

    /// The node refuses these changes (section 11's limits on a change log).
    async fn refused(&self, changes: &[Change]) {
        match self.node.post_log(&self.id, changes).await {
            Err(Error::Node { status: 413, .. }) => {}
            r => panic!("expected the node to refuse, got {r:?}"),
        }
    }

    /// The log as a reader reads it with `extra` changes added: for reading rules about changes
    /// a node refuses to store.
    async fn read_with(&self, extra: &[Change]) -> Identity {
        let mut changes = self.node.get_log(&self.id).await.unwrap();
        changes.extend(extra.iter().cloned());
        Identity::read(self.id, changes).unwrap()
    }

    /// Adds an ordinary device, signed by `by`.
    async fn add(&self, key: &SigningKey, by: Hash, prev: Vec<Hash>, label: &str) -> (Hash, SigningKey) {
        let k = SigningKey::generate();
        let c = self.sign(key, by, prev, add_body(&k, label));
        self.post(std::slice::from_ref(&c)).await;
        (c.hash(), k)
    }
}

fn add_body(k: &SigningKey, label: &str) -> Body {
    Body::AddDevice { key: k.public().to_vec(), enc: EncKey::generate().public().to_vec(), label: label.into() }
}

fn handle(h: &str) -> Body {
    Body::SetHandle { handle: Some(h.into()) }
}

#[tokio::test(flavor = "multi_thread")]
async fn devices_signing_each_other_out_at_once_are_both_signed_out() {
    let node = aza_tests::node().await;
    let lab = Lab::new(&node).await;
    let (b, bk) = lab.add(&lab.a.1, lab.a.0, lab.heads().await, "B").await;
    let base = lab.heads().await;
    let a_out_b = lab.sign(&lab.a.1, lab.a.0, base.clone(), Body::SignOut { device: b, endorse: None });
    let b_out_a = lab.sign(&bk, b, base.clone(), Body::SignOut { device: lab.a.0, endorse: None });
    lab.post(&[a_out_b, b_out_a]).await;
    let log = lab.log().await;
    assert!(!log.is_current(&lab.a.0) && !log.is_current(&b), "neither wins by coming first");
    assert_eq!(log.sign_outs().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signed_out_device_s_unseen_work_is_ignored() {
    let node = aza_tests::node().await;
    let lab = Lab::new(&node).await;
    let (b, bk) = lab.add(&lab.a.1, lab.a.0, lab.heads().await, "B").await;
    let base = lab.heads().await;
    // B, offline, sets the handle and adds C; A hasn't seen either when it signs B out.
    let b_handle = lab.sign(&bk, b, base.clone(), handle("example.com"));
    let c_key = SigningKey::generate();
    let b_adds_c = lab.sign(&bk, b, base.clone(), add_body(&c_key, "C"));
    let c_handle = lab.sign(&c_key, b_adds_c.hash(), vec![b_adds_c.hash()], handle("example.org"));
    let a_out_b = lab.sign(&lab.a.1, lab.a.0, base.clone(), Body::SignOut { device: b, endorse: None });
    lab.post(&[b_handle.clone(), a_out_b]).await;
    // A node refuses B's addition of C, which wouldn't be applied; a reader ignores it anyway.
    lab.refused(std::slice::from_ref(&b_adds_c)).await;
    let log = lab.read_with(&[b_adds_c.clone(), c_handle]).await;
    assert!(!log.is_current(&b));
    assert!(!log.is_current(&b_adds_c.hash()), "a device B added after A's view is ignored");
    assert_eq!(log.handle(), None);
    assert!(!log.is_applied(&b_handle.hash()));
    // A sign-out made after seeing B's work keeps it.
    let lab2 = Lab::new(&node).await;
    let (b, bk) = lab2.add(&lab2.a.1, lab2.a.0, lab2.heads().await, "B").await;
    let h = lab2.sign(&bk, b, lab2.heads().await, handle("example.com"));
    lab2.post(&[h]).await;
    let out = lab2.sign(&lab2.a.1, lab2.a.0, lab2.heads().await, Body::SignOut { device: b, endorse: None });
    lab2.post(&[out]).await;
    assert_eq!(lab2.log().await.handle().as_deref(), Some("example.com"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_master_removal_keeps_history_up_to_keep_and_discards_the_rest() {
    let node = aza_tests::node().await;
    let lab = Lab::new(&node).await;
    let (b, bk) = lab.add(&lab.a.1, lab.a.0, lab.heads().await, "B").await;
    let keep = lab.sign(&bk, b, lab.heads().await, handle("example.com"));
    lab.post(std::slice::from_ref(&keep)).await;
    let (c, ck) = lab.add(&bk, b, lab.heads().await, "C").await;
    let c_change = lab.sign(&ck, c, lab.heads().await, handle("example.org"));
    lab.post(std::slice::from_ref(&c_change)).await;
    // B, now stolen, signs A out with a faked prev; the sign-out counts until the master acts.
    let b_out_a = lab.sign(&bk, b, vec![keep.hash()], Body::SignOut { device: lab.a.0, endorse: None });
    lab.post(std::slice::from_ref(&b_out_a)).await;
    assert!(!lab.log().await.is_current(&lab.a.0));
    // An ordinary device can't remove devices.
    let fake =
        lab.sign(&lab.a.1, lab.a.0, lab.heads().await, Body::RemoveDevice { device: b, keep: None, endorse: None });
    lab.post(std::slice::from_ref(&fake)).await;
    assert!(lab.log().await.removals().is_empty());
    let removal = lab.sign(
        &lab.master,
        lab.master_id,
        lab.heads().await,
        Body::RemoveDevice { device: b, keep: Some(keep.hash()), endorse: None },
    );
    lab.post(std::slice::from_ref(&removal)).await;
    let log = lab.log().await;
    assert_eq!(log.removals(), vec![(removal.hash(), b)]);
    assert!(log.is_current(&lab.a.0), "B's sign-out of A is discarded");
    assert!(log.is_discarded(&b_out_a.hash()));
    assert!(!log.is_current(&c), "the device B added after keep is discarded");
    assert!(log.is_discarded(&c_change.hash()), "and everything it signed");
    assert_eq!(log.handle().as_deref(), Some("example.com"), "B's work up to keep counts");
    assert!(!log.is_current(&b));
    // Removing again with an earlier keep: a change survives only if every removal keeps it.
    let again = lab.sign(
        &lab.master,
        lab.master_id,
        lab.heads().await,
        Body::RemoveDevice { device: b, keep: None, endorse: None },
    );
    lab.post(&[again]).await;
    let log = lab.log().await;
    assert!(log.is_discarded(&keep.hash()));
    assert_eq!(log.handle(), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_next_key_hands_off_and_disowns_a_stolen_master_key() {
    let node = aza_tests::node().await;
    let lab = Lab::new(&node).await;
    let (b, _) = lab.add(&lab.a.1, lab.a.0, lab.heads().await, "B").await;
    let before_theft = lab.heads().await;
    // A thief with the current master key removes A and adds a device of their own.
    let thief_removal = lab.sign(
        &lab.master,
        lab.master_id,
        before_theft.clone(),
        Body::RemoveDevice { device: lab.a.0, keep: None, endorse: None },
    );
    lab.post(std::slice::from_ref(&thief_removal)).await;
    let (t, _) = lab.add(&lab.master, lab.master_id, lab.heads().await, "thief").await;
    let log = lab.log().await;
    assert!(!log.is_current(&lab.a.0) && log.is_current(&t));
    // The person hands off with the next key, leaving the thief's changes out of prev.
    let new_master = SigningKey::generate();
    let new_next = SigningKey::generate();
    let handoff = Unsigned {
        identity: Some(lab.id),
        prev: log.heads_excluding(&[thief_removal.hash()]),
        time: now(),
        by: None,
        body: Body::SetMaster {
            reveal: lab.next.public().to_vec(),
            key: new_master.public().to_vec(),
            enc: EncKey::generate().public().to_vec(),
            next: new_next.fingerprint(),
            endorse: None,
        },
    }
    .sign(&lab.next);
    lab.post(std::slice::from_ref(&handoff)).await;
    let log = lab.log().await;
    assert_eq!(log.master().unwrap().id, handoff.hash());
    assert!(log.is_current(&lab.a.0), "the stolen key's removal stops counting");
    assert!(!log.is_current(&t), "and so does the thief's device");
    assert!(log.is_discarded(&thief_removal.hash()));
    assert!(log.is_current(&b));
    // The former master's changes made after the handoff don't count, however prev is faked.
    let late =
        lab.sign(&lab.master, lab.master_id, log.heads(), Body::RemoveDevice { device: b, keep: None, endorse: None });
    lab.post(std::slice::from_ref(&late)).await;
    let log = lab.log().await;
    assert!(log.is_current(&b));
    assert!(log.is_discarded(&late.hash()));
    // The new master can make repairs.
    let m_id = handoff.hash();
    let removal = lab.sign(&new_master, m_id, log.heads(), Body::RemoveDevice { device: b, keep: None, endorse: None });
    lab.post(&[removal]).await;
    assert!(!lab.log().await.is_current(&b));
    // A copy of the same handoff differing only in signature names the same master.
    let copy = Unsigned {
        identity: Some(lab.id),
        prev: handoff.prev.clone(),
        time: handoff.time,
        by: None,
        body: handoff.body.clone(),
    }
    .sign(&lab.next);
    assert_eq!(copy.hash(), handoff.hash());
}

#[tokio::test(flavor = "multi_thread")]
async fn competing_handoffs_leave_the_identity_without_a_master() {
    let node = aza_tests::node().await;
    let lab = Lab::new(&node).await;
    let heads = lab.heads().await;
    let handoff = |prev: Vec<Hash>| {
        Unsigned {
            identity: Some(lab.id),
            prev,
            time: now(),
            by: None,
            body: Body::SetMaster {
                reveal: lab.next.public().to_vec(),
                key: SigningKey::generate().public().to_vec(),
                enc: EncKey::generate().public().to_vec(),
                next: SigningKey::generate().fingerprint(),
                endorse: None,
            },
        }
        .sign(&lab.next)
    };
    let one = handoff(heads.clone());
    let two = handoff(heads.clone());
    lab.post(&[one, two]).await;
    let log = lab.log().await;
    assert!(log.has_master_conflict());
    assert!(log.master().is_none());
    assert!(log.is_current(&lab.a.0), "ordinary devices keep working");
    let (b, _) = lab.add(&lab.a.1, lab.a.0, lab.heads().await, "B").await;
    let removal = lab.sign(
        &lab.master,
        lab.master_id,
        lab.heads().await,
        Body::RemoveDevice { device: b, keep: None, endorse: None },
    );
    lab.post(&[removal]).await;
    assert!(lab.log().await.is_current(&b), "nothing can remove devices any more");
}

#[tokio::test(flavor = "multi_thread")]
async fn sixty_four_ordinary_devices_at_most() {
    let node = aza_tests::node().await;
    let lab = Lab::new(&node).await;
    let mut prev = lab.heads().await;
    let mut batch = Vec::new();
    for i in 0..63 {
        let c = lab.sign(&lab.a.1, lab.a.0, prev.clone(), add_body(&SigningKey::generate(), &format!("device {i}")));
        prev = vec![c.hash()];
        batch.push(c);
    }
    lab.post(&batch).await;
    assert_eq!(lab.log().await.current_ordinary_devices().len(), 64);
    let extra = lab.sign(&lab.a.1, lab.a.0, lab.heads().await, add_body(&SigningKey::generate(), "one too many"));
    lab.refused(std::slice::from_ref(&extra)).await;
    let log = lab.read_with(std::slice::from_ref(&extra)).await;
    assert!(!log.is_current(&extra.hash()));
    assert_eq!(log.current_ordinary_devices().len(), 64);
    // Signed-out devices still count until the master removes them.
    let out = lab.sign(&lab.a.1, lab.a.0, log.heads(), Body::SignOut { device: batch[0].hash(), endorse: None });
    lab.post(&[out]).await;
    let still = lab.sign(&lab.a.1, lab.a.0, lab.heads().await, add_body(&SigningKey::generate(), "still too many"));
    lab.refused(std::slice::from_ref(&still)).await;
    assert!(!lab.read_with(std::slice::from_ref(&still)).await.is_current(&still.hash()));
    let removal = lab.sign(
        &lab.master,
        lab.master_id,
        lab.heads().await,
        Body::RemoveDevice { device: batch[0].hash(), keep: None, endorse: None },
    );
    lab.post(&[removal]).await;
    let (fits, _) = lab.add(&lab.a.1, lab.a.0, lab.heads().await, "fits").await;
    assert!(lab.log().await.is_current(&fits));
}

#[tokio::test(flavor = "multi_thread")]
async fn keys_are_never_reused() {
    let node = aza_tests::node().await;
    let lab = Lab::new(&node).await;
    let heads = lab.heads().await;
    let with_master_key = lab.sign(
        &lab.a.1,
        lab.a.0,
        heads.clone(),
        Body::AddDevice {
            key: lab.master.public().to_vec(),
            enc: EncKey::generate().public().to_vec(),
            label: "copy".into(),
        },
    );
    let with_next_key = lab.sign(
        &lab.a.1,
        lab.a.0,
        heads.clone(),
        Body::AddDevice {
            key: lab.next.public().to_vec(),
            enc: EncKey::generate().public().to_vec(),
            label: "next".into(),
        },
    );
    let with_own_key = lab.sign(
        &lab.a.1,
        lab.a.0,
        heads.clone(),
        Body::AddDevice {
            key: lab.a.1.public().to_vec(),
            enc: EncKey::generate().public().to_vec(),
            label: "again".into(),
        },
    );
    let reused = [with_master_key, with_next_key, with_own_key];
    lab.refused(&reused).await;
    let log = lab.read_with(&reused).await;
    for c in &reused {
        assert!(!log.is_current(&c.hash()));
    }
    // A handoff whose new key is an old one isn't a link.
    let reuse = Unsigned {
        identity: Some(lab.id),
        prev: log.heads(),
        time: now(),
        by: None,
        body: Body::SetMaster {
            reveal: lab.next.public().to_vec(),
            key: lab.master.public().to_vec(),
            enc: EncKey::generate().public().to_vec(),
            next: fingerprint(SigningKey::generate().public()),
            endorse: None,
        },
    }
    .sign(&lab.next);
    lab.post(&[reuse]).await;
    assert_eq!(lab.log().await.master().unwrap().id, lab.master_id);
}

#[tokio::test(flavor = "multi_thread")]
async fn only_the_master_announces_secrets_and_masters_are_never_signed_out() {
    let node = aza_tests::node().await;
    let lab = Lab::new(&node).await;
    let heads = lab.heads().await;
    let by_device = lab.sign(&lab.a.1, lab.a.0, heads.clone(), Body::NewSecret { check: [7; 32] });
    let out_master = lab.sign(&lab.a.1, lab.a.0, heads.clone(), Body::SignOut { device: lab.master_id, endorse: None });
    lab.post(&[by_device.clone(), out_master]).await;
    let log = lab.log().await;
    assert_eq!(log.current_secret(), lab.id);
    assert!(log.master().unwrap().current);
    assert!(log.is_current(&lab.a.0));
    let by_master = lab.sign(&lab.master, lab.master_id, log.heads(), Body::NewSecret { check: [9; 32] });
    lab.post(std::slice::from_ref(&by_master)).await;
    let log = lab.log().await;
    assert_eq!(log.current_secret(), by_master.hash());
    assert_eq!(log.announced_secrets(), vec![lab.id, by_master.hash()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_may_sign_itself_out() {
    let node = aza_tests::node().await;
    let lab = Lab::new(&node).await;
    let out_self = lab.sign(&lab.a.1, lab.a.0, lab.heads().await, Body::SignOut { device: lab.a.0, endorse: None });
    lab.post(&[out_self]).await;
    let log = lab.log().await;
    assert!(!log.is_current(&lab.a.0));
    // Nothing it signs afterwards counts.
    let late = lab.sign(&lab.a.1, lab.a.0, log.heads(), Body::SetHandle { handle: Some("late.example".into()) });
    lab.post(&[late]).await;
    assert_eq!(lab.log().await.handle(), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_change_from_a_newer_version_blocks_reading_until_its_signer_is_signed_out() {
    let node = aza_tests::node().await;
    let lab = Lab::new(&node).await;
    let (b, bk) = lab.add(&lab.a.1, lab.a.0, lab.heads().await, "B").await;
    let base = lab.heads().await;
    let future = Value::map([
        ("v", 2u64.into()),
        ("identity", lab.id.into()),
        ("prev", Value::Array(base.iter().map(|h| (*h).into()).collect())),
        ("time", now().into()),
        ("by", b.into()),
        ("body", Value::map([("type", "teleport".into())])),
    ]);
    let sig = bk.sign(&future.to_bytes());
    let future = Change::from_value(future.with("sig", sig.into())).unwrap();
    lab.post(std::slice::from_ref(&future)).await;
    let log = lab.log().await;
    assert!(!log.readable());
    assert!(matches!(log.require_readable(), Err(Error::Unreadable)));
    assert!(!log.heads().contains(&future.hash()), "a change that can't be read is never listed in prev");
    // Signing B out with a sign-out that doesn't have the change as an ancestor ends it.
    let out = lab.sign(&lab.a.1, lab.a.0, base, Body::SignOut { device: b, endorse: None });
    lab.post(&[out]).await;
    assert!(lab.log().await.readable());
}

#[tokio::test(flavor = "multi_thread")]
async fn revocations_count_until_the_master_acts() {
    let node = aza_tests::node().await;
    let lab = Lab::new(&node).await;
    let (b, bk) = lab.add(&lab.a.1, lab.a.0, lab.heads().await, "B").await;
    let base = lab.heads().await;
    let client = [5u8; 32];
    let out_b = lab.sign(&lab.a.1, lab.a.0, base.clone(), Body::SignOut { device: b, endorse: None });
    let b_revokes = lab.sign(&bk, b, base.clone(), Body::RevokeClient { client });
    lab.post(&[out_b, b_revokes.clone()]).await;
    assert!(lab.log().await.is_revoked(&client), "judged on its own, B's revocation counts");
    let removal = lab.sign(
        &lab.master,
        lab.master_id,
        lab.heads().await,
        Body::RemoveDevice { device: b, keep: None, endorse: None },
    );
    lab.post(&[removal]).await;
    let log = lab.log().await;
    assert!(!log.is_revoked(&client));
    assert!(log.is_discarded(&b_revokes.hash()));
}

#[tokio::test(flavor = "multi_thread")]
async fn nodes_keep_only_deterministic_validly_signed_changes() {
    let node = aza_tests::node().await;
    let lab = Lab::new(&node).await;
    let heads = lab.heads().await;
    let good = lab.sign(&lab.a.1, lab.a.0, heads.clone(), handle("example.com"));
    // A forged signature is dropped.
    let forged = lab.sign(&SigningKey::generate(), lab.a.0, heads.clone(), handle("evil.com"));
    lab.post(std::slice::from_ref(&forged)).await;
    assert!(lab.log().await.change(&forged.hash()).is_none());
    // The same change with its integer `time` in a longer form than needed is rejected.
    let bytes = good.to_bytes();
    let mut v = Value::from_bytes(&bytes).unwrap();
    if let Value::Map(entries) = &mut v {
        entries.sort_by_key(|e| std::cmp::Reverse(e.0.to_bytes()));
    }
    let unsorted = aza::aza_core::cbor::encode(&v);
    assert!(Value::from_bytes(&unsorted).is_none(), "keys out of order");
    let mut long = vec![0x19, 0x00, 0x01];
    assert!(Value::from_bytes(&long).is_none(), "1 written in two bytes");
    long = vec![0x01];
    assert_eq!(Value::from_bytes(&long), Some(Value::Uint(1)));
    let body = [&[0x81u8][..], &unsorted].concat();
    let resp = reqwest_post(&format!("{node}/aza/v1/log/{}", hex(&lab.id)), body).await;
    assert_eq!(resp, 400);
    lab.post(std::slice::from_ref(&good)).await;
    assert_eq!(lab.log().await.handle().as_deref(), Some("example.com"));
    // A change for one identity can't be stored under another.
    let other = Lab::new(&node).await;
    assert!(other.node.post_log(&other.id, &[good]).await.is_err() || other.log().await.handle().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn nodes_charge_their_admission_price() {
    let strict = aza_tests::node_with(|c| c.min_work = 20).await;
    let err = AzaApp::create(&strict, "A", 6).await.err().expect("too little work");
    assert!(matches!(err, Error::Node { status: 403, .. }), "{err:?}");
}

fn hex(h: &Hash) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

async fn reqwest_post(url: &str, body: Vec<u8>) -> u16 {
    let url = url.strip_prefix("http://").unwrap();
    let (host, path) = url.split_once('/').unwrap();
    let mut stream = tokio::net::TcpStream::connect(host).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let head = format!(
        "POST /{path} HTTP/1.1\r\nhost: {host}\r\ncontent-type: application/cbor\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    let mut out = String::new();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    out.push_str(&String::from_utf8_lossy(&buf));
    out.split_whitespace().nth(1).unwrap().parse().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn copies_differing_only_in_signature_are_one_change() {
    let node = aza_tests::node().await;
    let lab = Lab::new(&node).await;
    let unsigned = Unsigned {
        identity: Some(lab.id),
        prev: lab.heads().await,
        time: now(),
        by: Some(lab.a.0),
        body: Body::SetHome { node: node.clone() },
    };
    // ML-DSA signs with fresh randomness, so the two copies' bytes differ.
    let (first, second) = (unsigned.clone().sign(&lab.a.1), unsigned.sign(&lab.a.1));
    assert_ne!(first.to_bytes(), second.to_bytes());
    assert_eq!(first.hash(), second.hash());
    let before = lab.node.get_log(&lab.id).await.unwrap().len();
    lab.post(&[first.clone(), second]).await;
    assert_eq!(lab.node.get_log(&lab.id).await.unwrap().len(), before + 1);
    // A copy with a broken signature never displaces a valid one.
    let mut changes = lab.node.get_log(&lab.id).await.unwrap();
    let forged = Change::from_value(first.to_value().with("sig", vec![0u8; 3373].into())).unwrap();
    changes.insert(0, forged);
    let log = Identity::read(lab.id, changes).unwrap();
    assert!(log.is_applied(&first.hash()));
}

#[tokio::test(flavor = "multi_thread")]
async fn strangers_cannot_fill_a_log_with_handoffs_of_their_own() {
    let node = aza_tests::node().await;
    let lab = Lab::new(&node).await;
    // Anyone can sign a set-master with a key of their own, but it reveals no link's next key.
    let stranger = SigningKey::generate();
    let junk = Unsigned {
        identity: Some(lab.id),
        prev: lab.heads().await,
        time: now(),
        by: None,
        body: Body::SetMaster {
            reveal: stranger.public().to_vec(),
            key: SigningKey::generate().public().to_vec(),
            enc: EncKey::generate().public().to_vec(),
            next: fingerprint(SigningKey::generate().public()),
            endorse: None,
        },
    }
    .sign(&stranger);
    lab.refused(&[junk]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_thief_s_device_runs_out_of_changes_but_can_still_be_signed_out() {
    let node = aza_tests::node().await;
    let lab = Lab::new(&node).await;
    let (b, bk) = lab.add(&lab.a.1, lab.a.0, lab.heads().await, "stolen").await;
    let base = lab.heads().await;
    let before = lab.node.get_log(&lab.id).await.unwrap().len();
    let spam: Vec<Change> = (0..aza::aza_core::admit::ALLOWANCE + 2)
        .map(|i: u64| {
            let mut client = [0u8; 32];
            client[..8].copy_from_slice(&i.to_be_bytes());
            lab.sign(&bk, b, base.clone(), Body::RevokeClient { client })
        })
        .collect();
    lab.refused(&spam).await;
    let held = lab.node.get_log(&lab.id).await.unwrap().len();
    assert_eq!(held, before + aza::aza_core::admit::ALLOWANCE as usize, "the node keeps B's allowance and no more");
    // The thief's allowance is spent, but A's isn't: A signs B out.
    lab.post(&[lab.sign(&lab.a.1, lab.a.0, lab.heads().await, Body::SignOut { device: b, endorse: None })]).await;
    assert!(!lab.log().await.is_current(&b));
}
