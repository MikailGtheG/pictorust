use pictochat_mls_lab::client::{Client, Incoming, KIND_APPLICATION, KIND_COMMIT};

#[test]
fn endpoint_owned_group_client_handles_three_peers_and_removal() {
    let mut alice = Client::new(b"Alice").unwrap();
    let mut bob = Client::new(b"Bob").unwrap();
    let mut charlie = Client::new(b"Charlie").unwrap();

    alice.start_group().unwrap();
    let (bob_add, welcome_bob) = alice.add(&bob.key_package().unwrap()).unwrap();
    bob.accept_welcome(&welcome_bob, alice.ratchet_tree().unwrap()).unwrap();
    assert_eq!(alice.count().unwrap(), 2);
    assert_eq!(bob.count().unwrap(), 2);
    let initial_message = alice.send("Hallo ÄÖÜ ğışç 😊".as_bytes()).unwrap();
    assert_eq!(
        bob.process(&initial_message, KIND_APPLICATION).unwrap(),
        Incoming::Application("Hallo ÄÖÜ ğışç 😊".as_bytes().to_vec())
    );

    let (charlie_add, welcome_charlie) = alice.add(&charlie.key_package().unwrap()).unwrap();
    assert_eq!(bob.process(&charlie_add, KIND_COMMIT).unwrap(), Incoming::MembershipChanged);
    charlie.accept_welcome(&welcome_charlie, alice.ratchet_tree().unwrap()).unwrap();
    assert_eq!(alice.count().unwrap(), 3);
    assert_eq!(bob.count().unwrap(), 3);
    assert_eq!(charlie.count().unwrap(), 3);
    assert_eq!(alice.epoch().unwrap(), bob.epoch().unwrap());
    assert_eq!(alice.epoch().unwrap(), charlie.epoch().unwrap());

    let before = alice.epoch().unwrap();
    let remove = alice.remove(bob.own_leaf().unwrap()).unwrap();
    assert_eq!(charlie.process(&remove, KIND_COMMIT).unwrap(), Incoming::MembershipChanged);
    assert_eq!(bob.process(&remove, KIND_COMMIT).unwrap(), Incoming::Removed);
    assert!(!bob.active());
    assert!(charlie.active());
    assert_eq!(alice.count().unwrap(), 2);
    assert_eq!(charlie.count().unwrap(), 2);
    assert!(alice.epoch().unwrap() > before);
    assert_eq!(alice.epoch().unwrap(), charlie.epoch().unwrap());

    let encrypted = alice.send("Neue Epoche: Alice und Charlie".as_bytes()).unwrap();
    assert_eq!(
        charlie.process(&encrypted, KIND_APPLICATION).unwrap(),
        Incoming::Application("Neue Epoche: Alice und Charlie".as_bytes().to_vec())
    );
    assert!(bob.process(&encrypted, KIND_APPLICATION).is_err());
    assert!(bob.process(&initial_message, KIND_APPLICATION).is_err());
    assert!(bob.process(&remove, KIND_APPLICATION).is_err());
    // A duplicated Commit cannot be merged again in a later epoch.
    assert!(charlie.process(&remove, KIND_COMMIT).is_err());
    // Older v2 browser framing must not accidentally be treated as MLS.
    assert!(charlie.process(&[2, 1, 42], KIND_APPLICATION).is_err());
    let _ = bob_add;
}

#[test]
fn malformed_control_packets_rejected_before_mls_processing() {
    use pictochat_mls_lab::client::{wrap, unwrap, KIND_WELCOME, KIND_KEY_PACKAGE, MAX_WIRE_SIZE};
    assert!(wrap(0, vec![1]).is_err());
    assert!(wrap(KIND_APPLICATION, vec![]).is_err());
    assert!(wrap(KIND_COMMIT, vec![9; MAX_WIRE_SIZE]).is_err());
    assert!(unwrap(&[3, KIND_APPLICATION], KIND_APPLICATION).is_err());
    assert!(unwrap(&[3, KIND_WELCOME, 9], KIND_APPLICATION).is_err());
    assert!(unwrap(&[3, KIND_KEY_PACKAGE, 9], KIND_COMMIT).is_err());
    assert!(unwrap(&[2, KIND_APPLICATION, 9], KIND_APPLICATION).is_err());
}

#[test]
fn wire_invite_membership_and_rejoin_rejects_stale_client() {
    let mut alice = Client::new(b"Alice").unwrap();
    let mut bob = Client::new(b"Bob").unwrap();
    let mut charlie = Client::new(b"Charlie").unwrap();
    alice.start_group().unwrap();
    let (bob_commit, bob_welcome, bob_tree) =
        alice.add_wire(&bob.key_package_wire().unwrap()).unwrap();
    assert!(!bob_commit.is_empty());
    bob.accept_welcome_wire(&bob_welcome, &bob_tree).unwrap();
    assert_eq!(bob.count().unwrap(), 2);
    let (charlie_commit, charlie_welcome, charlie_tree) =
        alice.add_wire(&charlie.key_package_wire().unwrap()).unwrap();
    assert_eq!(bob.process(&charlie_commit, KIND_COMMIT).unwrap(), Incoming::MembershipChanged);
    charlie.accept_welcome_wire(&charlie_welcome, &charlie_tree).unwrap();
    let member_list = alice.members().unwrap();
    assert_eq!(member_list.len(), 3);
    assert!(member_list.iter().all(|(_, credential, key)| !credential.is_empty() && !key.is_empty()));
    let bob_leaf = bob.own_leaf().unwrap().u32();
    assert!(alice.remove_leaf(4000000).is_err());
    assert!(alice.remove_leaf(alice.own_leaf().unwrap().u32()).is_err());
    let eviction = alice.remove_leaf(bob_leaf).unwrap();
    assert_eq!(charlie.process(&eviction, KIND_COMMIT).unwrap(), Incoming::MembershipChanged);
    assert_eq!(bob.process(&eviction, KIND_COMMIT).unwrap(), Incoming::Removed);
    assert!(!bob.active());
    assert!(bob.send(b"revoked").is_err());
    let new_epoch = alice.send(b"post-removal").unwrap();
    assert_eq!(charlie.process(&new_epoch, KIND_APPLICATION).unwrap(),
        Incoming::Application(b"post-removal".to_vec()));
    assert!(bob.process(&new_epoch, KIND_APPLICATION).is_err());
    charlie.mark_transport_interrupted();
    assert!(!charlie.synchronized());
    assert!(charlie.send(b"stale").is_err());
    assert!(charlie.process(&new_epoch, KIND_APPLICATION).is_err());
}
