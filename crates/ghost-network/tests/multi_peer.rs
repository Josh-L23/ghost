use std::{
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ghost_core::{
    dedup::ReplayCache,
    identity::{Identity, IdentityStore, fingerprint_from_public_key},
    messaging::{compose, compose_receipt, open_frame, open_receipt_frame},
    session::{self, DecryptedFrame},
    trust::TrustStore,
};
use ghost_network::{TransportCommand, TransportEvent, TransportHandle, start};
use tokio::time::sleep;

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

fn identity(name: &str) -> Identity {
    let dir = tempfile::tempdir().unwrap();
    let store = IdentityStore::new(dir.path().join("identity.ghost"));
    store.create(name, b"correct horse battery staple").unwrap()
}

fn verified_trust(peer: &Identity) -> TrustStore {
    let dir = tempfile::tempdir().unwrap();
    let mut trust = TrustStore::new(dir.path().join("trust.ghost"));
    trust
        .observe(peer.identity_id(), peer.username(), now())
        .unwrap();
    let fingerprint = fingerprint_from_public_key(&peer.identity_id().0).full();
    trust.verify(&fingerprint, &fingerprint, now()).unwrap();
    trust
}

async fn wait_event<T>(
    transport: &mut TransportHandle,
    mut predicate: impl FnMut(TransportEvent) -> Option<T>,
) -> T {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            while let Some(event) = transport.try_event() {
                if let Some(value) = predicate(event) {
                    return value;
                }
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("timed out waiting for transport event")
}

fn metadata(
    frame: &DecryptedFrame,
) -> (
    ghost_core::protocol::MessageId,
    ghost_core::protocol::IdentityId,
    ghost_core::protocol::MessageType,
    u64,
) {
    (
        frame.message_id,
        frame.sender,
        frame.message_type,
        frame.created_at,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn two_peers_exchange_authenticated_encrypted_messages_receipts_and_reject_replays() {
    let alice = identity("alice");
    let bob = identity("bob");

    let mut alice_net = start(loopback()).unwrap();
    let alice_addr = wait_event(&mut alice_net, |event| match event {
        TransportEvent::Listening(address) => Some(address),
        _ => None,
    })
    .await;
    let mut bob_net = start(loopback()).unwrap();
    let _ = wait_event(&mut bob_net, |event| match event {
        TransportEvent::Listening(address) => Some(address),
        _ => None,
    })
    .await;

    bob_net
        .command(TransportCommand::Connect(alice_addr))
        .unwrap();
    let bob_addr = wait_event(&mut alice_net, |event| match event {
        TransportEvent::Incoming(peer) => Some(peer),
        _ => None,
    })
    .await;
    let remote_alice = wait_event(&mut bob_net, |event| match event {
        TransportEvent::Connected(peer) => Some(peer),
        _ => None,
    })
    .await;

    let (alice_pending, alice_hello) = session::initiate(&alice).unwrap();
    let (bob_pending, bob_hello) = session::initiate(&bob).unwrap();
    alice_net
        .command(TransportCommand::Send {
            peer: bob_addr,
            frame: alice_hello,
        })
        .unwrap();
    bob_net
        .command(TransportCommand::Send {
            peer: remote_alice,
            frame: bob_hello,
        })
        .unwrap();

    let alice_sees_bob = wait_event(&mut alice_net, |event| match event {
        TransportEvent::Frame { peer, frame } if peer == bob_addr => Some(frame),
        _ => None,
    })
    .await;
    let bob_sees_alice = wait_event(&mut bob_net, |event| match event {
        TransportEvent::Frame { peer, frame } if peer == remote_alice => Some(frame),
        _ => None,
    })
    .await;

    let mut alice_trust = verified_trust(&bob);
    let mut bob_trust = verified_trust(&alice);
    let mut alice_session = alice_pending
        .complete(&alice, &mut alice_trust, &alice_sees_bob, now())
        .unwrap();
    let mut bob_session = bob_pending
        .complete(&bob, &mut bob_trust, &bob_sees_alice, now())
        .unwrap();

    let (sent, frame) = compose(
        &mut alice_session,
        &alice,
        bob.identity_id(),
        "two terminal secret",
        now(),
    )
    .unwrap();
    alice_net
        .command(TransportCommand::Send {
            peer: bob_addr,
            frame,
        })
        .unwrap();
    let delivered = wait_event(&mut bob_net, |event| match event {
        TransportEvent::Frame { peer, frame } if peer == remote_alice => Some(frame),
        _ => None,
    })
    .await;
    assert!(
        !delivered
            .windows(b"two terminal secret".len())
            .any(|w| w == b"two terminal secret")
    );

    let mut cache = ReplayCache::new();
    let decrypted = bob_session.decrypt(&delivered, now()).unwrap();
    let (id, sender, kind, created_at) = metadata(&decrypted);
    cache.accept(id, sender, kind, created_at, now()).unwrap();
    let received = open_frame(&bob_session, decrypted).unwrap();
    assert_eq!(received.text, "two terminal secret");
    assert_eq!(received.message_id, sent.message_id);

    let (_, receipt) = compose_receipt(&mut bob_session, &bob, received.message_id, now()).unwrap();
    bob_net
        .command(TransportCommand::Send {
            peer: remote_alice,
            frame: receipt,
        })
        .unwrap();
    let delivered_receipt = wait_event(&mut alice_net, |event| match event {
        TransportEvent::Frame { peer, frame } if peer == bob_addr => Some(frame),
        _ => None,
    })
    .await;
    let decrypted_receipt = alice_session.decrypt(&delivered_receipt, now()).unwrap();
    let (id, sender, kind, created_at) = metadata(&decrypted_receipt);
    cache.accept(id, sender, kind, created_at, now()).unwrap();
    let receipt = open_receipt_frame(&alice_session, decrypted_receipt).unwrap();
    assert_eq!(receipt.acknowledged, sent.message_id);

    assert!(cache.accept(id, sender, kind, created_at, now()).is_err());
}
