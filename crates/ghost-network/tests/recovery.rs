use std::{
    fs,
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ghost_core::{
    identity::{Identity, IdentityStore, fingerprint_from_public_key},
    messaging::{compose, open_frame},
    session::{self, EstablishedSession},
    trust::{TrustState, TrustStore},
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

fn identity_in(dir: &tempfile::TempDir, name: &str) -> Identity {
    let store = IdentityStore::new(dir.path().join("identity.ghost"));
    store.create(name, b"correct horse battery staple").unwrap()
}

fn verified_trust_at(peer: &Identity, path: std::path::PathBuf) -> TrustStore {
    let mut trust = TrustStore::new(path);
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

struct Handshake<'a> {
    alice_net: &'a mut TransportHandle,
    bob_net: &'a mut TransportHandle,
    alice_peer: SocketAddr,
    bob_peer: SocketAddr,
    alice: &'a Identity,
    bob: &'a Identity,
    alice_trust: &'a mut TrustStore,
    bob_trust: &'a mut TrustStore,
}

async fn handshake(h: Handshake<'_>) -> (EstablishedSession, EstablishedSession) {
    let (alice_pending, alice_hello) = session::initiate(h.alice).unwrap();
    let (bob_pending, bob_hello) = session::initiate(h.bob).unwrap();
    h.alice_net
        .command(TransportCommand::Send {
            peer: h.bob_peer,
            frame: alice_hello,
        })
        .unwrap();
    h.bob_net
        .command(TransportCommand::Send {
            peer: h.alice_peer,
            frame: bob_hello,
        })
        .unwrap();

    let bob_frame = wait_event(&mut *h.alice_net, |event| match event {
        TransportEvent::Frame { peer, frame } if peer == h.bob_peer => Some(frame),
        _ => None,
    })
    .await;
    let alice_frame = wait_event(&mut *h.bob_net, |event| match event {
        TransportEvent::Frame { peer, frame } if peer == h.alice_peer => Some(frame),
        _ => None,
    })
    .await;

    let alice_session = alice_pending
        .complete(h.alice, h.alice_trust, &bob_frame, now())
        .unwrap();
    let bob_session = bob_pending
        .complete(h.bob, h.bob_trust, &alice_frame, now())
        .unwrap();
    (alice_session, bob_session)
}

#[tokio::test(flavor = "multi_thread")]
async fn network_loss_reconnect_and_transport_restart_reverify_and_preserve_state() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let alice = identity_in(&alice_dir, "alice");
    let bob = identity_in(&bob_dir, "bob");
    let alice_trust_path = alice_dir.path().join("trust.ghost");
    let bob_trust_path = bob_dir.path().join("trust.ghost");
    let mut alice_trust = verified_trust_at(&bob, alice_trust_path.clone());
    let mut bob_trust = verified_trust_at(&alice, bob_trust_path.clone());

    let mut alice_net = start(loopback()).unwrap();
    let alice_listener = wait_event(&mut alice_net, |event| match event {
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
        .command(TransportCommand::Connect(alice_listener))
        .unwrap();
    let bob_peer = wait_event(&mut alice_net, |event| match event {
        TransportEvent::Incoming(peer) => Some(peer),
        _ => None,
    })
    .await;
    let alice_peer = wait_event(&mut bob_net, |event| match event {
        TransportEvent::Connected(peer) => Some(peer),
        _ => None,
    })
    .await;

    let (mut alice_session, mut bob_session) = handshake(Handshake {
        alice_net: &mut alice_net,
        bob_net: &mut bob_net,
        alice_peer,
        bob_peer,
        alice: &alice,
        bob: &bob,
        alice_trust: &mut alice_trust,
        bob_trust: &mut bob_trust,
    })
    .await;

    let (_, live_frame) = compose(
        &mut alice_session,
        &alice,
        bob.identity_id(),
        "live before disconnect",
        now(),
    )
    .unwrap();
    alice_net
        .command(TransportCommand::Send {
            peer: bob_peer,
            frame: live_frame,
        })
        .unwrap();
    let delivered = wait_event(&mut bob_net, |event| match event {
        TransportEvent::Frame { peer, frame } if peer == alice_peer => Some(frame),
        _ => None,
    })
    .await;
    let decrypted = bob_session.decrypt(&delivered, now()).unwrap();
    let received = open_frame(&bob_session, decrypted).unwrap();
    assert_eq!(received.text, "live before disconnect");

    let (_, stale_frame) = compose(
        &mut alice_session,
        &alice,
        bob.identity_id(),
        "stale after restart",
        now(),
    )
    .unwrap();
    bob_net.shutdown();
    let disconnected = wait_event(&mut alice_net, |event| match event {
        TransportEvent::Disconnected(peer, reason) if peer == bob_peer => Some(reason),
        _ => None,
    })
    .await;
    assert!(!disconnected.is_empty());

    let mut bob_net = start(loopback()).unwrap();
    let _ = wait_event(&mut bob_net, |event| match event {
        TransportEvent::Listening(address) => Some(address),
        _ => None,
    })
    .await;
    bob_net
        .command(TransportCommand::Connect(alice_listener))
        .unwrap();
    let bob_peer_after_restart = wait_event(&mut alice_net, |event| match event {
        TransportEvent::Incoming(peer) => Some(peer),
        _ => None,
    })
    .await;
    let alice_peer_after_restart = wait_event(&mut bob_net, |event| match event {
        TransportEvent::Connected(peer) => Some(peer),
        _ => None,
    })
    .await;

    let mut alice_trust = TrustStore::load_or_empty(&alice_trust_path).unwrap();
    let mut bob_trust = TrustStore::load_or_empty(&bob_trust_path).unwrap();
    assert_eq!(
        alice_trust.state_of(&bob.identity_id()),
        TrustState::Verified
    );
    assert_eq!(
        bob_trust.state_of(&alice.identity_id()),
        TrustState::Verified
    );

    let (alice_session_after_restart, mut bob_session_after_restart) = handshake(Handshake {
        alice_net: &mut alice_net,
        bob_net: &mut bob_net,
        alice_peer: alice_peer_after_restart,
        bob_peer: bob_peer_after_restart,
        alice: &alice,
        bob: &bob,
        alice_trust: &mut alice_trust,
        bob_trust: &mut bob_trust,
    })
    .await;
    assert_ne!(
        alice_session.session_id(),
        alice_session_after_restart.session_id()
    );
    assert!(
        bob_session_after_restart
            .decrypt(&stale_frame, now())
            .is_err()
    );

    let identity_bytes = fs::read(bob_dir.path().join("identity.ghost")).unwrap();
    let history_key = bob.history_key();
    let key_bytes = &history_key[..];
    assert!(
        !identity_bytes
            .windows(key_bytes.len())
            .any(|window| window == key_bytes)
    );
}
