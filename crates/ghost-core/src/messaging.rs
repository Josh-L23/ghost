//! End-to-end private messages carried inside authenticated sessions.

use postcard::{from_bytes, to_allocvec};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    identity::Identity,
    protocol::{
        BoundedBytes, IdentityId, MAX_ENCRYPTED_PAYLOAD_BYTES, MessageId, MessageType,
        ProtocolError,
    },
    session::{self, DecryptedFrame, SessionError},
};

pub const MAX_TEXT_BYTES: usize = 4096;

pub const RECEIPT_DELIVERED: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateMessage {
    pub message_id: MessageId,
    pub sender: IdentityId,
    pub recipient: IdentityId,
    pub created_at: u64,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub message_id: MessageId,
    pub acknowledged: MessageId,
    pub sender: IdentityId,
    pub recipient: IdentityId,
    pub created_at: u64,
    pub result: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ReceiptWireMessage {
    message_id: MessageId,
    acknowledged: MessageId,
    sender: IdentityId,
    recipient: IdentityId,
    created_at: u64,
    result: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateWireMessage {
    pub message_id: MessageId,
    pub sender: IdentityId,
    pub recipient: IdentityId,
    pub created_at: u64,
    pub nonce: [u8; 12],
    pub ciphertext: BoundedBytes<MAX_ENCRYPTED_PAYLOAD_BYTES>,
}

#[derive(Debug)]
pub enum MessagingError {
    InvalidMessage(&'static str),
    UnexpectedMessageType(MessageType),
    Encoding(postcard::Error),
    Protocol(ProtocolError),
    Session(SessionError),
    InvalidUtf8,
}

impl std::fmt::Display for MessagingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMessage(reason) => write!(f, "invalid private message: {reason}"),
            Self::UnexpectedMessageType(kind) => {
                write!(f, "unexpected message type {} in conversation", kind.0)
            }
            Self::Encoding(error) => write!(f, "invalid message encoding: {error}"),
            Self::Protocol(error) => write!(f, "invalid message envelope: {error}"),
            Self::Session(error) => write!(f, "message rejected: {error}"),
            Self::InvalidUtf8 => f.write_str("message text is not valid UTF-8"),
        }
    }
}

impl std::error::Error for MessagingError {}

impl From<postcard::Error> for MessagingError {
    fn from(error: postcard::Error) -> Self {
        Self::Encoding(error)
    }
}

impl From<ProtocolError> for MessagingError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<SessionError> for MessagingError {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
}

pub fn compose(
    session: &mut session::EstablishedSession,
    identity: &Identity,
    recipient: IdentityId,
    text: &str,
    now: u64,
) -> Result<(PrivateMessage, Vec<u8>), MessagingError> {
    if text.is_empty() || text.len() > MAX_TEXT_BYTES {
        return Err(MessagingError::InvalidMessage(
            "text length is out of bounds",
        ));
    }
    if session.peer_id() != recipient {
        return Err(MessagingError::InvalidMessage(
            "recipient is not the session peer",
        ));
    }

    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    let message_id = MessageId(id);
    let sender = identity.identity_id();
    let (nonce, ciphertext) = session.encrypt_content(text.as_bytes(), &message_id, recipient)?;
    let wire = PrivateWireMessage {
        message_id,
        sender,
        recipient,
        created_at: now,
        nonce,
        ciphertext: BoundedBytes::new(ciphertext)?,
    };
    let payload = to_allocvec(&wire)?;
    let frame = session.encrypt_with_type(identity, &payload, now, MessageType::PRIVATE)?;
    let message = PrivateMessage {
        message_id,
        sender,
        recipient,
        created_at: now,
        text: text.to_owned(),
    };
    Ok((message, frame))
}

pub fn open(
    session: &mut session::EstablishedSession,
    frame: &[u8],
    now: u64,
) -> Result<PrivateMessage, MessagingError> {
    let decrypted = session.decrypt(frame, now)?;
    open_frame(session, decrypted)
}

pub fn open_frame(
    session: &session::EstablishedSession,
    decrypted: DecryptedFrame,
) -> Result<PrivateMessage, MessagingError> {
    if decrypted.message_type != MessageType::PRIVATE {
        return Err(MessagingError::UnexpectedMessageType(
            decrypted.message_type,
        ));
    }

    let wire: PrivateWireMessage = from_bytes(&decrypted.plaintext)?;
    if wire.message_id.is_zero() || wire.sender.is_zero() || wire.recipient.is_zero() {
        return Err(MessagingError::InvalidMessage("empty identifier"));
    }
    if wire.sender != session.peer_id() {
        return Err(MessagingError::InvalidMessage(
            "sender is not the session peer",
        ));
    }
    if wire.created_at != decrypted.created_at {
        return Err(MessagingError::InvalidMessage(
            "inner timestamp does not match envelope",
        ));
    }

    let plaintext = session.decrypt_content(
        &wire.nonce,
        wire.ciphertext.as_slice(),
        &wire.message_id,
        wire.sender,
    )?;
    if plaintext.is_empty() || plaintext.len() > MAX_TEXT_BYTES {
        return Err(MessagingError::InvalidMessage(
            "text length is out of bounds",
        ));
    }
    let text = String::from_utf8(plaintext).map_err(|_| MessagingError::InvalidUtf8)?;
    Ok(PrivateMessage {
        message_id: wire.message_id,
        sender: wire.sender,
        recipient: wire.recipient,
        created_at: wire.created_at,
        text,
    })
}

pub fn compose_receipt(
    session: &mut session::EstablishedSession,
    identity: &Identity,
    acknowledged: MessageId,
    now: u64,
) -> Result<(Receipt, Vec<u8>), MessagingError> {
    if acknowledged.is_zero() {
        return Err(MessagingError::InvalidMessage("empty acknowledged id"));
    }
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    let receipt = Receipt {
        message_id: MessageId(id),
        acknowledged,
        sender: identity.identity_id(),
        recipient: session.peer_id(),
        created_at: now,
        result: RECEIPT_DELIVERED,
    };
    let wire = ReceiptWireMessage {
        message_id: receipt.message_id,
        acknowledged: receipt.acknowledged,
        sender: receipt.sender,
        recipient: receipt.recipient,
        created_at: receipt.created_at,
        result: receipt.result,
    };
    let payload = to_allocvec(&wire)?;
    let frame = session.encrypt_with_type(identity, &payload, now, MessageType::RECEIPT)?;
    Ok((receipt, frame))
}

pub fn open_receipt(
    session: &mut session::EstablishedSession,
    frame: &[u8],
    now: u64,
) -> Result<Receipt, MessagingError> {
    let decrypted = session.decrypt(frame, now)?;
    open_receipt_frame(session, decrypted)
}

pub fn open_receipt_frame(
    session: &session::EstablishedSession,
    decrypted: DecryptedFrame,
) -> Result<Receipt, MessagingError> {
    if decrypted.message_type != MessageType::RECEIPT {
        return Err(MessagingError::UnexpectedMessageType(
            decrypted.message_type,
        ));
    }
    let wire: ReceiptWireMessage = from_bytes(&decrypted.plaintext)?;
    if wire.message_id.is_zero() || wire.acknowledged.is_zero() {
        return Err(MessagingError::InvalidMessage("empty receipt identifier"));
    }
    if wire.sender != session.peer_id() || wire.recipient != session.local_id() {
        return Err(MessagingError::InvalidMessage(
            "receipt endpoints do not match the session",
        ));
    }
    if wire.result != RECEIPT_DELIVERED {
        return Err(MessagingError::InvalidMessage("unknown receipt result"));
    }
    if wire.created_at != decrypted.created_at {
        return Err(MessagingError::InvalidMessage(
            "inner timestamp does not match envelope",
        ));
    }
    Ok(Receipt {
        message_id: wire.message_id,
        acknowledged: wire.acknowledged,
        sender: wire.sender,
        recipient: wire.recipient,
        created_at: wire.created_at,
        result: wire.result,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::{IdentityStore, fingerprint_from_public_key},
        session::initiate,
        trust::TrustStore,
    };
    use tempfile::tempdir;

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or_default()
    }

    fn identity(name: &str) -> Identity {
        let dir = tempdir().unwrap();
        let store = IdentityStore::new(dir.path().join("identity.ghost"));
        store.create(name, b"correct horse battery staple").unwrap()
    }

    fn session_pair(
        local: &Identity,
        peer: &Identity,
    ) -> (session::EstablishedSession, session::EstablishedSession) {
        let (local_pending, local_hello) = initiate(local).unwrap();
        let (peer_pending, peer_hello) = initiate(peer).unwrap();
        let dir = tempdir().unwrap();
        let mut local_trust = TrustStore::new(dir.path().join("local-trust.ghost"));
        local_trust
            .observe(peer.identity_id(), peer.username(), now())
            .unwrap();
        let peer_fingerprint = fingerprint_from_public_key(&peer.identity_id().0).full();
        local_trust
            .verify(&peer_fingerprint, &peer_fingerprint, now())
            .unwrap();
        let local_session = local_pending
            .complete(local, &mut local_trust, &peer_hello, now())
            .unwrap();

        let dir = tempdir().unwrap();
        let mut peer_trust = TrustStore::new(dir.path().join("peer-trust.ghost"));
        peer_trust
            .observe(local.identity_id(), local.username(), now())
            .unwrap();
        let local_fingerprint = fingerprint_from_public_key(&local.identity_id().0).full();
        peer_trust
            .verify(&local_fingerprint, &local_fingerprint, now())
            .unwrap();
        let peer_session = peer_pending
            .complete(peer, &mut peer_trust, &local_hello, now())
            .unwrap();
        (local_session, peer_session)
    }

    #[test]
    fn trusted_peers_exchange_ciphertext_private_messages() {
        let alice = identity("alice");
        let bob = identity("bob");
        let (mut alice_session, mut bob_session) = session_pair(&alice, &bob);
        assert_eq!(alice_session.peer_id(), bob.identity_id());
        assert_eq!(bob_session.peer_id(), alice.identity_id());

        let (sent, frame) = compose(
            &mut alice_session,
            &alice,
            bob.identity_id(),
            "secret hello",
            now(),
        )
        .unwrap();
        assert!(
            !frame
                .windows(b"secret hello".len())
                .any(|w| w == b"secret hello")
        );
        let received = open(&mut bob_session, &frame, now()).unwrap();
        assert_eq!(received.text, "secret hello");
        assert_eq!(received.sender, alice.identity_id());
        assert_eq!(received.recipient, bob.identity_id());
        assert_eq!(received.message_id, sent.message_id);
    }

    #[test]
    fn tampered_message_is_rejected_without_leaking_payload() {
        let alice = identity("alice");
        let bob = identity("bob");
        let (mut alice_session, mut bob_session) = session_pair(&alice, &bob);

        let (_, mut frame) = compose(
            &mut alice_session,
            &alice,
            bob.identity_id(),
            "hidden content",
            now(),
        )
        .unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 1;

        let error = open(&mut bob_session, &frame, now()).unwrap_err();
        assert!(!error.to_string().contains("hidden content"));
    }

    #[test]
    fn inner_private_timestamp_must_match_the_envelope() {
        let alice = identity("alice");
        let bob = identity("bob");
        let (mut alice_session, mut bob_session) = session_pair(&alice, &bob);
        let (_, frame) = compose(
            &mut alice_session,
            &alice,
            bob.identity_id(),
            "timestamp check",
            now(),
        )
        .unwrap();
        let mut decrypted = bob_session.decrypt(&frame, now()).unwrap();
        let mut wire: PrivateWireMessage = from_bytes(&decrypted.plaintext).unwrap();
        wire.created_at += 1;
        decrypted.plaintext = to_allocvec(&wire).unwrap();

        let error = open_frame(&bob_session, decrypted).unwrap_err();
        assert!(error.to_string().contains("timestamp"));
    }

    #[test]
    fn unauthenticated_plaintext_is_never_rendered() {
        let alice = identity("alice");
        let bob = identity("bob");
        let (mut alice_session, mut bob_session) = session_pair(&alice, &bob);

        let frame = alice_session
            .encrypt_with_type(&alice, b"just plaintext", now(), MessageType::PRIVATE)
            .unwrap();
        assert!(open(&mut bob_session, &frame, now()).is_err());
    }

    #[test]
    fn valid_receipt_acknowledges_only_the_authenticated_message() {
        let alice = identity("alice");
        let bob = identity("bob");
        let (mut alice_session, mut bob_session) = session_pair(&alice, &bob);
        let (sent, frame) = compose(
            &mut alice_session,
            &alice,
            bob.identity_id(),
            "ack me",
            now(),
        )
        .unwrap();
        open(&mut bob_session, &frame, now()).unwrap();

        let (_, receipt) = compose_receipt(&mut bob_session, &bob, sent.message_id, now()).unwrap();
        let opened = open_receipt(&mut alice_session, &receipt, now()).unwrap();
        assert_eq!(opened.acknowledged, sent.message_id);
        assert_eq!(opened.sender, bob.identity_id());
        assert_eq!(opened.result, RECEIPT_DELIVERED);
    }

    #[test]
    fn inner_receipt_timestamp_must_match_the_envelope() {
        let alice = identity("alice");
        let bob = identity("bob");
        let (mut alice_session, mut bob_session) = session_pair(&alice, &bob);
        let (_, receipt) =
            compose_receipt(&mut bob_session, &bob, MessageId([7; 16]), now()).unwrap();
        let mut decrypted = alice_session.decrypt(&receipt, now()).unwrap();
        let mut wire: ReceiptWireMessage = from_bytes(&decrypted.plaintext).unwrap();
        wire.created_at += 1;
        decrypted.plaintext = to_allocvec(&wire).unwrap();

        let error = open_receipt_frame(&alice_session, decrypted).unwrap_err();
        assert!(error.to_string().contains("timestamp"));
    }

    #[test]
    fn receipt_from_unexpected_peer_is_rejected() {
        let alice = identity("alice");
        let bob = identity("bob");
        let mallory = identity("mallory");
        let (mut alice_session, _) = session_pair(&alice, &bob);
        let (mut mallory_session, _) = session_pair(&mallory, &alice);

        let (_, receipt) =
            compose_receipt(&mut mallory_session, &mallory, MessageId([7; 16]), now()).unwrap();
        assert!(open_receipt(&mut alice_session, &receipt, now()).is_err());
    }
}
