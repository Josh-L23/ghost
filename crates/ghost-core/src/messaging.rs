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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateMessage {
    pub message_id: MessageId,
    pub sender: IdentityId,
    pub recipient: IdentityId,
    pub created_at: u64,
    pub text: String,
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
    fn unauthenticated_plaintext_is_never_rendered() {
        let alice = identity("alice");
        let bob = identity("bob");
        let (mut alice_session, mut bob_session) = session_pair(&alice, &bob);

        let frame = alice_session
            .encrypt_with_type(&alice, b"just plaintext", now(), MessageType::PRIVATE)
            .unwrap();
        assert!(open(&mut bob_session, &frame, now()).is_err());
    }
}
