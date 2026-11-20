//! Authenticated, version-bound sessions over a raw transport connection.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use crate::{
    identity::Identity,
    protocol::{
        BoundedBytes, Envelope, IdentityId, MAX_ENCRYPTED_PAYLOAD_BYTES, MessageId, MessageType,
        PROTOCOL_VERSION, ProtocolError, Recipient, RoutingMetadata, decode_frame, encode_frame,
    },
    trust::{TrustError, TrustState, TrustStore},
};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MAX_SESSION_PLAINTEXT: usize = MAX_ENCRYPTED_PAYLOAD_BYTES - NONCE_LEN - TAG_LEN;
const SESSION_INFO: &[u8] = b"ghost-v1-session";

#[derive(Debug)]
pub enum SessionError {
    Protocol(ProtocolError),
    Trust(TrustError),
    Encoding,
    KeyDerivation,
    InvalidHello,
    UnsupportedVersion(u16),
    UntrustedPeer,
    BlockedPeer,
    KeyChanged,
    BadSignature,
    BadRecipient,
    BadCiphertext,
    PayloadTooLarge,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "session frame error: {error}"),
            Self::Trust(error) => write!(f, "session trust policy error: {error}"),
            Self::Encoding => f.write_str("session message encoding is invalid"),
            Self::KeyDerivation => f.write_str("session key derivation failed"),
            Self::InvalidHello => f.write_str("peer hello is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(f, "peer protocol version {version} is unsupported")
            }
            Self::UntrustedPeer => f.write_str("peer fingerprint is not verified; session refused"),
            Self::BlockedPeer => f.write_str("peer is blocked; session refused"),
            Self::KeyChanged => f.write_str("peer identity key changed; re-verification required"),
            Self::BadSignature => f.write_str("peer authentication failed"),
            Self::BadRecipient => f.write_str("session frame was addressed to another peer"),
            Self::BadCiphertext => f.write_str("session frame failed authentication"),
            Self::PayloadTooLarge => f.write_str("session payload is too large"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<ProtocolError> for SessionError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<TrustError> for SessionError {
    fn from(error: TrustError) -> Self {
        Self::Trust(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct HelloBody {
    ephemeral: [u8; 32],
    challenge: [u8; 32],
    label: BoundedBytes<64>,
}

impl HelloBody {
    fn label(&self) -> &str {
        std::str::from_utf8(self.label.as_slice()).unwrap_or("invalid label")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptedFrame {
    pub message_id: MessageId,
    pub sender: IdentityId,
    pub recipient: IdentityId,
    pub created_at: u64,
    pub message_type: MessageType,
    pub plaintext: Vec<u8>,
}

#[derive(Serialize)]
struct SignedHello<'a> {
    version: u16,
    message_id: &'a [u8; 16],
    sender: &'a [u8; 32],
    created_at: u64,
    expires_at: u64,
    body: &'a HelloBody,
}

pub struct PendingSession {
    secret: EphemeralSecret,
    local_id: IdentityId,
    local_challenge: [u8; 32],
    hello_frame: Vec<u8>,
}

impl PendingSession {
    pub fn hello_frame(&self) -> &[u8] {
        &self.hello_frame
    }

    pub fn complete(
        self,
        identity: &Identity,
        trust: &mut TrustStore,
        peer_frame: &[u8],
        now: u64,
    ) -> Result<EstablishedSession, SessionError> {
        let peer_envelope = decode_frame(peer_frame, now)?;
        if peer_envelope.protocol_version != PROTOCOL_VERSION {
            return Err(SessionError::UnsupportedVersion(
                peer_envelope.protocol_version,
            ));
        }
        if peer_envelope.message_type != MessageType::CONTROL {
            return Err(SessionError::InvalidHello);
        }
        if identity.identity_id() == peer_envelope.sender_identity {
            return Err(SessionError::InvalidHello);
        }

        let peer_body: HelloBody = postcard::from_bytes(peer_envelope.encrypted_payload.as_slice())
            .map_err(|_| SessionError::Encoding)?;
        let signed = signed_hello_bytes(
            peer_envelope.protocol_version,
            &peer_envelope.message_id.0,
            &peer_envelope.sender_identity.0,
            peer_envelope.created_at,
            peer_envelope.expires_at,
            &peer_body,
        )?;
        let peer_key = VerifyingKey::from_bytes(&peer_envelope.sender_identity.0)
            .map_err(|_| SessionError::BadSignature)?;
        peer_key
            .verify(
                &signed,
                &ed25519_dalek::Signature::from_bytes(&peer_envelope.authentication_data.0),
            )
            .map_err(|_| SessionError::BadSignature)?;

        let outcome = trust.observe(peer_envelope.sender_identity, peer_body.label(), now)?;
        match outcome {
            crate::trust::ObserveOutcome::KeyChange { .. } => {
                return Err(SessionError::KeyChanged);
            }
            crate::trust::ObserveOutcome::Blocked => {
                return Err(SessionError::BlockedPeer);
            }
            crate::trust::ObserveOutcome::New | crate::trust::ObserveOutcome::Existing => {}
        }
        match trust.state_of(&peer_envelope.sender_identity) {
            TrustState::Verified => {}
            TrustState::Unverified => return Err(SessionError::UntrustedPeer),
            TrustState::Blocked => return Err(SessionError::BlockedPeer),
        }

        let peer_public = PublicKey::from(peer_body.ephemeral);
        let shared = self.secret.diffie_hellman(&peer_public);
        let transcript = transcript_hash(
            self.local_id,
            &self.hello_frame,
            peer_envelope.sender_identity,
            peer_frame,
        );

        let mut challenges = [
            (self.local_id.0, self.local_challenge),
            (peer_envelope.sender_identity.0, peer_body.challenge),
        ];
        challenges.sort_by_key(|entry| entry.0);
        let mut salt = [0u8; 64];
        salt[..32].copy_from_slice(&challenges[0].1);
        salt[32..].copy_from_slice(&challenges[1].1);
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
        let mut info = SESSION_INFO.to_vec();
        info.extend_from_slice(&transcript);
        let mut key = [0u8; 32];
        hkdf.expand(&info, &mut key)
            .map_err(|_| SessionError::KeyDerivation)?;

        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&transcript[..16]);
        Ok(EstablishedSession {
            key: Zeroizing::new(key),
            session_id,
            transcript,
            local_id: self.local_id,
            peer_id: peer_envelope.sender_identity,
            peer_label: peer_body.label().to_owned(),
            send_sequence: 0,
            recv_sequence: 0,
        })
    }
}

pub struct EstablishedSession {
    key: Zeroizing<[u8; 32]>,
    session_id: [u8; 16],
    transcript: [u8; 32],
    local_id: IdentityId,
    peer_id: IdentityId,
    peer_label: String,
    send_sequence: u64,
    recv_sequence: u64,
}

impl EstablishedSession {
    pub fn local_id(&self) -> IdentityId {
        self.local_id
    }

    pub fn peer_id(&self) -> IdentityId {
        self.peer_id
    }

    pub fn peer_label(&self) -> &str {
        &self.peer_label
    }

    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    pub fn encrypt(
        &mut self,
        identity: &Identity,
        plaintext: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, SessionError> {
        self.encrypt_with_type(identity, plaintext, now, MessageType::CONTROL)
    }

    pub fn encrypt_with_type(
        &mut self,
        identity: &Identity,
        plaintext: &[u8],
        now: u64,
        message_type: MessageType,
    ) -> Result<Vec<u8>, SessionError> {
        if plaintext.is_empty() || plaintext.len() > MAX_SESSION_PLAINTEXT {
            return Err(SessionError::PayloadTooLarge);
        }

        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let aad = self.aad(self.send_sequence, self.local_id, self.peer_id);
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key[..])
            .map_err(|_| SessionError::KeyDerivation)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| SessionError::BadCiphertext)?;
        let mut payload = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ciphertext);

        let mut message_id = [0u8; 16];
        OsRng.fill_bytes(&mut message_id);
        let envelope = Envelope {
            protocol_version: PROTOCOL_VERSION,
            message_id: MessageId(message_id),
            sender_identity: self.local_id,
            recipient: Recipient::Peer(self.peer_id),
            message_type,
            created_at: now,
            expires_at: now.saturating_add(60),
            routing: RoutingMetadata {
                hop_count: 0,
                hop_limit: 0,
            },
            encrypted_payload: BoundedBytes::new(payload)?,
            authentication_data: identity.sign(&aad),
        };
        self.send_sequence = self.send_sequence.saturating_add(1);
        encode_frame(&envelope).map_err(Into::into)
    }

    pub fn decrypt(&mut self, frame: &[u8], now: u64) -> Result<DecryptedFrame, SessionError> {
        let envelope = decode_frame(frame, now)?;
        if envelope.sender_identity != self.peer_id
            || envelope.recipient != Recipient::Peer(self.local_id)
        {
            return Err(SessionError::BadRecipient);
        }

        let aad = self.aad(self.recv_sequence, envelope.sender_identity, self.local_id);
        let peer_key =
            VerifyingKey::from_bytes(&self.peer_id.0).map_err(|_| SessionError::BadSignature)?;
        peer_key
            .verify(
                &aad,
                &ed25519_dalek::Signature::from_bytes(&envelope.authentication_data.0),
            )
            .map_err(|_| SessionError::BadSignature)?;

        let payload = envelope.encrypted_payload.as_slice();
        if payload.len() < NONCE_LEN + TAG_LEN {
            return Err(SessionError::BadCiphertext);
        }
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key[..])
            .map_err(|_| SessionError::KeyDerivation)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&payload[..NONCE_LEN]),
                Payload {
                    msg: &payload[NONCE_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| SessionError::BadCiphertext)?;
        self.recv_sequence = self.recv_sequence.saturating_add(1);
        Ok(DecryptedFrame {
            message_id: envelope.message_id,
            sender: envelope.sender_identity,
            recipient: match envelope.recipient {
                Recipient::Peer(id) => id,
                Recipient::Group(_) => return Err(SessionError::BadRecipient),
            },
            created_at: envelope.created_at,
            message_type: envelope.message_type,
            plaintext,
        })
    }

    pub fn encrypt_content(
        &self,
        plaintext: &[u8],
        message_id: &MessageId,
        recipient: IdentityId,
    ) -> Result<([u8; NONCE_LEN], Vec<u8>), SessionError> {
        if plaintext.is_empty() || plaintext.len() > MAX_SESSION_PLAINTEXT {
            return Err(SessionError::PayloadTooLarge);
        }
        let key = self.message_key(message_id, self.local_id, recipient)?;
        let aad = self.content_aad(message_id, self.local_id, recipient);
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let cipher =
            ChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| SessionError::KeyDerivation)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| SessionError::BadCiphertext)?;
        Ok((nonce, ciphertext))
    }

    pub fn decrypt_content(
        &self,
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
        message_id: &MessageId,
        sender: IdentityId,
    ) -> Result<Vec<u8>, SessionError> {
        let key = self.message_key(message_id, sender, self.local_id)?;
        let aad = self.content_aad(message_id, sender, self.local_id);
        let cipher =
            ChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| SessionError::KeyDerivation)?;
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| SessionError::BadCiphertext)
    }

    fn message_key(
        &self,
        message_id: &MessageId,
        first: IdentityId,
        second: IdentityId,
    ) -> Result<Zeroizing<[u8; 32]>, SessionError> {
        let mut parties = [first.0, second.0];
        parties.sort();
        let hkdf = Hkdf::<Sha256>::new(Some(&self.session_id), &self.key[..]);
        let mut info = b"ghost-v1-message".to_vec();
        info.extend_from_slice(&message_id.0);
        for party in parties {
            info.extend_from_slice(&party);
        }
        let mut key = [0u8; 32];
        hkdf.expand(&info, &mut key)
            .map_err(|_| SessionError::KeyDerivation)?;
        Ok(Zeroizing::new(key))
    }

    fn content_aad(
        &self,
        message_id: &MessageId,
        sender: IdentityId,
        recipient: IdentityId,
    ) -> Vec<u8> {
        let mut aad = Vec::with_capacity(16 + 32 + 16 + 32 + 32);
        aad.extend_from_slice(&self.session_id);
        aad.extend_from_slice(&self.transcript);
        aad.extend_from_slice(&message_id.0);
        aad.extend_from_slice(&sender.0);
        aad.extend_from_slice(&recipient.0);
        aad
    }

    fn aad(&self, sequence: u64, sender: IdentityId, recipient: IdentityId) -> Vec<u8> {
        let mut aad = Vec::with_capacity(16 + 32 + 32 + 32 + 8 + 32);
        aad.extend_from_slice(&self.session_id);
        aad.extend_from_slice(&self.transcript);
        aad.extend_from_slice(&sender.0);
        aad.extend_from_slice(&recipient.0);
        aad.extend_from_slice(&sequence.to_be_bytes());
        aad
    }
}

pub fn fingerprint_of(identity_id: &IdentityId) -> String {
    crate::identity::fingerprint_from_public_key(&identity_id.0).short()
}

pub fn initiate(identity: &Identity) -> Result<(PendingSession, Vec<u8>), SessionError> {
    initiate_with_version(identity, PROTOCOL_VERSION)
}

pub fn initiate_with_version(
    identity: &Identity,
    version: u16,
) -> Result<(PendingSession, Vec<u8>), SessionError> {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral = PublicKey::from(&secret).to_bytes();
    let mut challenge = [0u8; 32];
    OsRng.fill_bytes(&mut challenge);

    let body = HelloBody {
        ephemeral,
        challenge,
        label: BoundedBytes::new(identity.username().as_bytes().to_vec())?,
    };
    let mut message_id = [0u8; 16];
    OsRng.fill_bytes(&mut message_id);
    let now = now();
    let signed = signed_hello_bytes(
        version,
        &message_id,
        &identity.identity_id().0,
        now,
        now.saturating_add(60),
        &body,
    )?;
    let envelope = Envelope {
        protocol_version: version,
        message_id: MessageId(message_id),
        sender_identity: identity.identity_id(),
        recipient: Recipient::Peer(identity.identity_id()),
        message_type: MessageType::CONTROL,
        created_at: now,
        expires_at: now.saturating_add(60),
        routing: RoutingMetadata {
            hop_count: 0,
            hop_limit: 0,
        },
        encrypted_payload: BoundedBytes::new(
            postcard::to_allocvec(&body).map_err(|_| SessionError::Encoding)?,
        )?,
        authentication_data: identity.sign(&signed),
    };
    let hello_frame = encode_frame(&envelope)?;
    let pending = PendingSession {
        secret,
        local_id: identity.identity_id(),
        local_challenge: challenge,
        hello_frame: hello_frame.clone(),
    };
    Ok((pending, hello_frame))
}

fn signed_hello_bytes(
    version: u16,
    message_id: &[u8; 16],
    sender: &[u8; 32],
    created_at: u64,
    expires_at: u64,
    body: &HelloBody,
) -> Result<Vec<u8>, SessionError> {
    postcard::to_allocvec(&SignedHello {
        version,
        message_id,
        sender,
        created_at,
        expires_at,
        body,
    })
    .map_err(|_| SessionError::Encoding)
}

fn transcript_hash(
    local_id: IdentityId,
    local_frame: &[u8],
    peer_id: IdentityId,
    peer_frame: &[u8],
) -> [u8; 32] {
    let mut hellos = [(local_id.0, local_frame), (peer_id.0, peer_frame)];
    hellos.sort_by_key(|entry| entry.0);
    let mut hasher = Sha256::new();
    for (identity, frame) in hellos {
        hasher.update(identity);
        hasher.update((frame.len() as u32).to_be_bytes());
        hasher.update(frame);
    }
    hasher.finalize().into()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::{IdentityStore, fingerprint_from_public_key},
        trust::TrustStore,
    };
    use tempfile::tempdir;

    fn identity(name: &str) -> Identity {
        let dir = tempdir().unwrap();
        let store = IdentityStore::new(dir.path().join("identity.ghost"));
        store.create(name, b"correct horse battery staple").unwrap()
    }

    fn trust_for(peer: &Identity) -> TrustStore {
        let dir = tempdir().unwrap();
        let mut trust = TrustStore::new(dir.path().join("trust.ghost"));
        trust
            .observe(peer.identity_id(), peer.username(), now())
            .unwrap();
        let fingerprint = fingerprint_from_public_key(&peer.identity_id().0).full();
        trust.verify(&fingerprint, &fingerprint, now()).unwrap();
        trust
    }

    #[test]
    fn trusted_peers_establish_a_session_and_exchange_data() {
        let alice = identity("alice");
        let bob = identity("bob");
        let (alice_pending, alice_hello) = initiate(&alice).unwrap();
        let (bob_pending, bob_hello) = initiate(&bob).unwrap();
        let mut alice_trust = trust_for(&bob);
        let mut bob_trust = trust_for(&alice);

        let mut alice_session = alice_pending
            .complete(&alice, &mut alice_trust, &bob_hello, now())
            .unwrap();
        let mut bob_session = bob_pending
            .complete(&bob, &mut bob_trust, &alice_hello, now())
            .unwrap();
        assert_eq!(alice_session.session_id(), bob_session.session_id());
        assert_eq!(alice_session.peer_id(), bob.identity_id());
        assert_eq!(bob_session.peer_id(), alice.identity_id());

        let frame = alice_session.encrypt(&alice, b"hello bob", now()).unwrap();
        assert_eq!(
            bob_session.decrypt(&frame, now()).unwrap().plaintext,
            b"hello bob"
        );

        let reply = bob_session.encrypt(&bob, b"hello alice", now()).unwrap();
        assert_eq!(
            alice_session.decrypt(&reply, now()).unwrap().plaintext,
            b"hello alice"
        );
    }

    #[test]
    fn unverified_peer_is_rejected() {
        let alice = identity("alice");
        let bob = identity("bob");
        let (alice_pending, _) = initiate(&alice).unwrap();
        let (_, bob_hello) = initiate(&bob).unwrap();
        let dir = tempdir().unwrap();
        let mut trust = TrustStore::new(dir.path().join("trust.ghost"));

        assert!(matches!(
            alice_pending.complete(&alice, &mut trust, &bob_hello, now()),
            Err(SessionError::UntrustedPeer)
        ));
    }

    #[test]
    fn impersonating_peer_is_rejected() {
        let alice = identity("alice");
        let mallory = identity("bob");
        let (alice_pending, _) = initiate(&alice).unwrap();
        let (_, mallory_hello) = initiate(&mallory).unwrap();
        let mut trust = trust_for(&identity("bob"));

        assert!(matches!(
            alice_pending.complete(&alice, &mut trust, &mallory_hello, now()),
            Err(SessionError::KeyChanged
                | SessionError::UntrustedPeer
                | SessionError::BadSignature)
        ));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let alice = identity("alice");
        let bob = identity("bob");
        let (alice_pending, _) = initiate(&alice).unwrap();
        let (_, bad_hello) = initiate_with_version(&bob, 2).unwrap();
        let mut trust = trust_for(&bob);

        assert!(
            alice_pending
                .complete(&alice, &mut trust, &bad_hello, now())
                .is_err()
        );
    }
}
