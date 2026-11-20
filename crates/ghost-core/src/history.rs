//! Encrypted message history records.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::protocol::{IdentityId, MessageId};

pub const MAX_HISTORY_BODY_BYTES: usize = 4096;
const NONCE_LEN: usize = 12;

#[derive(Debug)]
pub enum HistoryCryptoError {
    Invalid(&'static str),
    Encrypt,
    Decrypt,
    Encoding,
}

impl std::fmt::Display for HistoryCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid history record: {reason}"),
            Self::Encrypt => f.write_str("could not encrypt history record"),
            Self::Decrypt => f.write_str("history record authentication failed"),
            Self::Encoding => f.write_str("history record encoding is invalid"),
        }
    }
}

impl std::error::Error for HistoryCryptoError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryRecord {
    pub message_id: MessageId,
    pub conversation_id: String,
    pub sender: IdentityId,
    pub recipient: IdentityId,
    pub created_at: u64,
    pub outgoing: bool,
    pub body: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedHistoryRecord {
    pub message_id: MessageId,
    pub conversation_id: String,
    pub sender: IdentityId,
    pub recipient: IdentityId,
    pub created_at: u64,
    pub outgoing: bool,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

fn aad(record: &EncryptedHistoryRecord) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 4 + record.conversation_id.len() + 32 + 32 + 8 + 1);
    aad.extend_from_slice(&record.message_id.0);
    aad.extend_from_slice(&(record.conversation_id.len() as u32).to_be_bytes());
    aad.extend_from_slice(record.conversation_id.as_bytes());
    aad.extend_from_slice(&record.sender.0);
    aad.extend_from_slice(&record.recipient.0);
    aad.extend_from_slice(&record.created_at.to_be_bytes());
    aad.push(u8::from(record.outgoing));
    aad
}

pub fn encrypt_record(
    record: &HistoryRecord,
    key: &Zeroizing<[u8; 32]>,
) -> Result<EncryptedHistoryRecord, HistoryCryptoError> {
    if record.body.is_empty() || record.body.len() > MAX_HISTORY_BODY_BYTES {
        return Err(HistoryCryptoError::Invalid("body length is out of bounds"));
    }
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let mut encrypted = EncryptedHistoryRecord {
        message_id: record.message_id,
        conversation_id: record.conversation_id.clone(),
        sender: record.sender,
        recipient: record.recipient,
        created_at: record.created_at,
        outgoing: record.outgoing,
        nonce,
        ciphertext: Vec::new(),
    };
    let cipher =
        ChaCha20Poly1305::new_from_slice(&**key).map_err(|_| HistoryCryptoError::Encrypt)?;
    let aad = aad(&encrypted);
    encrypted.ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: record.body.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| HistoryCryptoError::Encrypt)?;
    Ok(encrypted)
}

pub fn decrypt_record(
    encrypted: &EncryptedHistoryRecord,
    key: &Zeroizing<[u8; 32]>,
) -> Result<HistoryRecord, HistoryCryptoError> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(&**key).map_err(|_| HistoryCryptoError::Decrypt)?;
    let aad = aad(encrypted);
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&encrypted.nonce),
            Payload {
                msg: &encrypted.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| HistoryCryptoError::Decrypt)?;
    if plaintext.is_empty() || plaintext.len() > MAX_HISTORY_BODY_BYTES {
        return Err(HistoryCryptoError::Invalid("body length is out of bounds"));
    }
    let body = String::from_utf8(plaintext).map_err(|_| HistoryCryptoError::Encoding)?;
    Ok(HistoryRecord {
        message_id: encrypted.message_id,
        conversation_id: encrypted.conversation_id.clone(),
        sender: encrypted.sender,
        recipient: encrypted.recipient,
        created_at: encrypted.created_at,
        outgoing: encrypted.outgoing,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Zeroizing<[u8; 32]> {
        Zeroizing::new([7u8; 32])
    }

    fn sample() -> HistoryRecord {
        HistoryRecord {
            message_id: MessageId([1; 16]),
            conversation_id: "peer-a".into(),
            sender: IdentityId([2; 32]),
            recipient: IdentityId([3; 32]),
            created_at: 123,
            outgoing: true,
            body: "secret history".into(),
        }
    }

    #[test]
    fn round_trip_preserves_plaintext() {
        let record = sample();
        let encrypted = encrypt_record(&record, &key()).unwrap();
        assert_ne!(encrypted.ciphertext, b"secret history");
        let decrypted = decrypt_record(&encrypted, &key()).unwrap();
        assert_eq!(decrypted, record);
    }

    #[test]
    fn tampered_ciphertext_or_metadata_fails_safely() {
        let encrypted = encrypt_record(&sample(), &key()).unwrap();
        let mut tampered = encrypted.clone();
        tampered.ciphertext[0] ^= 1;
        let err = decrypt_record(&tampered, &key()).unwrap_err();
        assert_eq!(err.to_string(), "history record authentication failed");

        let mut swapped = encrypted;
        swapped.conversation_id = "peer-b".into();
        assert!(decrypt_record(&swapped, &key()).is_err());
    }
}
