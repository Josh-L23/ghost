//! Versioned wire envelope and bounded validation rules.
//!
//! These types describe the GHOST v1 wire format. They do not implement
//! cryptography; cryptographic constructions are specified in `docs/protocol.md`.

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{SeqAccess, Visitor},
    ser::{SerializeSeq, SerializeTuple},
};

pub const PROTOCOL_VERSION: u16 = 1;
pub const FRAME_HEADER_LEN: usize = 4;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_ENVELOPE_BYTES: usize = MAX_FRAME_BYTES - FRAME_HEADER_LEN;
pub const MAX_ENCRYPTED_PAYLOAD_BYTES: usize = 16 * 1024;
pub const ENCRYPTED_PAYLOAD_OVERHEAD: usize = 12 + 16;
pub const MAX_MESSAGE_LIFETIME_SECS: u64 = 24 * 60 * 60;
pub const MAX_FUTURE_SKEW_SECS: u64 = 5 * 60;
pub const MAX_HOP_LIMIT: u8 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    FrameTooLarge(usize),
    InvalidFrameLength(usize),
    TrailingBytes(usize),
    Encoding(postcard::Error),
    UnsupportedVersion(u16),
    UnknownMessageType(u8),
    ZeroMessageId,
    ZeroIdentityId,
    ZeroSignature,
    PayloadTooShort(usize),
    PayloadTooLarge(usize),
    InvalidTimestamps,
    ExcessiveLifetime(u64),
    FutureTimestamp,
    Expired,
    InvalidHops,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FrameTooLarge(len) => write!(f, "frame length {len} exceeds the limit"),
            Self::InvalidFrameLength(len) => write!(f, "invalid frame length {len}"),
            Self::TrailingBytes(len) => write!(f, "{len} trailing bytes after envelope"),
            Self::Encoding(error) => write!(f, "invalid envelope encoding: {error}"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported protocol version {version}")
            }
            Self::UnknownMessageType(kind) => write!(f, "unknown message type {kind}"),
            Self::ZeroMessageId => f.write_str("message id is empty"),
            Self::ZeroIdentityId => f.write_str("identity id is empty"),
            Self::ZeroSignature => f.write_str("authentication data is empty"),
            Self::PayloadTooShort(len) => write!(f, "encrypted payload is too short: {len}"),
            Self::PayloadTooLarge(len) => write!(f, "encrypted payload is too large: {len}"),
            Self::InvalidTimestamps => f.write_str("expiry must be later than creation"),
            Self::ExcessiveLifetime(secs) => write!(f, "message lifetime {secs}s is too long"),
            Self::FutureTimestamp => f.write_str("creation time is too far in the future"),
            Self::Expired => f.write_str("message has expired"),
            Self::InvalidHops => f.write_str("hop count exceeds hop limit"),
        }
    }
}

impl std::error::Error for ProtocolError {}

macro_rules! fixed_id {
    ($name:ident, $len:expr) => {
        #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            pub fn is_zero(&self) -> bool {
                self.0.iter().all(|byte| *byte == 0)
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut tuple = serializer.serialize_tuple($len)?;
                for byte in &self.0 {
                    tuple.serialize_element(byte)?;
                }
                tuple.end()
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct BytesVisitor<const N: usize>;

                impl<'de, const N: usize> Visitor<'de> for BytesVisitor<N> {
                    type Value = [u8; N];

                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(f, "exactly {N} bytes")
                    }

                    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                    where
                        A: SeqAccess<'de>,
                    {
                        let mut bytes = [0u8; N];
                        for (index, byte) in bytes.iter_mut().enumerate() {
                            *byte = seq
                                .next_element()?
                                .ok_or_else(|| serde::de::Error::invalid_length(index, &self))?;
                        }
                        if seq.next_element::<u8>()?.is_some() {
                            return Err(serde::de::Error::invalid_length(N + 1, &self));
                        }
                        Ok(bytes)
                    }
                }

                deserializer
                    .deserialize_tuple($len, BytesVisitor::<$len>)
                    .map(Self)
            }
        }
    };
}

fixed_id!(MessageId, 16);
fixed_id!(IdentityId, 32);
fixed_id!(GroupId, 32);
fixed_id!(Signature, 64);

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Recipient {
    Peer(IdentityId),
    Group(GroupId),
}

impl Recipient {
    pub fn is_zero(&self) -> bool {
        match self {
            Self::Peer(id) => id.is_zero(),
            Self::Group(id) => id.is_zero(),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MessageType(pub u8);

impl MessageType {
    pub const PRIVATE: Self = Self(1);
    pub const GROUP: Self = Self(2);
    pub const RECEIPT: Self = Self(3);
    pub const CONTROL: Self = Self(4);

    pub fn is_known(self) -> bool {
        matches!(self.0, 1..=4)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingMetadata {
    pub hop_count: u8,
    pub hop_limit: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundedBytes<const N: usize>(Vec<u8>);

impl<const N: usize> BoundedBytes<N> {
    pub fn new(bytes: Vec<u8>) -> Result<Self, ProtocolError> {
        if bytes.is_empty() {
            return Err(ProtocolError::PayloadTooShort(0));
        }
        if bytes.len() > N {
            return Err(ProtocolError::PayloadTooLarge(bytes.len()));
        }
        Ok(Self(bytes))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl<const N: usize> Serialize for BoundedBytes<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for byte in &self.0 {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }
}

impl<'de, const N: usize> Deserialize<'de> for BoundedBytes<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor<const N: usize>;

        impl<'de, const N: usize> Visitor<'de> for BytesVisitor<N> {
            type Value = BoundedBytes<N>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "a byte sequence of at most {N} bytes")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let hint = seq.size_hint().unwrap_or(0);
                if hint > N {
                    return Err(serde::de::Error::custom(
                        "byte sequence exceeds maximum length",
                    ));
                }
                let mut bytes = Vec::with_capacity(hint.min(N));
                while let Some(byte) = seq.next_element::<u8>()? {
                    if bytes.len() == N {
                        return Err(serde::de::Error::custom(
                            "byte sequence exceeds maximum length",
                        ));
                    }
                    bytes.push(byte);
                }
                BoundedBytes::new(bytes).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_seq(BytesVisitor::<N>)
    }
}

pub type EncryptedPayload = BoundedBytes<MAX_ENCRYPTED_PAYLOAD_BYTES>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub protocol_version: u16,
    pub message_id: MessageId,
    pub sender_identity: IdentityId,
    pub recipient: Recipient,
    pub message_type: MessageType,
    pub created_at: u64,
    pub expires_at: u64,
    pub routing: RoutingMetadata,
    pub encrypted_payload: EncryptedPayload,
    pub authentication_data: Signature,
}

pub fn validate(envelope: &Envelope, now: u64) -> Result<(), ProtocolError> {
    if envelope.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(envelope.protocol_version));
    }
    if !envelope.message_type.is_known() {
        return Err(ProtocolError::UnknownMessageType(envelope.message_type.0));
    }
    if envelope.message_id.is_zero() {
        return Err(ProtocolError::ZeroMessageId);
    }
    if envelope.sender_identity.is_zero() || envelope.recipient.is_zero() {
        return Err(ProtocolError::ZeroIdentityId);
    }
    if envelope.authentication_data.is_zero() {
        return Err(ProtocolError::ZeroSignature);
    }
    if envelope.routing.hop_count > envelope.routing.hop_limit
        || envelope.routing.hop_limit > MAX_HOP_LIMIT
    {
        return Err(ProtocolError::InvalidHops);
    }

    let payload_len = envelope.encrypted_payload.as_slice().len();
    if payload_len == 0 {
        return Err(ProtocolError::PayloadTooShort(0));
    }
    if payload_len > MAX_ENCRYPTED_PAYLOAD_BYTES {
        return Err(ProtocolError::PayloadTooLarge(payload_len));
    }
    if envelope.message_type != MessageType::CONTROL && payload_len < ENCRYPTED_PAYLOAD_OVERHEAD {
        return Err(ProtocolError::PayloadTooShort(payload_len));
    }

    let lifetime = envelope
        .expires_at
        .checked_sub(envelope.created_at)
        .ok_or(ProtocolError::InvalidTimestamps)?;
    if lifetime == 0 {
        return Err(ProtocolError::InvalidTimestamps);
    }
    if lifetime > MAX_MESSAGE_LIFETIME_SECS {
        return Err(ProtocolError::ExcessiveLifetime(lifetime));
    }
    if envelope.created_at > now.saturating_add(MAX_FUTURE_SKEW_SECS) {
        return Err(ProtocolError::FutureTimestamp);
    }
    if envelope.expires_at <= now {
        return Err(ProtocolError::Expired);
    }
    Ok(())
}

pub fn encode_frame(envelope: &Envelope) -> Result<Vec<u8>, ProtocolError> {
    let payload = postcard::to_allocvec(envelope).map_err(ProtocolError::Encoding)?;
    if payload.is_empty() || payload.len() > MAX_ENVELOPE_BYTES {
        return Err(ProtocolError::FrameTooLarge(payload.len()));
    }
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_frame(frame: &[u8], now: u64) -> Result<Envelope, ProtocolError> {
    if frame.len() < FRAME_HEADER_LEN {
        return Err(ProtocolError::InvalidFrameLength(frame.len()));
    }
    let declared = u32::from_be_bytes(frame[..FRAME_HEADER_LEN].try_into().unwrap()) as usize;
    if declared == 0 || declared > MAX_ENVELOPE_BYTES {
        return Err(ProtocolError::FrameTooLarge(declared));
    }
    if frame.len() != FRAME_HEADER_LEN + declared {
        return Err(ProtocolError::InvalidFrameLength(declared));
    }
    decode_envelope(&frame[FRAME_HEADER_LEN..], now)
}

pub fn decode_envelope(payload: &[u8], now: u64) -> Result<Envelope, ProtocolError> {
    if payload.len() > MAX_ENVELOPE_BYTES {
        return Err(ProtocolError::FrameTooLarge(payload.len()));
    }
    let (envelope, remainder) =
        postcard::take_from_bytes::<Envelope>(payload).map_err(ProtocolError::Encoding)?;
    if !remainder.is_empty() {
        return Err(ProtocolError::TrailingBytes(remainder.len()));
    }
    validate(&envelope, now)?;
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    fn sample() -> Envelope {
        Envelope {
            protocol_version: PROTOCOL_VERSION,
            message_id: MessageId([1; 16]),
            sender_identity: IdentityId([2; 32]),
            recipient: Recipient::Peer(IdentityId([3; 32])),
            message_type: MessageType::PRIVATE,
            created_at: NOW,
            expires_at: NOW + 3_600,
            routing: RoutingMetadata {
                hop_count: 0,
                hop_limit: 4,
            },
            encrypted_payload: EncryptedPayload::new(vec![7; 12 + 16 + 8]).unwrap(),
            authentication_data: Signature([9; 64]),
        }
    }

    #[test]
    fn frame_round_trip() {
        let original = sample();
        let frame = encode_frame(&original).unwrap();
        assert_eq!(
            frame.len(),
            FRAME_HEADER_LEN + postcard::to_allocvec(&original).unwrap().len()
        );
        assert_eq!(decode_frame(&frame, NOW).unwrap(), original);
    }

    #[test]
    fn rejects_oversized_declared_length_without_reading_payload() {
        let frame = u32::MAX.to_be_bytes();
        assert_eq!(
            decode_frame(&frame, NOW),
            Err(ProtocolError::FrameTooLarge(u32::MAX as usize))
        );
    }

    #[test]
    fn rejects_truncated_and_extended_frames() {
        let frame = encode_frame(&sample()).unwrap();
        assert!(matches!(
            decode_frame(&frame[..frame.len() - 1], NOW),
            Err(ProtocolError::InvalidFrameLength(_))
        ));
        let mut extended = frame.clone();
        extended.push(0);
        assert!(matches!(
            decode_frame(&extended, NOW),
            Err(ProtocolError::InvalidFrameLength(_))
        ));
    }

    #[test]
    fn rejects_trailing_bytes_inside_declared_length() {
        let mut payload = postcard::to_allocvec(&sample()).unwrap();
        payload.push(0);
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);
        assert_eq!(
            decode_frame(&frame, NOW),
            Err(ProtocolError::TrailingBytes(1))
        );
    }

    #[test]
    fn bounds_payload_length_from_wire_input() {
        let huge_length = postcard::to_allocvec(&1_000_000usize).unwrap();
        assert!(postcard::from_bytes::<BoundedBytes<16>>(&huge_length).is_err());
    }

    #[test]
    fn random_frames_never_panic() {
        let mut state = 0x1234_5678_u64;
        for len in 0..256 {
            let mut frame = Vec::with_capacity(len);
            for _ in 0..len {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                frame.push((state >> 33) as u8);
            }
            let _ = decode_frame(&frame, NOW);
        }
    }

    #[test]
    fn validates_required_fields() {
        let mut envelope = sample();
        envelope.protocol_version = 2;
        assert_eq!(
            validate(&envelope, NOW),
            Err(ProtocolError::UnsupportedVersion(2))
        );

        let mut envelope = sample();
        envelope.message_type = MessageType(99);
        assert_eq!(
            validate(&envelope, NOW),
            Err(ProtocolError::UnknownMessageType(99))
        );

        let mut envelope = sample();
        envelope.message_id = MessageId([0; 16]);
        assert_eq!(validate(&envelope, NOW), Err(ProtocolError::ZeroMessageId));

        let mut envelope = sample();
        envelope.routing.hop_count = 5;
        assert_eq!(validate(&envelope, NOW), Err(ProtocolError::InvalidHops));

        let mut envelope = sample();
        envelope.routing.hop_limit = MAX_HOP_LIMIT + 1;
        assert_eq!(validate(&envelope, NOW), Err(ProtocolError::InvalidHops));

        let mut envelope = sample();
        envelope.expires_at = envelope.created_at;
        assert_eq!(
            validate(&envelope, NOW),
            Err(ProtocolError::InvalidTimestamps)
        );

        let mut envelope = sample();
        envelope.expires_at = envelope.created_at + MAX_MESSAGE_LIFETIME_SECS + 1;
        assert_eq!(
            validate(&envelope, NOW),
            Err(ProtocolError::ExcessiveLifetime(
                MAX_MESSAGE_LIFETIME_SECS + 1
            ))
        );

        let mut envelope = sample();
        envelope.created_at = NOW + MAX_FUTURE_SKEW_SECS + 1;
        envelope.expires_at = envelope.created_at + 60;
        assert_eq!(
            validate(&envelope, NOW),
            Err(ProtocolError::FutureTimestamp)
        );

        let mut envelope = sample();
        envelope.created_at = NOW - 3_600;
        envelope.expires_at = NOW;
        assert_eq!(validate(&envelope, NOW), Err(ProtocolError::Expired));

        let mut envelope = sample();
        envelope.encrypted_payload = EncryptedPayload::new(vec![1; 3]).unwrap();
        assert_eq!(
            validate(&envelope, NOW),
            Err(ProtocolError::PayloadTooShort(3))
        );
    }

    #[test]
    fn control_messages_allow_short_payloads() {
        let mut envelope = sample();
        envelope.message_type = MessageType::CONTROL;
        envelope.encrypted_payload = EncryptedPayload::new(vec![1]).unwrap();
        assert!(validate(&envelope, NOW).is_ok());
    }

    #[test]
    fn wire_tags_are_stable() {
        let peer = postcard::to_allocvec(&Recipient::Peer(IdentityId([1; 32]))).unwrap();
        let group = postcard::to_allocvec(&Recipient::Group(GroupId([1; 32]))).unwrap();
        assert_eq!(peer[0], 0);
        assert_eq!(group[0], 1);
        assert_eq!(
            postcard::to_allocvec(&MessageType::PRIVATE).unwrap(),
            vec![1]
        );
        assert_eq!(
            postcard::to_allocvec(&MessageType::CONTROL).unwrap(),
            vec![4]
        );
    }
}
