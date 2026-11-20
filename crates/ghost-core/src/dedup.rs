//! Bounded replay protection for authenticated envelopes.

use std::collections::{HashMap, VecDeque};

use crate::protocol::{
    IdentityId, MAX_FUTURE_SKEW_SECS, MAX_MESSAGE_LIFETIME_SECS, MessageId, MessageType,
};

pub const MAX_DEDUP_ENTRIES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayError {
    Duplicate,
    ContextMismatch,
    Expired,
    FutureTimestamp,
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Duplicate => f.write_str("duplicate message id"),
            Self::ContextMismatch => f.write_str("message id reused with different context"),
            Self::Expired => f.write_str("message timestamp is too old"),
            Self::FutureTimestamp => f.write_str("message timestamp is too far in the future"),
        }
    }
}

impl std::error::Error for ReplayError {}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Entry {
    sender: IdentityId,
    message_type: MessageType,
    created_at: u64,
}

#[derive(Debug, Default)]
pub struct ReplayCache {
    entries: HashMap<MessageId, Entry>,
    order: VecDeque<MessageId>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn accept(
        &mut self,
        message_id: MessageId,
        sender: IdentityId,
        message_type: MessageType,
        created_at: u64,
        now: u64,
    ) -> Result<(), ReplayError> {
        if created_at > now.saturating_add(MAX_FUTURE_SKEW_SECS) {
            return Err(ReplayError::FutureTimestamp);
        }
        if now.saturating_sub(created_at) > MAX_MESSAGE_LIFETIME_SECS {
            return Err(ReplayError::Expired);
        }
        let entry = Entry {
            sender,
            message_type,
            created_at,
        };
        if let Some(existing) = self.entries.get(&message_id) {
            return if *existing == entry {
                Err(ReplayError::Duplicate)
            } else {
                Err(ReplayError::ContextMismatch)
            };
        }
        while self.entries.len() >= MAX_DEDUP_ENTRIES {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(message_id, entry);
        self.order.push_back(message_id);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache() -> ReplayCache {
        ReplayCache::new()
    }

    #[test]
    fn duplicate_envelope_is_seen_once() {
        let mut cache = cache();
        let id = MessageId([1; 16]);
        let sender = IdentityId([2; 32]);
        assert!(
            cache
                .accept(id, sender, MessageType::PRIVATE, 100, 100)
                .is_ok()
        );
        assert_eq!(
            cache.accept(id, sender, MessageType::PRIVATE, 100, 101),
            Err(ReplayError::Duplicate)
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn context_reuse_and_old_timestamps_are_rejected() {
        let mut cache = cache();
        let id = MessageId([3; 16]);
        let sender = IdentityId([4; 32]);
        cache
            .accept(id, sender, MessageType::PRIVATE, 100, 100)
            .unwrap();
        assert_eq!(
            cache.accept(id, sender, MessageType::RECEIPT, 100, 101),
            Err(ReplayError::ContextMismatch)
        );
        assert_eq!(
            cache.accept(
                MessageId([5; 16]),
                sender,
                MessageType::PRIVATE,
                10,
                100_000
            ),
            Err(ReplayError::Expired)
        );
        assert_eq!(
            cache.accept(
                MessageId([6; 16]),
                sender,
                MessageType::PRIVATE,
                100 + MAX_FUTURE_SKEW_SECS + 1,
                100
            ),
            Err(ReplayError::FutureTimestamp)
        );
    }

    #[test]
    fn cache_growth_is_bounded_by_evicting_oldest_entries() {
        let mut cache = cache();
        for id in 0..MAX_DEDUP_ENTRIES + 10 {
            let mut bytes = [0u8; 16];
            bytes[..2].copy_from_slice(&(id as u16).to_be_bytes());
            cache
                .accept(
                    MessageId(bytes),
                    IdentityId([9; 32]),
                    MessageType::PRIVATE,
                    100,
                    100,
                )
                .unwrap();
        }
        assert_eq!(cache.len(), MAX_DEDUP_ENTRIES);
    }
}
