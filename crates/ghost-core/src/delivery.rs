//! Best-effort delivery state tracking for direct messages.

use std::collections::HashMap;

use crate::protocol::MessageId;

pub const MAX_PENDING_MESSAGES: usize = 32;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeliveryState {
    Composed,
    Encrypted,
    Queued,
    Sent,
    Received,
    Acknowledged,
    Expired,
    Failed,
}

impl DeliveryState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Composed => "composed",
            Self::Encrypted => "encrypted",
            Self::Queued => "queued",
            Self::Sent => "sent",
            Self::Received => "received",
            Self::Acknowledged => "acknowledged",
            Self::Expired => "expired",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackedMessage {
    pub message: crate::messaging::PrivateMessage,
    pub state: DeliveryState,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeliveryError {
    QueueFull,
    UnknownMessage,
}

impl std::fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueueFull => f.write_str("pending message queue is full"),
            Self::UnknownMessage => f.write_str("message is no longer pending"),
        }
    }
}

impl std::error::Error for DeliveryError {}

#[derive(Debug, Default)]
pub struct PendingQueue {
    entries: HashMap<MessageId, TrackedMessage>,
}

impl PendingQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        message: crate::messaging::PrivateMessage,
        expires_at: u64,
    ) -> Result<(), DeliveryError> {
        if self.entries.len() >= MAX_PENDING_MESSAGES {
            return Err(DeliveryError::QueueFull);
        }
        let message_id = message.message_id;
        self.entries.insert(
            message_id,
            TrackedMessage {
                message,
                state: DeliveryState::Queued,
                expires_at,
            },
        );
        Ok(())
    }

    pub fn set_state(
        &mut self,
        message_id: &MessageId,
        state: DeliveryState,
    ) -> Result<TrackedMessage, DeliveryError> {
        let entry = self
            .entries
            .get_mut(message_id)
            .ok_or(DeliveryError::UnknownMessage)?;
        entry.state = state;
        Ok(entry.clone())
    }

    pub fn acknowledge(&mut self, message_id: &MessageId) -> Result<TrackedMessage, DeliveryError> {
        self.set_state(message_id, DeliveryState::Acknowledged)
    }

    pub fn expire(&mut self, now: u64) -> Vec<MessageId> {
        let mut expired = Vec::new();
        let mut removable = Vec::new();
        for (id, entry) in &self.entries {
            if entry.expires_at <= now && entry.state != DeliveryState::Acknowledged {
                expired.push(*id);
                removable.push(*id);
            } else if entry.state == DeliveryState::Acknowledged {
                removable.push(*id);
            }
        }
        for id in removable {
            self.entries.remove(&id);
        }
        expired
    }

    pub fn get(&self, message_id: &MessageId) -> Option<&TrackedMessage> {
        self.entries.get(message_id)
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
    use crate::protocol::{IdentityId, MessageId};

    fn message(id: u8) -> crate::messaging::PrivateMessage {
        crate::messaging::PrivateMessage {
            message_id: MessageId([id; 16]),
            sender: IdentityId([1; 32]),
            recipient: IdentityId([2; 32]),
            created_at: 10,
            text: "hello".into(),
        }
    }

    #[test]
    fn queue_is_bounded_and_reuses_expired_slots() {
        let mut queue = PendingQueue::new();
        for id in 0..MAX_PENDING_MESSAGES as u8 {
            queue.insert(message(id), 20).unwrap();
        }
        assert!(matches!(
            queue.insert(message(255), 100),
            Err(DeliveryError::QueueFull)
        ));
        assert_eq!(queue.expire(20).len(), MAX_PENDING_MESSAGES);
        queue.insert(message(255), 100).unwrap();
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn only_valid_acknowledgements_move_state() {
        let mut queue = PendingQueue::new();
        let sent = message(1);
        let id = sent.message_id;
        queue.insert(sent, 100).unwrap();
        queue.set_state(&id, DeliveryState::Sent).unwrap();
        assert_eq!(queue.get(&id).unwrap().state, DeliveryState::Sent);
        assert!(queue.acknowledge(&MessageId([9; 16])).is_err());
        queue.acknowledge(&id).unwrap();
        assert_eq!(queue.get(&id).unwrap().state, DeliveryState::Acknowledged);
    }

    #[test]
    fn acknowledged_entries_are_pruned_without_being_reported_as_expired() {
        let mut queue = PendingQueue::new();
        let acknowledged = message(1);
        let id = acknowledged.message_id;
        queue.insert(acknowledged, 100).unwrap();
        queue.acknowledge(&id).unwrap();
        assert!(queue.expire(200).is_empty());
        assert!(queue.is_empty());
    }
}
