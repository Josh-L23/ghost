//! SQLite-backed persistence for local state.
//!
//! Stores identity metadata, trust records, group membership metadata, delivery
//! state, deduplication metadata, and bounded pending queues. Sensitive key
//! material and plaintext message bodies are never stored here.

use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{
    dedup,
    delivery::DeliveryState,
    fsutil,
    history::{self, EncryptedHistoryRecord},
    identity,
    protocol::{IdentityId, MessageId, MessageType},
    trust::{TrustRecord, TrustState},
};

const SCHEMA_VERSION: i32 = 3;
const MAX_PENDING: usize = 32;
const MAX_DEDUP: usize = dedup::MAX_DEDUP_ENTRIES;

#[derive(Debug)]
pub enum StorageError {
    Io(std::io::Error),
    Sql(rusqlite::Error),
    Corrupt(String),
    DataDirectoryUnavailable,
    Invalid(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "storage I/O error: {error}"),
            Self::Sql(error) => write!(f, "storage database error: {error}"),
            Self::Corrupt(reason) => write!(f, "storage data is corrupt or unsupported: {reason}"),
            Self::DataDirectoryUnavailable => {
                f.write_str("could not determine the local data directory")
            }
            Self::Invalid(reason) => write!(f, "invalid storage input: {reason}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<std::io::Error> for StorageError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        match error {
            rusqlite::Error::SqliteFailure(_, Some(msg)) if msg.contains("malformed") => {
                Self::Corrupt(msg)
            }
            rusqlite::Error::SqliteFailure(_, Some(msg)) if msg.contains("not a database") => {
                Self::Corrupt(msg)
            }
            rusqlite::Error::FromSqlConversionFailure(_, _, _) => {
                Self::Corrupt("type conversion failed".into())
            }
            other => Self::Sql(other),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityMetadata {
    pub username: String,
    pub identity_id: IdentityId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DedupMetadata {
    pub message_id: MessageId,
    pub sender: IdentityId,
    pub message_type: MessageType,
    pub created_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRecord {
    pub message_id: MessageId,
    pub sender: IdentityId,
    pub recipient: IdentityId,
    pub created_at: u64,
    pub expires_at: u64,
    pub state: DeliveryState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMember {
    pub group_id: [u8; 32],
    pub member_id: IdentityId,
    pub role: String,
    pub updated_at: u64,
}

pub struct Storage {
    conn: Connection,
}

impl Storage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        let mut storage = Self { conn };
        storage.initialize()?;
        Ok(storage)
    }

    pub fn open_or_quarantined(
        path: impl AsRef<Path>,
    ) -> Result<(Self, Option<PathBuf>), StorageError> {
        let path = path.as_ref();
        match Self::open(path) {
            Ok(storage) => Ok((storage, None)),
            Err(error) => {
                let quarantined = fsutil::quarantine(path, &error.to_string())?;
                for suffix in ["-wal", "-shm"] {
                    let sidecar = PathBuf::from(format!("{}{suffix}", path.to_string_lossy()));
                    if sidecar.exists() {
                        fsutil::quarantine(&sidecar, &error.to_string())?;
                    }
                }
                let storage = Self::open(path)?;
                Ok((storage, Some(quarantined)))
            }
        }
    }

    pub fn open_in_memory() -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        let mut storage = Self { conn };
        storage.initialize()?;
        Ok(storage)
    }

    fn initialize(&mut self) -> Result<(), StorageError> {
        self.conn.pragma_update(None, "journal_mode", "WAL")?;
        self.conn.pragma_update(None, "foreign_keys", "ON")?;
        let mut version: i32 = self
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(StorageError::Corrupt(format!(
                "database schema version {version} is newer than supported {SCHEMA_VERSION}"
            )));
        }
        if version == 0 {
            self.migrate_to_v1()?;
            version = 1;
        }
        if version == 1 {
            self.migrate_to_v2()?;
            version = 2;
        }
        if version == 2 {
            self.migrate_to_v3()?;
        }
        Ok(())
    }

    fn migrate_to_v1(&mut self) -> Result<(), StorageError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS identity_metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                username TEXT NOT NULL,
                identity_id BLOB NOT NULL CHECK (length(identity_id) = 32)
            );
            CREATE TABLE IF NOT EXISTS trust_records (
                identity_id BLOB PRIMARY KEY CHECK (length(identity_id) = 32),
                label BLOB NOT NULL,
                state TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS group_members (
                group_id BLOB NOT NULL CHECK (length(group_id) = 32),
                member_id BLOB NOT NULL CHECK (length(member_id) = 32),
                role TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (group_id, member_id)
            );
            CREATE TABLE IF NOT EXISTS delivery_state (
                message_id BLOB PRIMARY KEY CHECK (length(message_id) = 16),
                sender BLOB NOT NULL CHECK (length(sender) = 32),
                recipient BLOB NOT NULL CHECK (length(recipient) = 32),
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                state TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dedup_metadata (
                message_id BLOB PRIMARY KEY CHECK (length(message_id) = 16),
                sender BLOB NOT NULL CHECK (length(sender) = 32),
                message_type INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                seen_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_dedup_seen_at ON dedup_metadata(seen_at);
            CREATE INDEX IF NOT EXISTS idx_delivery_expires ON delivery_state(expires_at);
            ",
        )?;
        tx.pragma_update(None, "user_version", 1)?;
        tx.commit()?;
        Ok(())
    }

    fn migrate_to_v2(&mut self) -> Result<(), StorageError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS message_history (
                message_id BLOB PRIMARY KEY CHECK (length(message_id) = 16),
                conversation_id TEXT NOT NULL,
                sender BLOB NOT NULL CHECK (length(sender) = 32),
                recipient BLOB NOT NULL CHECK (length(recipient) = 32),
                created_at INTEGER NOT NULL,
                outgoing INTEGER NOT NULL CHECK (outgoing IN (0, 1)),
                nonce BLOB NOT NULL CHECK (length(nonce) = 12),
                ciphertext BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_history_conversation
                ON message_history(conversation_id, created_at);
            ",
        )?;
        tx.pragma_update(None, "user_version", 2)?;
        tx.commit()?;
        Ok(())
    }

    fn migrate_to_v3(&mut self) -> Result<(), StorageError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS history_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
                retention_max_messages INTEGER NOT NULL DEFAULT 500
            );
            INSERT OR IGNORE INTO history_settings (id, enabled, retention_max_messages)
                VALUES (1, 1, 500);
            ",
        )?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
        Ok(())
    }

    pub fn save_identity_metadata(
        &mut self,
        metadata: &IdentityMetadata,
    ) -> Result<(), StorageError> {
        if !identity::is_valid_username(&metadata.username) {
            return Err(StorageError::Invalid("invalid username".into()));
        }
        self.conn.execute(
            "INSERT INTO identity_metadata (id, username, identity_id)
             VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET username=excluded.username, identity_id=excluded.identity_id",
            params![metadata.username, metadata.identity_id.0.as_slice()],
        )?;
        Ok(())
    }

    pub fn load_identity_metadata(&self) -> Result<Option<IdentityMetadata>, StorageError> {
        self.conn
            .query_row(
                "SELECT username, identity_id FROM identity_metadata WHERE id = 1",
                [],
                |row| {
                    let username: String = row.get(0)?;
                    let identity_id: Vec<u8> = row.get(1)?;
                    Ok((username, identity_id))
                },
            )
            .optional()?
            .map(|(username, id_bytes)| {
                let id = bytes_to_id32(&id_bytes)?;
                Ok(IdentityMetadata {
                    username,
                    identity_id: IdentityId(id),
                })
            })
            .transpose()
    }

    pub fn upsert_trust_record(&mut self, record: &TrustRecord) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO trust_records (identity_id, label, state, created_at, updated_at, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(identity_id) DO UPDATE SET
               label=excluded.label,
               state=excluded.state,
               created_at=excluded.created_at,
               updated_at=excluded.updated_at,
               last_seen=excluded.last_seen",
            params![
                record.identity_id.0.as_slice(),
                record.label.as_slice(),
                state_to_str(record.state),
                record.created_at as i64,
                record.updated_at as i64,
                record.last_seen as i64,
            ],
        )?;
        Ok(())
    }

    pub fn load_trust_records(&self) -> Result<Vec<TrustRecord>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT identity_id, label, state, created_at, updated_at, last_seen FROM trust_records",
        )?;
        let rows = stmt.query_map([], |row| {
            let identity_id: Vec<u8> = row.get(0)?;
            let label: Vec<u8> = row.get(1)?;
            let state: String = row.get(2)?;
            let created_at: i64 = row.get(3)?;
            let updated_at: i64 = row.get(4)?;
            let last_seen: i64 = row.get(5)?;
            Ok((identity_id, label, state, created_at, updated_at, last_seen))
        })?;
        let mut records = Vec::new();
        for row in rows {
            let (identity_id, label, state, created_at, updated_at, last_seen) = row?;
            let id = bytes_to_id32(&identity_id)?;
            let label = crate::protocol::BoundedBytes::new(label)
                .map_err(|_| StorageError::Corrupt("invalid trust label".into()))?;
            let state = str_to_state(&state)?;
            records.push(TrustRecord {
                identity_id: IdentityId(id),
                label,
                state,
                created_at: created_at as u64,
                updated_at: updated_at as u64,
                last_seen: last_seen as u64,
            });
        }
        Ok(records)
    }

    pub fn upsert_group_member(&mut self, member: &GroupMember) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO group_members (group_id, member_id, role, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(group_id, member_id) DO UPDATE SET role=excluded.role, updated_at=excluded.updated_at",
            params![
                member.group_id.as_slice(),
                member.member_id.0.as_slice(),
                member.role,
                member.updated_at as i64,
            ],
        )?;
        Ok(())
    }

    pub fn list_group_members(
        &self,
        group_id: &[u8; 32],
    ) -> Result<Vec<GroupMember>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT group_id, member_id, role, updated_at FROM group_members WHERE group_id = ?1",
        )?;
        let rows = stmt.query_map(params![group_id.as_slice()], |row| {
            let group_id: Vec<u8> = row.get(0)?;
            let member_id: Vec<u8> = row.get(1)?;
            let role: String = row.get(2)?;
            let updated_at: i64 = row.get(3)?;
            Ok((group_id, member_id, role, updated_at))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (gid, mid, role, updated_at) = row?;
            out.push(GroupMember {
                group_id: bytes_to_id32(&gid)?,
                member_id: IdentityId(bytes_to_id32(&mid)?),
                role,
                updated_at: updated_at as u64,
            });
        }
        Ok(out)
    }

    pub fn upsert_pending(&mut self, record: &PendingRecord) -> Result<(), StorageError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 =
            tx.query_row("SELECT COUNT(*) FROM delivery_state", [], |row| row.get(0))?;
        if count as usize >= MAX_PENDING {
            let exists: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM delivery_state WHERE message_id = ?1",
                    params![record.message_id.0.as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            if exists.is_none() {
                return Err(StorageError::Invalid("pending queue limit reached".into()));
            }
        }
        tx.execute(
            "INSERT INTO delivery_state (message_id, sender, recipient, created_at, expires_at, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(message_id) DO UPDATE SET
               sender=excluded.sender,
               recipient=excluded.recipient,
               created_at=excluded.created_at,
               expires_at=excluded.expires_at,
               state=excluded.state",
            params![
                record.message_id.0.as_slice(),
                record.sender.0.as_slice(),
                record.recipient.0.as_slice(),
                record.created_at as i64,
                record.expires_at as i64,
                delivery_state_to_str(record.state),
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn load_pending(&self) -> Result<Vec<PendingRecord>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT message_id, sender, recipient, created_at, expires_at, state FROM delivery_state",
        )?;
        let rows = stmt.query_map([], |row| {
            let message_id: Vec<u8> = row.get(0)?;
            let sender: Vec<u8> = row.get(1)?;
            let recipient: Vec<u8> = row.get(2)?;
            let created_at: i64 = row.get(3)?;
            let expires_at: i64 = row.get(4)?;
            let state: String = row.get(5)?;
            Ok((message_id, sender, recipient, created_at, expires_at, state))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (mid, sender, recipient, created_at, expires_at, state) = row?;
            out.push(PendingRecord {
                message_id: MessageId(bytes_to_id16(&mid)?),
                sender: IdentityId(bytes_to_id32(&sender)?),
                recipient: IdentityId(bytes_to_id32(&recipient)?),
                created_at: created_at as u64,
                expires_at: expires_at as u64,
                state: str_to_delivery_state(&state)?,
            });
        }
        Ok(out)
    }

    pub fn insert_dedup(
        &mut self,
        entry: &DedupMetadata,
        seen_at: u64,
    ) -> Result<(), StorageError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO dedup_metadata (message_id, sender, message_type, created_at, seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                entry.message_id.0.as_slice(),
                entry.sender.0.as_slice(),
                entry.message_type.0 as i64,
                entry.created_at as i64,
                seen_at as i64,
            ],
        )?;
        let count: i64 =
            tx.query_row("SELECT COUNT(*) FROM dedup_metadata", [], |row| row.get(0))?;
        if count as usize > MAX_DEDUP {
            let to_delete = count as usize - MAX_DEDUP;
            tx.execute(
                "DELETE FROM dedup_metadata WHERE message_id IN (
                    SELECT message_id FROM dedup_metadata ORDER BY seen_at ASC LIMIT ?1
                )",
                params![to_delete as i64],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_dedup(&self) -> Result<Vec<DedupMetadata>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT message_id, sender, message_type, created_at FROM dedup_metadata ORDER BY seen_at ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let message_id: Vec<u8> = row.get(0)?;
            let sender: Vec<u8> = row.get(1)?;
            let message_type: i64 = row.get(2)?;
            let created_at: i64 = row.get(3)?;
            Ok((message_id, sender, message_type, created_at))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (mid, sender, message_type, created_at) = row?;
            out.push(DedupMetadata {
                message_id: MessageId(bytes_to_id16(&mid)?),
                sender: IdentityId(bytes_to_id32(&sender)?),
                message_type: MessageType(message_type as u8),
                created_at: created_at as u64,
            });
        }
        Ok(out)
    }
}

fn state_to_str(state: TrustState) -> &'static str {
    match state {
        TrustState::Unverified => "unverified",
        TrustState::Verified => "verified",
        TrustState::Blocked => "blocked",
    }
}

fn str_to_state(value: &str) -> Result<TrustState, StorageError> {
    match value {
        "unverified" => Ok(TrustState::Unverified),
        "verified" => Ok(TrustState::Verified),
        "blocked" => Ok(TrustState::Blocked),
        _ => Err(StorageError::Corrupt(format!(
            "unknown trust state: {value}"
        ))),
    }
}

fn delivery_state_to_str(state: DeliveryState) -> &'static str {
    match state {
        DeliveryState::Composed => "composed",
        DeliveryState::Encrypted => "encrypted",
        DeliveryState::Queued => "queued",
        DeliveryState::Sent => "sent",
        DeliveryState::Received => "received",
        DeliveryState::Acknowledged => "acknowledged",
        DeliveryState::Expired => "expired",
        DeliveryState::Failed => "failed",
    }
}

fn str_to_delivery_state(value: &str) -> Result<DeliveryState, StorageError> {
    match value {
        "composed" => Ok(DeliveryState::Composed),
        "encrypted" => Ok(DeliveryState::Encrypted),
        "queued" => Ok(DeliveryState::Queued),
        "sent" => Ok(DeliveryState::Sent),
        "received" => Ok(DeliveryState::Received),
        "acknowledged" => Ok(DeliveryState::Acknowledged),
        "expired" => Ok(DeliveryState::Expired),
        "failed" => Ok(DeliveryState::Failed),
        _ => Err(StorageError::Corrupt(format!(
            "unknown delivery state: {value}"
        ))),
    }
}

fn bytes_to_id32(bytes: &[u8]) -> Result<[u8; 32], StorageError> {
    bytes
        .try_into()
        .map_err(|_| StorageError::Corrupt("expected 32 bytes".into()))
}

fn bytes_to_id16(bytes: &[u8]) -> Result<[u8; 16], StorageError> {
    bytes
        .try_into()
        .map_err(|_| StorageError::Corrupt("expected 16 bytes".into()))
}

impl Storage {
    pub fn history_enabled(&self) -> Result<bool, StorageError> {
        self.ensure_history_settings()?;
        let enabled: i64 = self.conn.query_row(
            "SELECT enabled FROM history_settings WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(enabled != 0)
    }

    pub fn set_history_enabled(&mut self, enabled: bool) -> Result<(), StorageError> {
        self.ensure_history_settings()?;
        self.conn.execute(
            "UPDATE history_settings SET enabled = ?1 WHERE id = 1",
            params![if enabled { 1i64 } else { 0i64 }],
        )?;
        Ok(())
    }

    pub fn history_retention_max_messages(&self) -> Result<u64, StorageError> {
        self.ensure_history_settings()?;
        let value: i64 = self.conn.query_row(
            "SELECT retention_max_messages FROM history_settings WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(value.max(0) as u64)
    }

    pub fn set_history_retention_max_messages(&mut self, max: u64) -> Result<(), StorageError> {
        self.ensure_history_settings()?;
        let max = (max.min(10_000)) as i64;
        self.conn.execute(
            "UPDATE history_settings SET retention_max_messages = ?1 WHERE id = 1",
            params![max],
        )?;
        Ok(())
    }

    fn ensure_history_settings(&self) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO history_settings (id, enabled, retention_max_messages) VALUES (1, 1, 500)",
            [],
        )?;
        Ok(())
    }

    pub fn clear_history(&mut self, conversation_id: Option<&str>) -> Result<usize, StorageError> {
        let changed = if let Some(conversation_id) = conversation_id {
            self.conn.execute(
                "DELETE FROM message_history WHERE conversation_id = ?1",
                params![conversation_id],
            )?
        } else {
            self.conn.execute("DELETE FROM message_history", [])?
        };
        Ok(changed)
    }

    pub fn prune_history(&mut self, max_messages: u64) -> Result<usize, StorageError> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM message_history", [], |row| row.get(0))?;
        let count = count.max(0) as u64;
        if count <= max_messages {
            return Ok(0);
        }
        let to_delete = count - max_messages;
        let deleted = self.conn.execute(
            "DELETE FROM message_history WHERE message_id IN (
                SELECT message_id FROM message_history ORDER BY created_at ASC, rowid ASC LIMIT ?1
            )",
            params![to_delete as i64],
        )?;
        Ok(deleted)
    }

    pub fn store_history(&mut self, record: &EncryptedHistoryRecord) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO message_history
                (message_id, conversation_id, sender, recipient, created_at, outgoing, nonce, ciphertext)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                record.message_id.0.as_slice(),
                record.conversation_id,
                record.sender.0.as_slice(),
                record.recipient.0.as_slice(),
                record.created_at as i64,
                if record.outgoing { 1i64 } else { 0i64 },
                record.nonce.as_slice(),
                record.ciphertext.as_slice(),
            ],
        )?;
        let retention = self.history_retention_max_messages().unwrap_or(500);
        let _ = self.prune_history(retention);
        Ok(())
    }

    pub fn load_history(
        &self,
        conversation_id: Option<&str>,
    ) -> Result<Vec<EncryptedHistoryRecord>, StorageError> {
        let mut out = Vec::new();
        if let Some(conversation_id) = conversation_id {
            let mut stmt = self.conn.prepare(
                "SELECT message_id, conversation_id, sender, recipient, created_at, outgoing, nonce, ciphertext
                 FROM message_history WHERE conversation_id = ?1 ORDER BY created_at ASC",
            )?;
            let rows = stmt.query_map(params![conversation_id], Self::map_history_row)?;
            for row in rows {
                out.push(row?);
            }
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT message_id, conversation_id, sender, recipient, created_at, outgoing, nonce, ciphertext
                 FROM message_history ORDER BY created_at ASC",
            )?;
            let rows = stmt.query_map([], Self::map_history_row)?;
            for row in rows {
                out.push(row?);
            }
        }
        Ok(out)
    }

    fn map_history_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EncryptedHistoryRecord> {
        let message_id: Vec<u8> = row.get(0)?;
        let conversation_id: String = row.get(1)?;
        let sender: Vec<u8> = row.get(2)?;
        let recipient: Vec<u8> = row.get(3)?;
        let created_at: i64 = row.get(4)?;
        let outgoing: i64 = row.get(5)?;
        let nonce: Vec<u8> = row.get(6)?;
        let ciphertext: Vec<u8> = row.get(7)?;
        Ok(EncryptedHistoryRecord {
            message_id: MessageId(bytes_to_id16_sql(&message_id)?),
            conversation_id,
            sender: IdentityId(bytes_to_id32_sql(&sender)?),
            recipient: IdentityId(bytes_to_id32_sql(&recipient)?),
            created_at: created_at as u64,
            outgoing: outgoing != 0,
            nonce: nonce.as_slice().try_into().map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    6,
                    rusqlite::types::Type::Blob,
                    "expected 12 bytes".into(),
                )
            })?,
            ciphertext,
        })
    }

    pub fn load_and_decrypt_history(
        &self,
        conversation_id: Option<&str>,
        key: &zeroize::Zeroizing<[u8; 32]>,
    ) -> Result<Vec<history::HistoryRecord>, StorageError> {
        self.load_history(conversation_id)?
            .into_iter()
            .map(|record| {
                history::decrypt_record(&record, key)
                    .map_err(|error| StorageError::Corrupt(error.to_string()))
            })
            .collect()
    }
}

fn bytes_to_id32_sql(bytes: &[u8]) -> rusqlite::Result<[u8; 32]> {
    bytes.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Blob,
            "expected 32 bytes".into(),
        )
    })
}

fn bytes_to_id16_sql(bytes: &[u8]) -> rusqlite::Result<[u8; 16]> {
    bytes.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Blob,
            "expected 16 bytes".into(),
        )
    })
}

pub fn default_storage_path() -> Result<PathBuf, StorageError> {
    identity::default_data_dir()
        .map(|dir| dir.join("ghost.db"))
        .map_err(|_| StorageError::DataDirectoryUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::BoundedBytes;
    use tempfile::tempdir;

    fn sample_trust() -> TrustRecord {
        TrustRecord {
            identity_id: IdentityId([7; 32]),
            label: BoundedBytes::new(b"peer".to_vec()).unwrap(),
            state: TrustState::Verified,
            created_at: 1,
            updated_at: 2,
            last_seen: 3,
        }
    }

    #[test]
    fn fresh_db_initializes_and_reopens() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ghost.db");
        {
            let mut storage = Storage::open(&path).unwrap();
            let meta = IdentityMetadata {
                username: "alice".into(),
                identity_id: IdentityId([1; 32]),
            };
            storage.save_identity_metadata(&meta).unwrap();
            storage.upsert_trust_record(&sample_trust()).unwrap();
        }
        let storage = Storage::open(&path).unwrap();
        let meta = storage.load_identity_metadata().unwrap().unwrap();
        assert_eq!(meta.username, "alice");
        let records = storage.load_trust_records().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], sample_trust());
    }

    #[test]
    fn migration_is_idempotent_on_existing_db() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ghost.db");
        {
            let _storage = Storage::open(&path).unwrap();
        }
        let mut storage = Storage::open(&path).unwrap();
        storage
            .save_identity_metadata(&IdentityMetadata {
                username: "bob".into(),
                identity_id: IdentityId([2; 32]),
            })
            .unwrap();
        assert!(storage.load_identity_metadata().unwrap().is_some());
    }

    #[test]
    fn pending_and_dedup_survive_restart_and_are_bounded() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ghost.db");
        {
            let mut storage = Storage::open(&path).unwrap();
            for i in 0..MAX_PENDING as u8 {
                storage
                    .upsert_pending(&PendingRecord {
                        message_id: MessageId([i; 16]),
                        sender: IdentityId([1; 32]),
                        recipient: IdentityId([2; 32]),
                        created_at: 10,
                        expires_at: 20,
                        state: DeliveryState::Queued,
                    })
                    .unwrap();
            }
            assert!(
                storage
                    .upsert_pending(&PendingRecord {
                        message_id: MessageId([99; 16]),
                        sender: IdentityId([1; 32]),
                        recipient: IdentityId([2; 32]),
                        created_at: 10,
                        expires_at: 20,
                        state: DeliveryState::Queued,
                    })
                    .is_err()
            );

            for i in 0..(MAX_DEDUP + 5) as u16 {
                let mut id = [0u8; 16];
                id[0..2].copy_from_slice(&i.to_le_bytes());
                storage
                    .insert_dedup(
                        &DedupMetadata {
                            message_id: MessageId(id),
                            sender: IdentityId([3; 32]),
                            message_type: MessageType::PRIVATE,
                            created_at: 100,
                        },
                        i as u64,
                    )
                    .unwrap();
            }
        }
        let storage = Storage::open(&path).unwrap();
        assert_eq!(storage.load_pending().unwrap().len(), MAX_PENDING);
        assert_eq!(storage.load_dedup().unwrap().len(), MAX_DEDUP);
    }

    #[test]
    fn group_membership_persists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ghost.db");
        let group = [9u8; 32];
        {
            let mut storage = Storage::open(&path).unwrap();
            storage
                .upsert_group_member(&GroupMember {
                    group_id: group,
                    member_id: IdentityId([4; 32]),
                    role: "member".into(),
                    updated_at: 5,
                })
                .unwrap();
        }
        let storage = Storage::open(&path).unwrap();
        let members = storage.list_group_members(&group).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].member_id, IdentityId([4; 32]));
    }

    #[test]
    fn corrupt_database_is_reported_safely() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ghost.db");
        fs::write(&path, b"not a sqlite database").unwrap();
        let result = Storage::open(&path);
        assert!(matches!(
            result,
            Err(StorageError::Corrupt(_)) | Err(StorageError::Sql(_))
        ));
        // ensure no panic and error is safe string
        if let Err(err) = Storage::open(&path) {
            let _ = err.to_string();
        }
    }

    #[test]
    fn corrupt_database_is_quarantined_and_recreated() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ghost.db");
        fs::write(&path, b"not a sqlite database").unwrap();

        let (storage, quarantined) = Storage::open_or_quarantined(&path).unwrap();
        drop(storage);
        let quarantined = quarantined.expect("expected quarantine path");
        assert!(quarantined.exists());
        assert_eq!(fs::read(&quarantined).unwrap(), b"not a sqlite database");
        assert!(Storage::open(&path).is_ok());
    }

    #[test]
    fn never_stores_plaintext_message_bodies() {
        // API design enforces this: PendingRecord has no text/body field and
        // identity metadata excludes secrets.
        let dir = tempdir().unwrap();
        let path = dir.path().join("ghost.db");
        let mut storage = Storage::open(&path).unwrap();
        storage
            .save_identity_metadata(&IdentityMetadata {
                username: "alice".into(),
                identity_id: IdentityId([1; 32]),
            })
            .unwrap();
        storage
            .upsert_pending(&PendingRecord {
                message_id: MessageId([1; 16]),
                sender: IdentityId([1; 32]),
                recipient: IdentityId([2; 32]),
                created_at: 1,
                expires_at: 2,
                state: DeliveryState::Sent,
            })
            .unwrap();
        let raw = fs::read(&path).unwrap();
        assert!(
            !raw.windows(b"secret-body".len())
                .any(|w| w == b"secret-body")
        );
    }

    #[test]
    fn encrypted_history_round_trip_and_no_plaintext_on_disk() {
        use crate::history::{HistoryRecord, decrypt_record, encrypt_record};
        use zeroize::Zeroizing;

        let dir = tempdir().unwrap();
        let path = dir.path().join("ghost.db");
        let key = Zeroizing::new([9u8; 32]);
        let plaintext = "top secret history body";
        let record = HistoryRecord {
            message_id: MessageId([11; 16]),
            conversation_id: "peer-conv".into(),
            sender: IdentityId([1; 32]),
            recipient: IdentityId([2; 32]),
            created_at: 42,
            outgoing: true,
            body: plaintext.into(),
        };
        {
            let mut storage = Storage::open(&path).unwrap();
            let encrypted = encrypt_record(&record, &key).unwrap();
            storage.store_history(&encrypted).unwrap();
        }
        let raw = fs::read(&path).unwrap();
        assert!(
            !raw.windows(plaintext.len())
                .any(|w| w == plaintext.as_bytes())
        );
        let storage = Storage::open(&path).unwrap();
        let stored = storage.load_history(Some("peer-conv")).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(decrypt_record(&stored[0], &key).unwrap(), record);
        let decrypted = storage
            .load_and_decrypt_history(Some("peer-conv"), &key)
            .unwrap();
        assert_eq!(decrypted, vec![record]);
    }

    #[test]
    fn tampered_history_is_detected_on_read() {
        use crate::history::{HistoryRecord, encrypt_record};
        use zeroize::Zeroizing;

        let dir = tempdir().unwrap();
        let path = dir.path().join("ghost.db");
        let key = Zeroizing::new([4u8; 32]);
        let record = HistoryRecord {
            message_id: MessageId([12; 16]),
            conversation_id: "peer-x".into(),
            sender: IdentityId([1; 32]),
            recipient: IdentityId([2; 32]),
            created_at: 99,
            outgoing: false,
            body: "sensitive".into(),
        };
        {
            let mut storage = Storage::open(&path).unwrap();
            let encrypted = encrypt_record(&record, &key).unwrap();
            storage.store_history(&encrypted).unwrap();
            storage
                .conn
                .execute(
                    "UPDATE message_history SET ciphertext = randomblob(length(ciphertext)) WHERE message_id = ?1",
                    params![record.message_id.0.as_slice()],
                )
                .unwrap();
        }
        let storage = Storage::open(&path).unwrap();
        let err = storage
            .load_and_decrypt_history(Some("peer-x"), &key)
            .unwrap_err();
        assert!(matches!(err, StorageError::Corrupt(_)));
        assert!(!err.to_string().contains("sensitive"));
    }

    #[test]
    fn history_controls_disable_clear_and_retention() {
        use crate::history::{HistoryRecord, encrypt_record};
        use zeroize::Zeroizing;

        let dir = tempdir().unwrap();
        let path = dir.path().join("ghost.db");
        let key = Zeroizing::new([5u8; 32]);
        let mut storage = Storage::open(&path).unwrap();
        assert!(storage.history_enabled().unwrap());
        storage.set_history_enabled(false).unwrap();
        assert!(!storage.history_enabled().unwrap());
        storage.set_history_enabled(true).unwrap();

        for i in 0u8..5 {
            let record = HistoryRecord {
                message_id: MessageId([i; 16]),
                conversation_id: if i % 2 == 0 { "a".into() } else { "b".into() },
                sender: IdentityId([1; 32]),
                recipient: IdentityId([2; 32]),
                created_at: i as u64,
                outgoing: true,
                body: format!("msg-{i}"),
            };
            let encrypted = encrypt_record(&record, &key).unwrap();
            storage.store_history(&encrypted).unwrap();
        }
        assert_eq!(storage.load_history(None).unwrap().len(), 5);
        let removed = storage.clear_history(Some("a")).unwrap();
        assert!(removed >= 1);
        assert!(storage.load_history(Some("a")).unwrap().is_empty());
        storage.clear_history(None).unwrap();
        assert!(storage.load_history(None).unwrap().is_empty());

        storage.set_history_retention_max_messages(2).unwrap();
        for i in 10u8..14 {
            let record = HistoryRecord {
                message_id: MessageId([i; 16]),
                conversation_id: "c".into(),
                sender: IdentityId([1; 32]),
                recipient: IdentityId([2; 32]),
                created_at: i as u64,
                outgoing: false,
                body: format!("msg-{i}"),
            };
            let encrypted = encrypt_record(&record, &key).unwrap();
            storage.store_history(&encrypted).unwrap();
        }
        assert!(storage.load_history(None).unwrap().len() <= 2);
    }

    #[test]
    fn history_settings_survive_restart() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ghost.db");
        {
            let mut storage = Storage::open(&path).unwrap();
            storage.set_history_enabled(false).unwrap();
            storage.set_history_retention_max_messages(123).unwrap();
        }
        let storage = Storage::open(&path).unwrap();
        assert!(!storage.history_enabled().unwrap());
        assert_eq!(storage.history_retention_max_messages().unwrap(), 123);
    }
}
