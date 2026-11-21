//! Local trust records for peers learned from authenticated session hellos.

use serde::{Deserialize, Serialize};
use std::{fmt, fs, path::PathBuf};

use crate::{
    identity::{default_data_dir, fingerprint_from_public_key},
    protocol::{BoundedBytes, IdentityId},
};

const MAGIC: &[u8; 8] = b"GHOSTTR1";
const VERSION: u16 = 1;
const MAX_LABEL_LEN: usize = 64;
const MAX_RECORDS: usize = 256;
const MAX_FILE_BYTES: usize = 64 * 1024;

type PeerLabel = BoundedBytes<MAX_LABEL_LEN>;

#[derive(Debug)]
pub enum TrustError {
    Io(std::io::Error),
    Encoding(postcard::Error),
    Corrupt,
    UnsupportedVersion(u16),
    InsecurePermissions,
    DataDirectoryUnavailable,
    NotFound,
    InvalidFingerprint,
    FingerprintMismatch,
    Blocked,
    TooManyRecords,
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "trust storage error: {error}"),
            Self::Encoding(_) => f.write_str("trust file encoding is invalid"),
            Self::Corrupt => f.write_str("trust file is corrupt or unsupported"),
            Self::UnsupportedVersion(version) => {
                write!(f, "trust file version {version} is unsupported")
            }
            Self::InsecurePermissions => {
                f.write_str("trust file must not be accessible by group or others")
            }
            Self::DataDirectoryUnavailable => {
                f.write_str("could not determine the local data directory")
            }
            Self::NotFound => f.write_str("unknown peer; connect to it before trusting it"),
            Self::InvalidFingerprint => {
                f.write_str("fingerprint must be 64 hexadecimal characters")
            }
            Self::FingerprintMismatch => {
                f.write_str("fingerprint does not match the peer's identity key")
            }
            Self::Blocked => f.write_str("peer is blocked; unblock it before trusting it"),
            Self::TooManyRecords => f.write_str("trust record limit reached"),
        }
    }
}

impl std::error::Error for TrustError {}

impl From<std::io::Error> for TrustError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<postcard::Error> for TrustError {
    fn from(error: postcard::Error) -> Self {
        Self::Encoding(error)
    }
}

impl From<crate::protocol::ProtocolError> for TrustError {
    fn from(_: crate::protocol::ProtocolError) -> Self {
        Self::Corrupt
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustState {
    Unverified,
    Verified,
    Blocked,
}

impl TrustState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unverified => "UNVERIFIED",
            Self::Verified => "VERIFIED",
            Self::Blocked => "BLOCKED",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRecord {
    pub identity_id: IdentityId,
    pub label: PeerLabel,
    pub state: TrustState,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_seen: u64,
}

impl TrustRecord {
    pub fn label(&self) -> &str {
        std::str::from_utf8(self.label.as_slice()).unwrap_or("invalid label")
    }

    pub fn short_fingerprint(&self) -> String {
        fingerprint_from_public_key(&self.identity_id.0).short()
    }

    pub fn full_fingerprint(&self) -> String {
        fingerprint_from_public_key(&self.identity_id.0).full()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ObserveOutcome {
    New,
    Existing,
    KeyChange { previous_fingerprint: String },
    Blocked,
}

#[derive(Serialize, Deserialize)]
struct StoredTrust {
    magic: [u8; 8],
    version: u16,
    records: Vec<TrustRecord>,
}

pub struct TrustStore {
    path: PathBuf,
    records: Vec<TrustRecord>,
}

impl TrustStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            records: Vec::new(),
        }
    }

    pub fn load_or_empty(path: impl Into<PathBuf>) -> Result<Self, TrustError> {
        let mut store = Self::new(path);
        if !store.path.exists() {
            return Ok(store);
        }
        check_permissions(&store.path)?;
        let bytes = fs::read(&store.path)?;
        let wrapped: BoundedBytes<MAX_FILE_BYTES> = postcard::from_bytes(&bytes)?;
        let (stored, remainder) = postcard::take_from_bytes::<StoredTrust>(wrapped.as_slice())?;
        if !remainder.is_empty() || &stored.magic != MAGIC {
            return Err(TrustError::Corrupt);
        }
        if stored.version != VERSION {
            return Err(TrustError::UnsupportedVersion(stored.version));
        }
        if stored.records.len() > MAX_RECORDS {
            return Err(TrustError::Corrupt);
        }
        store.records = stored.records;
        Ok(store)
    }

    pub fn records(&self) -> &[TrustRecord] {
        &self.records
    }

    pub fn state_of(&self, identity_id: &IdentityId) -> TrustState {
        self.records
            .iter()
            .find(|record| &record.identity_id == identity_id)
            .map(|record| record.state)
            .unwrap_or(TrustState::Unverified)
    }

    pub fn is_verified(&self, identity_id: &IdentityId) -> bool {
        self.state_of(identity_id) == TrustState::Verified
    }

    pub fn observe(
        &mut self,
        identity_id: IdentityId,
        label: &str,
        now: u64,
    ) -> Result<ObserveOutcome, TrustError> {
        if let Some(index) = self.index_of_identity(&identity_id) {
            let record = &mut self.records[index];
            let outcome = if record.state == TrustState::Blocked {
                ObserveOutcome::Blocked
            } else {
                ObserveOutcome::Existing
            };
            record.last_seen = now;
            self.persist()?;
            return Ok(outcome);
        }

        let previous = self
            .index_of_label(label)
            .map(|index| fingerprint_from_public_key(&self.records[index].identity_id.0).full());
        if self.records.len() >= MAX_RECORDS {
            return Err(TrustError::TooManyRecords);
        }

        self.records.push(TrustRecord {
            identity_id,
            label: BoundedBytes::new(label.as_bytes().to_vec())?,
            state: TrustState::Unverified,
            created_at: now,
            updated_at: now,
            last_seen: now,
        });
        self.persist()?;
        Ok(match previous {
            Some(previous_fingerprint) => ObserveOutcome::KeyChange {
                previous_fingerprint,
            },
            None => ObserveOutcome::New,
        })
    }

    pub fn verify(
        &mut self,
        selector: &str,
        fingerprint_hex: &str,
        now: u64,
    ) -> Result<TrustRecord, TrustError> {
        let expected = decode_hex(fingerprint_hex)
            .filter(|bytes| bytes.len() == 32)
            .ok_or(TrustError::InvalidFingerprint)?;
        let index = self
            .index_of_selector(selector)
            .ok_or(TrustError::NotFound)?;
        let actual = fingerprint_from_public_key(&self.records[index].identity_id.0);
        if expected != actual.as_bytes() {
            return Err(TrustError::FingerprintMismatch);
        }
        if self.records[index].state == TrustState::Blocked {
            return Err(TrustError::Blocked);
        }
        self.records[index].state = TrustState::Verified;
        self.records[index].updated_at = now;
        self.persist()?;
        Ok(self.records[index].clone())
    }

    pub fn block(&mut self, selector: &str, now: u64) -> Result<TrustRecord, TrustError> {
        self.set_state(selector, TrustState::Blocked, now)
    }

    pub fn unblock(&mut self, selector: &str, now: u64) -> Result<TrustRecord, TrustError> {
        self.set_state(selector, TrustState::Unverified, now)
    }

    fn set_state(
        &mut self,
        selector: &str,
        state: TrustState,
        now: u64,
    ) -> Result<TrustRecord, TrustError> {
        let index = self
            .index_of_selector(selector)
            .ok_or(TrustError::NotFound)?;
        self.records[index].state = state;
        self.records[index].updated_at = now;
        self.persist()?;
        Ok(self.records[index].clone())
    }

    fn index_of_identity(&self, identity_id: &IdentityId) -> Option<usize> {
        self.records
            .iter()
            .position(|record| &record.identity_id == identity_id)
    }

    fn index_of_label(&self, label: &str) -> Option<usize> {
        self.records
            .iter()
            .position(|record| record.label() == label)
    }

    fn index_of_selector(&self, selector: &str) -> Option<usize> {
        if let Some(bytes) = decode_hex(selector) {
            if bytes.len() == 32 {
                if let Some(index) = self
                    .records
                    .iter()
                    .position(|record| record.identity_id.0[..] == bytes[..])
                {
                    return Some(index);
                }
                if let Some(index) = self.records.iter().position(|record| {
                    let fingerprint = fingerprint_from_public_key(&record.identity_id.0);
                    fingerprint.as_bytes()[..] == bytes[..]
                }) {
                    return Some(index);
                }
            }
            if bytes.len() == 8 {
                if let Some(index) = self.records.iter().position(|record| {
                    let fingerprint = fingerprint_from_public_key(&record.identity_id.0);
                    fingerprint.as_bytes()[..8] == bytes[..]
                }) {
                    return Some(index);
                }
            }
        }
        self.index_of_label(selector)
    }

    fn persist(&self) -> Result<(), TrustError> {
        let stored = StoredTrust {
            magic: *MAGIC,
            version: VERSION,
            records: self.records.clone(),
        };
        let inner = postcard::to_allocvec(&stored)?;
        let wrapped = postcard::to_allocvec(&BoundedBytes::<MAX_FILE_BYTES>::new(inner)?)?;
        write_file(&self.path, &wrapped)?;
        Ok(())
    }
}

pub fn default_trust_path() -> Result<PathBuf, TrustError> {
    Ok(default_data_dir()
        .map_err(|_| TrustError::DataDirectoryUnavailable)?
        .join("trust.ghost"))
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
    if input.len() % 2 != 0 {
        return None;
    }
    (0..input.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&input[index..index + 2], 16).ok())
        .collect()
}

fn write_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), TrustError> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn check_permissions(path: &std::path::Path) -> Result<(), TrustError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            return Err(TrustError::InsecurePermissions);
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn identity(byte: u8) -> IdentityId {
        IdentityId([byte; 32])
    }

    fn fingerprint(identity_id: &IdentityId) -> String {
        fingerprint_from_public_key(&identity_id.0).full()
    }

    #[test]
    fn missing_file_loads_empty_and_unknown_peers_are_unverified() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("trust.ghost");
        let store = TrustStore::load_or_empty(&path).unwrap();

        assert!(store.records().is_empty());
        assert_eq!(store.state_of(&identity(1)), TrustState::Unverified);
        assert!(!store.is_verified(&identity(1)));
    }

    #[test]
    fn observe_verify_and_revocation_survive_restart() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("trust.ghost");
        let peer = identity(2);
        let expected = fingerprint(&peer);

        {
            let mut store = TrustStore::load_or_empty(&path).unwrap();
            assert_eq!(
                store.observe(peer, "ada", 100).unwrap(),
                ObserveOutcome::New
            );
            assert_eq!(
                store.observe(peer, "ada", 101).unwrap(),
                ObserveOutcome::Existing
            );
            assert_eq!(store.state_of(&peer), TrustState::Unverified);
            assert!(store.verify(&expected, &expected, 102).is_ok());
            assert_eq!(store.state_of(&peer), TrustState::Verified);
        }

        {
            let mut store = TrustStore::load_or_empty(&path).unwrap();
            assert_eq!(store.records().len(), 1);
            assert_eq!(store.records()[0].state, TrustState::Verified);
            store.block(&expected, 103).unwrap();
        }

        {
            let store = TrustStore::load_or_empty(&path).unwrap();
            assert_eq!(store.state_of(&peer), TrustState::Blocked);
        }
    }

    #[test]
    fn verification_requires_matching_full_fingerprint() {
        let dir = tempdir().unwrap();
        let mut store = TrustStore::load_or_empty(dir.path().join("trust.ghost")).unwrap();
        let peer = identity(3);
        store.observe(peer, "grace", 100).unwrap();

        assert!(matches!(
            store.verify("grace", &fingerprint(&identity(4)), 101),
            Err(TrustError::FingerprintMismatch)
        ));
        assert!(matches!(
            store.verify("grace", "abcd", 101),
            Err(TrustError::InvalidFingerprint)
        ));
        assert!(matches!(
            store.verify("nobody", &fingerprint(&peer), 101),
            Err(TrustError::NotFound)
        ));
    }

    #[test]
    fn key_change_is_reported_without_replacing_old_record() {
        let dir = tempdir().unwrap();
        let mut store = TrustStore::load_or_empty(dir.path().join("trust.ghost")).unwrap();
        let old = identity(5);
        let new = identity(6);
        store.observe(old, "linus", 100).unwrap();
        store
            .verify(&fingerprint(&old), &fingerprint(&old), 101)
            .unwrap();

        let outcome = store.observe(new, "linus", 102).unwrap();
        assert_eq!(
            outcome,
            ObserveOutcome::KeyChange {
                previous_fingerprint: fingerprint(&old)
            }
        );
        assert_eq!(store.records().len(), 2);
        assert_eq!(store.state_of(&old), TrustState::Verified);
        assert_eq!(store.state_of(&new), TrustState::Unverified);
    }

    #[test]
    fn blocked_peers_cannot_be_verified_until_unblocked() {
        let dir = tempdir().unwrap();
        let mut store = TrustStore::load_or_empty(dir.path().join("trust.ghost")).unwrap();
        let peer = identity(7);
        store.observe(peer, "barbara", 100).unwrap();
        store.block("barbara", 101).unwrap();

        assert!(matches!(
            store.verify("barbara", &fingerprint(&peer), 102),
            Err(TrustError::Blocked)
        ));
        store.unblock("barbara", 103).unwrap();
        assert!(store.verify("barbara", &fingerprint(&peer), 104).is_ok());
    }

    #[test]
    fn selectors_accept_short_fingerprint_and_identity_id() {
        let dir = tempdir().unwrap();
        let mut store = TrustStore::load_or_empty(dir.path().join("trust.ghost")).unwrap();
        let peer = identity(8);
        store.observe(peer, "alan", 100).unwrap();

        let short = fingerprint_from_public_key(&peer.0).short();
        let full_id = peer
            .0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(store.index_of_selector(&short), Some(0));
        assert_eq!(store.index_of_selector(&full_id), Some(0));
        assert_eq!(store.index_of_selector("alan"), Some(0));
    }

    #[test]
    fn corrupt_file_reports_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("trust.ghost");
        fs::write(&path, b"not trust data").unwrap();
        assert!(TrustStore::load_or_empty(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unix_permissions_are_restrictive() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("trust.ghost");
        let mut store = TrustStore::load_or_empty(&path).unwrap();
        store.observe(identity(9), "edsger", 100).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            TrustStore::load_or_empty(&path),
            Err(TrustError::InsecurePermissions)
        ));
    }

    #[test]
    fn lost_device_replacement_requires_reverification_and_old_can_be_revoked() {
        let dir = tempdir().unwrap();
        let mut store = TrustStore::load_or_empty(dir.path().join("trust.ghost")).unwrap();
        let old = identity(20);
        let replacement = identity(21);
        store.observe(old, "ada", 100).unwrap();
        store
            .verify(&fingerprint(&old), &fingerprint(&old), 101)
            .unwrap();
        assert_eq!(store.state_of(&old), TrustState::Verified);

        store.block(&fingerprint(&old), 102).unwrap();
        assert_eq!(store.state_of(&old), TrustState::Blocked);

        let outcome = store.observe(replacement, "ada", 103).unwrap();
        assert_eq!(
            outcome,
            ObserveOutcome::KeyChange {
                previous_fingerprint: fingerprint(&old)
            }
        );
        assert_eq!(store.state_of(&replacement), TrustState::Unverified);
        assert!(!store.is_verified(&replacement));

        let replacement_selector = fingerprint(&replacement);
        assert!(
            store
                .verify(&replacement_selector, &replacement_selector, 104)
                .is_ok()
        );
        assert_eq!(store.state_of(&replacement), TrustState::Verified);
        assert_eq!(store.state_of(&old), TrustState::Blocked);
    }
}
