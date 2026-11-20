//! Persistent local identity protected by a passphrase-derived key.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    env, fmt,
    fs::{self, DirBuilder, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

use crate::protocol::{BoundedBytes, IdentityId, Signature};

const MAGIC: &[u8; 8] = b"GHOSTID1";
const VERSION: u16 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SECRET_KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const ENCRYPTED_KEY_LEN: usize = SECRET_KEY_LEN + TAG_LEN;
const MAX_USERNAME_LEN: usize = 64;
const MAX_FILE_BYTES: usize = 4 * 1024;
const MIN_PASSPHRASE_LEN: usize = 8;

type StoredUsername = BoundedBytes<MAX_USERNAME_LEN>;
type EncryptedKey = BoundedBytes<ENCRYPTED_KEY_LEN>;

#[derive(Debug)]
pub enum IdentityError {
    AlreadyExists,
    InvalidUsername,
    WeakPassphrase,
    Io(std::io::Error),
    Encoding(postcard::Error),
    Corrupt,
    UnsupportedVersion(u16),
    WrongPassphrase,
    Crypto,
    InsecurePermissions,
    DataDirectoryUnavailable,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => f.write_str("an identity already exists at this location"),
            Self::InvalidUsername => f.write_str(
                "username must be 1-64 printable characters without slashes or surrounding whitespace",
            ),
            Self::WeakPassphrase => {
                write!(f, "passphrase must be at least {MIN_PASSPHRASE_LEN} characters")
            }
            Self::Io(error) => write!(f, "identity storage error: {error}"),
            Self::Encoding(_) => f.write_str("identity file encoding is invalid"),
            Self::Corrupt => f.write_str("identity file is corrupt or unsupported"),
            Self::UnsupportedVersion(version) => {
                write!(f, "identity file version {version} is unsupported")
            }
            Self::WrongPassphrase => {
                f.write_str("incorrect passphrase or corrupted identity file")
            }
            Self::Crypto => f.write_str("identity cryptographic operation failed"),
            Self::InsecurePermissions => {
                f.write_str("identity file must not be accessible by group or others")
            }
            Self::DataDirectoryUnavailable => {
                f.write_str("could not determine the local data directory")
            }
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<std::io::Error> for IdentityError {
    fn from(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            Self::AlreadyExists
        } else {
            Self::Io(error)
        }
    }
}

impl From<postcard::Error> for IdentityError {
    fn from(error: postcard::Error) -> Self {
        Self::Encoding(error)
    }
}

impl From<crate::protocol::ProtocolError> for IdentityError {
    fn from(_: crate::protocol::ProtocolError) -> Self {
        Self::Corrupt
    }
}

#[derive(Clone)]
struct Argon2Params(Params);

impl Default for Argon2Params {
    fn default() -> Self {
        Self(Params::DEFAULT)
    }
}

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    magic: [u8; 8],
    version: u16,
    username: StoredUsername,
    public_key: IdentityId,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    encrypted_key: EncryptedKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn full(&self) -> String {
        encode_hex(&self.0)
    }

    pub fn short(&self) -> String {
        encode_hex(&self.0[..8])
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.full())
    }
}

pub struct Identity {
    username: String,
    signing_key: SigningKey,
    public_key: VerifyingKey,
}

impl Identity {
    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn identity_id(&self) -> IdentityId {
        IdentityId(self.public_key.to_bytes())
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint(Sha256::digest(self.public_key.to_bytes()).into())
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let signature: ed25519_dalek::Signature = self.signing_key.sign(message);
        Signature(signature.to_bytes())
    }
}

pub struct IdentityStore {
    path: PathBuf,
    params: Argon2Params,
}

impl IdentityStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            params: Argon2Params::default(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn load_or_create(
        &self,
        username: &str,
        passphrase: &[u8],
    ) -> Result<Identity, IdentityError> {
        if self.exists() {
            self.load(passphrase)
        } else {
            self.create(username, passphrase)
        }
    }

    pub fn create(&self, username: &str, passphrase: &[u8]) -> Result<Identity, IdentityError> {
        validate_username(username)?;
        validate_passphrase(passphrase)?;
        if self.exists() {
            return Err(IdentityError::AlreadyExists);
        }

        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key();
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        let secret_key = Zeroizing::new(signing_key.to_bytes());
        let derived_key = derive_key(passphrase, &salt, &self.params)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(&*derived_key).map_err(|_| IdentityError::Crypto)?;
        let aad = associated_data(username.as_bytes(), &public_key.to_bytes(), &salt, &nonce);
        let encrypted_key = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &*secret_key,
                    aad: &aad,
                },
            )
            .map_err(|_| IdentityError::Crypto)?;

        let stored = StoredIdentity {
            magic: *MAGIC,
            version: VERSION,
            username: BoundedBytes::new(username.as_bytes().to_vec())?,
            public_key: IdentityId(public_key.to_bytes()),
            salt,
            nonce,
            encrypted_key: BoundedBytes::new(encrypted_key)?,
        };
        let bytes = postcard::to_allocvec(&stored)?;
        write_new_file(&self.path, &bytes)?;

        Ok(Identity {
            username: username.to_owned(),
            signing_key,
            public_key,
        })
    }

    pub fn load(&self, passphrase: &[u8]) -> Result<Identity, IdentityError> {
        validate_passphrase(passphrase)?;
        check_permissions(&self.path)?;
        let bytes = fs::read(&self.path)?;
        if bytes.is_empty() || bytes.len() > MAX_FILE_BYTES {
            return Err(IdentityError::Corrupt);
        }

        let (stored, remainder) = postcard::take_from_bytes::<StoredIdentity>(&bytes)?;
        if !remainder.is_empty() || &stored.magic != MAGIC {
            return Err(IdentityError::Corrupt);
        }
        if stored.version != VERSION {
            return Err(IdentityError::UnsupportedVersion(stored.version));
        }

        let username = String::from_utf8(stored.username.as_slice().to_vec())
            .map_err(|_| IdentityError::Corrupt)?;
        if !is_valid_username(&username) {
            return Err(IdentityError::Corrupt);
        }

        let derived_key = derive_key(passphrase, &stored.salt, &self.params)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(&*derived_key).map_err(|_| IdentityError::Crypto)?;
        let aad = associated_data(
            username.as_bytes(),
            &stored.public_key.0,
            &stored.salt,
            &stored.nonce,
        );
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&stored.nonce),
                    Payload {
                        msg: stored.encrypted_key.as_slice(),
                        aad: &aad,
                    },
                )
                .map_err(|_| IdentityError::WrongPassphrase)?,
        );
        if plaintext.len() != SECRET_KEY_LEN {
            return Err(IdentityError::Corrupt);
        }

        let secret_bytes: [u8; SECRET_KEY_LEN] = plaintext[..]
            .try_into()
            .map_err(|_| IdentityError::Corrupt)?;
        let secret_key = Zeroizing::new(secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_key);
        let public_key = signing_key.verifying_key();
        if public_key.to_bytes() != stored.public_key.0 {
            return Err(IdentityError::Corrupt);
        }

        Ok(Identity {
            username,
            signing_key,
            public_key,
        })
    }
}

pub fn default_identity_path() -> Result<PathBuf, IdentityError> {
    let base = env::var_os("XDG_DATA_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".local/share"))
        })
        .or_else(|| {
            env::var_os("USERPROFILE")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        })
        .ok_or(IdentityError::DataDirectoryUnavailable)?;
    Ok(base.join("ghost").join("identity.ghost"))
}

pub fn is_valid_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= MAX_USERNAME_LEN
        && username.trim() == username
        && username
            .chars()
            .all(|ch| !ch.is_control() && ch != '/' && ch != '\\')
}

pub fn is_valid_passphrase(passphrase: &[u8]) -> bool {
    passphrase.len() >= MIN_PASSPHRASE_LEN
}

fn validate_username(username: &str) -> Result<(), IdentityError> {
    if is_valid_username(username) {
        Ok(())
    } else {
        Err(IdentityError::InvalidUsername)
    }
}

fn validate_passphrase(passphrase: &[u8]) -> Result<(), IdentityError> {
    if is_valid_passphrase(passphrase) {
        Ok(())
    } else {
        Err(IdentityError::WeakPassphrase)
    }
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    params: &Argon2Params,
) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params.0.clone())
        .hash_password_into(passphrase, salt, &mut *key)
        .map_err(|_| IdentityError::Crypto)?;
    Ok(key)
}

fn associated_data(
    username: &[u8],
    public_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(MAGIC.len() + 2 + 4 + username.len() + 32 + SALT_LEN + NONCE_LEN);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&VERSION.to_be_bytes());
    aad.extend_from_slice(&(username.len() as u32).to_be_bytes());
    aad.extend_from_slice(username);
    aad.extend_from_slice(public_key);
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), IdentityError> {
    if let Some(parent) = path.parent() {
        let mut builder = DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(parent)?;
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
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

fn check_permissions(path: &Path) -> Result<(), IdentityError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(IdentityError::InsecurePermissions);
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use tempfile::tempdir;

    fn passphrase() -> &'static [u8] {
        b"correct horse battery staple"
    }

    #[test]
    fn create_and_load_round_trip() {
        let dir = tempdir().unwrap();
        let store = IdentityStore::new(dir.path().join("identity.ghost"));
        let created = store.create("ada", passphrase()).unwrap();
        let loaded = store.load(passphrase()).unwrap();

        assert_eq!(loaded.username(), "ada");
        assert_eq!(loaded.identity_id(), created.identity_id());
        assert_eq!(loaded.fingerprint(), created.fingerprint());

        let message = b"authenticated message";
        let signature = loaded.sign(message);
        assert!(
            created
                .public_key
                .verify(message, &ed25519_dalek::Signature::from_bytes(&signature.0))
                .is_ok()
        );
    }

    #[test]
    fn load_or_create_does_not_replace_existing_identity() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.ghost");
        let first = IdentityStore::new(&path)
            .load_or_create("ada", passphrase())
            .unwrap();
        let second = IdentityStore::new(&path)
            .load_or_create("grace", passphrase())
            .unwrap();

        assert_eq!(first.identity_id(), second.identity_id());
        assert_eq!(second.username(), "ada");
    }

    #[test]
    fn load_with_wrong_passphrase_fails() {
        let dir = tempdir().unwrap();
        let store = IdentityStore::new(dir.path().join("identity.ghost"));
        store.create("ada", passphrase()).unwrap();

        assert!(matches!(
            store.load(b"not the right passphrase"),
            Err(IdentityError::WrongPassphrase)
        ));
    }

    #[test]
    fn load_missing_file_fails() {
        let dir = tempdir().unwrap();
        let store = IdentityStore::new(dir.path().join("missing.ghost"));
        assert!(matches!(
            store.load(passphrase()),
            Err(IdentityError::Io(_))
        ));
    }

    #[test]
    fn corrupt_file_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.ghost");
        let store = IdentityStore::new(&path);
        store.create("ada", passphrase()).unwrap();
        fs::write(&path, b"not a ghost identity").unwrap();

        assert!(matches!(
            store.load(passphrase()),
            Err(IdentityError::Encoding(_)) | Err(IdentityError::Corrupt)
        ));
    }

    #[test]
    fn secret_key_bytes_are_not_written_in_plaintext() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.ghost");
        let store = IdentityStore::new(&path);
        let identity = store.create("ada", passphrase()).unwrap();
        let file = fs::read(&path).unwrap();

        let secret = identity.signing_key.to_bytes();
        assert!(!file.windows(secret.len()).any(|window| window == secret));
        assert!(!String::from_utf8_lossy(&file).contains("correct horse"));
    }

    #[test]
    fn fingerprints_are_stable_and_key_specific() {
        let dir = tempdir().unwrap();
        let first = IdentityStore::new(dir.path().join("one.ghost"))
            .create("ada", passphrase())
            .unwrap();
        let second = IdentityStore::new(dir.path().join("two.ghost"))
            .create("grace", passphrase())
            .unwrap();

        assert_eq!(first.fingerprint().full().len(), 64);
        assert_eq!(first.fingerprint().short().len(), 16);
        assert_eq!(first.fingerprint().full(), first.fingerprint().to_string());
        assert_ne!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn validates_username_and_passphrase() {
        assert!(is_valid_username("ada"));
        assert!(is_valid_username("Ada Lovelace"));
        assert!(!is_valid_username(""));
        assert!(!is_valid_username(" ada"));
        assert!(!is_valid_username("ada\n"));
        assert!(!is_valid_username("ada/lovelace"));
        assert!(is_valid_passphrase(b"12345678"));
        assert!(!is_valid_passphrase(b"1234567"));
    }

    #[cfg(unix)]
    #[test]
    fn unix_permissions_are_restrictive() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("ghost").join("identity.ghost");
        let store = IdentityStore::new(&path);
        store.create("ada", passphrase()).unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(store.load(passphrase()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn insecure_permissions_are_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.ghost");
        let store = IdentityStore::new(&path);
        store.create("ada", passphrase()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(matches!(
            store.load(passphrase()),
            Err(IdentityError::InsecurePermissions)
        ));
    }
}
