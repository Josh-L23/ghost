use openmls::prelude::{
    Ciphersuite, Credential, CredentialType, CredentialWithKey, GroupId as MlsGroupId, KeyPackage,
    KeyPackageIn, Member, MlsGroup, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn,
    ProcessedMessageContent, ProtocolVersion, StagedWelcome,
};
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::SqliteStorageProvider;
use openmls_traits::OpenMlsProvider;
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use std::{
    fmt, fs,
    path::{Path, PathBuf},
};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use crate::{
    identity::{self, Identity},
    protocol::{
        GroupId, GroupName, GroupWireMessage, IdentityId, MAX_GROUP_TEXT_BYTES, MlsMessageBytes,
        ProtocolError,
    },
    storage::{GroupMember, GroupMetadata, Storage, StorageError},
    trust::TrustStore,
};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
const MLS_CREDENTIAL_CONTEXT: &[u8] = b"ghost-mls-credential-v1";

type MlsStorage = SqliteStorageProvider<JsonCodec, rusqlite::Connection>;

#[derive(Debug)]
pub enum GroupError {
    Storage(StorageError),
    Mls(String),
    Protocol(ProtocolError),
    Encoding(postcard::Error),
    InvalidName,
    InvalidCredential,
    UnknownGroup,
    UnknownPeer,
    UntrustedPeer,
    NotMember,
    AlreadyMember,
    InvalidMessage,
}

impl fmt::Display for GroupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "group storage error: {error}"),
            Self::Mls(error) => write!(f, "MLS operation failed: {error}"),
            Self::Protocol(error) => write!(f, "group wire error: {error}"),
            Self::Encoding(_) => f.write_str("group message encoding is invalid"),
            Self::InvalidName => f.write_str("group name must be 1-64 printable characters"),
            Self::InvalidCredential => {
                f.write_str("MLS credential is not bound to a GHOST identity")
            }
            Self::UnknownGroup => f.write_str("unknown group"),
            Self::UnknownPeer => f.write_str("unknown peer"),
            Self::UntrustedPeer => f.write_str("peer fingerprint is not verified"),
            Self::NotMember => f.write_str("identity is not a group member"),
            Self::AlreadyMember => f.write_str("identity is already a group member"),
            Self::InvalidMessage => f.write_str("invalid group control message"),
        }
    }
}

impl std::error::Error for GroupError {}

impl From<StorageError> for GroupError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<std::io::Error> for GroupError {
    fn from(error: std::io::Error) -> Self {
        Self::Storage(StorageError::Io(error))
    }
}

impl From<rusqlite::Error> for GroupError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(StorageError::Sql(error))
    }
}

impl From<ProtocolError> for GroupError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<postcard::Error> for GroupError {
    fn from(error: postcard::Error) -> Self {
        Self::Encoding(error)
    }
}

fn mls_error<E: fmt::Display>(error: E) -> GroupError {
    GroupError::Mls(error.to_string())
}

#[derive(Default)]
struct JsonCodec;

impl openmls_sqlite_storage::Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

struct GhostMlsProvider {
    crypto: RustCrypto,
    storage: MlsStorage,
}

impl OpenMlsProvider for GhostMlsProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MlsStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupSummary {
    pub group_id: GroupId,
    pub name: GroupName,
    pub member_count: usize,
    pub epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMemberInfo {
    pub identity_id: IdentityId,
    pub role: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMessage {
    pub group_id: GroupId,
    pub sender: IdentityId,
    pub epoch: u64,
    pub created_at: u64,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupUpdate {
    Created { group_id: GroupId, name: GroupName },
    InviteSent { group_id: GroupId, peer: IdentityId },
    KeyPackageSent { group_id: GroupId },
    Joined { group_id: GroupId, name: GroupName },
    CommitApplied { group_id: GroupId },
    Message { message: GroupMessage },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupDirective {
    pub recipient: IdentityId,
    pub group_id: GroupId,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupRequestContext {
    pub sender: IdentityId,
    pub now: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupResult {
    pub update: GroupUpdate,
    pub directives: Vec<GroupDirective>,
}

pub struct GroupService {
    provider: GhostMlsProvider,
}

impl GroupService {
    pub fn open(_identity: &Identity, path: impl AsRef<Path>) -> Result<Self, GroupError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let conn = rusqlite::Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        restrict_permissions(path);
        let mut storage = SqliteStorageProvider::<JsonCodec, _>::new(conn);
        storage
            .run_migrations()
            .map_err(|error| GroupError::Mls(error.to_string()))?;
        Ok(Self {
            provider: GhostMlsProvider {
                crypto: RustCrypto::default(),
                storage,
            },
        })
    }

    pub fn create_group(
        &self,
        identity: &Identity,
        storage: &mut Storage,
        name: &str,
        now: u64,
    ) -> Result<GroupResult, GroupError> {
        let name = validate_name(name)?;
        let mut id_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut id_bytes);
        let group_id = GroupId(id_bytes);
        let group = MlsGroup::builder()
            .with_group_id(mls_group_id(&group_id))
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build(&self.provider, identity, self.credential(identity))
            .map_err(mls_error)?;
        self.persist_group(storage, identity, &group, &name, now)?;
        Ok(GroupResult {
            update: GroupUpdate::Created {
                group_id,
                name: name.clone(),
            },
            directives: Vec::new(),
        })
    }

    pub fn invite(
        &self,
        identity: &Identity,
        storage: &mut Storage,
        group_id: &GroupId,
        peer: IdentityId,
    ) -> Result<GroupResult, GroupError> {
        let group = self.load_group(group_id)?;
        self.ensure_member(identity.identity_id(), &group)?;
        let metadata = storage
            .load_group_metadata(&group_id.0)?
            .ok_or(GroupError::UnknownGroup)?;
        let payload = encode_wire(&GroupWireMessage::KeyPackageRequest {
            group_id: *group_id,
            group_name: metadata.name,
        })?;
        Ok(GroupResult {
            update: GroupUpdate::InviteSent {
                group_id: *group_id,
                peer,
            },
            directives: vec![GroupDirective {
                recipient: peer,
                group_id: *group_id,
                payload,
            }],
        })
    }

    pub fn send_application(
        &self,
        identity: &Identity,
        group_id: &GroupId,
        text: &str,
        now: u64,
    ) -> Result<GroupResult, GroupError> {
        let text_bytes =
            crate::protocol::BoundedBytes::<MAX_GROUP_TEXT_BYTES>::new(text.as_bytes().to_vec())?;
        let mut group = self.load_group(group_id)?;
        self.ensure_member(identity.identity_id(), &group)?;
        let message = group
            .create_message(&self.provider, identity, text_bytes.as_slice())
            .map_err(mls_error)?;
        let payload = encode_wire(&GroupWireMessage::Application {
            group_id: *group_id,
            epoch: group.epoch().as_u64(),
            message: mls_bytes(message.to_bytes().map_err(mls_error)?)?,
        })?;
        Ok(GroupResult {
            update: GroupUpdate::Message {
                message: GroupMessage {
                    group_id: *group_id,
                    sender: identity.identity_id(),
                    epoch: group.epoch().as_u64(),
                    created_at: now,
                    text: text.to_owned(),
                },
            },
            directives: group_members(&group)?
                .into_iter()
                .filter(|member| *member != identity.identity_id())
                .map(|recipient| GroupDirective {
                    recipient,
                    group_id: *group_id,
                    payload: payload.clone(),
                })
                .collect(),
        })
    }

    pub fn remove_member(
        &self,
        identity: &Identity,
        storage: &mut Storage,
        group_id: &GroupId,
        target: IdentityId,
        now: u64,
    ) -> Result<GroupResult, GroupError> {
        let mut group = self.load_group(group_id)?;
        self.ensure_member(identity.identity_id(), &group)?;
        if target == identity.identity_id() {
            return Err(GroupError::InvalidMessage);
        }
        let index = group
            .members()
            .find_map(|member| {
                if member_identity(&member).ok() == Some(target) {
                    Some(member.index)
                } else {
                    None
                }
            })
            .ok_or(GroupError::NotMember)?;
        let (commit, _, _) = group
            .remove_members(&self.provider, identity, &[index])
            .map_err(mls_error)?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(mls_error)?;
        let metadata = storage
            .load_group_metadata(&group_id.0)?
            .ok_or(GroupError::UnknownGroup)?;
        self.persist_group(storage, identity, &group, &metadata.name, now)?;
        storage.delete_group_member(&group_id.0, &target)?;
        let commit_payload = encode_wire(&GroupWireMessage::Commit {
            group_id: *group_id,
            commit: mls_bytes(commit.to_bytes().map_err(mls_error)?)?,
        })?;
        Ok(GroupResult {
            update: GroupUpdate::CommitApplied {
                group_id: *group_id,
            },
            directives: group_members(&group)?
                .into_iter()
                .filter(|member| *member != identity.identity_id() && *member != target)
                .map(|recipient| GroupDirective {
                    recipient,
                    group_id: *group_id,
                    payload: commit_payload.clone(),
                })
                .collect(),
        })
    }

    pub fn handle_wire(
        &self,
        identity: &Identity,
        storage: &mut Storage,
        trust: &TrustStore,
        context: GroupRequestContext,
        envelope_group_id: &GroupId,
        wire: &[u8],
    ) -> Result<GroupResult, GroupError> {
        if !trust.is_verified(&context.sender) {
            return Err(GroupError::UntrustedPeer);
        }
        let message = decode_wire(wire)?;
        if wire_group_id(&message) != envelope_group_id {
            return Err(GroupError::InvalidMessage);
        }
        match message {
            GroupWireMessage::KeyPackageRequest {
                group_id,
                group_name,
            } => self.handle_key_package_request(identity, storage, context, group_id, &group_name),
            GroupWireMessage::KeyPackage {
                group_id,
                key_package,
            } => self.handle_key_package(identity, storage, context, group_id, &key_package),
            GroupWireMessage::Join {
                group_id,
                group_name,
                welcome,
            } => self.handle_join(identity, storage, context, group_id, &group_name, &welcome),
            GroupWireMessage::Commit { group_id, commit } => {
                self.handle_commit(identity, storage, context, group_id, &commit)
            }
            GroupWireMessage::Application {
                group_id,
                epoch,
                message,
            } => self.handle_application(identity, context, group_id, epoch, &message),
        }
    }

    pub fn list_groups(&self, storage: &Storage) -> Result<Vec<GroupSummary>, GroupError> {
        let mut summaries = Vec::new();
        for metadata in storage.list_group_metadata()? {
            let member_count = storage.list_group_members(&metadata.group_id)?.len();
            summaries.push(GroupSummary {
                group_id: GroupId(metadata.group_id),
                name: metadata.name,
                member_count,
                epoch: metadata.epoch,
            });
        }
        Ok(summaries)
    }

    pub fn list_members(
        &self,
        storage: &Storage,
        group_id: &GroupId,
    ) -> Result<Vec<GroupMemberInfo>, GroupError> {
        storage
            .load_group_metadata(&group_id.0)?
            .ok_or(GroupError::UnknownGroup)?;
        Ok(storage
            .list_group_members(&group_id.0)?
            .into_iter()
            .map(|member| GroupMemberInfo {
                identity_id: member.member_id,
                role: member.role,
            })
            .collect())
    }

    pub fn resolve_group(&self, storage: &Storage, selector: &str) -> Result<GroupId, GroupError> {
        if let Some(id) = parse_group_id_hex(selector) {
            storage
                .load_group_metadata(&id.0)?
                .ok_or(GroupError::UnknownGroup)?;
            return Ok(id);
        }
        storage
            .list_group_metadata()?
            .into_iter()
            .find(|metadata| str::from_utf8(metadata.name.as_slice()) == Ok(selector))
            .map(|metadata| GroupId(metadata.group_id))
            .ok_or(GroupError::UnknownGroup)
    }

    fn credential(&self, identity: &Identity) -> CredentialWithKey {
        CredentialWithKey {
            credential: Credential::new(CredentialType::Basic, encode_credential(identity)),
            signature_key: identity.identity_id().0.to_vec().into(),
        }
    }

    fn load_group(&self, group_id: &GroupId) -> Result<MlsGroup, GroupError> {
        MlsGroup::load(self.provider.storage(), &mls_group_id(group_id))
            .map_err(mls_error)?
            .ok_or(GroupError::UnknownGroup)
    }

    fn ensure_member(&self, identity_id: IdentityId, group: &MlsGroup) -> Result<(), GroupError> {
        if group_members(group)?.contains(&identity_id) {
            Ok(())
        } else {
            Err(GroupError::NotMember)
        }
    }

    fn persist_group(
        &self,
        storage: &mut Storage,
        identity: &Identity,
        group: &MlsGroup,
        name: &GroupName,
        now: u64,
    ) -> Result<(), GroupError> {
        let group_id = group_id_from_mls(group.group_id())?;
        let members = group.members().map(|member| member.credential.clone());
        let mut identities = Vec::new();
        for credential in members {
            identities.push(parse_credential(&credential)?);
        }
        let creator = storage
            .load_group_metadata(&group_id.0)?
            .map(|metadata| metadata.creator)
            .unwrap_or_else(|| identity.identity_id());
        storage.upsert_group_metadata(&GroupMetadata {
            group_id: group_id.0,
            name: name.clone(),
            creator,
            created_at: now,
            epoch: group.epoch().as_u64(),
        })?;
        for member_id in &identities {
            storage.upsert_group_member(&GroupMember {
                group_id: group_id.0,
                member_id: *member_id,
                role: if *member_id == creator {
                    "owner".to_owned()
                } else {
                    "member".to_owned()
                },
                updated_at: now,
            })?;
        }
        for stored in storage.list_group_members(&group_id.0)? {
            if !identities.contains(&stored.member_id) {
                storage.delete_group_member(&group_id.0, &stored.member_id)?;
            }
        }
        Ok(())
    }

    fn handle_key_package_request(
        &self,
        identity: &Identity,
        storage: &mut Storage,
        context: GroupRequestContext,
        group_id: GroupId,
        group_name: &GroupName,
    ) -> Result<GroupResult, GroupError> {
        validate_name(str::from_utf8(group_name.as_slice()).map_err(|_| GroupError::InvalidName)?)?;
        let bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                identity,
                self.credential(identity),
            )
            .map_err(mls_error)?;
        let key_package = mls_bytes(
            bundle
                .key_package()
                .tls_serialize_detached()
                .map_err(mls_error)?,
        )?;
        storage.upsert_group_metadata(&GroupMetadata {
            group_id: group_id.0,
            name: group_name.clone(),
            creator: context.sender,
            created_at: context.now,
            epoch: 0,
        })?;
        Ok(GroupResult {
            update: GroupUpdate::KeyPackageSent { group_id },
            directives: vec![GroupDirective {
                recipient: context.sender,
                group_id,
                payload: encode_wire(&GroupWireMessage::KeyPackage {
                    group_id,
                    key_package,
                })?,
            }],
        })
    }

    fn handle_key_package(
        &self,
        identity: &Identity,
        storage: &mut Storage,
        context: GroupRequestContext,
        group_id: GroupId,
        key_package: &MlsMessageBytes,
    ) -> Result<GroupResult, GroupError> {
        let mut group = self.load_group(&group_id)?;
        self.ensure_member(identity.identity_id(), &group)?;
        let (key_package, new_member) = self.validate_key_package(key_package)?;
        if new_member != context.sender {
            return Err(GroupError::InvalidCredential);
        }
        if group_members(&group)?.contains(&new_member) {
            return Err(GroupError::AlreadyMember);
        }
        let (commit, welcome, _) = group
            .add_members(&self.provider, identity, &[key_package])
            .map_err(mls_error)?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(mls_error)?;
        let metadata = storage
            .load_group_metadata(&group_id.0)?
            .ok_or(GroupError::UnknownGroup)?;
        let recipients: Vec<IdentityId> = storage
            .list_group_members(&group_id.0)?
            .into_iter()
            .map(|member| member.member_id)
            .filter(|member| *member != identity.identity_id() && *member != new_member)
            .collect();
        self.persist_group(storage, identity, &group, &metadata.name, context.now)?;
        let mut directives = vec![GroupDirective {
            recipient: new_member,
            group_id,
            payload: encode_wire(&GroupWireMessage::Join {
                group_id,
                group_name: metadata.name,
                welcome: mls_bytes(welcome.to_bytes().map_err(mls_error)?)?,
            })?,
        }];
        let commit_payload = encode_wire(&GroupWireMessage::Commit {
            group_id,
            commit: mls_bytes(commit.to_bytes().map_err(mls_error)?)?,
        })?;
        directives.extend(recipients.into_iter().map(|recipient| GroupDirective {
            recipient,
            group_id,
            payload: commit_payload.clone(),
        }));
        Ok(GroupResult {
            update: GroupUpdate::CommitApplied { group_id },
            directives,
        })
    }

    fn handle_join(
        &self,
        identity: &Identity,
        storage: &mut Storage,
        context: GroupRequestContext,
        group_id: GroupId,
        group_name: &GroupName,
        welcome: &MlsMessageBytes,
    ) -> Result<GroupResult, GroupError> {
        validate_name(str::from_utf8(group_name.as_slice()).map_err(|_| GroupError::InvalidName)?)?;
        let welcome = parse_welcome(welcome)?;
        let join_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let group = StagedWelcome::new_from_welcome(&self.provider, &join_config, welcome, None)
            .map_err(mls_error)?
            .into_group(&self.provider)
            .map_err(mls_error)?;
        if group_id_from_mls(group.group_id())? != group_id {
            return Err(GroupError::InvalidMessage);
        }
        let members = group_members(&group)?;
        if !members.contains(&context.sender) || !members.contains(&identity.identity_id()) {
            return Err(GroupError::UntrustedPeer);
        }
        self.persist_group(storage, identity, &group, group_name, context.now)?;
        Ok(GroupResult {
            update: GroupUpdate::Joined {
                group_id,
                name: group_name.clone(),
            },
            directives: Vec::new(),
        })
    }

    fn handle_commit(
        &self,
        identity: &Identity,
        storage: &mut Storage,
        context: GroupRequestContext,
        group_id: GroupId,
        commit: &MlsMessageBytes,
    ) -> Result<GroupResult, GroupError> {
        let mut group = self.load_group(&group_id)?;
        self.ensure_member(identity.identity_id(), &group)?;
        let sender_credential = parse_message(commit, |message| {
            group
                .process_message(&self.provider, message)
                .map_err(mls_error)
        })?;
        let message_sender = parse_credential(sender_credential.credential())?;
        if message_sender != context.sender {
            return Err(GroupError::InvalidCredential);
        }
        match sender_credential.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                group
                    .merge_staged_commit(&self.provider, *staged)
                    .map_err(mls_error)?;
            }
            ProcessedMessageContent::OwnPendingCommit => {
                group
                    .merge_pending_commit(&self.provider)
                    .map_err(mls_error)?;
            }
            _ => return Err(GroupError::InvalidMessage),
        }
        let metadata = storage
            .load_group_metadata(&group_id.0)?
            .ok_or(GroupError::UnknownGroup)?;
        self.persist_group(storage, identity, &group, &metadata.name, context.now)?;
        Ok(GroupResult {
            update: GroupUpdate::CommitApplied { group_id },
            directives: Vec::new(),
        })
    }

    fn handle_application(
        &self,
        identity: &Identity,
        context: GroupRequestContext,
        group_id: GroupId,
        epoch: u64,
        message: &MlsMessageBytes,
    ) -> Result<GroupResult, GroupError> {
        let mut group = self.load_group(&group_id)?;
        self.ensure_member(identity.identity_id(), &group)?;
        if epoch != group.epoch().as_u64() {
            return Err(GroupError::InvalidMessage);
        }
        let processed = parse_message(message, |message| {
            group
                .process_message(&self.provider, message)
                .map_err(mls_error)
        })?;
        let message_sender = parse_credential(processed.credential())?;
        if message_sender != context.sender {
            return Err(GroupError::InvalidCredential);
        }
        if processed.epoch().as_u64() != epoch {
            return Err(GroupError::InvalidMessage);
        }
        let text = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application) => {
                let bytes = crate::protocol::BoundedBytes::<MAX_GROUP_TEXT_BYTES>::new(
                    application.into_bytes(),
                )?;
                String::from_utf8(bytes.into_inner()).map_err(|_| GroupError::InvalidMessage)?
            }
            _ => return Err(GroupError::InvalidMessage),
        };
        Ok(GroupResult {
            update: GroupUpdate::Message {
                message: GroupMessage {
                    group_id,
                    sender: context.sender,
                    epoch,
                    created_at: context.now,
                    text,
                },
            },
            directives: Vec::new(),
        })
    }

    fn validate_key_package(
        &self,
        bytes: &MlsMessageBytes,
    ) -> Result<(KeyPackage, IdentityId), GroupError> {
        let mut slice = bytes.as_slice();
        let key_package_in = KeyPackageIn::tls_deserialize(&mut slice).map_err(mls_error)?;
        let unverified = key_package_in.unverified_credential();
        let identity_id = parse_credential(&unverified.credential)?;
        if unverified.signature_key.as_slice() != identity_id.0.as_slice() {
            return Err(GroupError::InvalidCredential);
        }
        let key_package = key_package_in
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(mls_error)?;
        if key_package.ciphersuite() != CIPHERSUITE {
            return Err(GroupError::InvalidMessage);
        }
        Ok((key_package, identity_id))
    }
}

pub fn default_mls_storage_path() -> Result<PathBuf, GroupError> {
    Ok(identity::default_data_dir()
        .map_err(|_| GroupError::Storage(StorageError::DataDirectoryUnavailable))?
        .join("mls.ghost.db"))
}

pub fn encode_wire(message: &GroupWireMessage) -> Result<Vec<u8>, GroupError> {
    Ok(postcard::to_allocvec(message)?)
}

pub fn decode_wire(bytes: &[u8]) -> Result<GroupWireMessage, GroupError> {
    Ok(postcard::from_bytes(bytes)?)
}

fn wire_group_id(message: &GroupWireMessage) -> &GroupId {
    match message {
        GroupWireMessage::KeyPackageRequest { group_id, .. }
        | GroupWireMessage::KeyPackage { group_id, .. }
        | GroupWireMessage::Join { group_id, .. }
        | GroupWireMessage::Commit { group_id, .. }
        | GroupWireMessage::Application { group_id, .. } => group_id,
    }
}

fn validate_name(name: &str) -> Result<GroupName, GroupError> {
    if !identity::is_valid_username(name) {
        return Err(GroupError::InvalidName);
    }
    GroupName::new(name.as_bytes().to_vec()).map_err(|_| GroupError::InvalidName)
}

fn encode_credential(identity: &Identity) -> Vec<u8> {
    let username = identity.username().as_bytes();
    let mut bytes = Vec::with_capacity(MLS_CREDENTIAL_CONTEXT.len() + 32 + 1 + username.len());
    bytes.extend_from_slice(MLS_CREDENTIAL_CONTEXT);
    bytes.extend_from_slice(&identity.identity_id().0);
    bytes.push(username.len() as u8);
    bytes.extend_from_slice(username);
    bytes
}

fn parse_credential(credential: &Credential) -> Result<IdentityId, GroupError> {
    if credential.credential_type() != CredentialType::Basic {
        return Err(GroupError::InvalidCredential);
    }
    let bytes = credential.serialized_content();
    let prefix = MLS_CREDENTIAL_CONTEXT.len();
    if bytes.len() < prefix + 33 {
        return Err(GroupError::InvalidCredential);
    }
    if &bytes[..prefix] != MLS_CREDENTIAL_CONTEXT {
        return Err(GroupError::InvalidCredential);
    }
    let username_len = bytes[prefix + 32] as usize;
    if username_len == 0 || username_len > 64 {
        return Err(GroupError::InvalidCredential);
    }
    if bytes.len() != prefix + 33 + username_len {
        return Err(GroupError::InvalidCredential);
    }
    let username =
        str::from_utf8(&bytes[prefix + 33..]).map_err(|_| GroupError::InvalidCredential)?;
    if !identity::is_valid_username(username) {
        return Err(GroupError::InvalidCredential);
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes[prefix..prefix + 32]);
    Ok(IdentityId(id))
}

fn group_id_from_mls(group_id: &MlsGroupId) -> Result<GroupId, GroupError> {
    let bytes = group_id.as_slice();
    if bytes.len() != 32 {
        return Err(GroupError::InvalidMessage);
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(bytes);
    Ok(GroupId(id))
}

fn mls_group_id(group_id: &GroupId) -> MlsGroupId {
    MlsGroupId::from_slice(&group_id.0)
}

fn mls_bytes(bytes: Vec<u8>) -> Result<MlsMessageBytes, GroupError> {
    Ok(MlsMessageBytes::new(bytes)?)
}

fn member_identity(member: &Member) -> Result<IdentityId, GroupError> {
    let identity_id = parse_credential(&member.credential)?;
    if member.signature_key.as_slice() != identity_id.0.as_slice() {
        return Err(GroupError::InvalidCredential);
    }
    Ok(identity_id)
}

fn group_members(group: &MlsGroup) -> Result<Vec<IdentityId>, GroupError> {
    group
        .members()
        .map(|member: Member| member_identity(&member))
        .collect()
}

fn parse_message<T>(
    bytes: &MlsMessageBytes,
    parse: impl FnOnce(openmls::prelude::ProtocolMessage) -> Result<T, GroupError>,
) -> Result<T, GroupError> {
    let mut slice = bytes.as_slice();
    let message_in = MlsMessageIn::tls_deserialize(&mut slice).map_err(mls_error)?;
    let protocol_message = message_in.try_into_protocol_message().map_err(mls_error)?;
    parse(protocol_message)
}

fn parse_welcome(bytes: &MlsMessageBytes) -> Result<openmls::prelude::Welcome, GroupError> {
    let mut slice = bytes.as_slice();
    let message = MlsMessageIn::tls_deserialize(&mut slice).map_err(mls_error)?;
    match message.extract() {
        MlsMessageBodyIn::Welcome(welcome) => Ok(welcome),
        _ => Err(GroupError::InvalidMessage),
    }
}

fn parse_group_id_hex(selector: &str) -> Option<GroupId> {
    if selector.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, chunk) in bytes.as_chunks_mut::<2>().0.iter_mut().enumerate() {
        let offset = index * 2;
        let high = hex_nibble(selector.as_bytes()[offset])?;
        let low = hex_nibble(selector.as_bytes()[offset + 1])?;
        chunk[0] = (high << 4) | low;
    }
    Some(GroupId(bytes))
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        for suffix in ["-wal", "-shm"] {
            let sidecar = PathBuf::from(format!("{}{suffix}", path.to_string_lossy()));
            if sidecar.exists() {
                let _ = fs::set_permissions(sidecar, fs::Permissions::from_mode(0o600));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityStore;

    fn make_identity(dir: &Path, name: &str) -> Identity {
        IdentityStore::new(dir.join(format!("{name}.ghost")))
            .create(name, b"correct horse battery staple")
            .unwrap()
    }

    fn make_trust(dir: &Path, local: &str, remote: &Identity) -> TrustStore {
        let mut trust = TrustStore::new(dir.join(format!("{local}-trust.ghost")));
        trust
            .observe(remote.identity_id(), local, 1)
            .expect("observe should persist");
        trust
            .verify(local, &remote.fingerprint().full(), 1)
            .expect("fingerprint should verify");
        trust
    }

    fn first_directive(result: &GroupResult) -> (IdentityId, GroupId, Vec<u8>) {
        let directive = &result.directives[0];
        (
            directive.recipient,
            directive.group_id,
            directive.payload.clone(),
        )
    }

    #[test]
    fn group_round_trip_and_message_flow() {
        let dir = tempfile::tempdir().unwrap();
        let alice = make_identity(dir.path(), "alice");
        let bob = make_identity(dir.path(), "bob");
        let alice_groups =
            GroupService::open(&alice, dir.path().join("alice-mls.ghost.db")).unwrap();
        let bob_groups = GroupService::open(&bob, dir.path().join("bob-mls.ghost.db")).unwrap();
        let mut alice_storage = Storage::open_in_memory().unwrap();
        let mut bob_storage = Storage::open_in_memory().unwrap();
        let alice_trust = make_trust(dir.path(), "bob", &bob);
        let bob_trust = make_trust(dir.path(), "alice", &alice);

        let created = alice_groups
            .create_group(&alice, &mut alice_storage, "research", 100)
            .unwrap();
        let GroupUpdate::Created { group_id, name } = &created.update else {
            panic!("expected created update");
        };
        assert_eq!(name.as_slice(), b"research");
        let groups = alice_groups.list_groups(&alice_storage).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].group_id, *group_id);
        assert_eq!(groups[0].member_count, 1);
        let invite = alice_groups
            .invite(&alice, &mut alice_storage, group_id, bob.identity_id())
            .unwrap();
        let (recipient, envelope_group_id, payload) = first_directive(&invite);
        assert_eq!(recipient, bob.identity_id());

        let key_package = bob_groups
            .handle_wire(
                &bob,
                &mut bob_storage,
                &bob_trust,
                GroupRequestContext {
                    sender: alice.identity_id(),
                    now: 101,
                },
                &envelope_group_id,
                &payload,
            )
            .unwrap();
        assert!(matches!(
            key_package.update,
            GroupUpdate::KeyPackageSent { .. }
        ));
        let (_, _, key_package_payload) = first_directive(&key_package);

        let welcome = alice_groups
            .handle_wire(
                &alice,
                &mut alice_storage,
                &alice_trust,
                GroupRequestContext {
                    sender: bob.identity_id(),
                    now: 102,
                },
                &envelope_group_id,
                &key_package_payload,
            )
            .unwrap();
        assert!(matches!(welcome.update, GroupUpdate::CommitApplied { .. }));
        let (join_recipient, _, join_payload) = first_directive(&welcome);
        assert_eq!(join_recipient, bob.identity_id());

        let joined = bob_groups
            .handle_wire(
                &bob,
                &mut bob_storage,
                &bob_trust,
                GroupRequestContext {
                    sender: alice.identity_id(),
                    now: 103,
                },
                &envelope_group_id,
                &join_payload,
            )
            .unwrap();
        assert!(matches!(joined.update, GroupUpdate::Joined { .. }));
        assert_eq!(bob_groups.list_groups(&bob_storage).unwrap().len(), 1);
        assert_eq!(
            bob_groups
                .list_members(&bob_storage, group_id)
                .unwrap()
                .len(),
            2
        );

        let sent = alice_groups
            .send_application(&alice, group_id, "hello group", 104)
            .unwrap();
        let (_, _, message_payload) = first_directive(&sent);
        let received = bob_groups
            .handle_wire(
                &bob,
                &mut bob_storage,
                &bob_trust,
                GroupRequestContext {
                    sender: alice.identity_id(),
                    now: 105,
                },
                &envelope_group_id,
                &message_payload,
            )
            .unwrap();
        let GroupUpdate::Message { message } = received.update else {
            panic!("expected message update");
        };
        assert_eq!(message.text, "hello group");
        assert_eq!(message.sender, alice.identity_id());
        assert_eq!(message.group_id, *group_id);
    }

    #[test]
    fn rejects_untrusted_group_sender() {
        let dir = tempfile::tempdir().unwrap();
        let alice = make_identity(dir.path(), "alice");
        let bob = make_identity(dir.path(), "bob");
        let alice_groups =
            GroupService::open(&alice, dir.path().join("alice-mls.ghost.db")).unwrap();
        let bob_groups = GroupService::open(&bob, dir.path().join("bob-mls.ghost.db")).unwrap();
        let mut alice_storage = Storage::open_in_memory().unwrap();
        let mut bob_storage = Storage::open_in_memory().unwrap();
        let untrusted = TrustStore::new(dir.path().join("untrusted.ghost"));
        let created = alice_groups
            .create_group(&alice, &mut alice_storage, "untrusted", 100)
            .unwrap();
        let GroupUpdate::Created { group_id, .. } = created.update else {
            panic!("expected created update");
        };
        let invite = alice_groups
            .invite(&alice, &mut alice_storage, &group_id, bob.identity_id())
            .unwrap();
        let (_, envelope_group_id, payload) = first_directive(&invite);
        assert!(matches!(
            bob_groups.handle_wire(
                &bob,
                &mut bob_storage,
                &untrusted,
                GroupRequestContext {
                    sender: alice.identity_id(),
                    now: 101,
                },
                &envelope_group_id,
                &payload,
            ),
            Err(GroupError::UntrustedPeer)
        ));
    }
}
