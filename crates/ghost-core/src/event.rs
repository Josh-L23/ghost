//! Typed events exchanged between the terminal and application services.

use std::net::SocketAddr;

use crate::group::{GroupMemberInfo, GroupSummary, GroupUpdate};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupIntent {
    Create { name: String },
    List,
    Members { group: String },
    Invite { group: String, peer: String },
    Send { group: String, text: String },
    Remove { group: String, peer: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserIntent {
    RequestHelp,
    RequestIdentity,
    RequestPeers,
    Scan,
    Connect(SocketAddr),
    Disconnect(String),
    SendMessage { peer: String, text: String },
    OpenConversation(String),
    RequestHistory(Option<String>),
    SetRelayEnabled(bool),
    Group(GroupIntent),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppEvent {
    Notice(String),
    Warning(String),
    GroupList(Vec<GroupSummary>),
    GroupMembers(Vec<GroupMemberInfo>),
    GroupUpdate(GroupUpdate),
    Shutdown,
}
