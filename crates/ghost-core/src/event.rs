//! Typed events exchanged between the terminal and application services.

use std::net::SocketAddr;

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppEvent {
    Notice(String),
    Warning(String),
    Shutdown,
}
