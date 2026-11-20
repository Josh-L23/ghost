//! UI- and transport-independent concepts for GHOST.
//!
//! Identity, trust, sessions, and private messages are transport-independent.
//! The wire envelope and its validation rules are defined in [`protocol`].

pub mod command;
pub mod delivery;
pub mod event;
pub mod identity;
pub mod messaging;
pub mod protocol;
pub mod session;
pub mod trust;
