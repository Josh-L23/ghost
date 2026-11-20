//! UI- and transport-independent concepts for GHOST.
//!
//! Identity, transport, and cryptographic services are not implemented yet.
//! The wire envelope and its validation rules are defined in [`protocol`].

pub mod command;
pub mod event;
pub mod identity;
pub mod protocol;
pub mod trust;
