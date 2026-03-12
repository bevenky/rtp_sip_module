//! STUN (Session Traversal Utilities for NAT) implementation
//!
//! RFC 5389 compliant STUN client with:
//! - Sans-IO message codec (message.rs, attributes.rs)
//! - Sans-IO transaction state machine with retransmit (transaction.rs)
//! - Async client for binding requests (client.rs)

pub mod attributes;
pub mod client;
pub mod message;
pub mod pool;
pub mod transaction;

pub use attributes::StunAttribute;
pub use client::StunClient;
pub use message::{StunMessage, TransactionId, MAGIC_COOKIE};
pub use pool::StunServerPool;
pub use transaction::StunTransaction;
