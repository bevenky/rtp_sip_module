//! TURN (Traversal Using Relays around NAT) implementation
//!
//! RFC 5766 TURN relay for Symmetric NAT fallback.
//!
//! Provides:
//! - Message types and ChannelData codec (`message.rs`)
//! - Full TURN client lifecycle (`client.rs`): Allocate, CreatePermission,
//!   ChannelBind, Refresh, Deallocate with long-term credential auth

pub mod client;
pub mod message;

pub use client::{TurnAllocation, TurnClient, TurnState};
pub use message::{build_channel_data, is_valid_channel, parse_channel_data};
