//! Provider module
//!
//! Handles multi-provider configuration and routing.

pub mod config;
pub mod router;

pub use config::{ProviderConfig, ProviderStats, Transport};
pub use router::{ProviderRouter, RouterHandle};
