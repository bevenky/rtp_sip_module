//! SIP module - thin wrapper around libfs mod_sofia
//!
//! libfs handles all SIP signaling via sofia-sip.
//! This module provides:
//! - SipTransport for managing trunks and calls
//! - Configuration types for SIP and trunks
//! - SipSession for audio capture/injection via media bugs
//!
//! # Mode Selection
//!
//! Using SipTransport locks the process to SIP mode. You cannot use
//! RtpSession in the same process after SipTransport is started.
//! Restart required to switch modes.

mod config;
pub mod media_bug;
pub mod session;
pub mod transport;

pub use config::{PyswitchConfig, SipConfig, TrunkConfig};
pub use media_bug::{MediaBugFrame, MediaBugState};
pub use session::{SipCallDirection, SipSession};
pub use transport::SipTransport;
