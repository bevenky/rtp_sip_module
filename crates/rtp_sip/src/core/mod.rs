//! rtp_sip_core - Core telephony logic
//!
//! Thin wrappers around libfs for:
//! - RTP session management (Mode 3: RTP-only)
//! - SIP stack via mod_sofia (Mode 1 & 2)
//! - Audio frame handling
//! - Resampling via libfs's bundled Speex
//!
//! libfs handles codec encoding/decoding, jitter buffer, etc.
//!
//! # Mode Selection
//!
//! The module operates in one of two mutually exclusive modes:
//! - **RtpOnly**: For Mode 3 (external SIP, internal RTP via switch_rtp_*)
//! - **Sip**: For Mode 1/2 (internal SIP via mod_sofia)
//!
//! The mode is determined by which component is initialized first
//! and cannot be changed without restarting the process.

pub mod audio;
pub mod call;
pub mod error;
pub mod libfs_worker;
pub mod rtp;
pub mod runtime;
pub mod sip;

pub use audio::{AudioFrame, Codec};
pub use call::{Call, CallDirection, CallState};
pub use error::{Error, Result};
pub use rtp::{RtpConfig, RtpSession};
pub use runtime::{FsMode, Runtime};
pub use sip::{PyswitchConfig, SipConfig, SipTransport, TrunkConfig};
