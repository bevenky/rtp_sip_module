//! SIP (Session Initiation Protocol) module
//!
//! This module provides:
//! - SIP signaling with rsipstack
//! - SDP parsing and generation
//! - Call management

pub mod engine;
pub mod sdp;

pub use engine::{
    CallEvent, CallSession, CallState, Direction, ProviderCredentials, SipEngine, SipEngineConfig,
};
pub use sdp::{MediaDescription, RtpMapEntry, Sdp, SdpBuilder, SdpOrigin};

// Re-export rsipstack's Credential for convenience
pub use rsipstack::dialog::authenticate::Credential;
