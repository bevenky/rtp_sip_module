//! SIP (Session Initiation Protocol) module
//!
//! This module provides:
//! - SIP signaling with rsipstack
//! - SDP parsing and generation
//! - Call management

pub mod digest_auth;
pub mod dns;
pub mod engine;
pub mod sdp;
pub mod session_timer;

pub use digest_auth::{
    DigestAlgorithm, DigestChallenge, DigestCredentials, Qop,
    build_auth_header, compute_response, parse_challenge,
};
pub use engine::{
    CallEvent, CallSession, CallState, Direction, ProviderCredentials, RegistrationState,
    SipEngine, SipEngineConfig,
};
pub use sdp::{MediaDescription, RtpMapEntry, Sdp, SdpBuilder, SdpOrigin};
pub use session_timer::{RefreshRole, SessionTimer, SessionTimerConfig};

// Re-export rsipstack's Credential for convenience
pub use rsipstack::dialog::authenticate::Credential;
