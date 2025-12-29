//! Error types for rtp_sip_core

use thiserror::Error;

/// Result type for pyswitch operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error types for pyswitch
#[derive(Debug, Error)]
pub enum Error {
    /// RTP session error
    #[error("RTP error: {0}")]
    Rtp(String),

    /// Audio codec error
    #[error("Codec error: {0}")]
    Codec(String),

    /// Resampler error
    #[error("Resampler error: {0}")]
    Resampler(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Runtime error
    #[error("Runtime error: {0}")]
    Runtime(String),

    /// Channel error (send/recv)
    #[error("Channel error: {0}")]
    Channel(String),

    /// Timeout error
    #[error("Timeout")]
    Timeout,

    /// Session closed
    #[error("Session closed")]
    SessionClosed,

    /// FFI error
    #[error("FFI error: {0}")]
    Ffi(String),

    /// Session error
    #[error("Session error: {0}")]
    Session(String),

    /// Call error
    #[error("Call error: {0}")]
    Call(String),

    /// SIP error
    #[error("SIP error: {0}")]
    Sip(String),
}
