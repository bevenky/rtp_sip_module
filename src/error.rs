use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::PyErr;
use thiserror::Error;

/// Main error type for rtpsip
#[derive(Error, Debug)]
pub enum RtpSipError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("RTP error: {0}")]
    Rtp(String),

    #[error("SIP error: {0}")]
    Sip(String),

    #[error("SDP error: {0}")]
    Sdp(String),

    #[error("Codec error: {0}")]
    Codec(String),

    #[error("Session error: {0}")]
    Session(String),

    #[error("Provider error: {0}")]
    Provider(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Not connected")]
    NotConnected,

    #[error("Already started")]
    AlreadyStarted,

    #[error("Not started")]
    NotStarted,

    #[error("Invalid state: {0}")]
    InvalidState(String),
}

impl From<RtpSipError> for PyErr {
    fn from(err: RtpSipError) -> Self {
        match &err {
            RtpSipError::Config(_) | RtpSipError::Parse(_) => {
                PyValueError::new_err(err.to_string())
            }
            _ => PyRuntimeError::new_err(err.to_string()),
        }
    }
}

/// Result type alias for rtpsip operations
pub type Result<T> = std::result::Result<T, RtpSipError>;
