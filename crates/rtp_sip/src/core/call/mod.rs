//! Call module - call session management
//!
//! Thin wrapper around libfs session.
//! libfs handles SIP signaling, RTP, codec, jitter buffer.

mod session;

pub use session::{Call, CallDirection, CallState};
