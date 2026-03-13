//! rtpsip - High-performance SIP/RTP library for Voice AI
//!
//! A Rust library for SIP signaling and RTP media handling,
//! exposed to Python via PyO3. Designed for Voice AI applications
//! requiring low-latency telephony integration.
//!
//! ## Operating Modes
//!
//! ### Mode A: Full SIP + RTP
//! Complete SIP signaling with integrated RTP media.
//!
//! ### Mode B: RTP-Only (External Signaling)
//! For use with WebSocket-based signaling (e.g., Twilio Media Streams).
//!
//! ## Example (RTP-Only Mode)
//!
//! ```python
//! from rtpsip import RtpSession
//!
//! session = RtpSession(
//!     local_addr="0.0.0.0:0",
//!     remote_addr="1.2.3.4:5678",
//!     codec="PCMU",
//! )
//! session.start()
//!
//! # Send audio (PCM i16 samples, 8kHz mono)
//! session.send_audio(samples)
//!
//! # Receive audio
//! audio = session.recv_audio(100)  # 100ms timeout
//!
//! session.stop()
//! ```

use pyo3::prelude::*;

pub mod config;
pub mod error;
pub mod nat;
pub mod provider;
pub mod rtp;
pub mod session;
pub mod sip;

mod python;

pub use error::{Result, RtpSipError};
pub use rtp::{CodecType, G711Codec, JitterBuffer, JitterStats, RtpEngine, RtpPacket};

/// Python module definition
#[pymodule]
fn _rtpsip(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Initialize tracing for logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("rtpsip=info".parse().unwrap()),
        )
        .try_init()
        .ok();

    // === Mode A: Full SIP + RTP ===
    m.add_class::<python::PySipRunner>()?;
    m.add_class::<python::PyCallEvent>()?;
    m.add_class::<python::PyCallState>()?;
    m.add_class::<python::PyDtmfMode>()?;

    // === Mode B: RTP-only ===
    m.add_class::<python::PyRtpSession>()?;

    // Statistics
    m.add_class::<python::session::PyJitterStats>()?;

    // Version info
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    Ok(())
}
