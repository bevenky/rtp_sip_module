//! rtp_sip - Python bindings for libfs telephony
//!
//! Thin wrappers around libfs for SIP/RTP telephony.
//! libfs handles all the heavy lifting.
//!
//! # Modes
//!
//! - **Mode 3 (RTP-only)**: External SIP handling, rtp_sip handles RTP
//! - **Mode 1 (Outbound)**: Python initiates calls via SIP.dial()
//! - **Mode 2 (Inbound)**: Python receives calls via set_inbound_handler()
//!
//! # Example: Mode 3 (RTP-only)
//!
//! ```python
//! import asyncio
//! from rtp_sip import RtpSession
//!
//! async def main():
//!     # WebSocket gives you remote endpoint
//!     session = RtpSession(remote_ip, remote_port)
//!
//!     # Start - auto-allocates local port
//!     await session.start()
//!     local_port = session.local_port  # Tell WebSocket this
//!
//!     # Receive/send audio
//!     frame = await session.recv_audio(100)
//!     await session.send_audio(response_frame)
//!
//!     await session.stop()
//! ```
//!
//! # Example: Mode 1 (Outbound)
//!
//! ```python
//! import asyncio
//! from rtp_sip import SIP, SipConfig, TrunkConfig
//!
//! async def main():
//!     sip = SIP(SipConfig())
//!     await sip.start()
//!     await sip.add_trunk(TrunkConfig("mytrunk", "sip.provider.com"))
//!
//!     call = await sip.dial("18005551234", "mytrunk")
//!     while call.is_active:
//!         frame = await call.recv_audio(100)
//!         # process audio...
//!     await call.hangup()
//! ```
//!
//! # Shutdown
//!
//! The module automatically registers an atexit handler for cleanup.
//! You can also call `shutdown()` explicitly for graceful shutdown.

mod audio;
mod call;
mod config;
pub mod core;
mod error;
mod rtp;
mod sip;

use pyo3::prelude::*;

use crate::error::to_py_err;

/// Gracefully shutdown the libfs worker and cleanup resources
///
/// This is automatically called on process exit via atexit,
/// but can be called explicitly for controlled shutdown.
///
/// # Example
/// ```python
/// import rtp_sip
/// # ... use rtp_sip ...
/// rtp_sip.shutdown()  # explicit cleanup
/// ```
#[pyfunction]
fn shutdown(py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        if let Ok(worker) = crate::core::libfs_worker::LibFsWorker::get() {
            worker.shutdown().await.map_err(to_py_err)?;
        }
        Ok(())
    })
}

/// Synchronous shutdown for use in atexit handler
#[pyfunction]
fn _shutdown_sync() -> PyResult<()> {
    tracing::info!("rtp_sip atexit shutdown triggered");
    // Only shutdown if worker was already created - don't create one just for shutdown
    if let Some(worker) = crate::core::libfs_worker::LibFsWorker::get_if_initialized() {
        let _ = worker.shutdown_sync();
    }
    Ok(())
}

/// Check if the libfs worker is running
#[pyfunction]
fn is_running() -> bool {
    crate::core::libfs_worker::LibFsWorker::get()
        .map(|w| w.is_running())
        .unwrap_or(false)
}

/// Initialize the rtp_sip module
#[pymodule]
fn rtp_sip(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Initialize tracing (optional, for debugging)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .try_init()
        .ok();

    // Initialize Tokio runtime only - libfs will be initialized lazily
    crate::core::Runtime::init()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

    // Config class
    m.add_class::<config::PyConfig>()?;

    // RTP classes (Mode 3)
    m.add_class::<rtp::PyRtpConfig>()?;
    m.add_class::<rtp::PyRtpSession>()?;
    m.add_class::<rtp::PyRtpStats>()?;

    // Audio classes
    m.add_class::<audio::PyAudioFrame>()?;
    m.add_class::<audio::PyCodec>()?;

    // SIP classes (Mode 1 & 2)
    m.add_class::<sip::PyPyswitchConfig>()?;
    m.add_class::<sip::PySipConfig>()?;
    m.add_class::<sip::PyTrunkConfig>()?;
    m.add_class::<sip::PySip>()?;

    // Call classes
    m.add_class::<call::PyCall>()?;
    m.add_class::<call::PyCallDirection>()?;

    // Module functions
    m.add_function(wrap_pyfunction!(shutdown, m)?)?;
    m.add_function(wrap_pyfunction!(_shutdown_sync, m)?)?;
    m.add_function(wrap_pyfunction!(is_running, m)?)?;

    // Module version
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    // Register atexit handler for automatic cleanup
    // Must be done AFTER _shutdown_sync is added to the module
    {
        let atexit = m.py().import_bound("atexit")?;
        let shutdown_fn = m.getattr("_shutdown_sync")?;
        atexit.call_method1("register", (shutdown_fn,))?;
        tracing::debug!("Registered atexit handler for rtp_sip cleanup");
    }

    Ok(())
}
