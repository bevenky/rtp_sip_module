//! Python bindings for RTP session
//!
//! # Panic Safety
//!
//! Uses parking_lot::Mutex which doesn't poison on panic and provides
//! better performance. All lock acquisitions are documented.

use pyo3::prelude::*;
use crate::core::rtp::{RtpConfig, RtpSession};
use crate::core::audio::Codec;
use std::sync::Arc;
use parking_lot::Mutex;

use crate::audio::PyAudioFrame;
use crate::error::to_py_err;

/// RTP session for audio transport (Mode 3: RTP-only)
///
/// Use when SIP signaling is handled externally (e.g., via WebSocket).
/// Audio is received/sent via RTP.
///
/// Example:
///     # WebSocket gives you remote endpoint
///     session = RtpSession(remote_ip, remote_port)
///
///     # Start session - auto-allocates local port
///     await session.start()
///     local_port = session.local_port  # Tell WebSocket this
///
///     # Receive/send audio
///     frame = await session.recv_audio()
///     await session.send_audio(response)
#[pyclass(name = "RtpSession")]
pub struct PyRtpSession {
    /// The active RTP session (None until started)
    /// Wrapped in Arc<Mutex> for safe sharing across async boundaries
    session: Arc<Mutex<Option<Arc<RtpSession>>>>,
    /// Cached session for hot-path operations (set on start, cleared on stop)
    /// This avoids lock + Arc::clone on every recv_audio/send_audio call
    cached_session: Arc<Mutex<Option<Arc<RtpSession>>>>,
    /// Configuration (mutable until start())
    config: Arc<Mutex<RtpConfig>>,
}

#[pymethods]
impl PyRtpSession {
    /// Create a new RTP session
    ///
    /// Args:
    ///     remote_ip: Remote IP to send RTP to
    ///     remote_port: Remote RTP port
    #[new]
    fn new(remote_ip: String, remote_port: u16) -> Self {
        Self {
            session: Arc::new(Mutex::new(None)),
            cached_session: Arc::new(Mutex::new(None)),
            config: Arc::new(Mutex::new(RtpConfig::new(remote_ip, remote_port))),
        }
    }

    /// Set the local IP address to bind to
    fn with_local_ip(&self, ip: String) {
        self.config.lock().local_ip = ip;
    }

    /// Set the local port to bind to (0 = auto-allocate)
    fn with_local_port(&self, port: u16) {
        self.config.lock().local_port = port;
    }

    /// Set the codec (PCMU or PCMA)
    fn with_codec(&self, codec: String) -> PyResult<()> {
        let codec_val = Codec::from_str(&codec).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid codec: {}", codec))
        })?;
        self.config.lock().codec = codec_val;
        Ok(())
    }

    /// Set jitter buffer depth in packets
    ///
    /// Recommended values:
    /// - 3 packets (60ms): LAN, low-latency needs
    /// - 5 packets (100ms): Internet telephony (default)
    /// - 7-10 packets (140-200ms): Poor networks, mobile, international
    fn with_jitter_buffer(&self, packets: usize) {
        self.config.lock().jitter_buffer_packets = packets.max(2).min(20);
    }

    /// Start the RTP session
    ///
    /// This is fully async - libfs operations are delegated to a dedicated
    /// worker thread via channels, maintaining thread affinity while allowing
    /// concurrent session creation from Python.
    fn start<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let config = self.config.lock().clone();
        let session_arc = self.session.clone();
        let cached_arc = self.cached_session.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            // Create session (config validation only, no FFI)
            let session = RtpSession::new(config).map_err(to_py_err)?;

            // Start session - this sends command to LibFsWorker thread
            // No blocking, fully async via channels
            session.start().await.map_err(to_py_err)?;

            let session = Arc::new(session);
            *session_arc.lock() = Some(Arc::clone(&session));
            *cached_arc.lock() = Some(session);

            Ok(())
        })
    }

    /// Stop the RTP session
    fn stop<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let session_arc = self.session.clone();
        let cached_arc = self.cached_session.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            // Clear cached session first (stop hot-path operations)
            cached_arc.lock().take();
            // Take the session out while holding the lock, then drop lock before await
            let session = session_arc.lock().take();
            if let Some(session) = session {
                session.stop().await.map_err(to_py_err)?;
            }
            Ok(())
        })
    }

    /// Receive next audio frame from remote
    ///
    /// Uses cached session Arc to avoid lock overhead in hot path.
    #[pyo3(signature = (timeout_ms = 100))]
    fn recv_audio<'py>(&self, py: Python<'py>, timeout_ms: u64) -> PyResult<Bound<'py, PyAny>> {
        // Use cached session for hot-path (avoids lock + clone on every call)
        let cached_arc = self.cached_session.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            // Get cached session reference (single lock, no clone needed after first access)
            let session = {
                let guard = cached_arc.lock();
                match &*guard {
                    Some(s) => Arc::clone(s),
                    None => return Err(pyo3::exceptions::PyRuntimeError::new_err(
                        "Session not started",
                    )),
                }
            };

            // Now we can await without holding the lock
            match session.recv_audio(timeout_ms).await {
                Ok(Some(frame)) => Ok(Some(PyAudioFrame::from(frame))),
                Ok(None) => Ok(None),
                Err(e) => Err(to_py_err(e)),
            }
        })
    }

    /// Send audio frame to remote
    ///
    /// Uses cached session Arc to avoid lock overhead in hot path.
    fn send_audio<'py>(&self, py: Python<'py>, frame: PyAudioFrame) -> PyResult<Bound<'py, PyAny>> {
        // Use cached session for hot-path (avoids lock + clone on every call)
        let cached_arc = self.cached_session.clone();
        let audio_frame = frame.inner;

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            // Get cached session reference (single lock, no clone needed after first access)
            let session = {
                let guard = cached_arc.lock();
                match &*guard {
                    Some(s) => Arc::clone(s),
                    None => return Err(pyo3::exceptions::PyRuntimeError::new_err(
                        "Session not started",
                    )),
                }
            };

            // Now we can await without holding the lock
            session.send_audio(audio_frame).await.map_err(to_py_err)
        })
    }

    /// Synchronous send audio (for debugging)
    fn send_audio_sync(&self, frame: PyAudioFrame) -> PyResult<()> {
        let session = {
            let guard = self.session.lock();
            match &*guard {
                Some(s) => Arc::clone(s),
                None => return Err(pyo3::exceptions::PyRuntimeError::new_err("Session not started")),
            }
        };

        // Use our own tokio runtime
        let rt = crate::core::Runtime::get()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

        rt.block_on(session.send_audio(frame.inner)).map_err(to_py_err)
    }

    /// Get the actual bound local port
    #[getter]
    fn local_port(&self) -> u16 {
        let guard = self.session.lock();
        if let Some(ref session) = *guard {
            session.local_port()
        } else {
            self.config.lock().local_port
        }
    }

    /// Check if session is running
    #[getter]
    fn is_running(&self) -> bool {
        self.session.lock().as_ref().map(|s| s.is_running()).unwrap_or(false)
    }

    /// Get RTP statistics
    #[getter]
    fn stats(&self) -> PyRtpStats {
        let guard = self.session.lock();
        if let Some(ref session) = *guard {
            let stats = session.stats();
            PyRtpStats {
                packets_sent: stats.packets_sent,
                packets_received: stats.packets_received,
                packets_lost: stats.packets_lost,
                jitter_ms: stats.jitter_ms,
                rtt_ms: stats.rtt_ms,
                target_delay_ms: stats.target_delay_ms,
                buffer_pool_available: stats.buffer_pool_available,
            }
        } else {
            PyRtpStats::default()
        }
    }

    fn __repr__(&self) -> String {
        // Get all values first to avoid nested locking
        let (remote_ip, remote_port) = {
            let config = self.config.lock();
            (config.remote_ip.clone(), config.remote_port)
        };
        let local_port = self.local_port();
        let is_running = self.is_running();

        format!(
            "RtpSession(remote={}:{}, local_port={}, running={})",
            remote_ip,
            remote_port,
            local_port,
            is_running
        )
    }
}

/// RTP session statistics
#[pyclass(name = "RtpStats")]
#[derive(Clone, Default)]
pub struct PyRtpStats {
    /// Packets sent
    #[pyo3(get)]
    pub packets_sent: u64,
    /// Packets received
    #[pyo3(get)]
    pub packets_received: u64,
    /// Packets lost
    #[pyo3(get)]
    pub packets_lost: u64,
    /// Jitter in milliseconds
    #[pyo3(get)]
    pub jitter_ms: f64,
    /// Round-trip time in milliseconds
    #[pyo3(get)]
    pub rtt_ms: f64,
    /// Target delay from adaptive jitter buffer
    #[pyo3(get)]
    pub target_delay_ms: f64,
    /// Number of buffers available in pool (performance metric)
    #[pyo3(get)]
    pub buffer_pool_available: u64,
}

#[pymethods]
impl PyRtpStats {
    fn __repr__(&self) -> String {
        format!(
            "RtpStats(sent={}, received={}, lost={}, target_delay={:.0}ms)",
            self.packets_sent, self.packets_received, self.packets_lost, self.target_delay_ms
        )
    }
}

/// RTP session configuration (deprecated, use RtpSession directly)
#[pyclass(name = "RtpConfig")]
#[derive(Clone)]
pub struct PyRtpConfig {
    pub(crate) inner: RtpConfig,
}

#[pymethods]
impl PyRtpConfig {
    #[new]
    #[pyo3(signature = (remote_ip, remote_port, local_ip=None, local_port=None))]
    fn new(
        remote_ip: String,
        remote_port: u16,
        local_ip: Option<String>,
        local_port: Option<u16>,
    ) -> Self {
        let mut config = RtpConfig::new(remote_ip, remote_port);
        if let Some(ip) = local_ip {
            config = config.with_local_ip(ip);
        }
        if let Some(port) = local_port {
            config = config.with_local_port(port);
        }
        Self { inner: config }
    }

    #[getter]
    fn remote_ip(&self) -> &str {
        &self.inner.remote_ip
    }

    #[getter]
    fn remote_port(&self) -> u16 {
        self.inner.remote_port
    }

    #[getter]
    fn local_ip(&self) -> &str {
        &self.inner.local_ip
    }

    #[getter]
    fn local_port(&self) -> u16 {
        self.inner.local_port
    }

    fn __repr__(&self) -> String {
        format!(
            "RtpConfig(remote={}:{}, local={}:{})",
            self.inner.remote_ip,
            self.inner.remote_port,
            self.inner.local_ip,
            self.inner.local_port
        )
    }
}
