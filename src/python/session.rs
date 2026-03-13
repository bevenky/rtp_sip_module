//! Python RTP session bindings
//!
//! # GIL Optimization
//!
//! All blocking operations release the GIL using `py.allow_threads()`
//! to allow other Python threads to run concurrently.

use crate::rtp::{CodecType, JitterStats, RtpEngine, RtpEngineConfig};
use pyo3::prelude::*;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

/// Python-exposed jitter buffer statistics
#[pyclass(name = "JitterStats")]
#[derive(Clone)]
pub struct PyJitterStats {
    #[pyo3(get)]
    pub packets_received: u64,
    #[pyo3(get)]
    pub packets_lost: u64,
    #[pyo3(get)]
    pub packets_dropped: u64,
    #[pyo3(get)]
    pub packets_reordered: u64,
    #[pyo3(get)]
    pub jitter_ms: f64,
    #[pyo3(get)]
    pub buffer_delay_ms: u32,
    #[pyo3(get)]
    pub buffer_size: usize,
}

impl From<JitterStats> for PyJitterStats {
    fn from(stats: JitterStats) -> Self {
        Self {
            packets_received: stats.packets_received,
            packets_lost: stats.packets_lost,
            packets_dropped: stats.packets_dropped,
            packets_reordered: stats.packets_reordered,
            jitter_ms: stats.jitter_ms,
            buffer_delay_ms: stats.buffer_delay_ms,
            buffer_size: stats.buffer_size,
        }
    }
}

/// RTP-only session for use with external signaling
///
/// Example:
/// ```python
/// from rtpsip import RtpSession
///
/// session = RtpSession(
///     local_addr="0.0.0.0:0",
///     remote_addr="1.2.3.4:5678",
///     codec="PCMU",
/// )
/// session.start()
///
/// # Send audio (PCM i16 samples, 8kHz mono)
/// session.send_audio(samples)
///
/// # Receive audio
/// audio = session.recv_audio(100)  # 100ms timeout
///
/// session.stop()
/// ```
#[pyclass(name = "RtpSession")]
pub struct PyRtpSession {
    engine: Option<Arc<RtpEngine>>,
    runtime: Arc<Runtime>,
    local_addr: String,
    remote_addr: Option<String>,
    codec: String,
    ssrc: Option<u32>,
}

#[pymethods]
impl PyRtpSession {
    #[new]
    #[pyo3(signature = (local_addr="0.0.0.0:0", remote_addr=None, codec="PCMU", ssrc=None))]
    fn new(
        local_addr: &str,
        remote_addr: Option<&str>,
        codec: &str,
        ssrc: Option<u32>,
    ) -> PyResult<Self> {
        // Validate codec
        CodecType::from_str(codec).map_err(|e| PyValueError::new_err(e.to_string()))?;

        let runtime = Runtime::new()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to create runtime: {}", e)))?;

        Ok(Self {
            engine: None,
            runtime: Arc::new(runtime),
            local_addr: local_addr.to_string(),
            remote_addr: remote_addr.map(|s| s.to_string()),
            codec: codec.to_string(),
            ssrc,
        })
    }

    /// Get the local address (available after start)
    #[getter]
    fn local_addr(&self) -> PyResult<String> {
        if let Some(engine) = &self.engine {
            Ok(engine.local_addr().to_string())
        } else {
            Ok(self.local_addr.clone())
        }
    }

    /// Get the remote address
    #[getter]
    fn remote_addr(&self) -> Option<String> {
        if let Some(engine) = &self.engine {
            engine.remote_addr().map(|a| a.to_string())
        } else {
            self.remote_addr.clone()
        }
    }

    /// Get the SSRC
    #[getter]
    fn ssrc(&self) -> PyResult<u32> {
        if let Some(engine) = &self.engine {
            Ok(engine.ssrc())
        } else {
            self.ssrc.ok_or_else(|| PyRuntimeError::new_err("Session not started"))
        }
    }

    /// Get the codec type
    #[getter]
    fn codec(&self) -> String {
        self.codec.clone()
    }

    /// Check if the session is running
    #[getter]
    fn is_running(&self) -> bool {
        self.engine.as_ref().map(|e| e.is_running()).unwrap_or(false)
    }

    /// Set the remote address
    /// Bug #R11-7: Return error when called before start() instead of silently
    /// discarding the address. The engine must be initialized first.
    fn set_remote(&self, addr: &str) -> PyResult<()> {
        let addr: SocketAddr = addr
            .parse()
            .map_err(|e| PyValueError::new_err(format!("Invalid address: {}", e)))?;

        if let Some(engine) = &self.engine {
            engine.set_remote(addr);
        } else {
            return Err(PyRuntimeError::new_err(
                "Session not started. Call start() first, or pass remote_addr to constructor.",
            ));
        }
        Ok(())
    }

    /// Start the RTP session
    ///
    /// Bug #R6-3: Release GIL during async engine creation to avoid
    /// blocking the Python interpreter.
    fn start(&mut self, py: Python<'_>) -> PyResult<()> {
        if self.engine.is_some() {
            return Err(PyRuntimeError::new_err("Session already started"));
        }

        let local_addr: SocketAddr = self.local_addr
            .parse()
            .map_err(|e| PyValueError::new_err(format!("Invalid local address: {}", e)))?;

        let codec_type = CodecType::from_str(&self.codec)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        // RTP-only mode: disable DTMF since signaling is external (websocket)
        let config = RtpEngineConfig {
            codec: codec_type,
            ssrc: self.ssrc,
            enable_dtmf: false,  // No RFC 2833 in RTP-only mode
            ..Default::default()
        };

        let runtime = self.runtime.clone();
        let engine = py.allow_threads(|| {
            // Bug R15-1 fix: Enter runtime context before block_on() so that
            // tokio::spawn and other runtime-dependent calls inside RtpEngine::new()
            // can find the runtime handle. Matches pattern in send_audio() (Bug #12 fix).
            let _guard = runtime.enter();
            runtime.block_on(async {
                RtpEngine::new(local_addr, config).await
            })
        }).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        let engine = Arc::new(engine);

        if let Some(addr_str) = &self.remote_addr {
            let addr: SocketAddr = addr_str.parse()
                .map_err(|e| PyValueError::new_err(format!("Invalid remote address: {}", e)))?;
            engine.set_remote(addr);
        }

        // Enter runtime context for tokio::spawn in engine.start()
        let _guard = self.runtime.enter();
        engine.start()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        self.engine = Some(engine);
        Ok(())
    }

    /// Stop the RTP session
    fn stop(&mut self) -> PyResult<()> {
        if let Some(engine) = &self.engine {
            engine.stop();
        }
        self.engine = None;
        Ok(())
    }

    /// Send audio samples (PCM i16, 8kHz mono)
    ///
    /// Releases GIL during the blocking send operation.
    fn send_audio(&self, py: Python<'_>, samples: Vec<i16>) -> PyResult<()> {
        let engine = self.engine.clone()
            .ok_or_else(|| PyRuntimeError::new_err("Session not started"))?;

        let runtime = self.runtime.clone();

        py.allow_threads(|| {
            // Bug #12 fix: Enter runtime context before block_on() so that
            // tokio::spawn and other runtime-dependent calls inside send_audio
            // can find the runtime handle.
            let _guard = runtime.enter();
            runtime.block_on(async {
                engine.send_audio(&samples).await
            }).map_err(|e| PyRuntimeError::new_err(e.to_string()))
        })
    }

    /// Receive audio samples with timeout (in milliseconds)
    ///
    /// Releases GIL during the blocking receive operation.
    /// Returns None if no audio is available within timeout
    fn recv_audio(&self, py: Python<'_>, timeout_ms: u64) -> PyResult<Option<Vec<i16>>> {
        let engine = self.engine.clone()
            .ok_or_else(|| PyRuntimeError::new_err("Session not started"))?;

        let timeout = Duration::from_millis(timeout_ms);

        py.allow_threads(|| {
            engine.recv_audio_blocking(timeout)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))
        })
    }

    /// Try to receive audio without blocking
    /// Returns None if no audio is immediately available
    fn try_recv_audio(&self) -> PyResult<Option<Vec<i16>>> {
        let engine = self.engine.as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("Session not started"))?;

        engine.recv_audio_try()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// Get jitter buffer statistics
    fn get_stats(&self) -> PyResult<PyJitterStats> {
        let engine = self.engine.as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("Session not started"))?;

        Ok(engine.jitter_stats().into())
    }

    /// Reset the jitter buffer
    fn reset_jitter_buffer(&self) -> PyResult<()> {
        let engine = self.engine.as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("Session not started"))?;

        engine.reset_jitter_buffer();
        Ok(())
    }
}
