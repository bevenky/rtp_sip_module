//! Python SIP client
//!
//! Main Python interface for SIP + RTP operations.
//!
//! # GIL Optimization
//!
//! This module releases the GIL during all blocking operations to allow
//! other Python threads to run. Key patterns:
//!
//! - `py.allow_threads(|| ...)` for blocking Rust operations
//! - Clone Arc references before releasing GIL
//! - Minimize time holding Python objects
//!
//! # Performance Notes
//!
//! - Audio data uses `Vec<i16>` which PyO3 converts efficiently
//! - Events use broadcast channel (single producer, multi-consumer)
//! - All sync primitives use parking_lot for better performance

use crate::config::Config;
use crate::python::events::{PyCallEvent, PyCallState};
use crate::sip::engine::{
    CallEvent as RustCallEvent, DtmfMode, ProviderCredentials, SipEngine, SipEngineConfig,
};
use parking_lot::Mutex as SyncMutex;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::broadcast;

/// DTMF transmission mode
///
/// Controls how DTMF digits are sent and received.
#[pyclass(name = "DtmfMode", eq)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PyDtmfMode {
    /// Automatically detect based on remote SDP (recommended)
    /// Uses RFC 2833 if remote supports telephone-event, else SIP INFO
    Auto,
    /// RFC 2833/4733 telephone-event in RTP stream
    Rfc2833,
    /// SIP INFO with application/dtmf-relay
    Info,
}

#[pymethods]
impl PyDtmfMode {
    fn __repr__(&self) -> &'static str {
        match self {
            PyDtmfMode::Auto => "DtmfMode.Auto",
            PyDtmfMode::Rfc2833 => "DtmfMode.Rfc2833",
            PyDtmfMode::Info => "DtmfMode.Info",
        }
    }
}

impl From<DtmfMode> for PyDtmfMode {
    fn from(mode: DtmfMode) -> Self {
        match mode {
            DtmfMode::Auto => PyDtmfMode::Auto,
            DtmfMode::Rfc2833 => PyDtmfMode::Rfc2833,
            DtmfMode::Info => PyDtmfMode::Info,
        }
    }
}

impl From<PyDtmfMode> for DtmfMode {
    fn from(mode: PyDtmfMode) -> Self {
        match mode {
            PyDtmfMode::Auto => DtmfMode::Auto,
            PyDtmfMode::Rfc2833 => DtmfMode::Rfc2833,
            PyDtmfMode::Info => DtmfMode::Info,
        }
    }
}

/// SipRunner - Main Python interface for SIP+RTP operations
///
/// Provides a high-level API for making and receiving SIP calls
/// with integrated RTP audio handling. Supports multiple providers
/// with longest-prefix routing.
///
/// # Tokio Runtime (Bug #38)
///
/// Each PySipRunner creates its own tokio runtime. This is intentional:
/// the runtime is used for both the SIP engine's async operations and for
/// blocking Python<->Rust bridge calls (via `block_on`). A single runtime
/// per runner keeps the lifecycle simple — when the runner is dropped, the
/// runtime and all its spawned tasks are cleaned up together.
///
/// TODO(P2): Consider sharing a runtime across multiple PySipRunner instances
/// if resource usage becomes a concern in multi-runner deployments.
///
/// Example:
/// ```python
/// from rtpsip import SipRunner
///
/// # Load from config file
/// runner = SipRunner.from_config("config.toml")
/// runner.start()
///
/// # Make a call (auto-routes based on prefix)
/// call_id = runner.call(to="+14155551234", from_="+14155550000")
///
/// # Wait for events
/// event = runner.next_event(timeout_ms=30000)
/// if event and event.is_answered():
///     runner.send_audio(call_id, samples)
///     audio = runner.recv_audio(call_id, timeout_ms=100)
///
/// runner.hangup(call_id)
/// runner.stop()
/// ```
#[pyclass(name = "SipRunner")]
pub struct PySipRunner {
    /// Tokio runtime for async operations
    runtime: Arc<Runtime>,
    /// Configuration
    config: Config,
    /// SIP engine (initialized on start)
    engine: SyncMutex<Option<Arc<SipEngine>>>,
    /// Event receiver
    event_rx: SyncMutex<Option<broadcast::Receiver<RustCallEvent>>>,
    /// Running state
    running: SyncMutex<bool>,
}

#[pymethods]
impl PySipRunner {
    /// Create a new SipRunner from a config file
    ///
    /// Args:
    ///     config_path: Path to the TOML configuration file
    #[staticmethod]
    fn from_config(config_path: &str) -> PyResult<Self> {
        let config = Config::from_file(config_path).map_err(|e| {
            PyValueError::new_err(format!("Failed to load config: {}", e))
        })?;

        config.validate().map_err(|e| {
            PyValueError::new_err(format!("Invalid config: {}", e))
        })?;

        let runtime = Runtime::new().map_err(|e| {
            PyRuntimeError::new_err(format!("Failed to create tokio runtime: {}", e))
        })?;

        Ok(Self {
            runtime: Arc::new(runtime),
            config,
            engine: SyncMutex::new(None),
            event_rx: SyncMutex::new(None),
            running: SyncMutex::new(false),
        })
    }

    /// Create a new SipRunner with programmatic configuration (single provider)
    ///
    /// For multiple providers, use from_config() with a TOML file.
    ///
    /// Args:
    ///     provider_name: Provider name for logging
    ///     provider_server: SIP server hostname
    ///     username: Authentication username
    ///     password: Authentication password
    ///     provider_port: SIP server port (default: 5060)
    ///     sip_ip: Local SIP bind IP (default: "0.0.0.0")
    ///     sip_port: Local SIP port (default: 5060)
    ///     transport: "udp" or "tls" (default: "udp")
    ///     rtp_ip: Local RTP bind IP (default: "0.0.0.0")
    ///     rtp_port_start: RTP port range start (default: 10000)
    ///     rtp_port_end: RTP port range end (default: 20000)
    ///     prefixes: List of prefixes to handle (default: [] = all)
    ///     blocked_prefixes: List of blocked prefixes (default: [])
    #[new]
    #[pyo3(signature = (
        provider_name,
        provider_server,
        username = "",
        password = "",
        provider_port = 5060,
        sip_ip = "0.0.0.0",
        sip_port = 5060,
        transport = "udp",
        rtp_ip = "0.0.0.0",
        rtp_port_start = 10000,
        rtp_port_end = 20000,
        prefixes = None,
        blocked_prefixes = None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        provider_name: &str,
        provider_server: &str,
        username: &str,
        password: &str,
        provider_port: u16,
        sip_ip: &str,
        sip_port: u16,
        transport: &str,
        rtp_ip: &str,
        rtp_port_start: u16,
        rtp_port_end: u16,
        prefixes: Option<Vec<String>>,
        blocked_prefixes: Option<Vec<String>>,
    ) -> PyResult<Self> {
        use crate::config::{ProviderConfig, RoutingConfig, RtpConfig, SipConfig};

        if rtp_port_start >= rtp_port_end {
            return Err(PyValueError::new_err(
                "rtp_port_start must be less than rtp_port_end",
            ));
        }

        let config = Config {
            sip: SipConfig {
                local_ip: sip_ip.to_string(),
                local_port: sip_port,
                transport: transport.to_string(),
                tls_cert: None,
                tls_key: None,
                timer_t1_ms: None,
                timer_t2_ms: None,
                timer_t1x64_ms: None,
                tls_verify: true,
                tls_ca_cert: None,
            },
            rtp: RtpConfig {
                local_ip: rtp_ip.to_string(),
                port_start: rtp_port_start,
                port_end: rtp_port_end,
            },
            providers: vec![ProviderConfig {
                name: provider_name.to_string(),
                server: provider_server.to_string(),
                port: provider_port,
                username: username.to_string(),
                password: password.to_string(),
                realm: None,
                prefixes: prefixes.unwrap_or_default(),
                default: true, // Single provider is always default
            }],
            routing: RoutingConfig {
                blocked_prefixes: blocked_prefixes.unwrap_or_default(),
            },
        };

        config.validate().map_err(|e| {
            PyValueError::new_err(format!("Invalid config: {}", e))
        })?;

        let runtime = Runtime::new().map_err(|e| {
            PyRuntimeError::new_err(format!("Failed to create tokio runtime: {}", e))
        })?;

        Ok(Self {
            runtime: Arc::new(runtime),
            config,
            engine: SyncMutex::new(None),
            event_rx: SyncMutex::new(None),
            running: SyncMutex::new(false),
        })
    }

    /// Start the SIP engine
    ///
    /// This starts the SIP engine and begins listening for incoming calls.
    /// Must be called before making or receiving calls.
    // Bug #R9-4: Added py parameter to release GIL during blocking engine creation
    fn start(&self, py: Python<'_>) -> PyResult<()> {
        if *self.running.lock() {
            return Err(PyRuntimeError::new_err("Runner is already running"));
        }

        let local_addr = format!(
            "{}:{}",
            self.config.sip.local_ip, self.config.sip.local_port
        )
        .parse()
        .map_err(|e| PyValueError::new_err(format!("Invalid SIP address: {}", e)))?;

        let sip_config = SipEngineConfig {
            local_addr,
            user_agent: Config::user_agent(),
            rtp_port_start: self.config.rtp.port_start,
            rtp_port_end: self.config.rtp.port_end,
            ..Default::default()
        };

        let runtime = self.runtime.clone();

        // Create engine — release GIL during async I/O
        let engine = py.allow_threads(|| {
            let _guard = runtime.enter();
            runtime
                .block_on(async { SipEngine::new(sip_config).await })
        })
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to create SIP engine: {}", e)))?;

        // Add all provider credentials
        for provider in &self.config.providers {
            let creds = ProviderCredentials {
                id: provider.name.clone(),
                sip_server: provider.server.clone(),
                sip_port: provider.port,
                username: provider.username.clone(),
                password: provider.password.clone(),
                realm: provider.realm.clone(),
                register: false, // Registration not supported
            };
            engine.add_provider(creds);
        }

        // Bug #R11-6: Enter runtime context before calling engine.start() which
        // uses tokio::spawn. The _guard from py.allow_threads was dropped when that
        // closure returned, leaving no active runtime context.
        let _guard = self.runtime.enter();

        // Start the incoming call listener
        engine.start().map_err(|e| {
            PyRuntimeError::new_err(format!("Failed to start incoming call listener: {}", e))
        })?;

        // Subscribe to events
        let event_rx = engine.subscribe();
        *self.event_rx.lock() = Some(event_rx);

        *self.engine.lock() = Some(engine);
        *self.running.lock() = true;

        Ok(())
    }

    /// Stop the SIP engine
    fn stop(&self, py: Python<'_>) -> PyResult<()> {
        if !*self.running.lock() {
            return Ok(());
        }

        let runtime = self.runtime.clone();
        let engine_opt = self.engine.lock().clone();

        // Bug #R10-1: Release GIL during blocking hangup calls to avoid deadlock.
        // Same pattern as start() fix in Round 9.
        if let Some(ref engine) = engine_opt {
            let calls = engine.active_calls();
            py.allow_threads(|| {
                let _guard = runtime.enter();
                for call_id in calls {
                    let _ = runtime.block_on(engine.hangup(&call_id));
                }
                // Stop the incoming call listener
                engine.stop();
            });
        }

        *self.engine.lock() = None;
        *self.event_rx.lock() = None;
        *self.running.lock() = false;

        Ok(())
    }

    /// Check if the engine is running
    fn is_running(&self) -> bool {
        *self.running.lock()
    }

    /// Make an outbound call
    ///
    /// Auto-routes to the best provider based on longest prefix match.
    /// Releases GIL during the blocking call operation.
    ///
    /// Args:
    ///     to: Destination phone number (e.g., "+14155551234")
    ///     from_: Caller phone number (e.g., "+14155550000")
    ///
    /// Returns:
    ///     Call ID string
    ///
    /// Raises:
    ///     ValueError: If destination is blocked or no provider matches
    ///     RuntimeError: If call fails
    #[pyo3(signature = (to, from_))]
    fn call(&self, py: Python<'_>, to: &str, from_: &str) -> PyResult<String> {
        // Check if blocked
        if self.config.is_blocked(to) {
            return Err(PyValueError::new_err(format!(
                "Destination '{}' is blocked by configuration",
                to
            )));
        }

        // Route to best provider
        let provider = self.config.route(to).ok_or_else(|| {
            PyValueError::new_err(format!(
                "No provider matches destination '{}' and no default provider configured",
                to
            ))
        })?;

        let engine = self.engine.lock().clone().ok_or_else(|| {
            PyRuntimeError::new_err("Runner not started. Call start() first.")
        })?;

        // Build SIP URIs - clone strings before releasing GIL
        let to_uri = format!("sip:{}@{}", to, provider.server);
        let from_uri = format!("sip:{}@{}", from_, provider.server);
        let provider_name = provider.name.clone();
        let runtime = self.runtime.clone();

        // Release GIL during blocking call
        py.allow_threads(|| {
            let _guard = runtime.enter();
            runtime
                .block_on(engine.call(&to_uri, &from_uri, &provider_name))
                .map_err(|e| PyRuntimeError::new_err(format!("Call failed: {}", e)))
        })
    }

    /// Hangup a call
    ///
    /// Releases GIL during the blocking operation.
    ///
    /// Args:
    ///     call_id: Call ID to hangup
    fn hangup(&self, py: Python<'_>, call_id: &str) -> PyResult<()> {
        let engine = self.engine.lock().clone().ok_or_else(|| {
            PyRuntimeError::new_err("Runner not started")
        })?;

        let call_id = call_id.to_string();
        let runtime = self.runtime.clone();

        py.allow_threads(|| {
            let _guard = runtime.enter();
            runtime
                .block_on(engine.hangup(&call_id))
                .map_err(|e| PyRuntimeError::new_err(format!("Hangup failed: {}", e)))
        })
    }

    /// Answer an incoming call
    ///
    /// Sends 200 OK with SDP to accept the call. Only works for inbound calls
    /// that are in Ringing state. After answering, audio can be sent/received.
    ///
    /// Args:
    ///     call_id: Call ID to answer
    ///
    /// Example:
    ///     event = runner.next_event(timeout_ms=30000)
    ///     if event and event.is_incoming():
    ///         runner.answer(event.call_id)
    fn answer(&self, py: Python<'_>, call_id: &str) -> PyResult<()> {
        let engine = self.engine.lock().clone().ok_or_else(|| {
            PyRuntimeError::new_err("Runner not started")
        })?;

        // Bug #39: Release the GIL before acquiring Rust locks to avoid
        // deadlocks with other Python threads that may also hold the GIL
        // while waiting on Rust locks.
        let call_id = call_id.to_string();
        py.allow_threads(move || {
            engine
                .answer(&call_id)
                .map_err(|e| PyRuntimeError::new_err(format!("Answer failed: {}", e)))
        })
    }

    /// Reject an incoming call
    ///
    /// Sends an error response to reject the call. Only works for inbound calls.
    ///
    /// Common status codes:
    /// - 486: Busy Here
    /// - 603: Decline
    /// - 480: Temporarily Unavailable
    /// - 488: Not Acceptable Here
    ///
    /// Args:
    ///     call_id: Call ID to reject
    ///     status_code: SIP status code (default: 603 Decline)
    ///
    /// Example:
    ///     event = runner.next_event(timeout_ms=30000)
    ///     if event and event.is_incoming():
    ///         runner.reject(event.call_id, 486)  # Busy
    #[pyo3(signature = (call_id, status_code = 603))]
    fn reject(&self, py: Python<'_>, call_id: &str, status_code: u16) -> PyResult<()> {
        let engine = self.engine.lock().clone().ok_or_else(|| {
            PyRuntimeError::new_err("Runner not started")
        })?;

        // Bug #39: Release GIL to avoid deadlocks with other Python threads.
        let call_id = call_id.to_string();
        py.allow_threads(move || {
            engine
                .reject(&call_id, status_code)
                .map_err(|e| PyRuntimeError::new_err(format!("Reject failed: {}", e)))
        })
    }

    /// Send audio samples to a call
    ///
    /// Releases GIL during the blocking send operation for better concurrency.
    ///
    /// Args:
    ///     call_id: Call ID
    ///     samples: List of PCM i16 samples (8kHz mono)
    fn send_audio(&self, py: Python<'_>, call_id: &str, samples: Vec<i16>) -> PyResult<()> {
        let engine = self.engine.lock().clone().ok_or_else(|| {
            PyRuntimeError::new_err("Runner not started")
        })?;

        let session = engine.get_call(call_id).ok_or_else(|| {
            PyRuntimeError::new_err(format!("Call not found: {}", call_id))
        })?;

        let rtp = {
            let sess = session.lock();
            sess.rtp().cloned().ok_or_else(|| {
                PyRuntimeError::new_err("RTP not established for this call")
            })?
        };

        let runtime = self.runtime.clone();

        // Release GIL during blocking send - samples already copied from Python
        py.allow_threads(|| {
            let _guard = runtime.enter();
            runtime
                .block_on(rtp.send_audio(&samples))
                .map_err(|e| PyRuntimeError::new_err(format!("Send audio failed: {}", e)))
        })
    }

    /// Receive audio samples from a call
    ///
    /// Releases GIL during the blocking receive operation.
    ///
    /// Args:
    ///     call_id: Call ID
    ///     timeout_ms: Timeout in milliseconds
    ///
    /// Returns:
    ///     List of PCM i16 samples (8kHz mono), or None if timeout
    fn recv_audio(&self, py: Python<'_>, call_id: &str, timeout_ms: u64) -> PyResult<Option<Vec<i16>>> {
        let engine = self.engine.lock().clone().ok_or_else(|| {
            PyRuntimeError::new_err("Runner not started")
        })?;

        let session = engine.get_call(call_id).ok_or_else(|| {
            PyRuntimeError::new_err(format!("Call not found: {}", call_id))
        })?;

        let rtp = {
            let sess = session.lock();
            sess.rtp().cloned().ok_or_else(|| {
                PyRuntimeError::new_err("RTP not established for this call")
            })?
        };

        let timeout = Duration::from_millis(timeout_ms);
        let runtime = self.runtime.clone();

        // Release GIL during blocking recv
        py.allow_threads(|| {
            let _guard = runtime.enter();
            rtp.recv_audio_blocking(timeout)
                .map_err(|e| PyRuntimeError::new_err(format!("Recv audio failed: {}", e)))
        })
    }

    /// Send DTMF digits (auto-selects RFC 2833 or SIP INFO)
    ///
    /// **Automatic method selection based on remote SDP:**
    /// - If remote supports telephone-event -> RFC 2833 (in RTP stream)
    /// - Otherwise -> SIP INFO with application/dtmf-relay
    ///
    /// This provides the best compatibility with different endpoints.
    ///
    /// Args:
    ///     call_id: Call ID
    ///     digits: DTMF digits to send (0-9, *, #, A-D, w=500ms pause, W=1000ms pause)
    ///     duration_ms: Duration per digit in milliseconds (default 100)
    ///     inter_digit_ms: Delay between digits in milliseconds (default 100)
    ///
    /// Example:
    ///     # Send PIN followed by pound
    ///     runner.send_dtmf(call_id, "1234#")
    ///
    ///     # With pauses (w=500ms, W=1000ms)
    ///     runner.send_dtmf(call_id, "1w2w3w4")
    #[pyo3(signature = (call_id, digits, duration_ms = 100, inter_digit_ms = 100))]
    fn send_dtmf(
        &self,
        py: Python<'_>,
        call_id: &str,
        digits: &str,
        duration_ms: u32,
        inter_digit_ms: u64,
    ) -> PyResult<()> {
        let engine = self.engine.lock().clone().ok_or_else(|| {
            PyRuntimeError::new_err("Runner not started")
        })?;

        // Validate the digits (allow w/W for pauses)
        for c in digits.chars() {
            if !matches!(c, '0'..='9' | '*' | '#' | 'A'..='D' | 'a'..='d' | 'w' | 'W') {
                return Err(PyValueError::new_err(format!("Invalid DTMF digit: {}", c)));
            }
        }

        let call_id = call_id.to_string();
        let digits = digits.to_string();
        let runtime = self.runtime.clone();

        // Release GIL during blocking DTMF send
        py.allow_threads(|| {
            let _guard = runtime.enter();
            runtime
                .block_on(engine.send_dtmf_digits(&call_id, &digits, duration_ms, inter_digit_ms))
                .map_err(|e| PyRuntimeError::new_err(format!("DTMF failed: {}", e)))
        })
    }

    /// Receive DTMF digit (non-blocking)
    ///
    /// Checks for RFC 2833 DTMF in the RTP stream.
    /// SIP INFO DTMF arrives via next_event() as CallEvent with is_dtmf() == True.
    ///
    /// Args:
    ///     call_id: Call ID
    ///
    /// Returns:
    ///     Tuple of (digit, duration_ms) or None if no DTMF available
    ///
    /// Example:
    ///     dtmf = runner.recv_dtmf(call_id)
    ///     if dtmf:
    ///         digit, duration = dtmf
    ///         print(f"Received DTMF: {digit}")
    fn recv_dtmf(&self, py: Python<'_>, call_id: &str) -> PyResult<Option<(char, u32)>> {
        let engine = self.engine.lock().clone().ok_or_else(|| {
            PyRuntimeError::new_err("Runner not started")
        })?;

        // Bug #R6-5: Release GIL during DTMF check
        let call_id = call_id.to_string();
        py.allow_threads(|| engine.recv_dtmf(&call_id))
            .map_err(|e| PyRuntimeError::new_err(format!("recv_dtmf failed: {}", e)))
    }

    /// Receive DTMF digit with timeout (blocking)
    ///
    /// Waits for RFC 2833 DTMF in the RTP stream.
    /// Releases GIL during the blocking wait.
    /// SIP INFO DTMF arrives via next_event() as CallEvent with is_dtmf() == True.
    ///
    /// Args:
    ///     call_id: Call ID
    ///     timeout_ms: Timeout in milliseconds
    ///
    /// Returns:
    ///     Tuple of (digit, duration_ms) or None if timeout
    #[pyo3(signature = (call_id, timeout_ms = 5000))]
    fn recv_dtmf_blocking(
        &self,
        py: Python<'_>,
        call_id: &str,
        timeout_ms: u64,
    ) -> PyResult<Option<(char, u32)>> {
        let engine = self.engine.lock().clone().ok_or_else(|| {
            PyRuntimeError::new_err("Runner not started")
        })?;

        let call_id = call_id.to_string();
        let timeout = Duration::from_millis(timeout_ms);
        let runtime = self.runtime.clone();

        py.allow_threads(|| {
            let _guard = runtime.enter();
            engine
                .recv_dtmf_blocking(&call_id, timeout)
                .map_err(|e| PyRuntimeError::new_err(format!("recv_dtmf_blocking failed: {}", e)))
        })
    }

    /// Get the effective DTMF mode for a call
    ///
    /// Returns the mode that will be used for sending/receiving DTMF.
    /// - DtmfMode.Rfc2833 if remote supports telephone-event
    /// - DtmfMode.Info otherwise
    ///
    /// Args:
    ///     call_id: Call ID
    ///
    /// Returns:
    ///     DtmfMode enum value
    fn get_dtmf_mode(&self, py: Python<'_>, call_id: &str) -> PyResult<PyDtmfMode> {
        let engine = self.engine.lock().clone().ok_or_else(|| {
            PyRuntimeError::new_err("Runner not started")
        })?;

        // Bug #39: Release GIL to avoid deadlocks with other Python threads.
        let call_id = call_id.to_string();
        py.allow_threads(move || {
            engine
                .get_dtmf_mode(&call_id)
                .map(|m| m.into())
                .map_err(|e| PyRuntimeError::new_err(format!("get_dtmf_mode failed: {}", e)))
        })
    }

    /// Set the DTMF mode for a call
    ///
    /// Override the automatic DTMF mode selection.
    ///
    /// Args:
    ///     call_id: Call ID
    ///     mode: DtmfMode.Auto, DtmfMode.Rfc2833, or DtmfMode.Info
    fn set_dtmf_mode(&self, py: Python<'_>, call_id: &str, mode: PyDtmfMode) -> PyResult<()> {
        let engine = self.engine.lock().clone().ok_or_else(|| {
            PyRuntimeError::new_err("Runner not started")
        })?;

        // Bug #39: Release GIL to avoid deadlocks with other Python threads.
        let call_id = call_id.to_string();
        let mode: DtmfMode = mode.into();
        py.allow_threads(move || {
            engine
                .set_dtmf_mode(&call_id, mode)
                .map_err(|e| PyRuntimeError::new_err(format!("set_dtmf_mode failed: {}", e)))
        })
    }

    /// Put call on hold
    ///
    /// Sends a re-INVITE with sendonly SDP to put the call on hold.
    /// Releases GIL during the blocking operation.
    ///
    /// Args:
    ///     call_id: Call ID to hold
    fn hold(&self, py: Python<'_>, call_id: &str) -> PyResult<()> {
        let engine = self.engine.lock().clone().ok_or_else(|| {
            PyRuntimeError::new_err("Runner not started")
        })?;

        let call_id = call_id.to_string();
        let runtime = self.runtime.clone();

        py.allow_threads(|| {
            let _guard = runtime.enter();
            runtime
                .block_on(engine.hold(&call_id))
                .map_err(|e| PyRuntimeError::new_err(format!("Hold failed: {}", e)))
        })
    }

    /// Resume call from hold
    ///
    /// Sends a re-INVITE with sendrecv SDP to resume the call.
    /// Releases GIL during the blocking operation.
    ///
    /// Args:
    ///     call_id: Call ID to resume
    fn unhold(&self, py: Python<'_>, call_id: &str) -> PyResult<()> {
        let engine = self.engine.lock().clone().ok_or_else(|| {
            PyRuntimeError::new_err("Runner not started")
        })?;

        let call_id = call_id.to_string();
        let runtime = self.runtime.clone();

        py.allow_threads(|| {
            let _guard = runtime.enter();
            runtime
                .block_on(engine.unhold(&call_id))
                .map_err(|e| PyRuntimeError::new_err(format!("Unhold failed: {}", e)))
        })
    }

    /// Send re-INVITE with custom SDP
    ///
    /// Uses rsipstack's dialog.reinvite() for session modification.
    /// Releases GIL during the blocking operation.
    ///
    /// Args:
    ///     call_id: Call ID
    ///     sdp: New SDP offer (optional, uses current if None)
    #[pyo3(signature = (call_id, sdp = None))]
    fn reinvite(&self, py: Python<'_>, call_id: &str, sdp: Option<&str>) -> PyResult<()> {
        let engine = self.engine.lock().clone().ok_or_else(|| {
            PyRuntimeError::new_err("Runner not started")
        })?;

        let call_id = call_id.to_string();
        let sdp = sdp.map(|s| s.to_string());
        let runtime = self.runtime.clone();

        py.allow_threads(|| {
            let _guard = runtime.enter();
            runtime
                .block_on(engine.send_reinvite(&call_id, sdp.as_deref()))
                .map_err(|e| PyRuntimeError::new_err(format!("Re-INVITE failed: {}", e)))
        })
    }

    /// Get the next event (blocking)
    ///
    /// Releases GIL during the blocking wait to allow other Python threads.
    /// This is the main event loop method - optimized for low latency.
    ///
    /// Args:
    ///     timeout_ms: Timeout in milliseconds
    ///
    /// Returns:
    ///     CallEvent or None if timeout
    fn next_event(&self, py: Python<'_>, timeout_ms: u64) -> PyResult<Option<PyCallEvent>> {
        // Bug #40 fix: Take the receiver out of the mutex, use it, then put it back.
        // This preserves the receiver's position in the broadcast buffer across calls,
        // preventing event loss between consecutive next_event() invocations.
        //
        // Bug R14-3 fix: Distinguish "not started" from "temporarily borrowed by another
        // thread". If the runner is running but the receiver is None, another thread has
        // it — return None instead of an error.
        let mut rx = match self.event_rx.lock().take() {
            Some(rx) => rx,
            None => {
                if *self.running.lock() {
                    // Receiver temporarily borrowed by a concurrent next_event() call
                    tracing::debug!("Event receiver temporarily borrowed by another thread");
                    return Ok(None);
                } else {
                    return Err(PyRuntimeError::new_err("Runner not started"));
                }
            }
        };

        let runtime = self.runtime.clone();
        let timeout = Duration::from_millis(timeout_ms);

        // Release GIL during blocking wait - critical for multi-threaded Python
        let (result, rx) = py.allow_threads(move || {
            let _guard = runtime.enter();
            let result = runtime.block_on(async {
                tokio::time::timeout(timeout, rx.recv()).await
            });
            (result, rx)
        });

        // Put the receiver back for next call
        *self.event_rx.lock() = Some(rx);

        match result {
            Ok(Ok(event)) => Ok(Some(event.into())),
            Ok(Err(broadcast::error::RecvError::Lagged(n))) => {
                tracing::warn!("Event receiver lagged, skipped {} events", n);
                Ok(None)
            }
            Ok(Err(_)) => Ok(None), // Channel closed
            Err(_) => Ok(None),     // Timeout
        }
    }

    // Note: Early media events (ringing, early_media) and answer events
    // are delivered via next_event(). Use is_ringing(), is_early_media(),
    // and is_answered() to check event types.

    /// Get all active call IDs
    fn active_calls(&self) -> PyResult<Vec<String>> {
        let engine = self.engine.lock().clone().ok_or_else(|| {
            PyRuntimeError::new_err("Runner not started")
        })?;

        Ok(engine.active_calls())
    }

    /// Get the state of a call
    fn get_call_state(&self, call_id: &str) -> PyResult<Option<PyCallState>> {
        let engine = self.engine.lock().clone().ok_or_else(|| {
            PyRuntimeError::new_err("Runner not started")
        })?;

        Ok(engine.get_call(call_id).map(|s| s.lock().state.into()))
    }

    /// Get list of provider names
    #[getter]
    fn provider_names(&self) -> Vec<String> {
        self.config.providers.iter().map(|p| p.name.clone()).collect()
    }

    /// Get number of providers
    #[getter]
    fn provider_count(&self) -> usize {
        self.config.providers.len()
    }

    /// Check if using TLS
    #[getter]
    fn is_tls(&self) -> bool {
        self.config.is_tls()
    }

    /// Get blocked prefixes
    #[getter]
    fn blocked_prefixes(&self) -> Vec<String> {
        self.config.routing.blocked_prefixes.clone()
    }

    /// Cancel an outbound call before it's answered
    ///
    /// Sends SIP CANCEL for calls in Ringing or EarlyMedia state.
    /// For active calls, use hangup() instead.
    ///
    /// Args:
    ///     call_id: Call ID to cancel
    fn cancel(&self, py: Python<'_>, call_id: &str) -> PyResult<()> {
        let engine = self.engine.lock().clone().ok_or_else(|| {
            PyRuntimeError::new_err("Runner not started")
        })?;

        let call_id = call_id.to_string();
        let runtime = self.runtime.clone();

        py.allow_threads(|| {
            let _guard = runtime.enter();
            runtime
                .block_on(engine.cancel(&call_id))
                .map_err(|e| PyRuntimeError::new_err(format!("Cancel failed: {}", e)))
        })
    }

    /// Get current registration state
    ///
    /// Returns:
    ///     str: "registered", "unregistered", or "no_providers"
    fn registration_state(&self) -> PyResult<String> {
        let engine = self.engine.lock().clone().ok_or_else(|| {
            PyRuntimeError::new_err("Runner not started")
        })?;

        Ok(engine.registration_state_str())
    }

    fn __repr__(&self) -> String {
        let running = *self.running.lock();
        let providers: Vec<&str> = self.config.providers.iter().map(|p| p.name.as_str()).collect();
        format!(
            "SipRunner(providers={:?}, running={})",
            providers, running
        )
    }
}

impl PySipRunner {
    /// Internal stop without GIL release — used by Drop where no Python token is available.
    /// During interpreter shutdown the GIL state is unpredictable, so we do direct blocking.
    fn stop_inner(&self) {
        if !*self.running.lock() {
            return;
        }

        let _guard = self.runtime.enter();

        if let Some(ref engine) = *self.engine.lock() {
            let calls = engine.active_calls();
            for call_id in calls {
                let _ = self.runtime.block_on(engine.hangup(&call_id));
            }
            engine.stop();
        }

        *self.engine.lock() = None;
        *self.event_rx.lock() = None;
        *self.running.lock() = false;
    }
}

impl Drop for PySipRunner {
    fn drop(&mut self) {
        // Stop engine on drop. Wrap in catch_unwind to avoid panicking
        // during Python interpreter shutdown when the runtime may already
        // be partially torn down.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.stop_inner();
        }));
    }
}
