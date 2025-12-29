//! Python bindings for SIP types
//!
//! Uses SipTransport with media bugs for audio capture/injection,
//! which works correctly with mod_sofia's internal RTP management.
//!
//! # Thread Safety
//!
//! The inbound handler uses a lock-free pattern to avoid deadlocks:
//! 1. Handler is stored in a sync RwLock
//! 2. When callback fires, we clone the Py handle while holding lock
//! 3. Lock is dropped before acquiring GIL
//! 4. This prevents GIL + Lock ordering deadlocks

use std::sync::Arc;

use parking_lot::RwLock;
use pyo3::prelude::*;
use pyo3::types::PyFunction;
use crate::core::sip::{PyswitchConfig, SipConfig, TrunkConfig, SipTransport};

use crate::call::PyCall;
use crate::error::to_py_err;

/// Complete pyswitch configuration
///
/// Can be loaded from TOML or created programmatically.
///
/// TOML format:
/// ```toml
/// [sip]
/// local_ip = "0.0.0.0"
/// local_port = 5060
///
/// [[trunks]]
/// name = "twilio"
/// host = "sip.twilio.com"
/// username = "AC123..."
/// password = "secret"
/// ```
#[pyclass(name = "PyswitchConfig")]
#[derive(Clone)]
pub struct PyPyswitchConfig {
    pub(crate) inner: PyswitchConfig,
}

#[pymethods]
impl PyPyswitchConfig {
    /// Create a new configuration with defaults
    #[new]
    fn new() -> Self {
        Self {
            inner: PyswitchConfig::default(),
        }
    }

    /// Load configuration from a TOML file
    #[staticmethod]
    fn from_file(path: &str) -> PyResult<Self> {
        let inner = PyswitchConfig::from_file(path).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Load configuration from a TOML string
    #[staticmethod]
    fn from_toml(toml_str: &str) -> PyResult<Self> {
        let inner = PyswitchConfig::from_toml(toml_str).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Get SIP configuration
    #[getter]
    fn sip(&self) -> PySipConfig {
        PySipConfig {
            inner: self.inner.sip.clone(),
        }
    }

    /// Get list of trunks
    #[getter]
    fn trunks(&self) -> Vec<PyTrunkConfig> {
        self.inner
            .trunks
            .iter()
            .map(|t| PyTrunkConfig { inner: t.clone() })
            .collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "PyswitchConfig(sip={}:{}, trunks={})",
            self.inner.sip.local_ip,
            self.inner.sip.local_port,
            self.inner.trunks.len()
        )
    }
}

/// SIP stack configuration
#[pyclass(name = "SipConfig")]
#[derive(Clone)]
pub struct PySipConfig {
    pub(crate) inner: SipConfig,
}

#[pymethods]
impl PySipConfig {
    /// Create a new SIP configuration
    ///
    /// # Arguments
    /// * `local_ip` - Local IP address (default: "0.0.0.0")
    /// * `local_port` - Local SIP port (default: 5060)
    /// * `external_ip` - External IP for NAT (optional)
    /// * `debug` - Enable debug logging (default: false)
    #[new]
    #[pyo3(signature = (local_ip = "0.0.0.0", local_port = 5060, external_ip = None, debug = false))]
    fn new(
        local_ip: &str,
        local_port: u16,
        external_ip: Option<&str>,
        debug: bool,
    ) -> Self {
        Self {
            inner: SipConfig {
                local_ip: local_ip.to_string(),
                local_port,
                external_ip: external_ip.map(|s| s.to_string()),
                debug,
                rtp_port_start: 16384,
                rtp_port_end: 32768,
            },
        }
    }

    #[getter]
    fn local_ip(&self) -> &str {
        &self.inner.local_ip
    }

    #[getter]
    fn local_port(&self) -> u16 {
        self.inner.local_port
    }

    /// User agent string (hardcoded, not configurable)
    #[getter]
    fn user_agent(&self) -> String {
        SipConfig::user_agent()
    }

    #[getter]
    fn external_ip(&self) -> Option<&str> {
        self.inner.external_ip.as_deref()
    }

    #[getter]
    fn debug(&self) -> bool {
        self.inner.debug
    }

    fn __repr__(&self) -> String {
        format!(
            "SipConfig(local_ip='{}', local_port={})",
            self.inner.local_ip, self.inner.local_port
        )
    }
}

/// SIP trunk configuration
///
/// Defines a connection to a SIP carrier/provider for placing calls.
#[pyclass(name = "TrunkConfig")]
#[derive(Clone)]
pub struct PyTrunkConfig {
    pub(crate) inner: TrunkConfig,
}

#[pymethods]
impl PyTrunkConfig {
    /// Create a new trunk configuration
    ///
    /// # Arguments
    /// * `name` - Trunk name (used in dial strings)
    /// * `host` - Gateway host (IP or hostname)
    /// * `port` - Gateway port (default: 5060)
    /// * `username` - Auth username (optional)
    /// * `password` - Auth password (optional)
    /// * `caller_id_name` - Caller ID name (optional)
    /// * `caller_id_number` - Caller ID number (optional)
    /// * `transport` - Transport protocol: udp, tcp, tls (default: udp)
    /// * `codecs` - Codec preference (default: "PCMU,PCMA")
    #[new]
    #[pyo3(signature = (name, host, port = 5060, username = None, password = None, caller_id_name = None, caller_id_number = None, transport = "udp", codecs = "PCMU,PCMA"))]
    fn new(
        name: &str,
        host: &str,
        port: u16,
        username: Option<&str>,
        password: Option<&str>,
        caller_id_name: Option<&str>,
        caller_id_number: Option<&str>,
        transport: &str,
        codecs: &str,
    ) -> Self {
        Self {
            inner: TrunkConfig {
                name: name.to_string(),
                host: host.to_string(),
                port,
                username: username.map(|s| s.to_string()),
                password: password.map(|s| s.to_string()),
                outbound_proxy: None,
                caller_id_name: caller_id_name.map(|s| s.to_string()),
                caller_id_number: caller_id_number.map(|s| s.to_string()),
                transport: transport.to_string(),
                codecs: codecs.to_string(),
            },
        }
    }

    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }

    #[getter]
    fn host(&self) -> &str {
        &self.inner.host
    }

    #[getter]
    fn port(&self) -> u16 {
        self.inner.port
    }

    #[getter]
    fn username(&self) -> Option<&str> {
        self.inner.username.as_deref()
    }

    #[getter]
    fn caller_id_name(&self) -> Option<&str> {
        self.inner.caller_id_name.as_deref()
    }

    #[getter]
    fn caller_id_number(&self) -> Option<&str> {
        self.inner.caller_id_number.as_deref()
    }

    #[getter]
    fn transport(&self) -> &str {
        &self.inner.transport
    }

    #[getter]
    fn codecs(&self) -> &str {
        &self.inner.codecs
    }

    fn __repr__(&self) -> String {
        format!(
            "TrunkConfig(name='{}', host='{}:{}')",
            self.inner.name, self.inner.host, self.inner.port
        )
    }
}

/// Thread-safe storage for Python handler
///
/// Uses RwLock for fast reads and cloning the Py handle to avoid
/// holding the lock while acquiring GIL.
type HandlerStorage = Arc<RwLock<Option<PyObject>>>;

/// SIP transport for managing trunks and calls
///
/// Uses embedded FreeSWITCH with mod_sofia and media bugs
/// for audio capture/injection.
#[pyclass(name = "SIP")]
pub struct PySip {
    inner: Arc<SipTransport>,
    /// Stored inbound handler for Python callback (lock-free access pattern)
    inbound_handler: HandlerStorage,
}

#[pymethods]
impl PySip {
    /// Create a new SIP transport from configuration
    ///
    /// # Arguments
    /// * `config` - Either a SipConfig or a PyswitchConfig
    #[new]
    fn new(config: &Bound<'_, PyAny>) -> PyResult<Self> {
        // Try to extract as PySipConfig first
        if let Ok(sip_config) = config.extract::<PySipConfig>() {
            let inner = SipTransport::new(sip_config.inner).map_err(to_py_err)?;
            return Ok(Self {
                inner: Arc::new(inner),
                inbound_handler: Arc::new(RwLock::new(None)),
            });
        }

        // Try to extract as PyPyswitchConfig
        if let Ok(pyswitch_config) = config.extract::<PyPyswitchConfig>() {
            let inner = SipTransport::new(pyswitch_config.inner.sip).map_err(to_py_err)?;
            let stack = Self {
                inner: Arc::new(inner),
                inbound_handler: Arc::new(RwLock::new(None)),
            };
            // Note: Trunks would need to be added separately
            return Ok(stack);
        }

        Err(pyo3::exceptions::PyTypeError::new_err(
            "config must be a SipConfig or PyswitchConfig",
        ))
    }

    /// Create a SIP transport from a TOML config file
    #[staticmethod]
    fn from_config_file<'py>(py: Python<'py>, path: &str) -> PyResult<Bound<'py, PyAny>> {
        let path = path.to_string();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let config = PyswitchConfig::from_file(&path).map_err(to_py_err)?;
            let inner = SipTransport::new(config.sip).map_err(to_py_err)?;
            let stack = PySip {
                inner: Arc::new(inner),
                inbound_handler: Arc::new(RwLock::new(None)),
            };

            // Add trunks from config
            for trunk in config.trunks {
                stack.inner.add_trunk(trunk).await.map_err(to_py_err)?;
            }

            Ok(stack)
        })
    }

    /// Start the SIP transport
    fn start<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.start().await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Stop the SIP transport
    fn stop<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.stop().await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Add a SIP trunk
    fn add_trunk<'py>(&self, py: Python<'py>, trunk: PyTrunkConfig) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.add_trunk(trunk.inner).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Remove a SIP trunk
    fn remove_trunk<'py>(&self, py: Python<'py>, name: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.remove_trunk(&name).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Dial an outbound call
    ///
    /// # Arguments
    /// * `destination` - Phone number or SIP URI
    /// * `trunk` - Trunk name to use
    /// * `timeout_sec` - Call timeout in seconds (default: 60)
    /// * `caller_id_name` - Override caller ID name (optional)
    /// * `caller_id_number` - Override caller ID number (optional)
    ///
    /// # Returns
    /// Call object representing the active call
    #[pyo3(signature = (destination, trunk, timeout_sec = None, caller_id_name = None, caller_id_number = None))]
    fn dial<'py>(
        &self,
        py: Python<'py>,
        destination: String,
        trunk: String,
        timeout_sec: Option<u32>,
        caller_id_name: Option<String>,
        caller_id_number: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let session = inner
                .dial(
                    &destination,
                    &trunk,
                    timeout_sec,
                    caller_id_name.as_deref(),
                    caller_id_number.as_deref(),
                )
                .await
                .map_err(to_py_err)?;
            Ok(PyCall::new(session))
        })
    }

    /// Handle an inbound call by UUID
    ///
    /// Returns a Call object for the session.
    fn handle_inbound<'py>(&self, py: Python<'py>, uuid: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let session = inner
                .handle_inbound_call(&uuid)
                .await
                .map_err(to_py_err)?;
            Ok(PyCall::new(session))
        })
    }

    /// Set handler for inbound calls
    ///
    /// The handler is called for each incoming call with a Call object.
    /// The handler should be an async function that handles the call.
    ///
    /// # Example
    /// ```python
    /// async def on_call(call):
    ///     await call.answer()
    ///     while call.is_active:
    ///         frame = await call.recv_audio()
    ///         # process audio...
    ///     await call.hangup()
    ///
    /// sip.set_inbound_handler(on_call)
    /// ```
    fn set_inbound_handler(&self, py: Python<'_>, handler: Py<PyFunction>) -> PyResult<()> {
        // Store the handler as PyObject with write lock
        {
            let mut guard = self.inbound_handler.write();
            *guard = Some(handler.into_py(py));
        }

        // TODO: Hook into FreeSWITCH event system to receive inbound calls
        // For now, the user must poll for inbound calls or use handle_inbound()

        tracing::info!("Inbound handler registered (note: automatic dispatch not yet implemented)");
        Ok(())
    }

    /// Get a session by UUID
    fn get_session<'py>(&self, py: Python<'py>, uuid: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            match inner.get_session(&uuid).await {
                Some(session) => Ok(Some(PyCall::new(session))),
                None => Ok(None),
            }
        })
    }

    /// List active session UUIDs
    fn list_sessions<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sessions = inner.list_sessions().await;
            Ok(sessions)
        })
    }

    /// Check if transport is running
    #[getter]
    fn is_running(&self) -> bool {
        self.inner.is_running()
    }

    fn __repr__(&self) -> String {
        format!("SIP(running={})", self.inner.is_running())
    }
}

