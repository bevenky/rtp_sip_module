//! Python config bindings
//!
//! Provides a unified Config class that can be loaded from TOML.
//!
//! # TOML Format
//!
//! ```toml
//! # Mode: "rtp_only" or "sip"
//! mode = "rtp_only"
//!
//! [rtp]
//! local_ip = "0.0.0.0"
//! port_start = 16384
//! port_end = 32768
//! codec = "PCMU"  # PCMU or PCMA
//!
//! [sip]
//! local_ip = "0.0.0.0"
//! local_port = 5060
//! external_ip = "auto"  # optional, for NAT
//!
//! [[trunks]]
//! name = "provider1"
//! host = "sip.provider.com"
//! port = 5060
//! username = "user"
//! password = "pass"
//! ```

use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::Path;


/// Operation mode for pyswitch
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// RTP-only mode - external SIP signaling (WebSocket, etc.)
    #[default]
    RtpOnly,
    /// Full SIP mode - handles both SIP signaling and RTP
    Sip,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mode::RtpOnly => write!(f, "rtp_only"),
            Mode::Sip => write!(f, "sip"),
        }
    }
}

/// RTP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtpConfigToml {
    /// Local IP to bind RTP sockets
    #[serde(default = "default_local_ip")]
    pub local_ip: String,
    /// Start of RTP port range
    #[serde(default = "default_rtp_port_start")]
    pub port_start: u16,
    /// End of RTP port range
    #[serde(default = "default_rtp_port_end")]
    pub port_end: u16,
    /// Default codec (PCMU or PCMA)
    #[serde(default = "default_codec")]
    pub codec: String,
}

impl Default for RtpConfigToml {
    fn default() -> Self {
        Self {
            local_ip: default_local_ip(),
            port_start: default_rtp_port_start(),
            port_end: default_rtp_port_end(),
            codec: default_codec(),
        }
    }
}

/// SIP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SipConfigToml {
    /// Local IP for SIP
    #[serde(default = "default_local_ip")]
    pub local_ip: String,
    /// Local SIP port
    #[serde(default = "default_sip_port")]
    pub local_port: u16,
    /// External IP for NAT traversal (optional)
    pub external_ip: Option<String>,
    /// Enable debug logging
    #[serde(default)]
    pub debug: bool,
}

impl Default for SipConfigToml {
    fn default() -> Self {
        Self {
            local_ip: default_local_ip(),
            local_port: default_sip_port(),
            external_ip: None,
            debug: false,
        }
    }
}

/// Trunk configuration for SIP mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrunkConfigToml {
    /// Trunk name (used in dial strings)
    pub name: String,
    /// Gateway host
    pub host: String,
    /// Gateway port
    #[serde(default = "default_sip_port")]
    pub port: u16,
    /// Auth username
    pub username: Option<String>,
    /// Auth password
    pub password: Option<String>,
    /// Caller ID name
    pub caller_id_name: Option<String>,
    /// Caller ID number
    pub caller_id_number: Option<String>,
    /// Transport: udp, tcp, tls
    #[serde(default = "default_transport")]
    pub transport: String,
    /// Codec preferences
    #[serde(default = "default_codecs")]
    pub codecs: String,
}

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigToml {
    /// Operation mode
    #[serde(default)]
    pub mode: Mode,
    /// RTP configuration
    #[serde(default)]
    pub rtp: RtpConfigToml,
    /// SIP configuration (for sip mode)
    #[serde(default)]
    pub sip: SipConfigToml,
    /// Trunk configurations (for sip mode)
    #[serde(default)]
    pub trunks: Vec<TrunkConfigToml>,
}

// Default value functions
fn default_local_ip() -> String { "0.0.0.0".to_string() }
fn default_rtp_port_start() -> u16 { 16384 }
fn default_rtp_port_end() -> u16 { 32768 }
fn default_sip_port() -> u16 { 5060 }
fn default_codec() -> String { "PCMU".to_string() }
fn default_transport() -> String { "udp".to_string() }
fn default_codecs() -> String { "PCMU,PCMA".to_string() }

impl ConfigToml {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;
        Self::from_toml(&content)
    }

    /// Parse configuration from a TOML string
    pub fn from_toml(toml_str: &str) -> Result<Self, String> {
        toml::from_str(toml_str)
            .map_err(|e| format!("Failed to parse TOML: {}", e))
    }

    /// Serialize configuration to TOML string
    pub fn to_toml(&self) -> Result<String, String> {
        toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))
    }
}

/// Python Config class
///
/// Unified configuration for pyswitch that can be loaded from TOML.
///
/// # Example
/// ```python
/// from pyswitch import Config
///
/// # Load from file
/// config = Config.from_file("config.toml")
///
/// # Or create programmatically
/// config = Config(mode="rtp_only")
/// config.rtp_local_ip = "0.0.0.0"
/// config.rtp_port_start = 16384
/// ```
#[pyclass(name = "Config")]
#[derive(Clone)]
pub struct PyConfig {
    inner: ConfigToml,
}

#[pymethods]
impl PyConfig {
    /// Create a new configuration
    ///
    /// # Arguments
    /// * `mode` - Operation mode: "rtp_only" or "sip" (default: "rtp_only")
    #[new]
    #[pyo3(signature = (mode = "rtp_only"))]
    fn new(mode: &str) -> PyResult<Self> {
        let mode = match mode {
            "rtp_only" => Mode::RtpOnly,
            "sip" => Mode::Sip,
            _ => return Err(pyo3::exceptions::PyValueError::new_err(
                "mode must be 'rtp_only' or 'sip'"
            )),
        };
        Ok(Self {
            inner: ConfigToml {
                mode,
                ..Default::default()
            },
        })
    }

    /// Load configuration from a TOML file
    #[staticmethod]
    fn from_file(path: &str) -> PyResult<Self> {
        let inner = ConfigToml::from_file(path)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
        Ok(Self { inner })
    }

    /// Load configuration from a TOML string
    #[staticmethod]
    fn from_toml(toml_str: &str) -> PyResult<Self> {
        let inner = ConfigToml::from_toml(toml_str)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
        Ok(Self { inner })
    }

    /// Serialize configuration to TOML string
    fn to_toml(&self) -> PyResult<String> {
        self.inner.to_toml()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
    }

    /// Save configuration to a file
    fn save(&self, path: &str) -> PyResult<()> {
        let toml_str = self.to_toml()?;
        std::fs::write(path, toml_str)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))
    }

    // Mode
    #[getter]
    fn mode(&self) -> String {
        self.inner.mode.to_string()
    }

    #[setter]
    fn set_mode(&mut self, mode: &str) -> PyResult<()> {
        self.inner.mode = match mode {
            "rtp_only" => Mode::RtpOnly,
            "sip" => Mode::Sip,
            _ => return Err(pyo3::exceptions::PyValueError::new_err(
                "mode must be 'rtp_only' or 'sip'"
            )),
        };
        Ok(())
    }

    // RTP config
    #[getter]
    fn rtp_local_ip(&self) -> &str {
        &self.inner.rtp.local_ip
    }

    #[setter]
    fn set_rtp_local_ip(&mut self, ip: String) {
        self.inner.rtp.local_ip = ip;
    }

    #[getter]
    fn rtp_port_start(&self) -> u16 {
        self.inner.rtp.port_start
    }

    #[setter]
    fn set_rtp_port_start(&mut self, port: u16) {
        self.inner.rtp.port_start = port;
    }

    #[getter]
    fn rtp_port_end(&self) -> u16 {
        self.inner.rtp.port_end
    }

    #[setter]
    fn set_rtp_port_end(&mut self, port: u16) {
        self.inner.rtp.port_end = port;
    }

    #[getter]
    fn rtp_codec(&self) -> &str {
        &self.inner.rtp.codec
    }

    #[setter]
    fn set_rtp_codec(&mut self, codec: String) {
        self.inner.rtp.codec = codec;
    }

    // SIP config
    #[getter]
    fn sip_local_ip(&self) -> &str {
        &self.inner.sip.local_ip
    }

    #[setter]
    fn set_sip_local_ip(&mut self, ip: String) {
        self.inner.sip.local_ip = ip;
    }

    #[getter]
    fn sip_local_port(&self) -> u16 {
        self.inner.sip.local_port
    }

    #[setter]
    fn set_sip_local_port(&mut self, port: u16) {
        self.inner.sip.local_port = port;
    }

    #[getter]
    fn sip_external_ip(&self) -> Option<&str> {
        self.inner.sip.external_ip.as_deref()
    }

    #[setter]
    fn set_sip_external_ip(&mut self, ip: Option<String>) {
        self.inner.sip.external_ip = ip;
    }

    #[getter]
    fn sip_debug(&self) -> bool {
        self.inner.sip.debug
    }

    #[setter]
    fn set_sip_debug(&mut self, debug: bool) {
        self.inner.sip.debug = debug;
    }

    fn __repr__(&self) -> String {
        format!(
            "Config(mode='{}', rtp_ports={}-{}, sip_port={})",
            self.inner.mode,
            self.inner.rtp.port_start,
            self.inner.rtp.port_end,
            self.inner.sip.local_port
        )
    }
}
