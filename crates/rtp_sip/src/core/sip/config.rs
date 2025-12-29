//! SIP configuration types
//!
//! Configuration for SIP stack and trunk registration.
//! Supports loading from TOML files.

use serde::{Deserialize, Serialize};

use crate::core::error::{Error, Result};

/// Complete rtp_sip configuration
///
/// Can be loaded from TOML:
/// ```toml
/// [sip]
/// local_ip = "0.0.0.0"
/// local_port = 5060
///
/// [[trunks]]
/// name = "twilio"
/// host = "sip.twilio.com"
/// username = "AC123..."
/// password = "auth_token"
///
/// [[trunks]]
/// name = "provider"
/// host = "sip.provider.com"
/// port = 5061
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PyswitchConfig {
    /// SIP stack configuration
    #[serde(default)]
    pub sip: SipConfig,

    /// SIP trunks (carriers/providers)
    #[serde(default)]
    pub trunks: Vec<TrunkConfig>,
}

impl PyswitchConfig {
    /// Load configuration from TOML string
    pub fn from_toml(toml_str: &str) -> Result<Self> {
        toml::from_str(toml_str).map_err(|e| Error::Config(format!("Invalid TOML: {}", e)))
    }

    /// Load configuration from TOML file
    pub fn from_file(path: &str) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).map_err(|e| Error::Config(format!("Failed to read {}: {}", path, e)))?;
        Self::from_toml(&content)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        self.sip.validate()?;
        for trunk in &self.trunks {
            trunk.validate()?;
        }
        Ok(())
    }
}

/// SIP stack configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SipConfig {
    /// Local IP address (default: "0.0.0.0")
    #[serde(default = "default_local_ip")]
    pub local_ip: String,

    /// Local SIP port (default: 5060)
    #[serde(default = "default_sip_port")]
    pub local_port: u16,

    /// Enable SIP debug logging
    #[serde(default)]
    pub debug: bool,

    /// External IP for NAT traversal (optional)
    /// If set, this IP will be used in SDP for RTP
    #[serde(default)]
    pub external_ip: Option<String>,

    /// RTP port range start (default: 16384)
    #[serde(default = "default_rtp_port_start")]
    pub rtp_port_start: u16,

    /// RTP port range end (default: 32768)
    #[serde(default = "default_rtp_port_end")]
    pub rtp_port_end: u16,
}

fn default_local_ip() -> String {
    "0.0.0.0".to_string()
}

fn default_sip_port() -> u16 {
    5060
}

fn default_rtp_port_start() -> u16 {
    16384
}

fn default_rtp_port_end() -> u16 {
    32768
}

impl Default for SipConfig {
    fn default() -> Self {
        Self {
            local_ip: default_local_ip(),
            local_port: default_sip_port(),
            debug: false,
            external_ip: None,
            rtp_port_start: default_rtp_port_start(),
            rtp_port_end: default_rtp_port_end(),
        }
    }
}

impl SipConfig {
    /// Get the user agent string (hardcoded, not configurable)
    pub fn user_agent() -> String {
        format!("plivo_rtp_sip/{}", env!("CARGO_PKG_VERSION"))
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.local_port = port;
        self
    }

    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.local_ip = ip.into();
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.local_port == 0 {
            return Err(Error::Config("local_port cannot be 0".to_string()));
        }
        if self.rtp_port_start >= self.rtp_port_end {
            return Err(Error::Config(
                "rtp_port_start must be less than rtp_port_end".to_string(),
            ));
        }
        Ok(())
    }
}

/// SIP trunk configuration for connecting to carriers/providers
///
/// Trunks define outbound gateways for placing calls.
/// No registration support - pyswitch is for outbound-initiated calls only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrunkConfig {
    /// Trunk name (used in dial strings)
    pub name: String,

    /// Gateway host (IP or hostname)
    pub host: String,

    /// Gateway port (default: 5060)
    #[serde(default = "default_sip_port")]
    pub port: u16,

    /// Username for authentication (optional)
    #[serde(default)]
    pub username: Option<String>,

    /// Password for authentication (optional)
    #[serde(default)]
    pub password: Option<String>,

    /// Outbound proxy (optional, for routing through a proxy)
    #[serde(default)]
    pub outbound_proxy: Option<String>,

    /// Default caller ID name for this trunk
    #[serde(default)]
    pub caller_id_name: Option<String>,

    /// Default caller ID number for this trunk
    #[serde(default)]
    pub caller_id_number: Option<String>,

    /// Transport protocol (udp, tcp, tls)
    #[serde(default = "default_transport")]
    pub transport: String,

    /// Codec preference (comma-separated, e.g., "PCMU,PCMA")
    #[serde(default = "default_codecs")]
    pub codecs: String,
}

fn default_transport() -> String {
    "udp".to_string()
}

fn default_codecs() -> String {
    "PCMU,PCMA".to_string()
}

impl TrunkConfig {
    pub fn new(name: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port: 5060,
            username: None,
            password: None,
            outbound_proxy: None,
            caller_id_name: None,
            caller_id_number: None,
            transport: default_transport(),
            codecs: default_codecs(),
        }
    }

    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    pub fn with_caller_id(mut self, name: impl Into<String>, number: impl Into<String>) -> Self {
        self.caller_id_name = Some(name.into());
        self.caller_id_number = Some(number.into());
        self
    }

    /// Build libfs dial string for this trunk
    ///
    /// Uses direct SIP URI format instead of gateway to avoid needing
    /// pre-configured gateways in FreeSWITCH XML.
    ///
    /// Format: "sofia/external/sip:destination@host:port"
    /// With auth: "sofia/external/sip:destination@host:port;fs_path=sip:username@host:port"
    pub fn dial_string(&self, destination: &str) -> String {
        // Use the external profile with direct SIP URI
        // This doesn't require a pre-configured gateway
        format!(
            "sofia/external/sip:{}@{}:{}",
            destination,
            self.host,
            self.port
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(Error::Config("trunk name cannot be empty".to_string()));
        }
        if self.host.is_empty() {
            return Err(Error::Config("trunk host cannot be empty".to_string()));
        }
        // Validate transport
        match self.transport.as_str() {
            "udp" | "tcp" | "tls" => {}
            _ => {
                return Err(Error::Config(format!(
                    "invalid transport '{}', must be udp, tcp, or tls",
                    self.transport
                )))
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_toml() {
        let toml = r#"
[sip]
local_ip = "192.168.1.100"
local_port = 5080
debug = true

[[trunks]]
name = "twilio"
host = "sip.twilio.com"
username = "AC123"
password = "secret"

[[trunks]]
name = "provider"
host = "sip.provider.com"
port = 5061
transport = "tcp"
"#;

        let config = PyswitchConfig::from_toml(toml).expect("Failed to parse TOML");

        assert_eq!(config.sip.local_ip, "192.168.1.100");
        assert_eq!(config.sip.local_port, 5080);
        assert!(config.sip.debug);
        // user_agent is not configurable - it's hardcoded
        assert!(SipConfig::user_agent().starts_with("plivo_rtp_sip/"));

        assert_eq!(config.trunks.len(), 2);

        assert_eq!(config.trunks[0].name, "twilio");
        assert_eq!(config.trunks[0].host, "sip.twilio.com");
        assert_eq!(config.trunks[0].username.as_deref(), Some("AC123"));

        assert_eq!(config.trunks[1].name, "provider");
        assert_eq!(config.trunks[1].port, 5061);
        assert_eq!(config.trunks[1].transport, "tcp");
    }

    #[test]
    fn test_default_config() {
        let config = PyswitchConfig::default();
        assert_eq!(config.sip.local_port, 5060);
        assert_eq!(config.sip.local_ip, "0.0.0.0");
        assert!(config.trunks.is_empty());
    }

    #[test]
    fn test_dial_string() {
        let trunk = TrunkConfig::new("mytrunk", "sip.example.com");
        // Uses direct SIP URI format: sofia/external/sip:dest@host:port
        assert_eq!(
            trunk.dial_string("+18005551234"),
            "sofia/external/sip:+18005551234@sip.example.com:5060"
        );
    }
}
