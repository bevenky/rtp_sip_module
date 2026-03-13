//! Configuration module
//!
//! Handles loading configuration from TOML files.

use crate::error::{Result, RtpSipError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// SIP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SipConfig {
    /// Local IP to bind SIP socket.
    ///
    /// Use "0.0.0.0" for IPv4 any-address, or "::" for IPv6 any-address (Fix 13).
    /// When using "::", the SIP engine will bind to all IPv6 (and typically
    /// IPv4-mapped) addresses.
    #[serde(default = "default_local_ip")]
    pub local_ip: String,
    /// Local SIP port
    #[serde(default = "default_sip_port")]
    pub local_port: u16,
    /// Transport: "udp", "tcp", or "tls"
    #[serde(default = "default_transport")]
    pub transport: String,
    /// TLS certificate path
    pub tls_cert: Option<String>,
    /// TLS key path
    pub tls_key: Option<String>,

    // --- Fix 3: Transaction timer configuration (RFC 3261) ---

    /// Timer T1: RTT estimate in milliseconds (default 500ms).
    /// Controls initial retransmission interval for unreliable transports.
    pub timer_t1_ms: Option<u32>,
    /// Timer T2: Maximum retransmit interval in milliseconds (default 4000ms).
    /// Non-INVITE retransmissions cap at this interval.
    pub timer_t2_ms: Option<u32>,
    /// Timer T1x64: Maximum retransmit time in milliseconds (default 32000ms).
    /// Transaction timeout after this duration.
    pub timer_t1x64_ms: Option<u32>,

    // --- Fix 11: TLS support ---

    /// Verify server TLS certificate (default true).
    /// Set to false for self-signed certificates in development.
    #[serde(default = "default_true")]
    pub tls_verify: bool,
    /// Path to CA certificate for TLS verification.
    /// If not specified, system trust store is used.
    pub tls_ca_cert: Option<String>,
}

impl Default for SipConfig {
    fn default() -> Self {
        Self {
            local_ip: default_local_ip(),
            local_port: default_sip_port(),
            transport: default_transport(),
            tls_cert: None,
            tls_key: None,
            timer_t1_ms: None,
            timer_t2_ms: None,
            timer_t1x64_ms: None,
            tls_verify: true,
            tls_ca_cert: None,
        }
    }
}

/// SIP transport type (Fix 11)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transport {
    /// UDP transport (default)
    Udp,
    /// TCP transport
    Tcp,
    /// TLS transport (SIP over TLS / SIPS)
    Tls,
}

impl Transport {
    /// Parse from a transport string (case-insensitive)
    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "tls" => Transport::Tls,
            "tcp" => Transport::Tcp,
            _ => Transport::Udp,
        }
    }
}

impl Default for Transport {
    fn default() -> Self {
        Transport::Udp
    }
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Transport::Udp => write!(f, "udp"),
            Transport::Tcp => write!(f, "tcp"),
            Transport::Tls => write!(f, "tls"),
        }
    }
}

/// RTP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtpConfig {
    /// Local IP to bind RTP sockets
    #[serde(default = "default_local_ip")]
    pub local_ip: String,
    /// RTP port range start
    #[serde(default = "default_rtp_port_start")]
    pub port_start: u16,
    /// RTP port range end
    #[serde(default = "default_rtp_port_end")]
    pub port_end: u16,
}

impl Default for RtpConfig {
    fn default() -> Self {
        Self {
            local_ip: default_local_ip(),
            port_start: default_rtp_port_start(),
            port_end: default_rtp_port_end(),
        }
    }
}

/// Provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Provider name (for logging/identification)
    pub name: String,
    /// SIP server hostname
    pub server: String,
    /// SIP server port
    #[serde(default = "default_sip_port")]
    pub port: u16,
    /// Authentication username
    #[serde(default)]
    pub username: String,
    /// Authentication password
    #[serde(default)]
    pub password: String,
    /// Authentication realm (optional, defaults to server)
    pub realm: Option<String>,
    /// Prefixes this provider handles (longest match wins)
    #[serde(default)]
    pub prefixes: Vec<String>,
    /// Is this the default provider for unmatched prefixes?
    #[serde(default)]
    pub default: bool,
}

/// Routing configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingConfig {
    /// Blocked prefixes (calls to these fail immediately)
    #[serde(default)]
    pub blocked_prefixes: Vec<String>,
}

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// SIP configuration
    #[serde(default)]
    pub sip: SipConfig,
    /// RTP configuration
    #[serde(default)]
    pub rtp: RtpConfig,
    /// Provider configurations (multiple providers supported)
    #[serde(default)]
    pub providers: Vec<ProviderConfig>,
    /// Routing configuration
    #[serde(default)]
    pub routing: RoutingConfig,
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            RtpSipError::Config(format!("Failed to read config file: {}", e))
        })?;
        Self::from_str(&content)
    }

    /// Parse configuration from a TOML string
    pub fn from_str(content: &str) -> Result<Self> {
        toml::from_str(content).map_err(|e| {
            RtpSipError::Config(format!("Failed to parse config: {}", e))
        })
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Check transport
        if self.sip.transport != "udp"
            && self.sip.transport != "tcp"
            && self.sip.transport != "tls"
        {
            return Err(RtpSipError::Config(format!(
                "Invalid transport '{}'. Must be 'udp', 'tcp', or 'tls'",
                self.sip.transport
            )));
        }

        // Check TLS config
        if self.sip.transport == "tls" {
            if self.sip.tls_cert.is_none() || self.sip.tls_key.is_none() {
                return Err(RtpSipError::Config(
                    "TLS transport requires tls_cert and tls_key".to_string(),
                ));
            }
        }

        // Check at least one provider
        if self.providers.is_empty() {
            return Err(RtpSipError::Config(
                "At least one provider is required".to_string(),
            ));
        }

        // Check provider servers
        for provider in &self.providers {
            if provider.server.is_empty() {
                return Err(RtpSipError::Config(format!(
                    "Provider '{}' has empty server",
                    provider.name
                )));
            }
            if provider.name.is_empty() {
                return Err(RtpSipError::Config(
                    "Provider name is required".to_string(),
                ));
            }
            if provider.port == 0 {
                return Err(RtpSipError::Config(format!(
                    "Provider '{}' has invalid port 0",
                    provider.name
                )));
            }
        }

        // Check RTP port range
        if self.rtp.port_start >= self.rtp.port_end {
            return Err(RtpSipError::Config(
                "RTP port_start must be less than port_end".to_string(),
            ));
        }

        // Bug #29 fix: Require at least 2 ports in the range (one for RTP, one for RTCP)
        if self.rtp.port_end - self.rtp.port_start < 2 {
            return Err(RtpSipError::Config(
                "RTP port range must contain at least 2 ports (one RTP + one RTCP)".to_string(),
            ));
        }

        Ok(())
    }

    /// Check if a destination is blocked
    pub fn is_blocked(&self, destination: &str) -> bool {
        let dest = Self::normalize_destination(destination);
        self.routing
            .blocked_prefixes
            .iter()
            .any(|prefix| dest.starts_with(prefix))
    }

    /// Route a destination to the best provider (longest prefix match)
    /// Returns None if no provider matches and no default is set
    pub fn route(&self, destination: &str) -> Option<&ProviderConfig> {
        let dest = Self::normalize_destination(destination);

        // Find all matching providers with their match lengths
        let mut matches: Vec<(&ProviderConfig, usize)> = self
            .providers
            .iter()
            .filter_map(|p| {
                // Find the longest matching prefix for this provider
                let best_match = p
                    .prefixes
                    .iter()
                    .filter(|prefix| dest.starts_with(prefix.as_str()))
                    .map(|prefix| prefix.len())
                    .max();

                best_match.map(|len| (p, len))
            })
            .collect();

        // Sort by match length (longest first)
        matches.sort_by(|a, b| b.1.cmp(&a.1));

        // Return the best match, or the default provider
        matches
            .first()
            .map(|(p, _)| *p)
            .or_else(|| self.providers.iter().find(|p| p.default))
    }

    /// Normalize destination (remove sip: prefix, extract user part)
    fn normalize_destination(destination: &str) -> &str {
        destination
            .strip_prefix("sip:")
            .unwrap_or(destination)
            .split('@')
            .next()
            .unwrap_or(destination)
    }

    /// Get the user agent string
    pub fn user_agent() -> String {
        format!("plivo-sip-rtp/{}", env!("CARGO_PKG_VERSION"))
    }

    /// Check if using TLS
    pub fn is_tls(&self) -> bool {
        self.sip.transport == "tls"
    }

    /// Get the parsed transport type (Fix 11)
    pub fn transport(&self) -> Transport {
        Transport::from_str_lossy(&self.sip.transport)
    }

    /// Get provider by name
    pub fn get_provider(&self, name: &str) -> Option<&ProviderConfig> {
        self.providers.iter().find(|p| p.name == name)
    }
}

// Default value functions
fn default_local_ip() -> String {
    "0.0.0.0".to_string()
}

fn default_sip_port() -> u16 {
    5060
}

fn default_transport() -> String {
    "udp".to_string()
}

fn default_rtp_port_start() -> u16 {
    10000
}

fn default_rtp_port_end() -> u16 {
    20000
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_provider() {
        let config_str = r#"
[[providers]]
name = "plivo"
server = "sip.plivo.com"
username = "user"
password = "pass"
"#;
        let config = Config::from_str(config_str).unwrap();
        config.validate().unwrap();
        assert_eq!(config.providers.len(), 1);
        assert_eq!(config.providers[0].name, "plivo");
    }

    #[test]
    fn test_parse_multiple_providers() {
        let config_str = r#"
[sip]
local_port = 5080
transport = "udp"

[rtp]
port_start = 20000
port_end = 30000

[[providers]]
name = "plivo"
server = "sip.plivo.com"
port = 5060
username = "AUTH_ID"
password = "AUTH_TOKEN"
prefixes = ["+1", "+1415"]

[[providers]]
name = "telnyx"
server = "sip.telnyx.com"
port = 5060
username = "USER"
password = "PASS"
prefixes = ["+44", "+49"]
default = true

[routing]
blocked_prefixes = ["+1900", "+1976"]
"#;
        let config = Config::from_str(config_str).unwrap();
        config.validate().unwrap();

        assert_eq!(config.sip.local_port, 5080);
        assert_eq!(config.rtp.port_start, 20000);
        assert_eq!(config.providers.len(), 2);
        assert_eq!(config.providers[0].name, "plivo");
        assert_eq!(config.providers[1].name, "telnyx");
        assert!(config.providers[1].default);
        assert_eq!(config.routing.blocked_prefixes.len(), 2);
    }

    #[test]
    fn test_routing_longest_prefix() {
        let config_str = r#"
[[providers]]
name = "plivo"
server = "sip.plivo.com"
prefixes = ["+1"]

[[providers]]
name = "plivo-sf"
server = "sip.plivo.com"
prefixes = ["+1415"]
"#;
        let config = Config::from_str(config_str).unwrap();

        // +1415 should match plivo-sf (longer prefix)
        let provider = config.route("+14155551234").unwrap();
        assert_eq!(provider.name, "plivo-sf");

        // +1212 should match plivo (+1)
        let provider = config.route("+12125551234").unwrap();
        assert_eq!(provider.name, "plivo");
    }

    #[test]
    fn test_routing_default_provider() {
        let config_str = r#"
[[providers]]
name = "plivo"
server = "sip.plivo.com"
prefixes = ["+1"]

[[providers]]
name = "telnyx"
server = "sip.telnyx.com"
default = true
"#;
        let config = Config::from_str(config_str).unwrap();

        // +44 has no matching prefix, should use default
        let provider = config.route("+442071234567").unwrap();
        assert_eq!(provider.name, "telnyx");
    }

    #[test]
    fn test_routing_no_match() {
        let config_str = r#"
[[providers]]
name = "plivo"
server = "sip.plivo.com"
prefixes = ["+1"]
"#;
        let config = Config::from_str(config_str).unwrap();

        // +44 has no matching prefix and no default
        let provider = config.route("+442071234567");
        assert!(provider.is_none());
    }

    #[test]
    fn test_is_blocked() {
        let config_str = r#"
[[providers]]
name = "plivo"
server = "sip.plivo.com"

[routing]
blocked_prefixes = ["+1900", "+1976"]
"#;
        let config = Config::from_str(config_str).unwrap();

        assert!(config.is_blocked("+19005551234"));
        assert!(config.is_blocked("sip:+19005551234@example.com"));
        assert!(!config.is_blocked("+14155551234"));
    }

    #[test]
    fn test_user_agent() {
        let ua = Config::user_agent();
        assert!(ua.starts_with("plivo-sip-rtp/"));
    }

    #[test]
    fn test_no_providers_error() {
        let config_str = r#"
[sip]
local_port = 5060
"#;
        let config = Config::from_str(config_str).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_tls_requires_certs() {
        let config_str = r#"
[sip]
transport = "tls"

[[providers]]
name = "plivo"
server = "sip.plivo.com"
"#;
        let config = Config::from_str(config_str).unwrap();
        assert!(config.validate().is_err());
    }
}
