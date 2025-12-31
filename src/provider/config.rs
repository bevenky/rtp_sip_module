//! Provider configuration
//!
//! Defines SIP provider configuration for multi-provider support.

use serde::{Deserialize, Serialize};

/// Transport protocol for SIP
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Transport {
    #[default]
    Udp,
    Tcp,
    Tls,
    WebSocket,
}

impl Transport {
    pub fn as_str(&self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
            Transport::Tls => "tls",
            Transport::WebSocket => "ws",
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            Transport::Udp | Transport::Tcp => 5060,
            Transport::Tls => 5061,
            Transport::WebSocket => 80,
        }
    }
}

/// SIP Provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Unique provider identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// SIP server hostname or IP
    pub sip_server: String,
    /// SIP server port
    pub sip_port: u16,
    /// Transport protocol
    pub transport: Transport,
    /// Authentication username
    pub username: String,
    /// Authentication password
    pub password: String,
    /// Optional realm for authentication
    pub realm: Option<String>,
    /// Override From domain (some providers require specific domain)
    pub from_domain: Option<String>,
    /// Phone number prefixes this provider handles (e.g., ["+1", "+44"])
    pub prefixes: Vec<String>,
    /// Priority (lower = higher priority)
    pub priority: u8,
    /// Maximum concurrent calls (None = unlimited)
    pub max_concurrent: Option<usize>,
    /// Whether to REGISTER with this provider
    pub register: bool,
    /// Registration refresh interval in seconds
    pub register_interval: u32,
    /// Outbound proxy (if different from sip_server)
    pub outbound_proxy: Option<String>,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            sip_server: String::new(),
            sip_port: 5060,
            transport: Transport::Udp,
            username: String::new(),
            password: String::new(),
            realm: None,
            from_domain: None,
            prefixes: Vec::new(),
            priority: 1,
            max_concurrent: None,
            register: false,
            register_interval: 300,
            outbound_proxy: None,
        }
    }
}

impl ProviderConfig {
    /// Create a new provider config with required fields
    pub fn new(id: &str, sip_server: &str, username: &str, password: &str) -> Self {
        Self {
            id: id.to_string(),
            name: id.to_string(),
            sip_server: sip_server.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            ..Default::default()
        }
    }

    /// Set prefixes this provider handles
    pub fn with_prefixes(mut self, prefixes: Vec<String>) -> Self {
        self.prefixes = prefixes;
        self
    }

    /// Set priority
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Enable registration
    pub fn with_register(mut self, register: bool) -> Self {
        self.register = register;
        self
    }

    /// Set transport
    pub fn with_transport(mut self, transport: Transport) -> Self {
        self.transport = transport;
        if self.sip_port == 5060 {
            self.sip_port = transport.default_port();
        }
        self
    }

    /// Get the SIP URI for this provider
    pub fn sip_uri(&self) -> String {
        format!("sip:{}", self.sip_server)
    }

    /// Get the registrar URI
    pub fn registrar_uri(&self) -> String {
        format!("sip:{}", self.sip_server)
    }

    /// Check if this provider matches a destination number
    pub fn matches(&self, destination: &str) -> bool {
        if self.prefixes.is_empty() {
            return true; // Catch-all
        }
        self.prefixes
            .iter()
            .any(|prefix| destination.starts_with(prefix))
    }

    /// Get the longest matching prefix length
    pub fn match_length(&self, destination: &str) -> usize {
        self.prefixes
            .iter()
            .filter(|prefix| destination.starts_with(*prefix))
            .map(|prefix| prefix.len())
            .max()
            .unwrap_or(0)
    }
}

/// Provider statistics
#[derive(Debug, Clone, Default)]
pub struct ProviderStats {
    /// Currently active calls
    pub active_calls: usize,
    /// Total calls made
    pub total_calls: u64,
    /// Failed calls
    pub failed_calls: u64,
    /// Registration status
    pub registered: bool,
    /// Last error message
    pub last_error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_config_new() {
        let config = ProviderConfig::new("plivo", "sip.plivo.com", "user", "pass");
        assert_eq!(config.id, "plivo");
        assert_eq!(config.sip_server, "sip.plivo.com");
        assert_eq!(config.sip_port, 5060);
    }

    #[test]
    fn test_provider_matches() {
        let config = ProviderConfig::new("us", "sip.test.com", "u", "p")
            .with_prefixes(vec!["+1".to_string(), "+1415".to_string()]);

        assert!(config.matches("+14155551234"));
        assert!(config.matches("+12125551234"));
        assert!(!config.matches("+447700900000"));
    }

    #[test]
    fn test_provider_match_length() {
        let config = ProviderConfig::new("us", "sip.test.com", "u", "p")
            .with_prefixes(vec!["+1".to_string(), "+1415".to_string()]);

        assert_eq!(config.match_length("+14155551234"), 5); // +1415
        assert_eq!(config.match_length("+12125551234"), 2); // +1
        assert_eq!(config.match_length("+447700900000"), 0);
    }

    #[test]
    fn test_catch_all_provider() {
        let config = ProviderConfig::new("default", "sip.test.com", "u", "p");
        assert!(config.matches("+14155551234"));
        assert!(config.matches("+447700900000"));
        assert!(config.matches("anything"));
    }

    #[test]
    fn test_transport_ports() {
        assert_eq!(Transport::Udp.default_port(), 5060);
        assert_eq!(Transport::Tcp.default_port(), 5060);
        assert_eq!(Transport::Tls.default_port(), 5061);
    }
}
