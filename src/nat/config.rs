//! NAT traversal configuration

use serde::{Deserialize, Serialize};

/// NAT traversal configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatConfig {
    /// Enable NAT traversal (default: false)
    #[serde(default)]
    pub enabled: bool,

    /// STUN server address (e.g., "stun.l.google.com:19302")
    pub stun_server: Option<String>,

    /// Additional STUN servers for failover (tried if primary fails)
    #[serde(default)]
    pub stun_servers: Vec<String>,

    /// TURN server address (for symmetric NAT fallback)
    pub turn_server: Option<String>,
    /// TURN username
    pub turn_username: Option<String>,
    /// TURN password
    pub turn_password: Option<String>,

    /// Keepalive minimum interval in seconds (default 15)
    #[serde(default = "default_keepalive_min")]
    pub keepalive_min_secs: u64,

    /// Keepalive maximum interval in seconds (default 25)
    #[serde(default = "default_keepalive_max")]
    pub keepalive_max_secs: u64,

    /// Enable symmetric RTP address learning (default: true)
    #[serde(default = "default_true")]
    pub symmetric_rtp: bool,

    /// Symmetric RTP consistency threshold (default 3)
    #[serde(default = "default_symmetric_threshold")]
    pub symmetric_rtp_threshold: u32,

    /// Number of hole-punch packets to send (default 3)
    #[serde(default = "default_hole_punch_count")]
    pub hole_punch_count: usize,

    /// Force a specific traversal mode (overrides auto-detection)
    /// Valid values: "direct", "hole_punch", "relay"
    pub force_mode: Option<String>,
}

impl NatConfig {
    /// Validate configuration values. Returns error description if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.keepalive_min_secs > self.keepalive_max_secs {
            return Err(format!(
                "keepalive_min_secs ({}) must be <= keepalive_max_secs ({})",
                self.keepalive_min_secs, self.keepalive_max_secs
            ));
        }
        if self.keepalive_min_secs == 0 {
            return Err("keepalive_min_secs must be > 0".to_string());
        }
        if self.symmetric_rtp_threshold == 0 {
            return Err("symmetric_rtp_threshold must be > 0".to_string());
        }
        // P2-NAT-14: Limit hole_punch_count to prevent excessive packet bursts.
        // 20 packets is more than enough to open a NAT pinhole.
        if self.hole_punch_count > 20 {
            return Err(format!(
                "hole_punch_count ({}) must be <= 20",
                self.hole_punch_count
            ));
        }
        Ok(())
    }
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            stun_server: None,
            stun_servers: Vec::new(),
            turn_server: None,
            turn_username: None,
            turn_password: None,
            keepalive_min_secs: default_keepalive_min(),
            keepalive_max_secs: default_keepalive_max(),
            symmetric_rtp: true,
            symmetric_rtp_threshold: default_symmetric_threshold(),
            hole_punch_count: default_hole_punch_count(),
            force_mode: None,
        }
    }
}

fn default_keepalive_min() -> u64 {
    15
}

fn default_keepalive_max() -> u64 {
    25
}

fn default_true() -> bool {
    true
}

fn default_symmetric_threshold() -> u32 {
    3
}

fn default_hole_punch_count() -> usize {
    3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NatConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.keepalive_min_secs, 15);
        assert_eq!(config.keepalive_max_secs, 25);
        assert!(config.symmetric_rtp);
        assert_eq!(config.symmetric_rtp_threshold, 3);
        assert_eq!(config.hole_punch_count, 3);
    }

    #[test]
    fn test_config_from_toml() {
        let toml_str = r#"
enabled = true
stun_server = "stun.l.google.com:19302"
symmetric_rtp = true
symmetric_rtp_threshold = 5
hole_punch_count = 5
"#;
        let config: NatConfig = toml::from_str(toml_str).unwrap();
        assert!(config.enabled);
        assert_eq!(
            config.stun_server.as_deref(),
            Some("stun.l.google.com:19302")
        );
        assert_eq!(config.symmetric_rtp_threshold, 5);
        assert_eq!(config.hole_punch_count, 5);
    }

    #[test]
    fn test_config_with_turn() {
        let toml_str = r#"
enabled = true
stun_server = "stun.l.google.com:19302"
turn_server = "turn.example.com:3478"
turn_username = "user"
turn_password = "pass"
"#;
        let config: NatConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.turn_server.as_deref(),
            Some("turn.example.com:3478")
        );
        assert_eq!(config.turn_username.as_deref(), Some("user"));
    }

    #[test]
    fn test_validation_defaults_pass() {
        assert!(NatConfig::default().validate().is_ok());
    }

    #[test]
    fn test_validation_min_gt_max() {
        let config = NatConfig {
            keepalive_min_secs: 30,
            keepalive_max_secs: 10,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_zero_threshold() {
        let config = NatConfig {
            symmetric_rtp_threshold: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_hole_punch_count_max() {
        // P2-NAT-14: hole_punch_count must be <= 20
        let config = NatConfig {
            hole_punch_count: 21,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config_ok = NatConfig {
            hole_punch_count: 20,
            ..Default::default()
        };
        assert!(config_ok.validate().is_ok());
    }
}
