//! RTP session configuration

use crate::core::audio::Codec;

/// RTP session configuration
///
/// Simple API for WebSocket-based SIP mode:
/// ```python
/// # WebSocket gives you remote endpoint
/// session = RtpSession(remote_ip, remote_port)
/// local_port = session.local_port  # Auto-allocated
///
/// # Tell WebSocket your port
/// await ws.send({"rtp_port": local_port})
///
/// # Start and receive audio
/// await session.start()
/// frame = await session.recv_audio()
/// ```
#[derive(Debug, Clone)]
pub struct RtpConfig {
    /// Remote IP to send RTP to (required)
    pub remote_ip: String,
    /// Remote port to send RTP to (required)
    pub remote_port: u16,
    /// Local IP to bind (default: "0.0.0.0")
    pub local_ip: String,
    /// Local port to bind (default: 0 = auto-allocate)
    pub local_port: u16,
    /// Audio codec (default: PCMU)
    pub codec: Codec,
    /// Packet time in milliseconds (default: 20)
    pub ptime_ms: u32,
    /// Jitter buffer depth in packets (default: 5 = 100ms at 20ms ptime)
    /// Use 3 for LAN, 5-7 for internet, 10 for poor networks
    pub jitter_buffer_packets: usize,
}

impl RtpConfig {
    /// Create RTP config with remote endpoint
    ///
    /// Local port is auto-allocated by default.
    pub fn new(remote_ip: impl Into<String>, remote_port: u16) -> Self {
        Self {
            remote_ip: remote_ip.into(),
            remote_port,
            local_ip: "0.0.0.0".to_string(),
            local_port: 0, // Auto-allocate
            codec: Codec::Pcmu,
            ptime_ms: 20,
            jitter_buffer_packets: 5, // 100ms default
        }
    }

    /// Set local bind address
    pub fn with_local_ip(mut self, ip: impl Into<String>) -> Self {
        self.local_ip = ip.into();
        self
    }

    /// Set local port (0 = auto-allocate)
    pub fn with_local_port(mut self, port: u16) -> Self {
        self.local_port = port;
        self
    }

    /// Set the codec (PCMU or PCMA)
    pub fn with_codec(mut self, codec: Codec) -> Self {
        self.codec = codec;
        self
    }

    /// Set the packet time in milliseconds
    pub fn with_ptime(mut self, ptime_ms: u32) -> Self {
        self.ptime_ms = ptime_ms;
        self
    }

    /// Set jitter buffer depth in packets
    /// - 3 packets (60ms): LAN, low-latency
    /// - 5 packets (100ms): Internet telephony (default)
    /// - 7-10 packets (140-200ms): Poor networks, mobile
    pub fn with_jitter_buffer(mut self, packets: usize) -> Self {
        self.jitter_buffer_packets = packets.max(2).min(20); // Clamp to 2-20
        self
    }

    /// Get samples per packet (at 8kHz)
    pub fn samples_per_packet(&self) -> u32 {
        8000 * self.ptime_ms / 1000
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.remote_ip.is_empty() {
            return Err("Remote IP is required".to_string());
        }
        if self.remote_port == 0 {
            return Err("Remote port cannot be 0".to_string());
        }
        if self.ptime_ms == 0 || self.ptime_ms > 100 {
            return Err("Packet time must be 1-100ms".to_string());
        }
        if self.codec == Codec::L16 {
            return Err("RTP mode only supports PCMU/PCMA, not L16".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_new() {
        let config = RtpConfig::new("192.168.1.100", 5006);

        assert_eq!(config.remote_ip, "192.168.1.100");
        assert_eq!(config.remote_port, 5006);
        assert_eq!(config.local_ip, "0.0.0.0");
        assert_eq!(config.local_port, 0); // Auto-allocate
        assert_eq!(config.codec, Codec::Pcmu);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_with_options() {
        let config = RtpConfig::new("192.168.1.100", 5006)
            .with_local_ip("10.0.0.1")
            .with_local_port(16384)
            .with_codec(Codec::Pcma)
            .with_ptime(30);

        assert_eq!(config.local_ip, "10.0.0.1");
        assert_eq!(config.local_port, 16384);
        assert_eq!(config.codec, Codec::Pcma);
        assert_eq!(config.ptime_ms, 30);
    }

    #[test]
    fn test_samples_per_packet() {
        let config = RtpConfig::new("192.168.1.100", 5006).with_ptime(20);
        assert_eq!(config.samples_per_packet(), 160); // 8000 * 20 / 1000
    }

    #[test]
    fn test_validate() {
        // Valid config
        assert!(RtpConfig::new("192.168.1.100", 5006).validate().is_ok());

        // Empty remote IP
        let mut config = RtpConfig::new("", 5006);
        assert!(config.validate().is_err());

        // Zero remote port
        config = RtpConfig::new("192.168.1.100", 0);
        assert!(config.validate().is_err());
    }
}
