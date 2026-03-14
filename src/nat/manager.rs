//! NAT traversal manager — top-level orchestrator
//!
//! Coordinates NAT detection, STUN keepalives, hole punching, symmetric RTP,
//! and provides the discovered public address for SDP/SIP headers.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::config::NatConfig;
use super::detect::NatDetector;
use super::hole_punch;
use super::keepalive::NatKeepalive;
use super::symmetric_rtp::SymmetricRtp;
use super::types::{NatType, TraversalStrategy};
use crate::error::{Result, RtpSipError};

/// Detection result updated atomically under a single lock
struct DetectionState {
    nat_type: NatType,
    strategy: TraversalStrategy,
    reflexive_addr: Option<SocketAddr>,
}

/// NAT traversal manager
pub struct NatManager {
    config: NatConfig,
    /// Detection results — single lock for atomic updates
    state: Mutex<DetectionState>,
    /// STUN server address (resolved)
    stun_server: Mutex<Option<SocketAddr>>,
    /// Active keepalive task
    keepalive: Mutex<Option<Arc<NatKeepalive>>>,
    /// Channel for NAT rebinding notifications
    addr_change_tx: Mutex<Option<mpsc::Sender<SocketAddr>>>,
}

impl NatManager {
    /// Create a new NAT manager from configuration.
    /// Does NOT run detection automatically — call `detect()` or `init()`.
    pub fn new(config: NatConfig) -> Self {
        let strategy = if let Some(ref mode) = config.force_mode {
            match mode.as_str() {
                "direct" => TraversalStrategy::Direct,
                "relay" => TraversalStrategy::Relay,
                _ => TraversalStrategy::HolePunch,
            }
        } else {
            TraversalStrategy::HolePunch // default until detection
        };

        Self {
            config,
            state: Mutex::new(DetectionState {
                nat_type: NatType::Unknown,
                strategy,
                reflexive_addr: None,
            }),
            stun_server: Mutex::new(None),
            keepalive: Mutex::new(None),
            addr_change_tx: Mutex::new(None),
        }
    }

    /// Initialize the NAT manager: resolve STUN server and run NAT detection.
    ///
    /// P2-NAT-11: Note that this method does NOT start keepalive automatically.
    /// Call `start_keepalive()` separately with the RTP socket after the
    /// session is established. The keepalive requires a specific socket to
    /// keep its NAT binding alive, which is not available at init time.
    pub async fn init(self: &Arc<Self>) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Resolve STUN server
        let stun_addr = self.resolve_stun_server().await?;
        *self.stun_server.lock() = Some(stun_addr);

        // Run NAT detection
        self.detect().await?;

        Ok(())
    }

    /// Run NAT detection and select traversal strategy.
    pub async fn detect(&self) -> Result<(NatType, TraversalStrategy)> {
        let stun_addr = self
            .stun_server
            .lock()
            .ok_or_else(|| RtpSipError::Config("No STUN server configured".to_string()))?;

        let detector = NatDetector::new(stun_addr);
        let (nat_type, reflexive) = detector.detect().await?;

        let strategy = if self.config.force_mode.is_some() {
            self.state.lock().strategy
        } else {
            TraversalStrategy::for_nat_type(nat_type)
        };

        // Check if relay strategy but no TURN configured
        if strategy == TraversalStrategy::Relay && self.config.turn_server.is_none() {
            tracing::warn!(
                "Symmetric NAT detected but no TURN server configured. \
                 Falling back to hole-punch (may fail)"
            );
        }

        // Atomic update of all detection state
        {
            let mut state = self.state.lock();
            state.nat_type = nat_type;
            state.strategy = strategy;
            state.reflexive_addr = Some(reflexive);
        }

        tracing::info!(
            nat_type = %nat_type,
            reflexive = %reflexive,
            strategy = ?strategy,
            "NAT detection complete"
        );

        Ok((nat_type, strategy))
    }

    /// Start keepalive on a specific socket.
    /// Should be called with the RTP socket to keep its NAT binding alive.
    pub fn start_keepalive(
        self: &Arc<Self>,
        socket: Arc<UdpSocket>,
    ) -> Option<mpsc::Receiver<SocketAddr>> {
        let stun_addr = match *self.stun_server.lock() {
            Some(addr) => addr,
            None => return None,
        };

        let (tx, rx) = mpsc::channel(4);
        *self.addr_change_tx.lock() = Some(tx.clone());

        let ka = Arc::new(NatKeepalive::new(
            socket,
            stun_addr,
            Duration::from_secs(self.config.keepalive_min_secs),
            Duration::from_secs(self.config.keepalive_max_secs),
        ));
        ka.start(Some(tx));
        *self.keepalive.lock() = Some(ka);

        Some(rx)
    }

    /// Prepare an RTP session for NAT traversal.
    /// Sends hole-punch packets to open NAT pinhole before media flow.
    pub async fn prepare_session(
        &self,
        socket: &UdpSocket,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        let strategy = self.state.lock().strategy;

        match strategy {
            TraversalStrategy::HolePunch | TraversalStrategy::Direct => {
                if self.config.hole_punch_count > 0 {
                    hole_punch::punch(
                        socket,
                        remote_addr,
                        self.config.hole_punch_count,
                        hole_punch::DEFAULT_HOLE_PUNCH_INTERVAL,
                    )
                    .await?;
                }
            }
            TraversalStrategy::Relay => {
                // TURN relay — hole punching goes through TURN server
                // For now, just punch to the target (TURN integration is Phase 7)
                if self.config.hole_punch_count > 0 {
                    hole_punch::punch(
                        socket,
                        remote_addr,
                        self.config.hole_punch_count,
                        hole_punch::DEFAULT_HOLE_PUNCH_INTERVAL,
                    )
                    .await?;
                }
            }
        }

        Ok(())
    }

    /// Get the address to use in SDP c= line and SIP Contact header.
    ///
    /// Returns reflexive (public) address if available, otherwise None
    /// (caller should fall back to local address).
    pub fn public_addr(&self) -> Option<SocketAddr> {
        self.state.lock().reflexive_addr
    }

    /// Get the public address for SDP/SIP usage.
    ///
    /// Returns the full reflexive address (both IP and port) from STUN.
    /// This is the correct address to advertise in SDP c= lines and SIP
    /// Contact headers, as it reflects the actual NAT-mapped IP and port.
    ///
    /// Callers should prefer `public_addr()` which returns the same value.
    /// This method is retained for backward compatibility but ignores
    /// the `local_port` parameter -- the reflexive port from STUN is always
    /// used because substituting the local port is incorrect for non-Full-Cone
    /// NAT types.
    #[deprecated(
        note = "Use public_addr() instead, which returns the full reflexive address"
    )]
    pub fn public_addr_with_port(&self, _local_port: u16) -> Option<SocketAddr> {
        self.state.lock().reflexive_addr
    }

    /// Create a SymmetricRtp instance with the configured threshold
    pub fn new_symmetric_rtp(&self) -> SymmetricRtp {
        if self.config.symmetric_rtp {
            SymmetricRtp::new(self.config.symmetric_rtp_threshold)
        } else {
            SymmetricRtp::disabled()
        }
    }

    /// Get detected NAT type
    pub fn nat_type(&self) -> NatType {
        self.state.lock().nat_type
    }

    /// Get selected strategy
    pub fn strategy(&self) -> TraversalStrategy {
        self.state.lock().strategy
    }

    /// Shutdown — stops keepalive
    pub async fn shutdown(&self) {
        if let Some(ka) = self.keepalive.lock().take() {
            ka.stop();
        }
    }

    /// Resolve STUN server hostname to SocketAddr
    async fn resolve_stun_server(&self) -> Result<SocketAddr> {
        let server_str = self
            .config
            .stun_server
            .as_deref()
            .unwrap_or("stun.l.google.com:19302");

        // Try direct parse first
        if let Ok(addr) = server_str.parse::<SocketAddr>() {
            return Ok(addr);
        }

        // DNS resolution
        use tokio::net::lookup_host;
        let addrs: Vec<SocketAddr> = lookup_host(server_str)
            .await
            .map_err(|e| {
                RtpSipError::Config(format!("Failed to resolve STUN server '{}': {}", server_str, e))
            })?
            .collect();

        addrs.into_iter().next().ok_or_else(|| {
            RtpSipError::Config(format!("STUN server '{}' resolved to no addresses", server_str))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_creates_manager() {
        let config = NatConfig::default();
        let mgr = NatManager::new(config);
        assert_eq!(mgr.nat_type(), NatType::Unknown);
        assert_eq!(mgr.strategy(), TraversalStrategy::HolePunch);
        assert!(mgr.public_addr().is_none());
    }

    #[test]
    fn test_force_mode() {
        let config = NatConfig {
            force_mode: Some("direct".to_string()),
            ..Default::default()
        };
        let mgr = NatManager::new(config);
        assert_eq!(mgr.strategy(), TraversalStrategy::Direct);

        let config2 = NatConfig {
            force_mode: Some("relay".to_string()),
            ..Default::default()
        };
        let mgr2 = NatManager::new(config2);
        assert_eq!(mgr2.strategy(), TraversalStrategy::Relay);
    }

    #[test]
    fn test_symmetric_rtp_creation() {
        let config = NatConfig {
            symmetric_rtp: true,
            symmetric_rtp_threshold: 5,
            ..Default::default()
        };
        let mgr = NatManager::new(config);
        let srtp = mgr.new_symmetric_rtp();
        // Verify it's enabled by checking behavior
        let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let mut srtp = srtp;
        srtp.set_configured(addr);
        assert_eq!(srtp.effective_remote(), Some(addr));
    }

    #[test]
    fn test_disabled_symmetric_rtp() {
        let config = NatConfig {
            symmetric_rtp: false,
            ..Default::default()
        };
        let mgr = NatManager::new(config);
        let srtp = mgr.new_symmetric_rtp();
        // Verify it's disabled
        let mut srtp = srtp;
        let configured: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let natted: SocketAddr = "203.0.113.5:12345".parse().unwrap();
        srtp.set_configured(configured);
        assert!(!srtp.process_incoming(natted));
        assert_eq!(srtp.effective_remote(), Some(configured));
    }
}
