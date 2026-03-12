//! NAT traversal module
//!
//! Provides comprehensive NAT traversal for SIP/RTP telephony:
//!
//! - **STUN client** (RFC 5389): Reflexive address discovery for SDP/SIP
//! - **NAT type detection** (RFC 3489/5780): Auto-detect NAT behavior
//! - **Symmetric RTP** (RFC 4961): Learn remote address from incoming packets
//! - **UDP hole punching**: Open NAT pinholes before media flow
//! - **NAT keepalive**: Maintain NAT bindings with periodic STUN packets
//! - **Packet demux**: Distinguish RTP/RTCP/STUN on shared sockets
//!
//! ## Usage
//!
//! ```rust,no_run
//! use rtpsip::nat::{NatConfig, NatManager};
//!
//! let config = NatConfig {
//!     enabled: true,
//!     stun_server: Some("stun.l.google.com:19302".to_string()),
//!     ..Default::default()
//! };
//! let mgr = std::sync::Arc::new(NatManager::new(config));
//! // mgr.init().await?; // Run detection + start keepalive
//! ```

pub mod config;
pub mod demux;
pub mod detect;
pub mod hole_punch;
pub mod keepalive;
pub mod manager;
pub mod stun;
pub mod symmetric_rtp;
pub mod turn;
pub mod types;

pub use config::NatConfig;
pub use demux::demux_packet;
pub use manager::NatManager;
pub use stun::StunServerPool;
pub use symmetric_rtp::SymmetricRtp;
pub use types::{NatType, TraversalStrategy};
