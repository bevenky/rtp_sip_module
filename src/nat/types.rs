//! Shared types for NAT traversal

use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// Detected NAT type per RFC 3489 / RFC 5780
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// No NAT — public IP observed
    Open,
    /// Full Cone: any external host can send to mapped addr
    FullCone,
    /// Restricted Cone: only hosts we've sent to can reach us (IP filter)
    RestrictedCone,
    /// Port Restricted Cone: restricted by IP and port
    PortRestrictedCone,
    /// Symmetric: different external mapping per destination
    Symmetric,
    /// Detection failed or blocked
    Unknown,
}

impl fmt::Display for NatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NatType::Open => write!(f, "Open (no NAT)"),
            NatType::FullCone => write!(f, "Full Cone"),
            NatType::RestrictedCone => write!(f, "Restricted Cone"),
            NatType::PortRestrictedCone => write!(f, "Port Restricted Cone"),
            NatType::Symmetric => write!(f, "Symmetric"),
            NatType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// NAT traversal strategy selected after detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraversalStrategy {
    /// Direct — no NAT or Full Cone (use reflexive addr in SDP)
    Direct,
    /// Hole punch — Restricted/PortRestricted Cone
    HolePunch,
    /// Relay — Symmetric NAT, must use TURN
    Relay,
}

impl TraversalStrategy {
    /// Select optimal strategy for a given NAT type.
    ///
    /// Note: Symmetric NAT does NOT require TURN/Relay in the common Voice AI
    /// case where one side has a public IP. The server uses symmetric RTP
    /// (auto-adjust) to learn the client's NAT-mapped address from incoming
    /// packets — this works for ALL NAT types. TURN is only needed when
    /// BOTH sides are behind Symmetric NAT (rare in telephony).
    ///
    /// Symmetric RTP auto-adjust handles Symmetric NAT without TURN.
    pub fn for_nat_type(nat_type: NatType) -> Self {
        match nat_type {
            NatType::Open | NatType::FullCone => TraversalStrategy::Direct,
            // All other NAT types: use hole-punch + symmetric RTP auto-adjust.
            // The server learns the real address from incoming packets.
            NatType::RestrictedCone
            | NatType::PortRestrictedCone
            | NatType::Symmetric => TraversalStrategy::HolePunch,
            NatType::Unknown => TraversalStrategy::HolePunch,
        }
    }
}

/// A discovered transport address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransportAddr {
    pub ip: IpAddr,
    pub port: u16,
}

impl From<SocketAddr> for TransportAddr {
    fn from(addr: SocketAddr) -> Self {
        Self {
            ip: addr.ip(),
            port: addr.port(),
        }
    }
}

impl From<TransportAddr> for SocketAddr {
    fn from(addr: TransportAddr) -> Self {
        SocketAddr::new(addr.ip, addr.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strategy_selection() {
        assert_eq!(TraversalStrategy::for_nat_type(NatType::Open), TraversalStrategy::Direct);
        assert_eq!(TraversalStrategy::for_nat_type(NatType::FullCone), TraversalStrategy::Direct);
        assert_eq!(
            TraversalStrategy::for_nat_type(NatType::RestrictedCone),
            TraversalStrategy::HolePunch
        );
        assert_eq!(
            TraversalStrategy::for_nat_type(NatType::PortRestrictedCone),
            TraversalStrategy::HolePunch
        );
        // Symmetric NAT uses HolePunch + symmetric RTP auto-adjust, NOT Relay
        // (server learns real address from incoming packets — no TURN needed)
        assert_eq!(
            TraversalStrategy::for_nat_type(NatType::Symmetric),
            TraversalStrategy::HolePunch
        );
        assert_eq!(TraversalStrategy::for_nat_type(NatType::Unknown), TraversalStrategy::HolePunch);
    }

    #[test]
    fn test_transport_addr_conversion() {
        let sock: SocketAddr = "192.168.1.1:5060".parse().unwrap();
        let ta = TransportAddr::from(sock);
        assert_eq!(ta.ip, sock.ip());
        assert_eq!(ta.port, sock.port());
        let back: SocketAddr = ta.into();
        assert_eq!(back, sock);
    }
}
