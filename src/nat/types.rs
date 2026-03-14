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
    /// P1-NAT-10: Symmetric NAT uses a different port mapping for each
    /// destination, so hole punching cannot work (the pinhole opened by
    /// punching to the remote peer's address will have a different external
    /// port than the one the peer sees). TURN relay is required.
    pub fn for_nat_type(nat_type: NatType) -> Self {
        match nat_type {
            NatType::Open | NatType::FullCone => TraversalStrategy::Direct,
            NatType::RestrictedCone
            | NatType::PortRestrictedCone => TraversalStrategy::HolePunch,
            // Symmetric NAT: different external mapping per destination,
            // hole punching is unreliable — must use TURN relay.
            NatType::Symmetric => TraversalStrategy::Relay,
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
        // P1-NAT-10: Symmetric NAT requires TURN relay because each
        // destination gets a different port mapping.
        assert_eq!(
            TraversalStrategy::for_nat_type(NatType::Symmetric),
            TraversalStrategy::Relay
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
