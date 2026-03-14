//! NAT type detection (RFC 3489 Section 10.1 / RFC 5780)
//!
//! Implements the classic 4-test algorithm to classify NAT behavior:
//!
//! Test I:  Binding Request to primary server
//!          → No response: UDP blocked
//!          → Same IP as local: Open (no NAT)
//!          → Different IP: behind NAT → continue
//!
//! Test II: Binding Request with CHANGE-REQUEST (change IP + port)
//!          → Response received: Full Cone NAT
//!          → No response: continue
//!
//! Test III: Binding Request to secondary server (different IP)
//!           Compare reflexive address with Test I result
//!           → Different reflexive: Symmetric NAT
//!           → Same reflexive: continue
//!
//! Test IV: Binding Request with CHANGE-REQUEST (change port only)
//!          → Response received: Restricted Cone
//!          → No response: Port Restricted Cone

use std::net::SocketAddr;

use tokio::net::UdpSocket;

use super::stun::client::StunClient;
use super::types::NatType;
use crate::error::{Result, RtpSipError};

/// NAT type detector
pub struct NatDetector {
    /// Primary STUN server
    primary_server: SocketAddr,
}

impl NatDetector {
    pub fn new(primary_server: SocketAddr) -> Self {
        Self { primary_server }
    }

    /// Run the full NAT detection algorithm.
    /// Returns the detected NAT type and the reflexive (public) address.
    ///
    /// Note: Full detection requires a STUN server that supports CHANGE-REQUEST
    /// (RFC 5780 / RFC 3489). Many public STUN servers only support basic binding.
    /// If CHANGE-REQUEST isn't supported, this falls back to a simpler detection:
    /// - If reflexive == local → Open
    /// - Otherwise → Unknown (likely behind NAT, type indeterminate)
    pub async fn detect(&self) -> Result<(NatType, SocketAddr)> {
        // Bug #4 fix: Use "[::]:0" for IPv6 STUN servers, "0.0.0.0:0" for IPv4.
        let bind_addr = if self.primary_server.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(RtpSipError::Io)?;
        let local_addr = socket.local_addr().map_err(RtpSipError::Io)?;

        let client = StunClient::new(self.primary_server);

        // === Test I: Basic binding request ===
        // We need the full response (not just the reflexive address) so we can
        // extract CHANGED-ADDRESS for Test III.
        let test1_full_response = match client
            .binding_request_full(&socket, self.primary_server)
            .await
        {
            Ok(resp) => resp,
            Err(_) => {
                tracing::warn!("NAT detection: STUN server unreachable, UDP may be blocked");
                return Ok((NatType::Unknown, local_addr));
            }
        };

        let reflexive = match test1_full_response.reflexive_address() {
            Some(addr) => addr,
            None => {
                tracing::warn!("NAT detection: STUN response missing reflexive address");
                return Ok((NatType::Unknown, local_addr));
            }
        };
        let test1_changed_addr = test1_full_response.changed_address();
        tracing::info!(
            local = %local_addr,
            reflexive = %reflexive,
            "NAT detection Test I: reflexive address"
        );

        // Check if we're not behind NAT
        // P2-NAT-1: Compare both IP AND port. A matching IP but different port
        // still indicates a NAT (port-preserving NAT where the IP happens to match,
        // or a NAT with port translation only). Both must match for "Open".
        if reflexive.ip() == local_addr.ip() && reflexive.port() == local_addr.port() {
            // Local and reflexive address fully match -- no NAT
            return Ok((NatType::Open, reflexive));
        }

        // === Test II: Change IP + Port ===
        match client
            .binding_request_with_change(&socket, self.primary_server, true, true)
            .await
        {
            Ok(_response) => {
                // Got a response from different IP+port — Full Cone
                tracing::info!("NAT detection Test II: Full Cone NAT");
                return Ok((NatType::FullCone, reflexive));
            }
            Err(_) => {
                tracing::debug!("NAT detection Test II: no response (not Full Cone)");
            }
        }

        // === Test III: Send to different server, compare reflexive ===
        // Per RFC 3489 Section 10.1, Test III sends a binding request to the
        // *alternate* server address (CHANGED-ADDRESS) obtained from Test I.
        // If the reflexive address differs from Test I, we have a Symmetric NAT.
        if let Some(changed_addr) = test1_changed_addr {
            match client
                .binding_request_on(&socket, changed_addr)
                .await
            {
                Ok(test3_reflexive) => {
                    if test3_reflexive != reflexive {
                        tracing::info!("NAT detection Test III: Symmetric NAT");
                        return Ok((NatType::Symmetric, reflexive));
                    }
                }
                Err(_) => {
                    tracing::debug!("NAT detection Test III: secondary server unreachable");
                }
            }
        } else {
            tracing::debug!(
                "NAT detection Test III: no CHANGED-ADDRESS in Test I response, \
                 cannot distinguish Symmetric from Restricted"
            );
        }

        // === Test IV: Change port only ===
        match client
            .binding_request_with_change(&socket, self.primary_server, false, true)
            .await
        {
            Ok(_) => {
                tracing::info!("NAT detection Test IV: Restricted Cone NAT");
                Ok((NatType::RestrictedCone, reflexive))
            }
            Err(_) => {
                tracing::info!("NAT detection Test IV: Port Restricted Cone NAT");
                Ok((NatType::PortRestrictedCone, reflexive))
            }
        }
    }

    /// Quick detection: just get the reflexive address without full NAT typing.
    /// Faster than full detection (single STUN exchange).
    pub async fn quick_reflexive(&self) -> Result<SocketAddr> {
        let client = StunClient::new(self.primary_server);
        client.binding_request().await
    }
}

/// Check if an IP address is a public (non-RFC1918) address.
///
/// Currently used only in tests, but retained as a utility for future
/// NAT detection enhancements (e.g., distinguishing 1:1 NAT from no NAT).
#[allow(dead_code)]
fn is_public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_public_ip() {
        assert!(!is_public_ip("192.168.1.1".parse().unwrap()));
        assert!(!is_public_ip("10.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("172.16.0.1".parse().unwrap()));
        assert!(!is_public_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("169.254.1.1".parse().unwrap()));
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(is_public_ip("203.0.113.1".parse().unwrap()));
    }
}
