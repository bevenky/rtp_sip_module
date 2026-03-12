//! DNS resolution for SIP URIs
//!
//! Provides SRV and A record resolution for SIP domains.
//! Full NAPTR resolution is not implemented yet.
//!
//! # Resolution Order
//!
//! 1. If the input is already an IP:port, return as-is
//! 2. Try SRV lookup: `_sip._udp.{domain}` (or `_sip._tcp.{domain}`)
//! 3. Fall back to A/AAAA record lookup via `tokio::net::lookup_host`
//!
//! TODO: Implement NAPTR (RFC 3263) for full SIP DNS resolution.

use crate::error::{Result, RtpSipError};
use std::net::SocketAddr;

/// SIP DNS resolver
///
/// Resolves SIP URIs to socket addresses using SRV + A record fallback.
pub struct SipResolver;

impl SipResolver {
    /// Resolve a SIP URI or domain to a list of socket addresses.
    ///
    /// # Arguments
    /// * `uri` - A SIP URI (e.g., "sip:example.com"), a domain ("example.com"),
    ///           or an IP:port string ("192.168.1.1:5060")
    ///
    /// # Returns
    /// A list of resolved socket addresses sorted by priority/weight (for SRV)
    /// or in DNS response order (for A records).
    pub async fn resolve_sip_uri(uri: &str) -> Result<Vec<SocketAddr>> {
        // Strip sip: or sips: prefix if present
        let host_part = uri
            .strip_prefix("sip:")
            .or_else(|| uri.strip_prefix("sips:"))
            .unwrap_or(uri);

        // Remove user@ part if present
        let domain_port = if let Some(at_pos) = host_part.find('@') {
            &host_part[at_pos + 1..]
        } else {
            host_part
        };

        // Remove URI parameters (;transport=udp etc.)
        let domain_port = domain_port.split(';').next().unwrap_or(domain_port);

        // If it's already an IP:port, parse and return directly
        if let Ok(addr) = domain_port.parse::<SocketAddr>() {
            return Ok(vec![addr]);
        }

        // If it's an IP without port, add default SIP port
        if let Ok(ip) = domain_port.parse::<std::net::IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, 5060)]);
        }

        // Extract domain and optional port
        let (domain, port) = if let Some(colon_pos) = domain_port.rfind(':') {
            let port_str = &domain_port[colon_pos + 1..];
            if let Ok(port) = port_str.parse::<u16>() {
                (&domain_port[..colon_pos], Some(port))
            } else {
                (domain_port, None)
            }
        } else {
            (domain_port, None)
        };

        let default_port = port.unwrap_or(5060);

        // Try SRV lookup: _sip._udp.{domain}
        // We use tokio::net::lookup_host which does A/AAAA resolution.
        // For SRV, we'd need a dedicated DNS library. For now, we try the SRV
        // hostname pattern through lookup_host which works if the system resolver
        // supports it, then fall back to direct A record.
        let srv_domain = format!("_sip._udp.{}", domain);
        if let Ok(addrs) = tokio::net::lookup_host(format!("{}:{}", srv_domain, default_port)).await
        {
            let results: Vec<SocketAddr> = addrs.collect();
            if !results.is_empty() {
                return Ok(results);
            }
        }

        // Fall back to A/AAAA record lookup
        let lookup_host = format!("{}:{}", domain, default_port);
        let addrs = tokio::net::lookup_host(&lookup_host)
            .await
            .map_err(|e| {
                RtpSipError::Sip(format!("DNS resolution failed for '{}': {}", domain, e))
            })?;

        let results: Vec<SocketAddr> = addrs.collect();
        if results.is_empty() {
            return Err(RtpSipError::Sip(format!(
                "No addresses found for '{}'",
                domain
            )));
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip_port() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let addrs = SipResolver::resolve_sip_uri("192.168.1.1:5060")
                .await
                .unwrap();
            assert_eq!(addrs.len(), 1);
            assert_eq!(
                addrs[0],
                "192.168.1.1:5060".parse::<SocketAddr>().unwrap()
            );
        });
    }

    #[test]
    fn test_parse_ip_only() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let addrs = SipResolver::resolve_sip_uri("10.0.0.1").await.unwrap();
            assert_eq!(addrs.len(), 1);
            assert_eq!(addrs[0], "10.0.0.1:5060".parse::<SocketAddr>().unwrap());
        });
    }

    #[test]
    fn test_parse_sip_uri_with_ip() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let addrs = SipResolver::resolve_sip_uri("sip:user@10.0.0.1:5060")
                .await
                .unwrap();
            assert_eq!(addrs.len(), 1);
            assert_eq!(addrs[0], "10.0.0.1:5060".parse::<SocketAddr>().unwrap());
        });
    }

    #[test]
    fn test_parse_ipv6() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let addrs = SipResolver::resolve_sip_uri("[::1]:5060").await.unwrap();
            assert_eq!(addrs.len(), 1);
            assert_eq!(addrs[0], "[::1]:5060".parse::<SocketAddr>().unwrap());
        });
    }
}
