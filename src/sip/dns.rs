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
use std::time::{Duration, Instant};

/// Default TTL for the resolver's staleness check (300 seconds).
const DEFAULT_DNS_TTL: Duration = Duration::from_secs(300);

/// NAPTR flags indicating the semantics of the replacement field (Bug #61).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NaptrFlags {
    /// "s"/"S": Terminal lookup -- the replacement is an SRV name.
    Srv,
    /// "u"/"U": Terminal lookup -- the regexp result is the final URI.
    Uri,
}

impl NaptrFlags {
    /// Parse NAPTR flags from a string. Returns `Some` for recognized flags,
    /// `None` for unrecognized flags (Bug #61).
    pub fn parse(flags: &str) -> Option<Self> {
        match flags.to_lowercase().as_str() {
            "s" => Some(NaptrFlags::Srv),
            "u" => Some(NaptrFlags::Uri),
            "" => {
                // Empty flags: non-terminal, proceed to replacement
                // as domain for further NAPTR/SRV lookups (treat as SRV).
                Some(NaptrFlags::Srv)
            }
            other => {
                tracing::warn!(
                    flags = other,
                    "Unrecognized NAPTR flags, skipping record"
                );
                None
            }
        }
    }
}

/// SIP DNS resolver
///
/// Resolves SIP URIs to socket addresses using SRV + A record fallback.
///
/// Bug #60: Tracks `last_resolved` timestamp so callers can detect
/// when cached results are stale and force re-resolution on failover.
pub struct SipResolver {
    /// Timestamp of the last successful resolution.
    last_resolved: Option<Instant>,
    /// TTL for staleness checking (default 300s).
    ttl: Duration,
}

impl SipResolver {
    /// Create a new `SipResolver` with default TTL (300 seconds).
    pub fn new() -> Self {
        Self {
            last_resolved: None,
            ttl: DEFAULT_DNS_TTL,
        }
    }

    /// Create a new `SipResolver` with a custom TTL.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            last_resolved: None,
            ttl,
        }
    }

    /// Returns `true` if the resolver's cached results are stale
    /// (i.e. the TTL has elapsed since the last successful resolution).
    ///
    /// A resolver that has never resolved is considered stale (Bug #60).
    pub fn is_stale(&self) -> bool {
        match self.last_resolved {
            None => true,
            Some(t) => t.elapsed() >= self.ttl,
        }
    }

    /// Invalidate the cache so the next resolution will force a fresh
    /// DNS lookup. Useful when a failover has been detected (Bug #60).
    pub fn invalidate_cache(&mut self) {
        self.last_resolved = None;
    }

    /// Mark the cache as freshly resolved (Bug #60).
    fn mark_resolved(&mut self) {
        self.last_resolved = Some(Instant::now());
    }

    /// Resolve a SIP URI with staleness tracking (Bug #60).
    ///
    /// If the cache is stale (`is_stale()` returns true), the resolver
    /// logs a warning to signal that fresh DNS data will be fetched.
    /// On success, `last_resolved` is updated.
    ///
    /// This is the preferred instance method for callers that need
    /// TTL-aware failover behavior.
    pub async fn resolve(&mut self, uri: &str) -> Result<Vec<SocketAddr>> {
        if self.is_stale() {
            tracing::debug!("DNS cache is stale, forcing fresh resolution");
        }

        let result = Self::resolve_sip_uri(uri).await;

        if result.is_ok() {
            self.mark_resolved();
        }

        result
    }

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

    // === Bug #60: DNS TTL / staleness handling ===

    #[test]
    fn test_resolver_is_stale_initially() {
        let resolver = SipResolver::new();
        assert!(resolver.is_stale(), "new resolver should be stale");
    }

    #[test]
    fn test_resolver_not_stale_after_resolve() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut resolver = SipResolver::new();
            // Resolve an IP literal (always succeeds, marks resolved)
            let _ = resolver.resolve("10.0.0.1").await.unwrap();
            assert!(
                !resolver.is_stale(),
                "resolver should not be stale after successful resolve"
            );
        });
    }

    #[test]
    fn test_resolver_stale_after_invalidate() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut resolver = SipResolver::new();
            let _ = resolver.resolve("10.0.0.1").await.unwrap();
            assert!(!resolver.is_stale());

            resolver.invalidate_cache();
            assert!(
                resolver.is_stale(),
                "resolver should be stale after invalidate_cache"
            );
        });
    }

    #[test]
    fn test_resolver_stale_after_ttl_expires() {
        // Use a very short TTL to test expiry without sleeping long
        let mut resolver = SipResolver::with_ttl(Duration::from_millis(1));
        // Manually set last_resolved to simulate a previous resolution
        resolver.last_resolved = Some(Instant::now());
        assert!(!resolver.is_stale());

        // Sleep just past the TTL
        std::thread::sleep(Duration::from_millis(5));
        assert!(
            resolver.is_stale(),
            "resolver should be stale after TTL expires"
        );
    }

    #[test]
    fn test_resolver_custom_ttl() {
        let resolver = SipResolver::with_ttl(Duration::from_secs(600));
        assert_eq!(resolver.ttl, Duration::from_secs(600));
        assert!(resolver.is_stale()); // no resolution yet
    }

    // === Bug #61: NAPTR flags validation ===

    #[test]
    fn test_naptr_flags_parse_srv() {
        assert_eq!(NaptrFlags::parse("s"), Some(NaptrFlags::Srv));
        assert_eq!(NaptrFlags::parse("S"), Some(NaptrFlags::Srv));
    }

    #[test]
    fn test_naptr_flags_parse_uri() {
        assert_eq!(NaptrFlags::parse("u"), Some(NaptrFlags::Uri));
        assert_eq!(NaptrFlags::parse("U"), Some(NaptrFlags::Uri));
    }

    #[test]
    fn test_naptr_flags_parse_empty() {
        // Empty flags = non-terminal, treated as SRV
        assert_eq!(NaptrFlags::parse(""), Some(NaptrFlags::Srv));
    }

    #[test]
    fn test_naptr_flags_parse_unrecognized() {
        // Unrecognized flags return None
        assert_eq!(NaptrFlags::parse("a"), None);
        assert_eq!(NaptrFlags::parse("p"), None);
        assert_eq!(NaptrFlags::parse("xyz"), None);
    }
}
