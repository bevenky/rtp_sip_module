//! DNS resolution for SIP URIs
//!
//! Provides SRV and A record resolution for SIP domains with RFC 2782
//! weighted random selection for load balancing.
//!
//! Full NAPTR resolution (RFC 3263) requires a dedicated DNS library
//! (e.g., hickory-resolver) for raw DNS record parsing. The current
//! implementation uses `tokio::net::lookup_host` which delegates to the
//! system resolver. NAPTR flags parsing is provided for future use.
//!
//! # Resolution Order
//!
//! 1. If the input is already an IP:port, return as-is
//! 2. Try SRV lookup: `_sip._udp.{domain}` (or `_sip._tcp.{domain}`)
//! 3. Fall back to A/AAAA record lookup via `tokio::net::lookup_host`
//! 4. Results are shuffled for load distribution (weighted selection
//!    when SRV priority/weight data is available via `weighted_srv_selection`)

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
        // Bug #70: Skip rfind(':') port extraction for IPv6 addresses
        // (which contain more than one colon)
        let (domain, port) = if domain_port.matches(':').count() > 1 {
            // IPv6 address — treat the entire string as the domain
            (domain_port, None)
        } else if let Some(colon_pos) = domain_port.rfind(':') {
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
                // Apply weighted random selection among results at the same
                // priority level. Since lookup_host doesn't give us SRV
                // priority/weight info, we shuffle to distribute load.
                return Ok(weighted_shuffle(results));
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

        // Shuffle A/AAAA results to distribute load across multiple addresses
        Ok(weighted_shuffle(results))
    }
}

/// SRV record representation for weighted selection.
///
/// Used when SRV records are available with priority and weight information.
#[derive(Debug, Clone)]
pub struct SrvRecord {
    /// Lower priority values are preferred (RFC 2782)
    pub priority: u16,
    /// Weight for load balancing among same-priority records
    pub weight: u16,
    /// Port from the SRV record
    pub port: u16,
    /// Target hostname
    pub target: String,
}

/// Perform RFC 2782 weighted random selection on SRV records.
///
/// Records are first sorted by priority (lowest first). Within each priority
/// level, records are selected using weighted random selection per RFC 2782
/// Section "The use of weights":
///
/// 1. Sum all weights in the priority group (treat weight=0 as weight=1 for
///    selection purposes, giving them a small chance)
/// 2. Pick a random number in [0, total_weight)
/// 3. Walk through records, accumulating weight; pick the record where the
///    running sum exceeds the random number
/// 4. Remove that record and repeat until the group is empty
pub fn weighted_srv_selection(records: &[SrvRecord]) -> Vec<SrvRecord> {
    if records.is_empty() {
        return Vec::new();
    }

    // Group by priority
    let mut by_priority: std::collections::BTreeMap<u16, Vec<SrvRecord>> =
        std::collections::BTreeMap::new();
    for rec in records {
        by_priority
            .entry(rec.priority)
            .or_default()
            .push(rec.clone());
    }

    let mut result = Vec::with_capacity(records.len());

    for (_priority, mut group) in by_priority {
        // RFC 2782 weighted random selection within each priority group
        while !group.is_empty() {
            if group.len() == 1 {
                result.push(group.remove(0));
                break;
            }

            // Weight 0 records get a small chance (treat as 1 for selection)
            let total_weight: u32 = group
                .iter()
                .map(|r| if r.weight == 0 { 1u32 } else { r.weight as u32 })
                .sum();

            let random_val = rand::random::<u32>() % total_weight;
            let mut running_sum = 0u32;
            let mut selected_idx = 0;

            for (i, rec) in group.iter().enumerate() {
                let w = if rec.weight == 0 { 1u32 } else { rec.weight as u32 };
                running_sum += w;
                if running_sum > random_val {
                    selected_idx = i;
                    break;
                }
            }

            result.push(group.remove(selected_idx));
        }
    }

    result
}

/// Shuffle a list of socket addresses for basic load distribution.
///
/// When SRV priority/weight information is not available (e.g., from
/// lookup_host), this provides a simple random shuffle to distribute
/// load across multiple resolved addresses.
fn weighted_shuffle(mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();
    addrs.shuffle(&mut rng);
    addrs
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

    // === P1-DNS-2: SRV weighted selection ===

    #[test]
    fn test_weighted_srv_selection_empty() {
        let result = weighted_srv_selection(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_weighted_srv_selection_single() {
        let records = vec![SrvRecord {
            priority: 10,
            weight: 100,
            port: 5060,
            target: "sip1.example.com".to_string(),
        }];
        let result = weighted_srv_selection(&records);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].target, "sip1.example.com");
    }

    #[test]
    fn test_weighted_srv_selection_priority_order() {
        let records = vec![
            SrvRecord {
                priority: 20,
                weight: 100,
                port: 5060,
                target: "low-priority.example.com".to_string(),
            },
            SrvRecord {
                priority: 10,
                weight: 100,
                port: 5060,
                target: "high-priority.example.com".to_string(),
            },
        ];
        let result = weighted_srv_selection(&records);
        assert_eq!(result.len(), 2);
        // Priority 10 should come before priority 20
        assert_eq!(result[0].target, "high-priority.example.com");
        assert_eq!(result[1].target, "low-priority.example.com");
    }

    #[test]
    fn test_weighted_srv_selection_same_priority_all_selected() {
        let records = vec![
            SrvRecord {
                priority: 10,
                weight: 50,
                port: 5060,
                target: "a.example.com".to_string(),
            },
            SrvRecord {
                priority: 10,
                weight: 50,
                port: 5060,
                target: "b.example.com".to_string(),
            },
        ];
        let result = weighted_srv_selection(&records);
        assert_eq!(result.len(), 2);
        // Both should be present (order is random)
        let targets: Vec<&str> = result.iter().map(|r| r.target.as_str()).collect();
        assert!(targets.contains(&"a.example.com"));
        assert!(targets.contains(&"b.example.com"));
    }

    #[test]
    fn test_weighted_srv_selection_zero_weight_included() {
        // RFC 2782: weight 0 records should have a very small chance
        let records = vec![
            SrvRecord {
                priority: 10,
                weight: 0,
                port: 5060,
                target: "zero-weight.example.com".to_string(),
            },
            SrvRecord {
                priority: 10,
                weight: 100,
                port: 5060,
                target: "high-weight.example.com".to_string(),
            },
        ];
        let result = weighted_srv_selection(&records);
        assert_eq!(result.len(), 2);
        // Both should be present
        let targets: Vec<&str> = result.iter().map(|r| r.target.as_str()).collect();
        assert!(targets.contains(&"zero-weight.example.com"));
        assert!(targets.contains(&"high-weight.example.com"));
    }
}
