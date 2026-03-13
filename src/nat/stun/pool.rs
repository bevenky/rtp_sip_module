//! STUN server pool with failover and health tracking
//!
//! Manages multiple STUN servers, tracks their health (response time, failure count),
//! and provides automatic failover when the primary server is unreachable.
//!
//! Selection strategy: prefer the fastest responding healthy server.
//! After 3 consecutive failures, a server is marked unhealthy and deprioritized.
//! Unhealthy servers are periodically probed (every 30s) to detect recovery.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::net::UdpSocket;

use super::client::StunClient;
use crate::error::{Result, RtpSipError};

/// Per-attempt timeout before trying the next server
const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(500);

/// Number of consecutive failures before marking a server unhealthy
const UNHEALTHY_THRESHOLD: u32 = 3;

/// How often to probe unhealthy servers for recovery
const PROBE_INTERVAL: Duration = Duration::from_secs(30);

/// Health state for a single STUN server
#[derive(Debug, Clone)]
struct ServerHealth {
    /// The server address
    addr: SocketAddr,
    /// Number of consecutive failures
    failure_count: u32,
    /// Last successful response time (if any)
    last_success: Option<Instant>,
    /// Average response time in microseconds (exponential moving average)
    avg_response_us: Option<u64>,
    /// When this server was last probed (success or failure)
    last_probe: Option<Instant>,
}

impl ServerHealth {
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            failure_count: 0,
            last_success: None,
            avg_response_us: None,
            last_probe: None,
        }
    }

    fn is_healthy(&self) -> bool {
        self.failure_count < UNHEALTHY_THRESHOLD
    }

    fn record_success(&mut self, response_time: Duration) {
        self.failure_count = 0;
        self.last_success = Some(Instant::now());
        self.last_probe = Some(Instant::now());
        let rtt_us = response_time.as_micros() as u64;
        self.avg_response_us = Some(match self.avg_response_us {
            Some(prev) => (prev * 7 + rtt_us) / 8, // EWMA with alpha=1/8
            None => rtt_us,
        });
    }

    fn record_failure(&mut self) {
        self.failure_count = self.failure_count.saturating_add(1);
        self.last_probe = Some(Instant::now());
    }

    /// Whether this server should be probed for recovery
    fn should_probe(&self, now: Instant) -> bool {
        if self.is_healthy() {
            return false;
        }
        match self.last_probe {
            Some(last) => now.duration_since(last) >= PROBE_INTERVAL,
            None => true,
        }
    }

    /// Sort key: healthy servers first, then by average response time.
    /// Returns (priority_tier, avg_response_us).
    /// Lower is better for both fields.
    fn sort_key(&self) -> (u8, u64) {
        let tier = if self.is_healthy() { 0 } else { 1 };
        let rtt = self.avg_response_us.unwrap_or(u64::MAX);
        (tier, rtt)
    }
}

/// A pool of STUN servers with health tracking and automatic failover.
///
/// Usage:
/// ```rust,no_run
/// use std::net::SocketAddr;
/// use rtpsip::nat::stun::StunServerPool;
///
/// let servers: Vec<SocketAddr> = vec![
///     "74.125.250.129:19302".parse().unwrap(),
///     "64.233.161.127:19302".parse().unwrap(),
/// ];
/// let pool = StunServerPool::new(servers);
/// // let addr = pool.binding_request().await?;
/// ```
pub struct StunServerPool {
    servers: Mutex<Vec<ServerHealth>>,
}

impl StunServerPool {
    /// Create a new pool from a list of STUN server addresses.
    ///
    /// The first address is treated as the initial primary. At least one server
    /// is required.
    ///
    /// # Panics
    /// Panics if `servers` is empty.
    pub fn new(servers: Vec<SocketAddr>) -> Self {
        assert!(!servers.is_empty(), "StunServerPool requires at least one server");
        let health: Vec<ServerHealth> = servers.into_iter().map(ServerHealth::new).collect();
        Self {
            servers: Mutex::new(health),
        }
    }

    /// Perform a STUN Binding Request with failover across pool servers.
    ///
    /// Tries the best (fastest healthy) server first. If it fails or times out
    /// after 500ms, tries the next server, and so on.
    pub async fn binding_request(&self) -> Result<SocketAddr> {
        // Bug #3 fix: Check if the best server is IPv6 and bind accordingly.
        // Binding to "0.0.0.0:0" would fail when sending to an IPv6 server.
        let bind_addr = match self.best_server() {
            Some(addr) if addr.is_ipv6() => "[::]:0",
            _ => "0.0.0.0:0",
        };
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(RtpSipError::Io)?;
        self.binding_request_on(&socket).await
    }

    /// Perform a STUN Binding Request on a specific socket, with failover.
    pub async fn binding_request_on(&self, socket: &UdpSocket) -> Result<SocketAddr> {
        let ordered = self.servers_by_priority();
        if ordered.is_empty() {
            return Err(RtpSipError::Config(
                "No STUN servers in pool".to_string(),
            ));
        }

        let mut last_err = None;

        for addr in &ordered {
            let start = Instant::now();
            let client = StunClient::new(*addr);
            match tokio::time::timeout(
                ATTEMPT_TIMEOUT,
                client.binding_request_on(socket, *addr),
            )
            .await
            {
                Ok(Ok(reflexive)) => {
                    let elapsed = start.elapsed();
                    self.record_success(*addr, elapsed);
                    return Ok(reflexive);
                }
                Ok(Err(e)) => {
                    self.record_failure(*addr);
                    tracing::debug!(
                        server = %addr,
                        error = %e,
                        "STUN server failed, trying next"
                    );
                    last_err = Some(e);
                }
                Err(_) => {
                    // Timeout
                    self.record_failure(*addr);
                    tracing::debug!(
                        server = %addr,
                        "STUN server timed out ({}ms), trying next",
                        ATTEMPT_TIMEOUT.as_millis()
                    );
                    last_err = Some(RtpSipError::Timeout(format!(
                        "STUN server {} timed out",
                        addr
                    )));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            RtpSipError::Timeout("All STUN servers failed or unreachable".to_string())
        }))
    }

    /// Perform a binding request on a shared socket (Arc).
    pub async fn binding_request_shared(
        &self,
        socket: &Arc<UdpSocket>,
    ) -> Result<SocketAddr> {
        self.binding_request_on(socket).await
    }

    /// Probe unhealthy servers to detect recovery.
    ///
    /// This should be called periodically (e.g., every 30s from a background task).
    /// It only probes servers that are currently unhealthy and haven't been
    /// probed recently.
    pub async fn probe_unhealthy(&self) {
        let now = Instant::now();
        let to_probe: Vec<SocketAddr> = {
            let servers = self.servers.lock();
            servers
                .iter()
                .filter(|s| s.should_probe(now))
                .map(|s| s.addr)
                .collect()
        };

        for addr in to_probe {
            let client = StunClient::new(addr);
            let start = Instant::now();
            match tokio::time::timeout(ATTEMPT_TIMEOUT, client.binding_request()).await {
                Ok(Ok(_)) => {
                    let elapsed = start.elapsed();
                    self.record_success(addr, elapsed);
                    tracing::info!(server = %addr, "STUN server recovered");
                }
                _ => {
                    self.record_failure(addr);
                    tracing::debug!(server = %addr, "STUN server still unhealthy");
                }
            }
        }
    }

    /// Start a background task that probes unhealthy servers every 30 seconds.
    ///
    /// Returns a handle that stops the probe task when dropped.
    pub fn start_probe_task(self: &Arc<Self>) -> ProbeTaskHandle {
        let pool = Arc::clone(self);
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(PROBE_INTERVAL);
            interval.tick().await; // skip immediate first tick
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        pool.probe_unhealthy().await;
                    }
                    _ = &mut rx => {
                        break;
                    }
                }
            }
        });

        ProbeTaskHandle { _cancel: tx }
    }

    /// Get the current best server (fastest healthy server).
    pub fn best_server(&self) -> Option<SocketAddr> {
        let servers = self.servers.lock();
        servers
            .iter()
            .filter(|s| s.is_healthy())
            .min_by_key(|s| s.sort_key())
            .map(|s| s.addr)
    }

    /// Get a snapshot of server health for diagnostics.
    pub fn server_stats(&self) -> Vec<ServerStats> {
        let servers = self.servers.lock();
        servers
            .iter()
            .map(|s| ServerStats {
                addr: s.addr,
                healthy: s.is_healthy(),
                failure_count: s.failure_count,
                avg_response_ms: s.avg_response_us.map(|us| us as f64 / 1000.0),
            })
            .collect()
    }

    /// Get servers ordered by priority (healthy + fastest first).
    fn servers_by_priority(&self) -> Vec<SocketAddr> {
        let mut servers = self.servers.lock().clone();
        servers.sort_by_key(|s| s.sort_key());
        servers.into_iter().map(|s| s.addr).collect()
    }

    fn record_success(&self, addr: SocketAddr, response_time: Duration) {
        let mut servers = self.servers.lock();
        if let Some(s) = servers.iter_mut().find(|s| s.addr == addr) {
            s.record_success(response_time);
        }
    }

    fn record_failure(&self, addr: SocketAddr) {
        let mut servers = self.servers.lock();
        if let Some(s) = servers.iter_mut().find(|s| s.addr == addr) {
            s.record_failure();
        }
    }
}

/// Diagnostic snapshot of a single server's health.
#[derive(Debug, Clone)]
pub struct ServerStats {
    pub addr: SocketAddr,
    pub healthy: bool,
    pub failure_count: u32,
    pub avg_response_ms: Option<f64>,
}

/// Handle for the background probe task. Stops the task when dropped.
pub struct ProbeTaskHandle {
    _cancel: tokio::sync::oneshot::Sender<()>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn test_new_pool_requires_servers() {
        let pool = StunServerPool::new(vec![addr(3478)]);
        assert_eq!(pool.server_stats().len(), 1);
    }

    #[test]
    #[should_panic(expected = "StunServerPool requires at least one server")]
    fn test_new_pool_empty_panics() {
        StunServerPool::new(vec![]);
    }

    #[test]
    fn test_all_servers_start_healthy() {
        let pool = StunServerPool::new(vec![addr(3478), addr(3479), addr(3480)]);
        let stats = pool.server_stats();
        assert!(stats.iter().all(|s| s.healthy));
        assert!(stats.iter().all(|s| s.failure_count == 0));
    }

    #[test]
    fn test_server_becomes_unhealthy_after_threshold() {
        let pool = StunServerPool::new(vec![addr(3478), addr(3479)]);

        // Record failures up to threshold
        for _ in 0..UNHEALTHY_THRESHOLD {
            pool.record_failure(addr(3478));
        }

        let stats = pool.server_stats();
        assert!(!stats[0].healthy);
        assert!(stats[1].healthy);
    }

    #[test]
    fn test_success_resets_failure_count() {
        let pool = StunServerPool::new(vec![addr(3478)]);

        // Accumulate failures just below threshold
        for _ in 0..(UNHEALTHY_THRESHOLD - 1) {
            pool.record_failure(addr(3478));
        }

        // Success should reset
        pool.record_success(addr(3478), Duration::from_millis(50));

        let stats = pool.server_stats();
        assert!(stats[0].healthy);
        assert_eq!(stats[0].failure_count, 0);
    }

    #[test]
    fn test_success_recovers_unhealthy_server() {
        let pool = StunServerPool::new(vec![addr(3478)]);

        // Mark unhealthy
        for _ in 0..UNHEALTHY_THRESHOLD {
            pool.record_failure(addr(3478));
        }
        assert!(!pool.server_stats()[0].healthy);

        // Recovery
        pool.record_success(addr(3478), Duration::from_millis(30));
        assert!(pool.server_stats()[0].healthy);
    }

    #[test]
    fn test_best_server_prefers_fastest() {
        let pool = StunServerPool::new(vec![addr(3478), addr(3479), addr(3480)]);

        // Simulate different response times
        pool.record_success(addr(3478), Duration::from_millis(100));
        pool.record_success(addr(3479), Duration::from_millis(20));
        pool.record_success(addr(3480), Duration::from_millis(50));

        assert_eq!(pool.best_server(), Some(addr(3479)));
    }

    #[test]
    fn test_best_server_skips_unhealthy() {
        let pool = StunServerPool::new(vec![addr(3478), addr(3479)]);

        // Make the first server fastest but unhealthy
        pool.record_success(addr(3478), Duration::from_millis(10));
        for _ in 0..UNHEALTHY_THRESHOLD {
            pool.record_failure(addr(3478));
        }
        pool.record_success(addr(3479), Duration::from_millis(50));

        assert_eq!(pool.best_server(), Some(addr(3479)));
    }

    #[test]
    fn test_servers_by_priority_order() {
        let pool = StunServerPool::new(vec![addr(3478), addr(3479), addr(3480)]);

        // Make addr(3480) fastest, addr(3478) unhealthy
        pool.record_success(addr(3480), Duration::from_millis(10));
        pool.record_success(addr(3479), Duration::from_millis(50));
        pool.record_success(addr(3478), Duration::from_millis(5));
        for _ in 0..UNHEALTHY_THRESHOLD {
            pool.record_failure(addr(3478));
        }

        let ordered = pool.servers_by_priority();
        // Healthy servers first, ordered by response time
        assert_eq!(ordered[0], addr(3480)); // healthy, 10ms
        assert_eq!(ordered[1], addr(3479)); // healthy, 50ms
        assert_eq!(ordered[2], addr(3478)); // unhealthy, deprioritized
    }

    #[test]
    fn test_avg_response_time_ewma() {
        let pool = StunServerPool::new(vec![addr(3478)]);

        // First measurement sets the baseline
        pool.record_success(addr(3478), Duration::from_millis(100));
        let stats = pool.server_stats();
        let avg1 = stats[0].avg_response_ms.unwrap();
        assert!((avg1 - 100.0).abs() < 1.0);

        // Second measurement: EWMA = (100000*7 + 20000) / 8 = 90000 us = 90ms
        pool.record_success(addr(3478), Duration::from_millis(20));
        let stats = pool.server_stats();
        let avg2 = stats[0].avg_response_ms.unwrap();
        assert!(avg2 < avg1);
        assert!(avg2 > 20.0); // Should be between 20 and 100
    }

    #[test]
    fn test_best_server_returns_none_when_all_unhealthy() {
        let pool = StunServerPool::new(vec![addr(3478), addr(3479)]);

        for _ in 0..UNHEALTHY_THRESHOLD {
            pool.record_failure(addr(3478));
            pool.record_failure(addr(3479));
        }

        assert_eq!(pool.best_server(), None);
    }

    #[test]
    fn test_should_probe_unhealthy() {
        let health = ServerHealth::new(addr(3478));
        // Healthy server should not be probed
        assert!(!health.should_probe(Instant::now()));
    }

    #[test]
    fn test_should_probe_after_interval() {
        let mut health = ServerHealth::new(addr(3478));
        // Mark unhealthy
        for _ in 0..UNHEALTHY_THRESHOLD {
            health.record_failure();
        }
        // Just failed, so last_probe is recent
        assert!(!health.should_probe(Instant::now()));

        // After probe interval, should probe
        let future = Instant::now() + PROBE_INTERVAL + Duration::from_secs(1);
        assert!(health.should_probe(future));
    }

    #[test]
    fn test_server_stats_snapshot() {
        let pool = StunServerPool::new(vec![addr(3478), addr(3479)]);
        pool.record_success(addr(3478), Duration::from_millis(42));
        pool.record_failure(addr(3479));

        let stats = pool.server_stats();
        assert_eq!(stats.len(), 2);

        let s1 = stats.iter().find(|s| s.addr == addr(3478)).unwrap();
        assert!(s1.healthy);
        assert_eq!(s1.failure_count, 0);
        assert!(s1.avg_response_ms.is_some());

        let s2 = stats.iter().find(|s| s.addr == addr(3479)).unwrap();
        assert!(s2.healthy); // one failure is below threshold
        assert_eq!(s2.failure_count, 1);
        assert!(s2.avg_response_ms.is_none());
    }

    #[test]
    fn test_failure_count_saturates() {
        let pool = StunServerPool::new(vec![addr(3478)]);
        // Record many failures — should not overflow
        for _ in 0..1000 {
            pool.record_failure(addr(3478));
        }
        let stats = pool.server_stats();
        assert!(!stats[0].healthy);
        assert_eq!(stats[0].failure_count, 1000);
    }

    #[tokio::test]
    async fn test_binding_request_all_fail() {
        // Use addresses that won't have STUN servers — should fail fast
        let pool = StunServerPool::new(vec![addr(19001), addr(19002)]);
        let result = pool.binding_request().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_probe_unhealthy_no_servers() {
        let pool = StunServerPool::new(vec![addr(3478)]);
        // All healthy — probe should be a no-op
        pool.probe_unhealthy().await;
        let stats = pool.server_stats();
        assert!(stats[0].healthy);
    }
}
