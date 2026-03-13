//! NAT keepalive -- periodic STUN binding indications
//!
//! Sends periodic STUN packets to maintain NAT binding entries.
//! Also detects NAT rebinding (reflexive address change) and
//! notifies the caller to trigger re-INVITE / SDP renegotiation.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::stun::client::StunClient;

/// Default keepalive interval range
pub const DEFAULT_KEEPALIVE_MIN_SECS: u64 = 15;
pub const DEFAULT_KEEPALIVE_MAX_SECS: u64 = 25;

/// Absolute minimum keepalive interval (floor for adaptive halving)
const ADAPTIVE_MIN_INTERVAL_SECS: u64 = 5;

/// Number of consecutive stable keepalives before increasing interval
const STABLE_THRESHOLD: u32 = 10;

/// NAT keepalive task
pub struct NatKeepalive {
    /// Socket to send keepalives on
    socket: Arc<UdpSocket>,
    /// STUN server to send keepalives to
    stun_server: SocketAddr,
    /// Minimum interval between keepalives
    min_interval: Duration,
    /// Maximum interval between keepalives
    max_interval: Duration,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Current effective minimum interval (adapts on rebinding)
    effective_min: Arc<Mutex<Duration>>,
    /// Bug #52: Whether a rebinding has been detected.
    /// After a rebinding, we require STABLE_THRESHOLD consecutive stable
    /// cycles from the LAST rebind before increasing the interval.
    rebind_occurred: Arc<AtomicBool>,
    /// Bug #52: Consecutive stable cycles since last rebinding
    stable_count_since_rebind: Arc<Mutex<u32>>,
    /// Bug #103: Store the background task handle to prevent task leaks.
    /// The Drop implementation calls stop() to signal the task to exit.
    task_handle: Mutex<Option<tokio::task::AbortHandle>>,
}

impl NatKeepalive {
    pub fn new(
        socket: Arc<UdpSocket>,
        stun_server: SocketAddr,
        min_interval: Duration,
        max_interval: Duration,
    ) -> Self {
        Self {
            socket,
            stun_server,
            min_interval,
            max_interval,
            running: Arc::new(AtomicBool::new(false)),
            effective_min: Arc::new(Mutex::new(min_interval)),
            rebind_occurred: Arc::new(AtomicBool::new(false)),
            stable_count_since_rebind: Arc::new(Mutex::new(0)),
            task_handle: Mutex::new(None),
        }
    }

    /// Get the current effective minimum interval
    pub fn effective_min_interval(&self) -> Duration {
        *self.effective_min.lock()
    }

    /// Start the keepalive loop as a background task.
    ///
    /// If `addr_change_tx` is provided, sends the new reflexive address
    /// when a NAT rebinding is detected.
    ///
    /// Implements adaptive keepalive: if NAT rebinding is detected, halve the
    /// interval (down to a minimum of 5 seconds). If stable for 10 consecutive
    /// keepalives after the LAST rebinding, increase interval by 25% (up to max).
    ///
    /// Bug #52 fix: Stability counting only begins after a rebinding event.
    /// Flapping back to the original address is treated as a rebinding
    /// (address changed), not as stability.
    pub fn start(
        self: &Arc<Self>,
        addr_change_tx: Option<mpsc::Sender<SocketAddr>>,
    ) -> tokio::task::JoinHandle<()> {
        self.running.store(true, Ordering::SeqCst);
        let weak = Arc::downgrade(self);

        let handle = tokio::spawn(async move {
            let mut last_reflexive: Option<SocketAddr> = None;
            // Bug #104: The background task now reads `rebind_occurred` from
            // the shared Arc<AtomicBool> (this.rebind_occurred) instead of
            // maintaining a separate local boolean. This ensures consistency
            // between the task's view and external callers using
            // notify_rebinding()/notify_stable(). The stable_count is still
            // local since only the task mutates it during the keepalive loop,
            // but the shared stable_count_since_rebind is kept in sync.
            let mut stable_count: u32 = 0;

            loop {
                let this = match weak.upgrade() {
                    Some(arc) => arc,
                    None => break,
                };

                if !this.running.load(Ordering::SeqCst) {
                    break;
                }

                let eff_min = *this.effective_min.lock();
                let min_secs = eff_min.as_secs_f64();
                let max_secs = this.max_interval.as_secs_f64();
                let interval = Duration::from_secs_f64(
                    min_secs
                        + rand::random::<f64>()
                            * (max_secs - min_secs).max(0.0),
                );

                let stun_server = this.stun_server;
                let socket = Arc::clone(&this.socket);
                let rebind_occurred = Arc::clone(&this.rebind_occurred);
                let effective_min = Arc::clone(&this.effective_min);
                let stable_count_since_rebind =
                    Arc::clone(&this.stable_count_since_rebind);
                let max_interval = this.max_interval;

                // Drop the strong reference before sleeping
                drop(this);

                tokio::time::sleep(interval).await;

                let this = match weak.upgrade() {
                    Some(arc) => arc,
                    None => break,
                };

                if !this.running.load(Ordering::SeqCst) {
                    break;
                }

                let client = StunClient::new(stun_server);
                match client
                    .binding_request_on(&socket, stun_server)
                    .await
                {
                    Ok(reflexive) => {
                        if let Some(prev) = last_reflexive {
                            if prev != reflexive {
                                tracing::warn!(
                                    old = %prev,
                                    new = %reflexive,
                                    "NAT rebinding detected"
                                );
                                if let Some(ref tx) = addr_change_tx {
                                    let _ = tx.send(reflexive).await;
                                }

                                // Adaptive: halve the effective min interval
                                {
                                    let mut eff = effective_min.lock();
                                    let halved = *eff / 2;
                                    let floor = Duration::from_secs(
                                        ADAPTIVE_MIN_INTERVAL_SECS,
                                    );
                                    *eff = halved.max(floor);
                                    tracing::debug!(
                                        new_min_ms = eff.as_millis(),
                                        "Adaptive keepalive: halved interval \
                                         after rebinding"
                                    );
                                }
                                // Bug #52: Reset stable count from the LAST
                                // rebind.
                                stable_count = 0;
                                // Bug #46: Sync shared stable count
                                *stable_count_since_rebind.lock() = stable_count;
                                // Bug #104: Write to shared state so external
                                // callers see the rebinding.
                                rebind_occurred.store(true, Ordering::SeqCst);
                            } else {
                                // Same reflexive address as last time.
                                // Bug #52: Only count toward stability if a
                                // rebinding has occurred. Before any rebinding,
                                // the interval should stay at its configured
                                // value.
                                // Bug #104: Read from shared state for consistency.
                                if rebind_occurred.load(Ordering::SeqCst) {
                                    stable_count += 1;
                                    // Bug #46: Sync shared stable count
                                    *stable_count_since_rebind.lock() =
                                        stable_count;
                                    if stable_count >= STABLE_THRESHOLD {
                                        let mut eff =
                                            effective_min.lock();
                                        let increased =
                                            eff.mul_f64(1.25);
                                        *eff = increased
                                            .min(max_interval);
                                        tracing::debug!(
                                            new_min_ms = eff.as_millis(),
                                            "Adaptive keepalive: increased \
                                             interval after {} stable cycles",
                                            stable_count
                                        );
                                        stable_count = 0;
                                        // Bug #46: Sync shared stable count
                                        *stable_count_since_rebind.lock() =
                                            stable_count;
                                    }
                                }
                            }
                        }
                        last_reflexive = Some(reflexive);
                    }
                    Err(e) => {
                        tracing::debug!(
                            error = %e,
                            "Keepalive STUN request failed"
                        );
                        let _ = StunClient::send_keepalive(
                            &socket,
                            stun_server,
                        )
                        .await;
                    }
                }

                // Drop the strong reference at the end of the loop iteration
                drop(this);
            }

            tracing::debug!("NAT keepalive task stopped");
        });

        // Bug #15: Store the AbortHandle so Drop can cancel the task
        *self.task_handle.lock() = Some(handle.abort_handle());

        handle
    }

    /// Stop the keepalive loop
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Whether the keepalive is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Simulate a NAT rebinding event for adaptive interval adjustment.
    /// This halves the effective_min interval (down to floor of 5 seconds)
    /// and resets the stable counter.
    /// Intended for testing and for manual triggering when rebinding is
    /// detected through other means (e.g., SIP Via received= mismatch).
    pub fn notify_rebinding(&self) {
        let mut eff = self.effective_min.lock();
        let halved = *eff / 2;
        let floor = Duration::from_secs(ADAPTIVE_MIN_INTERVAL_SECS);
        *eff = halved.max(floor);
        // Bug #52: mark that a rebinding has occurred and reset stable count
        self.rebind_occurred.store(true, Ordering::SeqCst);
        *self.stable_count_since_rebind.lock() = 0;
    }

    /// Simulate stability: if a rebinding has occurred, count consecutive
    /// stable cycles.  Only increase the interval after STABLE_THRESHOLD
    /// consecutive stable cycles since the LAST rebinding.
    ///
    /// Bug #52 fix: Before any rebinding has occurred, this is a no-op
    /// (the interval stays at its configured value).  After a rebinding,
    /// the counter must reach STABLE_THRESHOLD before the interval is
    /// increased.  This prevents premature recovery when the address
    /// flaps back to the original.
    pub fn notify_stable(&self) {
        // If no rebinding has ever occurred, don't increase the interval
        if !self.rebind_occurred.load(Ordering::SeqCst) {
            return;
        }

        // Bug #45: Lock effective_min first, then stable_count_since_rebind
        // to match the lock ordering in notify_rebinding() and avoid deadlock.
        let mut eff = self.effective_min.lock();
        let mut count = self.stable_count_since_rebind.lock();
        *count += 1;
        if *count >= STABLE_THRESHOLD {
            let increased = eff.mul_f64(1.25);
            *eff = increased.min(self.max_interval);
            *count = 0;
        }
    }

    /// Whether a rebinding has been detected (useful for testing)
    pub fn has_rebind_occurred(&self) -> bool {
        self.rebind_occurred.load(Ordering::SeqCst)
    }

    /// Current consecutive stable count since last rebind (useful for testing)
    pub fn stable_count(&self) -> u32 {
        *self.stable_count_since_rebind.lock()
    }
}

/// Bug #103 fix: Implement Drop to stop the keepalive task and prevent leaks.
/// When the NatKeepalive struct is dropped, we signal the background task to
/// stop and abort the JoinHandle if it was stored.
impl Drop for NatKeepalive {
    fn drop(&mut self) {
        self.stop();
        if let Some(handle) = self.task_handle.lock().take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_keepalive() -> NatKeepalive {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let socket = rt.block_on(async {
            Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())
        });
        let stun_server: SocketAddr = "127.0.0.1:3478".parse().unwrap();
        NatKeepalive::new(
            socket,
            stun_server,
            Duration::from_secs(20),
            Duration::from_secs(30),
        )
    }

    #[test]
    fn test_initial_effective_min_equals_min_interval() {
        let ka = make_keepalive();
        assert_eq!(ka.effective_min_interval(), Duration::from_secs(20));
    }

    #[test]
    fn test_rebinding_halves_interval() {
        let ka = make_keepalive();
        assert_eq!(ka.effective_min_interval(), Duration::from_secs(20));

        // First rebinding: 20s -> 10s
        ka.notify_rebinding();
        assert_eq!(ka.effective_min_interval(), Duration::from_secs(10));

        // Second rebinding: 10s -> 5s (floor)
        ka.notify_rebinding();
        assert_eq!(ka.effective_min_interval(), Duration::from_secs(5));

        // Third rebinding: should stay at 5s floor
        ka.notify_rebinding();
        assert_eq!(ka.effective_min_interval(), Duration::from_secs(5));
    }

    #[test]
    fn test_stability_increases_interval_only_after_rebind() {
        let ka = make_keepalive();

        // Bug #52: Before any rebinding, notify_stable is a no-op
        for _ in 0..20 {
            ka.notify_stable();
        }
        assert_eq!(ka.effective_min_interval(), Duration::from_secs(20));

        // After a rebinding, stability counting begins
        ka.notify_rebinding();
        assert_eq!(ka.effective_min_interval(), Duration::from_secs(10));

        // Need STABLE_THRESHOLD (10) stable cycles to increase
        for _ in 0..9 {
            ka.notify_stable();
        }
        // Still at 10s -- not yet at threshold
        assert_eq!(ka.effective_min_interval(), Duration::from_secs(10));

        // 10th stable cycle triggers increase: 10s * 1.25 = 12.5s
        ka.notify_stable();
        let eff = ka.effective_min_interval();
        assert!(
            eff >= Duration::from_millis(12_400)
                && eff <= Duration::from_millis(12_600)
        );
    }

    #[test]
    fn test_stability_capped_at_max() {
        let ka = make_keepalive();
        // max_interval is 30s

        // Need a rebinding first to enable stability counting
        ka.notify_rebinding();

        // Increase many times -- should cap at 30s
        for _ in 0..200 {
            ka.notify_stable();
        }
        assert_eq!(ka.effective_min_interval(), Duration::from_secs(30));
    }

    #[test]
    fn test_rebinding_then_recovery() {
        let ka = make_keepalive();

        // Normal: 20s
        assert_eq!(ka.effective_min_interval(), Duration::from_secs(20));

        // Rebinding: 20 -> 10
        ka.notify_rebinding();
        assert_eq!(ka.effective_min_interval(), Duration::from_secs(10));

        // Need 10 stable cycles to recover
        for _ in 0..10 {
            ka.notify_stable();
        }
        let eff = ka.effective_min_interval();
        // 10 * 1.25 = 12.5
        assert!(eff > Duration::from_secs(10));
        assert!(eff < Duration::from_secs(15));
    }

    // --- Bug #52 tests: rebind tracking prevents premature increase ---

    #[test]
    fn test_flap_back_to_original_is_not_stable() {
        // Bug #52 scenario: address A -> B -> A.
        // The flap back to A should be treated as a rebinding (because
        // the address changed), not as stability.
        //
        // We simulate this via the notify_ helpers:
        let ka = make_keepalive();
        assert_eq!(ka.effective_min_interval(), Duration::from_secs(20));

        // First rebinding (A -> B): 20 -> 10
        ka.notify_rebinding();
        assert_eq!(ka.effective_min_interval(), Duration::from_secs(10));
        assert!(ka.has_rebind_occurred());
        assert_eq!(ka.stable_count(), 0);

        // 5 stable cycles
        for _ in 0..5 {
            ka.notify_stable();
        }
        assert_eq!(ka.stable_count(), 5);

        // Flap back (B -> A): treated as another rebinding
        ka.notify_rebinding();
        assert_eq!(ka.stable_count(), 0); // reset!
        // Interval halved again: 10 -> 5 (floor)
        assert_eq!(ka.effective_min_interval(), Duration::from_secs(5));

        // Need full STABLE_THRESHOLD from the LAST rebinding
        for _ in 0..9 {
            ka.notify_stable();
        }
        // Still at 5s -- not yet at threshold
        assert_eq!(ka.effective_min_interval(), Duration::from_secs(5));

        // 10th stable cycle: 5 * 1.25 = 6.25s
        ka.notify_stable();
        let eff = ka.effective_min_interval();
        assert!(eff > Duration::from_secs(5));
        assert!(eff < Duration::from_secs(7));
    }

    #[test]
    fn test_no_premature_increase_without_rebind() {
        // Bug #52: If no rebinding has occurred at all, calling
        // notify_stable should not increase the interval.
        let ka = make_keepalive();
        assert!(!ka.has_rebind_occurred());

        for _ in 0..100 {
            ka.notify_stable();
        }
        // Interval must remain at original 20s
        assert_eq!(ka.effective_min_interval(), Duration::from_secs(20));
    }

    #[test]
    fn test_rebinding_resets_stable_count() {
        let ka = make_keepalive();

        // Trigger a rebinding to start stability counting
        ka.notify_rebinding();
        assert_eq!(ka.stable_count(), 0);

        // Accumulate 8 stable cycles
        for _ in 0..8 {
            ka.notify_stable();
        }
        assert_eq!(ka.stable_count(), 8);

        // Another rebinding resets the counter
        ka.notify_rebinding();
        assert_eq!(ka.stable_count(), 0);
    }
}
