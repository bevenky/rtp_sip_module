//! Symmetric RTP (RFC 4961) — Sans-IO
//!
//! Learns the actual remote address from incoming RTP/RTCP packets.
//! This is the PRIMARY mechanism for handling ALL NAT types (including
//! Symmetric NAT) in SIP/RTP telephony where one side has a public IP.
//!
//! Battle-tested approach for production RTP NAT traversal, handling
//! every NAT type without requiring TURN.
//!
//! ## How it handles Symmetric NAT
//!
//! 1. Server listens on public IP:port (advertised in SDP)
//! 2. Client behind Symmetric NAT sends RTP -> NAT creates mapping
//!    `NAT_IP:RANDOM_PORT -> Server:Port`
//! 3. Server receives packet from `NAT_IP:RANDOM_PORT` (differs from SDP)
//! 4. Server learns the real address after `threshold` consistent packets
//! 5. Server sends back to `NAT_IP:RANDOM_PORT` -- traverses existing NAT pinhole
//!
//! No TURN needed because the server IS the relay.
//!
//! ## Security
//!
//! The consistency threshold prevents a single spoofed packet from
//! redirecting media traffic. Default threshold=10 for RTP
//! and threshold=1 for RTCP (since RTCP is less frequent).
//!
//! In Always mode, a rate limiter (Bug #51 fix) prevents a spoofed packet
//! storm from continuously flipping the media destination. If more than
//! `max_switches` address changes occur within `switch_window_secs`, the
//! current address is locked.

use std::net::SocketAddr;
use std::time::Instant;

/// Symmetric RTP auto-adjust mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoAdjustMode {
    /// Learn once, then lock to learned address (default)
    Once,
    /// Continuously re-learn if address changes
    /// Use for endpoints that may change ports mid-call (e.g., mobile, call transfer)
    Always,
    /// Disabled -- always use configured address
    Disabled,
}

/// Rate-limiter configuration for Always mode (Bug #51).
///
/// In Always mode, if more than `max_switches` address changes occur within
/// `switch_window_secs`, the current address is locked and no further
/// changes are accepted.
#[derive(Debug, Clone)]
pub struct SwitchRateLimit {
    /// Maximum number of address switches allowed in the window (default 5)
    pub max_switches: u32,
    /// Sliding window duration in seconds (default 10)
    pub switch_window_secs: u64,
}

impl Default for SwitchRateLimit {
    fn default() -> Self {
        Self {
            max_switches: 5,
            switch_window_secs: 10,
        }
    }
}

/// Symmetric RTP handler for a single stream (RTP or RTCP)
///
pub struct SymmetricRtp {
    /// The SDP-configured remote address
    configured_addr: Option<SocketAddr>,
    /// The address we're currently learning from incoming packets
    candidate_addr: Option<SocketAddr>,
    /// Number of packets from candidate address
    tally: u32,
    /// Packets needed to accept candidate (default 10)
    threshold: u32,
    /// Learning window -- max packets to observe before giving up (default = threshold * 2)
    window: u32,
    /// Current window counter (counts down to 0)
    window_remaining: u32,
    /// The accepted learned address (once threshold is met)
    learned_addr: Option<SocketAddr>,
    /// Auto-adjust mode
    mode: AutoAdjustMode,
    /// Total packets processed (for diagnostics)
    packets_processed: u64,

    /// Learned SSRC for validating source consistency (Bug #16)
    learned_ssrc: Option<u32>,

    // --- Rate limiting for Always mode (Bug #51) ---
    /// Rate limit config
    rate_limit: SwitchRateLimit,
    /// Timestamps of recent address switches (sliding window)
    switch_times: Vec<Instant>,
    /// Whether the address has been locked due to excessive switching
    locked: bool,
}

impl SymmetricRtp {
    /// Create a new RTP auto-adjust handler.
    ///
    /// Default: threshold, window=threshold*2, mode=Always.
    /// Always mode keeps learning permanently enabled so that if the remote
    /// changes IP mid-call (network switch, failover), the handler re-learns
    /// the new address. This matches FreeSWITCH default behavior.
    /// For RTCP, use `new_rtcp()` which has threshold=1 (RTCP is infrequent).
    pub fn new(threshold: u32) -> Self {
        let threshold = threshold.max(1);
        Self {
            configured_addr: None,
            candidate_addr: None,
            tally: 0,
            threshold,
            window: threshold * 2,
            window_remaining: threshold * 2,
            learned_addr: None,
            mode: AutoAdjustMode::Always,
            packets_processed: 0,
            learned_ssrc: None,
            rate_limit: SwitchRateLimit::default(),
            switch_times: Vec::new(),
            locked: false,
        }
    }

    /// Create with production defaults (threshold=10, window=20, mode=Always)
    pub fn with_defaults() -> Self {
        let mut s = Self::new(10);
        s.mode = AutoAdjustMode::Always;
        s
    }

    /// Create for RTCP auto-adjust (threshold=1, mode=Always).
    /// RTCP packets are infrequent so we learn from the first one.
    pub fn new_rtcp() -> Self {
        Self {
            configured_addr: None,
            candidate_addr: None,
            tally: 0,
            threshold: 1,
            window: 4, // small window since RTCP is infrequent
            window_remaining: 4,
            learned_addr: None,
            mode: AutoAdjustMode::Always,
            packets_processed: 0,
            learned_ssrc: None,
            rate_limit: SwitchRateLimit::default(),
            switch_times: Vec::new(),
            locked: false,
        }
    }

    /// Create a disabled instance (always uses configured address)
    pub fn disabled() -> Self {
        Self {
            configured_addr: None,
            candidate_addr: None,
            tally: 0,
            threshold: 1,
            window: 0,
            window_remaining: 0,
            learned_addr: None,
            mode: AutoAdjustMode::Disabled,
            packets_processed: 0,
            learned_ssrc: None,
            rate_limit: SwitchRateLimit::default(),
            switch_times: Vec::new(),
            locked: false,
        }
    }

    /// Configure the rate limit for Always mode.
    ///
    /// If more than `max_switches` address changes occur within
    /// `switch_window_secs`, the current address is locked.
    pub fn set_rate_limit(
        &mut self,
        max_switches: u32,
        switch_window_secs: u64,
    ) {
        self.rate_limit = SwitchRateLimit {
            max_switches,
            switch_window_secs,
        };
    }

    /// Whether the address has been locked due to excessive switching
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Set the auto-adjust mode
    pub fn set_mode(&mut self, mode: AutoAdjustMode) {
        self.mode = mode;
        if mode != AutoAdjustMode::Disabled {
            // Re-arm the learning window
            self.window_remaining = self.window;
        }
    }

    /// Set the SDP-configured remote address
    pub fn set_configured(&mut self, addr: SocketAddr) {
        self.configured_addr = Some(addr);
    }

    /// Record an address switch and check rate limit (Always mode only).
    /// Returns true if the switch is allowed, false if locked.
    fn record_switch(&mut self, now: Instant) -> bool {
        if self.mode != AutoAdjustMode::Always {
            return true;
        }

        // Prune entries outside the sliding window
        let window_dur =
            std::time::Duration::from_secs(self.rate_limit.switch_window_secs);
        // Avoid underflow: if now < window_dur (shouldn't happen in practice
        // but can in contrived tests with Instant::now()), keep all entries.
        if let Some(window_start) = now.checked_sub(window_dur) {
            self.switch_times.retain(|&t| t >= window_start);
        }

        // Record this switch
        self.switch_times.push(now);

        // Check if we've exceeded the limit
        if self.switch_times.len() as u32 > self.rate_limit.max_switches {
            tracing::warn!(
                switches = self.switch_times.len(),
                window_secs = self.rate_limit.switch_window_secs,
                max = self.rate_limit.max_switches,
                "Auto-adjust: rate limit exceeded, locking address"
            );
            self.locked = true;
            return false;
        }

        true
    }

    /// Process an incoming packet's source address with SSRC validation (Bug #16).
    ///
    /// If an SSRC is provided, validates it against the previously learned SSRC.
    /// If the SSRC changes, the learning state is reset (candidate_addr cleared,
    /// tally reset to 0) because a new SSRC indicates a different media source
    /// and the previously learned address may no longer be valid.
    ///
    /// Returns true if the learned address changed.
    pub fn process_incoming_with_ssrc(
        &mut self,
        source: SocketAddr,
        ssrc: u32,
    ) -> bool {
        match self.learned_ssrc {
            Some(prev_ssrc) if prev_ssrc != ssrc => {
                tracing::warn!(
                    old_ssrc = prev_ssrc,
                    new_ssrc = ssrc,
                    "SSRC changed, resetting symmetric RTP learning state"
                );
                self.candidate_addr = None;
                self.tally = 0;
                self.learned_ssrc = Some(ssrc);
            }
            None => {
                self.learned_ssrc = Some(ssrc);
            }
            _ => {}
        }
        self.process_incoming_with_time(source, Instant::now())
    }

    /// Process an incoming packet's source address.
    ///
    /// Returns true if the learned address changed (caller must update send target).
    ///
    /// Algorithm:
    ///
    /// 1. If disabled or window expired (in Once mode), skip
    /// 2. If locked (rate limit exceeded in Always mode), skip
    /// 3. If source matches configured or already-learned addr, no action
    /// 4. If source matches candidate, increment tally
    /// 5. If tally >= threshold, accept candidate as learned addr
    /// 6. If new source, reset candidate and tally
    /// 7. Decrement window; if 0 in Once mode, stop learning
    pub fn process_incoming(&mut self, source: SocketAddr) -> bool {
        self.process_incoming_with_time(source, Instant::now())
    }

    /// Like `process_incoming` but accepts an explicit timestamp
    /// (for testing the rate limiter).
    pub fn process_incoming_with_time(
        &mut self,
        source: SocketAddr,
        now: Instant,
    ) -> bool {
        self.packets_processed += 1;

        if self.mode == AutoAdjustMode::Disabled {
            return false;
        }

        // Bug #51: If locked due to rate-limit, reject all changes
        if self.locked {
            return false;
        }

        // Check if learning window has expired (Once mode only)
        if self.mode == AutoAdjustMode::Once && self.window_remaining == 0 {
            return false;
        }

        // If source matches configured addr, nothing to learn.
        // Bug #30: Do NOT decrement the learning window here — packets from the
        // configured address are expected traffic and should not consume the
        // window budget that exists to learn a *different* (NATted) address.
        if self.configured_addr == Some(source) {
            return false;
        }

        // If we already learned this address, nothing changed
        if self.learned_addr == Some(source) {
            return false;
        }

        // Check if this matches our current candidate
        if self.candidate_addr == Some(source) {
            self.tally += 1;
            if self.tally >= self.threshold {
                let old = self.learned_addr;

                // Bug #51: rate-limit check before accepting the switch
                let is_switch = old.is_some() && old != Some(source);
                if is_switch && !self.record_switch(now) {
                    return false;
                }

                self.learned_addr = Some(source);

                tracing::info!(
                    old_addr = ?old.or(self.configured_addr),
                    learned = %source,
                    packets = self.packets_processed,
                    "Auto-adjust: learned remote address"
                );

                // In Once mode, stop learning after successful adjustment
                if self.mode == AutoAdjustMode::Once {
                    self.window_remaining = 0;
                }

                return old != Some(source);
            }
        } else {
            // New candidate -- reset learning
            self.candidate_addr = Some(source);
            self.tally = 1;

            // Threshold of 1 means accept immediately
            if self.threshold <= 1 {
                let old = self.learned_addr;

                // Bug #51: rate-limit check before accepting the switch
                let is_switch = old.is_some() && old != Some(source);
                if is_switch && !self.record_switch(now) {
                    return false;
                }

                self.learned_addr = Some(source);

                tracing::info!(
                    old_addr = ?old.or(self.configured_addr),
                    learned = %source,
                    "Auto-adjust: learned remote address (threshold=1)"
                );

                if self.mode == AutoAdjustMode::Once {
                    self.window_remaining = 0;
                }

                return old != Some(source);
            }
        }

        if self.mode == AutoAdjustMode::Once {
            self.decrement_window();
        }

        false
    }

    /// Decrement window counter
    fn decrement_window(&mut self) {
        if self.window_remaining > 0 {
            self.window_remaining -= 1;
            if self.window_remaining == 0 {
                tracing::debug!(
                    "Auto-adjust: learning window expired without adjustment"
                );
            }
        }
    }

    /// Re-arm the learning window (e.g., after re-INVITE or call transfer)
    pub fn rearm(&mut self) {
        self.window_remaining = self.window;
        self.candidate_addr = None;
        self.tally = 0;
        // Don't clear learned_addr -- keep using it until a new one is confirmed
    }

    /// Get the effective remote address for sending.
    /// Returns learned address if available, otherwise configured address.
    pub fn effective_remote(&self) -> Option<SocketAddr> {
        self.learned_addr.or(self.configured_addr)
    }

    /// Whether an address has been learned (different from configured)
    pub fn has_learned(&self) -> bool {
        self.learned_addr.is_some()
            && self.learned_addr != self.configured_addr
    }

    /// Whether the learning window is still open
    pub fn is_learning(&self) -> bool {
        match self.mode {
            AutoAdjustMode::Disabled => false,
            AutoAdjustMode::Always => !self.locked,
            AutoAdjustMode::Once => self.window_remaining > 0,
        }
    }

    /// Reset all state (e.g., on SDP renegotiation)
    pub fn reset(&mut self) {
        self.learned_addr = None;
        self.candidate_addr = None;
        self.tally = 0;
        self.window_remaining = self.window;
        self.packets_processed = 0;
        self.learned_ssrc = None;
        self.switch_times.clear();
        self.locked = false;
    }

    /// Get the current mode
    pub fn mode(&self) -> AutoAdjustMode {
        self.mode
    }

    /// Total packets processed
    pub fn packets_processed(&self) -> u64 {
        self.packets_processed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled() {
        let mut srtp = SymmetricRtp::disabled();
        let configured: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        srtp.set_configured(configured);

        let natted: SocketAddr = "203.0.113.5:12345".parse().unwrap();
        assert!(!srtp.process_incoming(natted));
        assert_eq!(srtp.effective_remote(), Some(configured));
        assert!(!srtp.is_learning());
    }

    #[test]
    fn test_no_learning_if_matches_configured() {
        let mut srtp = SymmetricRtp::new(3);
        let configured: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        srtp.set_configured(configured);

        assert!(!srtp.process_incoming(configured));
        assert!(!srtp.has_learned());
        assert_eq!(srtp.effective_remote(), Some(configured));
    }

    #[test]
    fn test_learns_after_threshold() {
        let mut srtp = SymmetricRtp::new(3);
        let configured: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let natted: SocketAddr = "203.0.113.5:12345".parse().unwrap();

        srtp.set_configured(configured);
        assert!(srtp.is_learning());

        // Below threshold -- no learning
        assert!(!srtp.process_incoming(natted));
        assert!(!srtp.process_incoming(natted));
        assert!(!srtp.has_learned());

        // Meets threshold
        assert!(srtp.process_incoming(natted));
        assert!(srtp.has_learned());
        assert_eq!(srtp.effective_remote(), Some(natted));
    }

    #[test]
    fn test_production_defaults() {
        let mut srtp = SymmetricRtp::with_defaults();
        srtp.set_configured("10.0.0.1:5000".parse().unwrap());

        let natted: SocketAddr = "203.0.113.5:12345".parse().unwrap();

        // Need 10 packets to learn (default threshold)
        for _ in 0..9 {
            assert!(!srtp.process_incoming(natted));
        }
        assert!(!srtp.has_learned());

        // 10th packet triggers learning
        assert!(srtp.process_incoming(natted));
        assert!(srtp.has_learned());
        assert_eq!(srtp.effective_remote(), Some(natted));
    }

    #[test]
    fn test_rtcp_threshold_one() {
        let mut srtp = SymmetricRtp::new_rtcp();
        srtp.set_configured("10.0.0.1:5001".parse().unwrap());

        let natted: SocketAddr = "203.0.113.5:12346".parse().unwrap();
        assert!(srtp.process_incoming(natted));
        assert_eq!(srtp.effective_remote(), Some(natted));
    }

    #[test]
    fn test_learning_window_expires() {
        let mut srtp = SymmetricRtp::new(5); // threshold=5, window=10
        srtp.set_mode(AutoAdjustMode::Once);
        srtp.set_configured("10.0.0.1:5000".parse().unwrap());

        let natted: SocketAddr = "203.0.113.5:12345".parse().unwrap();
        let noise: SocketAddr = "198.51.100.1:9999".parse().unwrap();

        // Alternate between two addresses -- never reaches threshold for either
        for _ in 0..5 {
            srtp.process_incoming(natted);
            srtp.process_incoming(noise);
        }

        // Window of 10 should be expired (or nearly so)
        // No learning should have occurred
        assert!(!srtp.has_learned());
        assert!(!srtp.is_learning()); // window expired
    }

    #[test]
    fn test_always_adjust_mode() {
        let mut srtp = SymmetricRtp::new(1);
        srtp.set_mode(AutoAdjustMode::Always);
        srtp.set_configured("10.0.0.1:5000".parse().unwrap());

        let addr1: SocketAddr = "203.0.113.5:12345".parse().unwrap();
        let addr2: SocketAddr =
            "203.0.113.5:54321".parse().unwrap(); // port changed

        // Learn first address
        assert!(srtp.process_incoming(addr1));
        assert_eq!(srtp.effective_remote(), Some(addr1));
        assert!(srtp.is_learning()); // Always mode -- still learning

        // NAT rebinds to new port
        assert!(srtp.process_incoming(addr2));
        assert_eq!(srtp.effective_remote(), Some(addr2));
    }

    #[test]
    fn test_once_mode_stops_after_learning() {
        let mut srtp = SymmetricRtp::new(1);
        srtp.set_mode(AutoAdjustMode::Once);
        srtp.set_configured("10.0.0.1:5000".parse().unwrap());

        let addr1: SocketAddr = "203.0.113.5:12345".parse().unwrap();
        let addr2: SocketAddr = "203.0.113.5:54321".parse().unwrap();

        // Learn first address
        assert!(srtp.process_incoming(addr1));
        assert!(!srtp.is_learning()); // Once mode -- stopped

        // Second address ignored because window is closed
        assert!(!srtp.process_incoming(addr2));
        assert_eq!(srtp.effective_remote(), Some(addr1));
    }

    #[test]
    fn test_rearm_after_reinvite() {
        let mut srtp = SymmetricRtp::new(1);
        srtp.set_mode(AutoAdjustMode::Once);
        srtp.set_configured("10.0.0.1:5000".parse().unwrap());

        let addr1: SocketAddr = "203.0.113.5:12345".parse().unwrap();
        let addr2: SocketAddr = "203.0.113.5:54321".parse().unwrap();

        // Learn first address
        srtp.process_incoming(addr1);
        assert!(!srtp.is_learning());

        // re-INVITE -- rearm
        srtp.rearm();
        assert!(srtp.is_learning());

        // Now can learn new address
        assert!(srtp.process_incoming(addr2));
        assert_eq!(srtp.effective_remote(), Some(addr2));
    }

    #[test]
    fn test_address_change_resets_tally() {
        let mut srtp = SymmetricRtp::new(3);
        srtp.set_configured("10.0.0.1:5000".parse().unwrap());

        let addr1: SocketAddr = "203.0.113.5:12345".parse().unwrap();
        let addr2: SocketAddr = "203.0.113.99:54321".parse().unwrap();

        // Start learning addr1 (2 of 3 needed)
        srtp.process_incoming(addr1);
        srtp.process_incoming(addr1);
        // Interruption -- different address resets tally
        srtp.process_incoming(addr2);

        assert!(!srtp.has_learned());
    }

    #[test]
    fn test_spoofing_protection() {
        let mut srtp = SymmetricRtp::new(3);
        srtp.set_mode(AutoAdjustMode::Always);
        srtp.set_configured("10.0.0.1:5000".parse().unwrap());

        let legit: SocketAddr = "203.0.113.5:12345".parse().unwrap();
        let spoof: SocketAddr = "198.51.100.1:666".parse().unwrap();

        // Legitimate packets -- learn
        srtp.process_incoming(legit);
        srtp.process_incoming(legit);
        srtp.process_incoming(legit);
        assert!(srtp.has_learned());
        assert_eq!(srtp.effective_remote(), Some(legit));

        // Single spoofed packet -- not enough to change
        assert!(!srtp.process_incoming(spoof));
        assert_eq!(srtp.effective_remote(), Some(legit));
    }

    #[test]
    fn test_no_change_if_already_learned() {
        let mut srtp = SymmetricRtp::new(1);
        let natted: SocketAddr = "203.0.113.5:12345".parse().unwrap();
        srtp.set_configured("10.0.0.1:5000".parse().unwrap());

        // First time -- returns true (changed)
        assert!(srtp.process_incoming(natted));
        // Second time -- returns false (no change)
        assert!(!srtp.process_incoming(natted));
    }

    #[test]
    fn test_reset() {
        let mut srtp = SymmetricRtp::new(1);
        let natted: SocketAddr = "203.0.113.5:12345".parse().unwrap();
        srtp.set_configured("10.0.0.1:5000".parse().unwrap());

        srtp.process_incoming(natted);
        assert!(srtp.has_learned());

        srtp.reset();
        assert!(!srtp.has_learned());
        assert!(srtp.is_learning()); // window re-armed
    }

    #[test]
    fn test_effective_remote_before_learning() {
        let mut srtp = SymmetricRtp::new(3);
        let configured: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        srtp.set_configured(configured);

        // Before learning, returns configured
        assert_eq!(srtp.effective_remote(), Some(configured));

        // No configured address
        let srtp2 = SymmetricRtp::new(3);
        assert_eq!(srtp2.effective_remote(), None);
    }

    #[test]
    fn test_packets_processed_counter() {
        let mut srtp = SymmetricRtp::new(3);
        srtp.set_configured("10.0.0.1:5000".parse().unwrap());

        let addr: SocketAddr = "203.0.113.5:12345".parse().unwrap();
        for _ in 0..5 {
            srtp.process_incoming(addr);
        }
        assert_eq!(srtp.packets_processed(), 5);
    }

    /// Simulates the exact Symmetric NAT scenario:
    /// Server has public IP, client behind Symmetric NAT sends from random port
    #[test]
    fn test_symmetric_nat_scenario() {
        // Server side: auto-adjust with production defaults
        let mut rtp_adj = SymmetricRtp::with_defaults();
        let mut rtcp_adj = SymmetricRtp::new_rtcp();

        // Verify defaults are Always mode
        assert_eq!(rtp_adj.mode(), AutoAdjustMode::Always);
        assert_eq!(rtcp_adj.mode(), AutoAdjustMode::Always);

        // SDP says client is at 10.0.0.50:5000 (private address -- unreachable)
        rtp_adj.set_configured("10.0.0.50:5000".parse().unwrap());
        rtcp_adj.set_configured("10.0.0.50:5001".parse().unwrap());

        // But client is behind Symmetric NAT, so packets arrive from:
        let nat_rtp: SocketAddr = "203.0.113.99:49152".parse().unwrap();
        let nat_rtcp: SocketAddr = "203.0.113.99:49153".parse().unwrap();

        // RTCP learns immediately (threshold=1)
        assert!(rtcp_adj.process_incoming(nat_rtcp));
        assert_eq!(rtcp_adj.effective_remote(), Some(nat_rtcp));

        // RTP needs 10 packets (default threshold)
        for i in 0..10 {
            let changed = rtp_adj.process_incoming(nat_rtp);
            if i < 9 {
                assert!(!changed);
            } else {
                assert!(changed);
            }
        }
        assert_eq!(rtp_adj.effective_remote(), Some(nat_rtp));

        // Now server sends to NAT-mapped addresses -- traverses existing pinhole
        // Client receives media. Symmetric NAT handled without TURN!
    }

    // --- R2 tests: default mode is Always ---

    #[test]
    fn test_default_mode_is_always() {
        let srtp = SymmetricRtp::new(5);
        assert_eq!(srtp.mode(), AutoAdjustMode::Always);

        let srtp2 = SymmetricRtp::with_defaults();
        assert_eq!(srtp2.mode(), AutoAdjustMode::Always);

        let srtp3 = SymmetricRtp::new_rtcp();
        assert_eq!(srtp3.mode(), AutoAdjustMode::Always);
    }

    #[test]
    fn test_always_mode_relearns_after_address_change() {
        let mut srtp = SymmetricRtp::new(2);
        assert_eq!(srtp.mode(), AutoAdjustMode::Always);
        srtp.set_configured("10.0.0.1:5000".parse().unwrap());

        let addr1: SocketAddr = "203.0.113.5:12345".parse().unwrap();
        let addr2: SocketAddr = "198.51.100.1:54321".parse().unwrap();

        // Learn first address (need 2 consistent packets)
        assert!(!srtp.process_incoming(addr1));
        assert!(srtp.process_incoming(addr1));
        assert_eq!(srtp.effective_remote(), Some(addr1));
        assert!(srtp.is_learning()); // Always mode keeps learning

        // Remote switches to new address (e.g., WiFi->cellular failover)
        // Need 2 consistent packets from the new address
        assert!(!srtp.process_incoming(addr2));
        assert!(srtp.process_incoming(addr2));
        assert_eq!(srtp.effective_remote(), Some(addr2));
    }

    #[test]
    fn test_always_mode_survives_multiple_address_changes() {
        let mut srtp = SymmetricRtp::new(1);
        assert_eq!(srtp.mode(), AutoAdjustMode::Always);
        srtp.set_configured("10.0.0.1:5000".parse().unwrap());

        // Only 3 switches within default window -- below default max of 5
        let addrs: Vec<SocketAddr> = vec![
            "203.0.113.1:10001".parse().unwrap(),
            "203.0.113.2:10002".parse().unwrap(),
            "203.0.113.3:10003".parse().unwrap(),
        ];

        for addr in &addrs {
            assert!(srtp.process_incoming(*addr));
            assert_eq!(srtp.effective_remote(), Some(*addr));
        }
    }

    // --- Bug #51 tests: rate limiting in Always mode ---

    #[test]
    fn test_rate_limit_locks_after_excessive_switches() {
        use std::time::{Duration, Instant};

        let mut srtp = SymmetricRtp::new(1);
        srtp.set_mode(AutoAdjustMode::Always);
        srtp.set_configured("10.0.0.1:5000".parse().unwrap());
        // Allow max 3 switches in 10 seconds
        srtp.set_rate_limit(3, 10);

        let now = Instant::now();

        // First address -- not a "switch" (no previous learned), always allowed
        let addr1: SocketAddr = "203.0.113.1:1001".parse().unwrap();
        assert!(srtp.process_incoming_with_time(addr1, now));
        assert!(!srtp.is_locked());

        // Switch 1: addr1 -> addr2
        let addr2: SocketAddr = "203.0.113.2:1002".parse().unwrap();
        assert!(srtp.process_incoming_with_time(
            addr2,
            now + Duration::from_secs(1)
        ));
        assert!(!srtp.is_locked());

        // Switch 2: addr2 -> addr3
        let addr3: SocketAddr = "203.0.113.3:1003".parse().unwrap();
        assert!(srtp.process_incoming_with_time(
            addr3,
            now + Duration::from_secs(2)
        ));
        assert!(!srtp.is_locked());

        // Switch 3: addr3 -> addr4
        let addr4: SocketAddr = "203.0.113.4:1004".parse().unwrap();
        assert!(srtp.process_incoming_with_time(
            addr4,
            now + Duration::from_secs(3)
        ));
        assert!(!srtp.is_locked());

        // Switch 4: exceeds max_switches=3 -- should lock
        let addr5: SocketAddr = "203.0.113.5:1005".parse().unwrap();
        assert!(!srtp.process_incoming_with_time(
            addr5,
            now + Duration::from_secs(4)
        ));
        assert!(srtp.is_locked());

        // Further changes are rejected
        let addr6: SocketAddr = "203.0.113.6:1006".parse().unwrap();
        assert!(!srtp.process_incoming_with_time(
            addr6,
            now + Duration::from_secs(5)
        ));

        // Current address stays at addr4 (last successful switch)
        assert_eq!(srtp.effective_remote(), Some(addr4));
    }

    #[test]
    fn test_rate_limit_sliding_window_expires() {
        use std::time::{Duration, Instant};

        let mut srtp = SymmetricRtp::new(1);
        srtp.set_mode(AutoAdjustMode::Always);
        srtp.set_configured("10.0.0.1:5000".parse().unwrap());
        // Allow max 2 switches in 5 seconds
        srtp.set_rate_limit(2, 5);

        let now = Instant::now();

        // Learn initial address
        let addr1: SocketAddr = "203.0.113.1:1001".parse().unwrap();
        assert!(srtp.process_incoming_with_time(addr1, now));

        // Switch 1 at t=0
        let addr2: SocketAddr = "203.0.113.2:1002".parse().unwrap();
        assert!(srtp.process_incoming_with_time(addr2, now));

        // Switch 2 at t=1 -- still within limit
        let addr3: SocketAddr = "203.0.113.3:1003".parse().unwrap();
        assert!(srtp.process_incoming_with_time(
            addr3,
            now + Duration::from_secs(1)
        ));

        // Switch 3 at t=2 -- exceeds limit (3 > max 2), locks
        let addr4: SocketAddr = "203.0.113.4:1004".parse().unwrap();
        assert!(!srtp.process_incoming_with_time(
            addr4,
            now + Duration::from_secs(2)
        ));
        assert!(srtp.is_locked());
    }

    #[test]
    fn test_rate_limit_reset_clears_lock() {
        use std::time::{Duration, Instant};

        let mut srtp = SymmetricRtp::new(1);
        srtp.set_mode(AutoAdjustMode::Always);
        srtp.set_configured("10.0.0.1:5000".parse().unwrap());
        srtp.set_rate_limit(1, 10);

        let now = Instant::now();

        // Learn then switch -- hits the limit immediately
        let addr1: SocketAddr = "203.0.113.1:1001".parse().unwrap();
        assert!(srtp.process_incoming_with_time(addr1, now));
        let addr2: SocketAddr = "203.0.113.2:1002".parse().unwrap();
        assert!(srtp.process_incoming_with_time(addr2, now));
        // This second switch exceeds max_switches=1
        let addr3: SocketAddr = "203.0.113.3:1003".parse().unwrap();
        assert!(!srtp.process_incoming_with_time(
            addr3,
            now + Duration::from_secs(1)
        ));
        assert!(srtp.is_locked());

        // Reset (e.g., SDP renegotiation) clears the lock
        srtp.reset();
        assert!(!srtp.is_locked());

        // Can learn again
        let addr4: SocketAddr = "203.0.113.4:1004".parse().unwrap();
        assert!(srtp.process_incoming_with_time(
            addr4,
            now + Duration::from_secs(2)
        ));
        assert_eq!(srtp.effective_remote(), Some(addr4));
    }

    #[test]
    fn test_rate_limit_not_applied_to_once_mode() {
        use std::time::{Duration, Instant};

        // Once mode doesn't need rate limiting (it stops after first learn)
        let mut srtp = SymmetricRtp::new(1);
        srtp.set_mode(AutoAdjustMode::Once);
        srtp.set_configured("10.0.0.1:5000".parse().unwrap());
        srtp.set_rate_limit(1, 10);

        let now = Instant::now();
        let addr1: SocketAddr = "203.0.113.1:1001".parse().unwrap();
        assert!(srtp.process_incoming_with_time(addr1, now));
        assert!(!srtp.is_locked());
        // Once mode closes window -- second address rejected, not rate limit
        let addr2: SocketAddr = "203.0.113.2:1002".parse().unwrap();
        assert!(!srtp.process_incoming_with_time(
            addr2,
            now + Duration::from_secs(1)
        ));
        assert!(!srtp.is_locked());
    }

    #[test]
    fn test_rate_limit_spoofed_packet_storm() {
        use std::time::{Duration, Instant};

        // Simulate a spoofed packet storm: many different addresses rapidly
        let mut srtp = SymmetricRtp::new(1);
        srtp.set_mode(AutoAdjustMode::Always);
        srtp.set_configured("10.0.0.1:5000".parse().unwrap());
        srtp.set_rate_limit(5, 10);

        let now = Instant::now();

        // Learn legitimate address
        let legit: SocketAddr = "203.0.113.100:5000".parse().unwrap();
        assert!(srtp.process_incoming_with_time(legit, now));

        // Storm of spoofed addresses -- each triggers a switch
        let mut last_accepted = legit;
        for i in 1..=20u16 {
            let spoof: SocketAddr = format!(
                "198.51.100.{}:{}",
                i % 255,
                10000 + i
            )
            .parse()
            .unwrap();
            let t = now + Duration::from_millis(i as u64 * 100);
            let changed = srtp.process_incoming_with_time(spoof, t);
            if changed {
                last_accepted = spoof;
            }
            if srtp.is_locked() {
                break;
            }
        }

        // Must be locked well before all 20 addresses are accepted
        assert!(srtp.is_locked());
        // The address is frozen at whatever was last accepted
        assert_eq!(srtp.effective_remote(), Some(last_accepted));
    }

    #[test]
    fn test_rate_limit_default_values() {
        let srtp = SymmetricRtp::new(1);
        // Default rate limit should be 5 switches in 10 seconds
        assert_eq!(srtp.rate_limit.max_switches, 5);
        assert_eq!(srtp.rate_limit.switch_window_secs, 10);
        assert!(!srtp.is_locked());
    }
}
