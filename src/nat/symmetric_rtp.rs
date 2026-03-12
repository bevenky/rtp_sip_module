//! Symmetric RTP (RFC 4961) — Sans-IO
//!
//! Learns the actual remote address from incoming RTP/RTCP packets.
//! This is the PRIMARY mechanism for handling ALL NAT types (including
//! Symmetric NAT) in SIP/RTP telephony where one side has a public IP.
//!
//! Modeled after FreeSWITCH's `SWITCH_RTP_FLAG_AUTOADJ` which has been
//! battle-tested in production for 15+ years handling every NAT type
//! without requiring TURN.
//!
//! ## How it handles Symmetric NAT
//!
//! 1. Server listens on public IP:port (advertised in SDP)
//! 2. Client behind Symmetric NAT sends RTP → NAT creates mapping
//!    `NAT_IP:RANDOM_PORT → Server:Port`
//! 3. Server receives packet from `NAT_IP:RANDOM_PORT` (differs from SDP)
//! 4. Server learns the real address after `threshold` consistent packets
//! 5. Server sends back to `NAT_IP:RANDOM_PORT` — traverses existing NAT pinhole
//!
//! No TURN needed because the server IS the relay.
//!
//! ## Security
//!
//! The consistency threshold prevents a single spoofed packet from
//! redirecting media traffic. FreeSWITCH uses threshold=10 for RTP
//! and threshold=1 for RTCP (since RTCP is less frequent).

use std::net::SocketAddr;

/// Symmetric RTP auto-adjust mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoAdjustMode {
    /// Learn once, then lock to learned address (FreeSWITCH default)
    Once,
    /// Continuously re-learn if address changes (FreeSWITCH `RTP_BUG_ALWAYS_AUTO_ADJUST`)
    /// Use for endpoints that may change ports mid-call (e.g., mobile, call transfer)
    Always,
    /// Disabled — always use configured address
    Disabled,
}

/// Symmetric RTP handler for a single stream (RTP or RTCP)
///
/// FreeSWITCH equivalents:
/// - `SWITCH_RTP_FLAG_AUTOADJ` → `mode != Disabled`
/// - `autoadj_threshold` → `threshold`
/// - `autoadj_window` → `window`
/// - `autoadj_tally` → `tally`
/// - `auto_adj_used` → `has_learned()`
/// - `RTP_BUG_ALWAYS_AUTO_ADJUST` → `mode == Always`
pub struct SymmetricRtp {
    /// The SDP-configured remote address
    configured_addr: Option<SocketAddr>,
    /// The address we're currently learning from incoming packets
    candidate_addr: Option<SocketAddr>,
    /// Number of packets from candidate address (FreeSWITCH: autoadj_tally)
    tally: u32,
    /// Packets needed to accept candidate (FreeSWITCH: autoadj_threshold, default 10)
    threshold: u32,
    /// Learning window — max packets to observe before giving up
    /// (FreeSWITCH: autoadj_window = threshold * 2)
    window: u32,
    /// Current window counter (counts down to 0)
    window_remaining: u32,
    /// The accepted learned address (once threshold is met)
    learned_addr: Option<SocketAddr>,
    /// Auto-adjust mode
    mode: AutoAdjustMode,
    /// Total packets processed (for diagnostics)
    packets_processed: u64,
}

impl SymmetricRtp {
    /// Create a new RTP auto-adjust handler.
    ///
    /// Default matches FreeSWITCH: threshold=10, window=20, mode=Once.
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
            mode: AutoAdjustMode::Once,
            packets_processed: 0,
        }
    }

    /// Create with FreeSWITCH production defaults (threshold=10, window=20)
    pub fn with_defaults() -> Self {
        Self::new(10)
    }

    /// Create for RTCP auto-adjust (threshold=1, matches FreeSWITCH)
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
            mode: AutoAdjustMode::Once,
            packets_processed: 0,
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
        }
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

    /// Process an incoming packet's source address.
    ///
    /// Returns true if the learned address changed (caller must update send target).
    ///
    /// Algorithm (matches FreeSWITCH `switch_rtp.c` lines 8686-8750):
    ///
    /// 1. If disabled or window expired (in Once mode), skip
    /// 2. If source matches configured or already-learned addr, no action
    /// 3. If source matches candidate, increment tally
    /// 4. If tally >= threshold, accept candidate as learned addr
    /// 5. If new source, reset candidate and tally
    /// 6. Decrement window; if 0 in Once mode, stop learning
    pub fn process_incoming(&mut self, source: SocketAddr) -> bool {
        self.packets_processed += 1;

        if self.mode == AutoAdjustMode::Disabled {
            return false;
        }

        // Check if learning window has expired (Once mode only)
        if self.mode == AutoAdjustMode::Once && self.window_remaining == 0 {
            return false;
        }

        // If source matches configured addr, nothing to learn
        if self.configured_addr == Some(source) {
            if self.mode == AutoAdjustMode::Once {
                self.decrement_window();
            }
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
            // New candidate — reset learning
            self.candidate_addr = Some(source);
            self.tally = 1;

            // Threshold of 1 means accept immediately
            if self.threshold <= 1 {
                let old = self.learned_addr;
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
        // Don't clear learned_addr — keep using it until a new one is confirmed
    }

    /// Get the effective remote address for sending.
    /// Returns learned address if available, otherwise configured address.
    pub fn effective_remote(&self) -> Option<SocketAddr> {
        self.learned_addr.or(self.configured_addr)
    }

    /// Whether an address has been learned (different from configured)
    pub fn has_learned(&self) -> bool {
        self.learned_addr.is_some() && self.learned_addr != self.configured_addr
    }

    /// Whether the learning window is still open
    pub fn is_learning(&self) -> bool {
        match self.mode {
            AutoAdjustMode::Disabled => false,
            AutoAdjustMode::Always => true,
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

        // Below threshold — no learning
        assert!(!srtp.process_incoming(natted));
        assert!(!srtp.process_incoming(natted));
        assert!(!srtp.has_learned());

        // Meets threshold
        assert!(srtp.process_incoming(natted));
        assert!(srtp.has_learned());
        assert_eq!(srtp.effective_remote(), Some(natted));
    }

    #[test]
    fn test_freeswitch_defaults() {
        let mut srtp = SymmetricRtp::with_defaults();
        srtp.set_configured("10.0.0.1:5000".parse().unwrap());

        let natted: SocketAddr = "203.0.113.5:12345".parse().unwrap();

        // Need 10 packets to learn (FreeSWITCH default)
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
        srtp.set_configured("10.0.0.1:5000".parse().unwrap());

        let natted: SocketAddr = "203.0.113.5:12345".parse().unwrap();
        let noise: SocketAddr = "198.51.100.1:9999".parse().unwrap();

        // Alternate between two addresses — never reaches threshold for either
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
        let addr2: SocketAddr = "203.0.113.5:54321".parse().unwrap(); // port changed (Symmetric NAT rebind)

        // Learn first address
        assert!(srtp.process_incoming(addr1));
        assert_eq!(srtp.effective_remote(), Some(addr1));
        assert!(srtp.is_learning()); // Always mode — still learning

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
        assert!(!srtp.is_learning()); // Once mode — stopped

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

        // re-INVITE — rearm
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
        // Interruption — different address resets tally
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

        // Legitimate packets — learn
        srtp.process_incoming(legit);
        srtp.process_incoming(legit);
        srtp.process_incoming(legit);
        assert!(srtp.has_learned());
        assert_eq!(srtp.effective_remote(), Some(legit));

        // Single spoofed packet — not enough to change
        assert!(!srtp.process_incoming(spoof));
        assert_eq!(srtp.effective_remote(), Some(legit));
    }

    #[test]
    fn test_no_change_if_already_learned() {
        let mut srtp = SymmetricRtp::new(1);
        let natted: SocketAddr = "203.0.113.5:12345".parse().unwrap();
        srtp.set_configured("10.0.0.1:5000".parse().unwrap());

        // First time — returns true (changed)
        assert!(srtp.process_incoming(natted));
        // Second time — returns false (no change)
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
        // Server side: auto-adjust with FreeSWITCH defaults
        let mut rtp_adj = SymmetricRtp::with_defaults();
        let mut rtcp_adj = SymmetricRtp::new_rtcp();

        // SDP says client is at 10.0.0.50:5000 (private address — unreachable)
        rtp_adj.set_configured("10.0.0.50:5000".parse().unwrap());
        rtcp_adj.set_configured("10.0.0.50:5001".parse().unwrap());

        // But client is behind Symmetric NAT, so packets arrive from:
        let nat_rtp: SocketAddr = "203.0.113.99:49152".parse().unwrap();
        let nat_rtcp: SocketAddr = "203.0.113.99:49153".parse().unwrap();

        // RTCP learns immediately (threshold=1)
        assert!(rtcp_adj.process_incoming(nat_rtcp));
        assert_eq!(rtcp_adj.effective_remote(), Some(nat_rtcp));

        // RTP needs 10 packets (FreeSWITCH default)
        for i in 0..10 {
            let changed = rtp_adj.process_incoming(nat_rtp);
            if i < 9 {
                assert!(!changed);
            } else {
                assert!(changed);
            }
        }
        assert_eq!(rtp_adj.effective_remote(), Some(nat_rtp));

        // Now server sends to NAT-mapped addresses — traverses existing pinhole
        // Client receives media. Symmetric NAT handled without TURN!
    }
}
