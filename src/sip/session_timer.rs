//! SIP Session Timer (RFC 4028)
//!
//! Prevents zombie calls by ensuring periodic session refresh.
//! If no refresh is received within Session-Expires, the call is terminated.
//!
//! The refresher sends re-INVITE or UPDATE at half the Session-Expires interval.
//! If no refresh arrives within the full interval (plus a 32-second grace period
//! per RFC 4028 Section 10), the session is considered expired and should be
//! torn down with BYE + Reason: SIP;cause=408.

use std::time::{Duration, Instant};

/// Session timer role (who refreshes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshRole {
    /// We are the refresher (send re-INVITE/UPDATE periodically)
    Local,
    /// Remote is the refresher (we expect re-INVITE/UPDATE from them)
    Remote,
}

/// Session timer configuration
#[derive(Debug, Clone)]
pub struct SessionTimerConfig {
    /// Whether session timers are enabled (default true)
    pub enabled: bool,
    /// Default Session-Expires value in seconds (default 1800 = 30 min)
    pub session_expires: u32,
    /// Minimum Session-Expires (Min-SE) in seconds (default 90)
    pub min_se: u32,
    /// Our preferred refresher role
    pub preferred_role: RefreshRole,
}

impl Default for SessionTimerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            session_expires: 1800,
            min_se: 90,
            preferred_role: RefreshRole::Local,
        }
    }
}

/// Grace period added to the session expiry before declaring the session dead.
/// RFC 4028 Section 10 recommends a value of at least one third of the
/// Session-Expires interval, but a fixed 32-second grace is a widely adopted
/// practical default.
const EXPIRY_GRACE_SECONDS: u64 = 32;

/// Active session timer state for a single call.
///
/// Create one `SessionTimer` per call leg. After the INVITE 200 OK exchange,
/// call [`start`](SessionTimer::start) with the negotiated values. Then
/// periodically check [`needs_refresh`](SessionTimer::needs_refresh) and
/// [`is_expired`](SessionTimer::is_expired) from your event loop.
pub struct SessionTimer {
    #[allow(dead_code)]
    config: SessionTimerConfig,
    /// Negotiated session expiry (seconds)
    session_expires: u32,
    /// Negotiated minimum session expiry (seconds)
    min_se: u32,
    /// Who is responsible for refreshing
    role: RefreshRole,
    /// When the session was last refreshed
    last_refresh: Instant,
    /// Whether the timer is active
    active: bool,
}

impl SessionTimer {
    /// Create a new `SessionTimer` from configuration.
    ///
    /// The timer starts in an inactive state. Call [`start`](SessionTimer::start)
    /// after negotiation completes (i.e. after receiving 200 OK for the INVITE).
    pub fn new(config: SessionTimerConfig) -> Self {
        Self {
            session_expires: config.session_expires,
            min_se: config.min_se,
            role: config.preferred_role,
            config,
            last_refresh: Instant::now(),
            active: false,
        }
    }

    /// Start the timer (call after INVITE 200 OK).
    ///
    /// `negotiated_expires` is the agreed-upon Session-Expires value (in seconds)
    /// from the SIP negotiation. `role` indicates who is responsible for sending
    /// refresh requests.
    pub fn start(&mut self, negotiated_expires: u32, role: RefreshRole) {
        // Clamp to our configured minimum
        self.session_expires = negotiated_expires.max(self.min_se);
        self.role = role;
        self.last_refresh = Instant::now();
        self.active = true;
    }

    /// Record that a refresh was received or sent.
    ///
    /// This resets the expiry window. Call this whenever:
    /// - We send a successful re-INVITE/UPDATE (Local refresher)
    /// - We receive a re-INVITE/UPDATE from the remote (Remote refresher)
    pub fn refresh(&mut self) {
        self.last_refresh = Instant::now();
    }

    /// Check if we need to send a refresh now.
    ///
    /// Returns `true` when half the session interval has passed since the last
    /// refresh (RFC 4028 Section 10). Only meaningful when we are the Local
    /// refresher; always returns `false` if the role is `Remote` or the timer
    /// is inactive.
    pub fn needs_refresh(&self) -> bool {
        if !self.active || self.role != RefreshRole::Local {
            return false;
        }
        let half_interval = Duration::from_secs(u64::from(self.session_expires) / 2);
        self.last_refresh.elapsed() >= half_interval
    }

    /// Check if the session has expired (no refresh received within interval).
    ///
    /// The expiry threshold is the negotiated `session_expires` plus a 32-second
    /// grace period. If this returns `true`, the call should be terminated with
    /// BYE and Reason header `SIP;cause=408`.
    pub fn is_expired(&self) -> bool {
        if !self.active {
            return false;
        }
        let expiry =
            Duration::from_secs(u64::from(self.session_expires) + EXPIRY_GRACE_SECONDS);
        self.last_refresh.elapsed() >= expiry
    }

    /// Time until the next refresh should be sent.
    ///
    /// Returns `None` if the remote is the refresher (we don't send refreshes)
    /// or if the timer is inactive. Returns `Duration::ZERO` if the refresh is
    /// already overdue.
    pub fn time_until_refresh(&self) -> Option<Duration> {
        if !self.active || self.role != RefreshRole::Local {
            return None;
        }
        let half_interval = Duration::from_secs(u64::from(self.session_expires) / 2);
        let elapsed = self.last_refresh.elapsed();
        Some(half_interval.saturating_sub(elapsed))
    }

    /// Time until session expiry (including the grace period).
    ///
    /// Returns `Duration::ZERO` if the session has already expired or the timer
    /// is not active.
    pub fn time_until_expiry(&self) -> Duration {
        if !self.active {
            return Duration::ZERO;
        }
        let expiry =
            Duration::from_secs(u64::from(self.session_expires) + EXPIRY_GRACE_SECONDS);
        let elapsed = self.last_refresh.elapsed();
        expiry.saturating_sub(elapsed)
    }

    /// Build the `Session-Expires` header value for outgoing SIP messages.
    ///
    /// Format: `<seconds>;refresher=<uac|uas>`
    ///
    /// The `refresher` parameter uses UAC/UAS terminology per RFC 4028:
    /// - `Local` maps to `uac` (we originated the dialog)
    /// - `Remote` maps to `uas`
    ///
    /// Callers that are the UAS side of the dialog should swap the mapping
    /// accordingly when constructing the final header.
    pub fn build_session_expires_header(&self) -> String {
        let refresher = match self.role {
            RefreshRole::Local => "uac",
            RefreshRole::Remote => "uas",
        };
        format!("{};refresher={}", self.session_expires, refresher)
    }

    /// Build the `Min-SE` header value for outgoing SIP messages.
    pub fn build_min_se_header(&self) -> String {
        self.min_se.to_string()
    }

    /// Parse a `Session-Expires` header value from a remote SIP message.
    ///
    /// Accepted formats:
    /// - `"1800"` (no refresher specified)
    /// - `"1800;refresher=uac"`
    /// - `"1800;refresher=uas"`
    ///
    /// Returns `None` if the header cannot be parsed. When the `refresher`
    /// parameter is absent, the second element of the tuple is `None`.
    pub fn parse_session_expires(header: &str) -> Option<(u32, Option<RefreshRole>)> {
        let header = header.trim();
        let mut parts = header.splitn(2, ';');

        let seconds_str = parts.next()?.trim();
        let seconds: u32 = seconds_str.parse().ok()?;

        let role = if let Some(params) = parts.next() {
            Self::extract_refresher_role(params)
        } else {
            None
        };

        Some((seconds, role))
    }

    /// Parse a `Min-SE` header value from a remote SIP message.
    ///
    /// The value is a plain integer representing seconds. Returns `None` if
    /// the header cannot be parsed.
    pub fn parse_min_se(header: &str) -> Option<u32> {
        // Min-SE may include parameters (e.g. "90;something"), take only the
        // numeric portion before any semicolon.
        let header = header.trim();
        let value_str = header.split(';').next()?.trim();
        value_str.parse().ok()
    }

    /// Is the timer active?
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Stop the timer.
    ///
    /// After stopping, [`needs_refresh`](SessionTimer::needs_refresh) and
    /// [`is_expired`](SessionTimer::is_expired) will always return `false`.
    pub fn stop(&mut self) {
        self.active = false;
    }

    // ── private helpers ──────────────────────────────────────────────

    /// Extract the `RefreshRole` from a parameters string like `"refresher=uac"`.
    fn extract_refresher_role(params: &str) -> Option<RefreshRole> {
        for param in params.split(';') {
            let param = param.trim();
            if let Some(value) = param.strip_prefix("refresher=") {
                let value = value.trim().to_lowercase();
                return match value.as_str() {
                    "uac" => Some(RefreshRole::Local),
                    "uas" => Some(RefreshRole::Remote),
                    _ => None,
                };
            }
        }
        None
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_default_config() {
        let config = SessionTimerConfig::default();
        assert!(config.enabled);
        assert_eq!(config.session_expires, 1800);
        assert_eq!(config.min_se, 90);
        assert_eq!(config.preferred_role, RefreshRole::Local);
    }

    #[test]
    fn test_timer_not_active_initially() {
        let timer = SessionTimer::new(SessionTimerConfig::default());
        assert!(!timer.is_active());
        assert!(!timer.needs_refresh());
        assert!(!timer.is_expired());
        assert!(timer.time_until_refresh().is_none());
        assert_eq!(timer.time_until_expiry(), Duration::ZERO);
    }

    #[test]
    fn test_needs_refresh_at_half_interval() {
        // Use a very short session expires so the test doesn't take forever.
        let config = SessionTimerConfig {
            session_expires: 2,
            min_se: 1,
            ..Default::default()
        };
        let mut timer = SessionTimer::new(config);
        timer.start(2, RefreshRole::Local);

        // Immediately after start, should not need refresh.
        assert!(!timer.needs_refresh());

        // After >= 1 second (half of 2), should need refresh.
        thread::sleep(Duration::from_millis(1050));
        assert!(timer.needs_refresh());
    }

    #[test]
    fn test_is_expired_after_full_interval() {
        // session_expires = 1 second, grace = 32 seconds is too long for a test.
        // We test the logic by using a 1-second interval and verifying that
        // is_expired is false before the full interval and true after
        // session_expires + grace.  Since the grace is 32s we cannot sleep that
        // long in a unit test; instead we test that the session is NOT expired
        // right after session_expires and rely on the arithmetic being correct
        // via time_until_expiry.
        let config = SessionTimerConfig {
            session_expires: 1,
            min_se: 1,
            ..Default::default()
        };
        let mut timer = SessionTimer::new(config);
        timer.start(1, RefreshRole::Local);

        // Immediately: not expired.
        assert!(!timer.is_expired());

        // After 1 second (session_expires) but before grace period: not expired.
        thread::sleep(Duration::from_millis(1100));
        assert!(!timer.is_expired());

        // Verify time_until_expiry is roughly 32 seconds minus the elapsed ~1s
        let remaining = timer.time_until_expiry();
        // Should be around 31 seconds (33 total - ~1.1s elapsed)
        assert!(remaining.as_secs() <= 32);
        assert!(remaining.as_secs() >= 29);
    }

    #[test]
    fn test_refresh_resets_timer() {
        let config = SessionTimerConfig {
            session_expires: 2,
            min_se: 1,
            ..Default::default()
        };
        let mut timer = SessionTimer::new(config);
        timer.start(2, RefreshRole::Local);

        // Wait past the half-interval.
        thread::sleep(Duration::from_millis(1050));
        assert!(timer.needs_refresh());

        // Refresh should reset the timer.
        timer.refresh();
        assert!(!timer.needs_refresh());
    }

    #[test]
    fn test_parse_session_expires_with_refresher() {
        let result = SessionTimer::parse_session_expires("1800;refresher=uac");
        assert_eq!(result, Some((1800, Some(RefreshRole::Local))));

        let result = SessionTimer::parse_session_expires("900;refresher=uas");
        assert_eq!(result, Some((900, Some(RefreshRole::Remote))));

        // With whitespace
        let result = SessionTimer::parse_session_expires("  3600 ; refresher=uac ");
        assert_eq!(result, Some((3600, Some(RefreshRole::Local))));
    }

    #[test]
    fn test_parse_session_expires_without_refresher() {
        let result = SessionTimer::parse_session_expires("1800");
        assert_eq!(result, Some((1800, None)));

        let result = SessionTimer::parse_session_expires("  600  ");
        assert_eq!(result, Some((600, None)));
    }

    #[test]
    fn test_parse_session_expires_invalid() {
        assert!(SessionTimer::parse_session_expires("").is_none());
        assert!(SessionTimer::parse_session_expires("abc").is_none());
        assert!(SessionTimer::parse_session_expires(";refresher=uac").is_none());
    }

    #[test]
    fn test_parse_min_se() {
        assert_eq!(SessionTimer::parse_min_se("90"), Some(90));
        assert_eq!(SessionTimer::parse_min_se("  120  "), Some(120));
        assert_eq!(SessionTimer::parse_min_se("90;some-ext"), Some(90));
        assert!(SessionTimer::parse_min_se("abc").is_none());
        assert!(SessionTimer::parse_min_se("").is_none());
    }

    #[test]
    fn test_build_headers() {
        let mut timer = SessionTimer::new(SessionTimerConfig::default());
        timer.start(1800, RefreshRole::Local);

        assert_eq!(
            timer.build_session_expires_header(),
            "1800;refresher=uac"
        );
        assert_eq!(timer.build_min_se_header(), "90");

        // Switch to remote role.
        timer.start(900, RefreshRole::Remote);
        assert_eq!(
            timer.build_session_expires_header(),
            "900;refresher=uas"
        );
    }

    #[test]
    fn test_remote_role_no_refresh_needed() {
        let config = SessionTimerConfig {
            session_expires: 2,
            min_se: 1,
            ..Default::default()
        };
        let mut timer = SessionTimer::new(config);
        timer.start(2, RefreshRole::Remote);

        // Even after the half-interval, needs_refresh should be false because
        // the remote is responsible for refreshing.
        thread::sleep(Duration::from_millis(1050));
        assert!(!timer.needs_refresh());
        assert!(timer.time_until_refresh().is_none());

        // The timer should still track expiry though.
        assert!(timer.is_active());
    }

    #[test]
    fn test_stop_deactivates_timer() {
        let mut timer = SessionTimer::new(SessionTimerConfig::default());
        timer.start(1800, RefreshRole::Local);
        assert!(timer.is_active());

        timer.stop();
        assert!(!timer.is_active());
        assert!(!timer.needs_refresh());
        assert!(!timer.is_expired());
    }

    #[test]
    fn test_start_clamps_to_min_se() {
        let config = SessionTimerConfig {
            session_expires: 1800,
            min_se: 90,
            ..Default::default()
        };
        let mut timer = SessionTimer::new(config);

        // Try to start with a value below min_se.
        timer.start(30, RefreshRole::Local);

        // The session_expires should be clamped to min_se (90).
        assert_eq!(timer.session_expires, 90);
        assert_eq!(
            timer.build_session_expires_header(),
            "90;refresher=uac"
        );
    }

    #[test]
    fn test_time_until_refresh_decreases() {
        let config = SessionTimerConfig {
            session_expires: 4,
            min_se: 1,
            ..Default::default()
        };
        let mut timer = SessionTimer::new(config);
        timer.start(4, RefreshRole::Local);

        let initial = timer.time_until_refresh().unwrap();
        // Half of 4 seconds = 2 seconds; should be close to 2s.
        assert!(initial.as_millis() <= 2000);
        assert!(initial.as_millis() >= 1900);

        thread::sleep(Duration::from_millis(500));

        let later = timer.time_until_refresh().unwrap();
        assert!(later < initial);
    }

    #[test]
    fn test_parse_session_expires_unknown_refresher() {
        // An unknown refresher value should yield None for the role.
        let result = SessionTimer::parse_session_expires("1800;refresher=unknown");
        assert_eq!(result, Some((1800, None)));
    }
}
