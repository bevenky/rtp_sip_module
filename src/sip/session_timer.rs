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

/// Result of handling a 422 (Session Interval Too Small) response (Bug #62).
///
/// Returns a struct instead of just the values, so the caller knows whether
/// to include the `Min-SE` header in the retry INVITE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handle422Result {
    /// The adjusted Session-Expires value for the retry
    pub session_expires: u32,
    /// The adjusted Min-SE value for the retry
    pub min_se: u32,
    /// Whether the retry INVITE must include a `Min-SE` header.
    /// This is `true` when the remote's Min-SE was higher than ours
    /// and forced an update.
    pub should_include_min_se_header: bool,
}

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

/// P1-TIMER-1: Compute the grace period for a given session_expires value.
/// Uses min(32, session_expires / 3) instead of a fixed 32s.
fn grace_seconds(session_expires: u32) -> u64 {
    std::cmp::min(32, u64::from(session_expires) / 3)
}

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
        let refresh_interval = self.refresh_interval();
        self.last_refresh.elapsed() >= refresh_interval
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
        let grace = grace_seconds(self.session_expires);
        let expiry = Duration::from_secs(u64::from(self.session_expires) + grace);
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
        let refresh_interval = self.refresh_interval();
        let elapsed = self.last_refresh.elapsed();
        Some(refresh_interval.saturating_sub(elapsed))
    }

    /// Time until session expiry (including the grace period).
    ///
    /// Returns `Duration::ZERO` if the session has already expired or the timer
    /// is not active.
    pub fn time_until_expiry(&self) -> Duration {
        if !self.active {
            return Duration::ZERO;
        }
        let grace = grace_seconds(self.session_expires);
        let expiry = Duration::from_secs(u64::from(self.session_expires) + grace);
        let elapsed = self.last_refresh.elapsed();
        expiry.saturating_sub(elapsed)
    }

    /// Build the `Session-Expires` header value for outgoing SIP messages.
    ///
    /// Format: `<seconds>;refresher=<uac|uas>`
    ///
    /// P1-TIMER-4: `is_uac` indicates whether *we* are the UAC side of the
    /// dialog. The mapping of Local/Remote to uac/uas depends on this:
    /// - If we are UAC: Local -> uac, Remote -> uas
    /// - If we are UAS: Local -> uas, Remote -> uac
    pub fn build_session_expires_header(&self, is_uac: bool) -> String {
        let refresher = match (self.role, is_uac) {
            (RefreshRole::Local, true) => "uac",
            (RefreshRole::Local, false) => "uas",
            (RefreshRole::Remote, true) => "uas",
            (RefreshRole::Remote, false) => "uac",
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
    /// Bug #71: `is_uac` indicates whether *we* are the UAC side of the dialog.
    /// This affects the mapping of `refresher=uac`/`refresher=uas` to Local/Remote.
    ///
    /// Returns `None` if the header cannot be parsed. When the `refresher`
    /// parameter is absent, the second element of the tuple is `None`.
    pub fn parse_session_expires(header: &str, is_uac: bool) -> Option<(u32, Option<RefreshRole>)> {
        let header = header.trim();
        let mut parts = header.splitn(2, ';');

        let seconds_str = parts.next()?.trim();
        let seconds: u32 = seconds_str.parse().ok()?;

        let role = if let Some(params) = parts.next() {
            Self::extract_refresher_role(params, is_uac)
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

    /// Handle a 422 (Session Interval Too Small) response (Bug #62).
    ///
    /// When the remote side rejects our INVITE with 422, it includes a `Min-SE`
    /// header indicating the minimum acceptable session interval. We must:
    /// 1. Update our `min_se` to be at least the remote's value
    /// 2. Ensure `session_expires` is >= the new `min_se`
    /// 3. Retry the INVITE with the updated values
    ///
    /// Returns a [`Handle422Result`] struct that includes
    /// `should_include_min_se_header` so the caller knows whether to add
    /// a `Min-SE` header to the retried INVITE.
    pub fn handle_422_response(&mut self, remote_min_se: u32) -> Handle422Result {
        // Track whether the remote forced an increase
        let should_include_min_se_header = remote_min_se > self.min_se;

        // Update min_se to be at least the remote's requirement
        if remote_min_se > self.min_se {
            self.min_se = remote_min_se;
        }

        // Ensure session_expires is at least min_se
        if self.session_expires < self.min_se {
            self.session_expires = self.min_se;
        }

        Handle422Result {
            session_expires: self.session_expires,
            min_se: self.min_se,
            should_include_min_se_header,
        }
    }

    /// Process a 200 OK response to an INVITE that requested session timers (Bug #63).
    ///
    /// If the remote omits the `Session-Expires` header from the 200 OK even though
    /// we requested session timers, we fall back to the default of 1800 seconds
    /// (RFC 4028 Section 5) and start the timer as the local refresher.
    ///
    /// # Arguments
    /// * `session_expires_header` - The raw `Session-Expires` header value from
    ///   the 200 OK, or `None` if the header was absent.
    /// * `is_uac` - Whether we are the UAC side of the dialog (Bug #71).
    ///
    /// # Returns
    /// The negotiated `(session_expires, RefreshRole)` that was applied to the timer.
    pub fn process_response(
        &mut self,
        session_expires_header: Option<&str>,
        is_uac: bool,
    ) -> (u32, RefreshRole) {
        const DEFAULT_SESSION_EXPIRES: u32 = 1800;

        match session_expires_header {
            Some(header) => {
                if let Some((seconds, role_opt)) = Self::parse_session_expires(header, is_uac) {
                    let role = role_opt.unwrap_or(self.config.preferred_role);
                    self.start(seconds, role);
                    (seconds.max(self.min_se), role)
                } else {
                    // Header present but unparseable -- fall back to default
                    tracing::warn!(
                        header = header,
                        "Could not parse Session-Expires from 200 OK, using default {}s",
                        DEFAULT_SESSION_EXPIRES
                    );
                    let role = RefreshRole::Local;
                    self.start(DEFAULT_SESSION_EXPIRES, role);
                    (DEFAULT_SESSION_EXPIRES, role)
                }
            }
            None => {
                // Bug #63: Remote omitted Session-Expires entirely.
                // Fall back to 1800s per RFC 4028 Section 5.
                tracing::warn!(
                    "Remote omitted Session-Expires in 200 OK, defaulting to {}s",
                    DEFAULT_SESSION_EXPIRES
                );
                let role = RefreshRole::Local;
                self.start(DEFAULT_SESSION_EXPIRES, role);
                (DEFAULT_SESSION_EXPIRES, role)
            }
        }
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

    /// P2-TIMER-6: Compute the refresh interval.
    /// Uses min(session_expires/2, session_expires - grace) where
    /// grace = min(32, session_expires/3).
    fn refresh_interval(&self) -> Duration {
        let se = u64::from(self.session_expires);
        let grace = grace_seconds(self.session_expires);
        let half = se / 2;
        let before_grace = se.saturating_sub(grace);
        Duration::from_secs(std::cmp::min(half, before_grace))
    }

    /// Extract the `RefreshRole` from a parameters string like `"refresher=uac"`.
    ///
    /// Bug #71: The mapping depends on whether *we* are the UAC or UAS:
    /// - If we are UAC: `refresher=uac` -> Local, `refresher=uas` -> Remote
    /// - If we are UAS: `refresher=uac` -> Remote, `refresher=uas` -> Local
    fn extract_refresher_role(params: &str, is_uac: bool) -> Option<RefreshRole> {
        for param in params.split(';') {
            let param = param.trim();
            if let Some(value) = param.strip_prefix("refresher=") {
                let value = value.trim().to_lowercase();
                return match value.as_str() {
                    "uac" => Some(if is_uac {
                        RefreshRole::Local
                    } else {
                        RefreshRole::Remote
                    }),
                    "uas" => Some(if is_uac {
                        RefreshRole::Remote
                    } else {
                        RefreshRole::Local
                    }),
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
        // P1-TIMER-1: grace = min(32, session_expires/3).
        // With session_expires=3, grace = min(32, 1) = 1. Total = 4s.
        // Use session_expires=3 so we can test within a reasonable time.
        let config = SessionTimerConfig {
            session_expires: 3,
            min_se: 1,
            ..Default::default()
        };
        let mut timer = SessionTimer::new(config);
        timer.start(3, RefreshRole::Local);

        // Immediately: not expired.
        assert!(!timer.is_expired());

        // After 3 seconds (session_expires) but before grace period: not expired.
        thread::sleep(Duration::from_millis(3100));
        assert!(!timer.is_expired());

        // Verify time_until_expiry is roughly grace (1s) minus the small overshoot
        let remaining = timer.time_until_expiry();
        // Total = 3 + 1 = 4s. Elapsed ~3.1s. Remaining ~0.9s.
        assert!(remaining.as_millis() <= 1000);
        assert!(remaining.as_millis() >= 700);

        // After total interval (4s), should be expired.
        thread::sleep(Duration::from_millis(1000));
        assert!(timer.is_expired());
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
        // As UAC: refresher=uac -> Local, refresher=uas -> Remote
        let result = SessionTimer::parse_session_expires("1800;refresher=uac", true);
        assert_eq!(result, Some((1800, Some(RefreshRole::Local))));

        let result = SessionTimer::parse_session_expires("900;refresher=uas", true);
        assert_eq!(result, Some((900, Some(RefreshRole::Remote))));

        // With whitespace
        let result = SessionTimer::parse_session_expires("  3600 ; refresher=uac ", true);
        assert_eq!(result, Some((3600, Some(RefreshRole::Local))));
    }

    #[test]
    fn test_parse_session_expires_with_refresher_as_uas() {
        // Bug #71: As UAS: refresher=uac -> Remote, refresher=uas -> Local
        let result = SessionTimer::parse_session_expires("1800;refresher=uac", false);
        assert_eq!(result, Some((1800, Some(RefreshRole::Remote))));

        let result = SessionTimer::parse_session_expires("900;refresher=uas", false);
        assert_eq!(result, Some((900, Some(RefreshRole::Local))));
    }

    #[test]
    fn test_parse_session_expires_without_refresher() {
        let result = SessionTimer::parse_session_expires("1800", true);
        assert_eq!(result, Some((1800, None)));

        let result = SessionTimer::parse_session_expires("  600  ", true);
        assert_eq!(result, Some((600, None)));
    }

    #[test]
    fn test_parse_session_expires_invalid() {
        assert!(SessionTimer::parse_session_expires("", true).is_none());
        assert!(SessionTimer::parse_session_expires("abc", true).is_none());
        assert!(SessionTimer::parse_session_expires(";refresher=uac", true).is_none());
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

        // P1-TIMER-4: As UAC, Local -> uac
        assert_eq!(
            timer.build_session_expires_header(true),
            "1800;refresher=uac"
        );
        // P1-TIMER-4: As UAS, Local -> uas
        assert_eq!(
            timer.build_session_expires_header(false),
            "1800;refresher=uas"
        );
        assert_eq!(timer.build_min_se_header(), "90");

        // Switch to remote role.
        timer.start(900, RefreshRole::Remote);
        // P1-TIMER-4: As UAC, Remote -> uas
        assert_eq!(
            timer.build_session_expires_header(true),
            "900;refresher=uas"
        );
        // P1-TIMER-4: As UAS, Remote -> uac
        assert_eq!(
            timer.build_session_expires_header(false),
            "900;refresher=uac"
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
            timer.build_session_expires_header(true),
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
        let result = SessionTimer::parse_session_expires("1800;refresher=unknown", true);
        assert_eq!(result, Some((1800, None)));
    }

    // === Bug #62: handle_422_response returns Handle422Result ===

    #[test]
    fn test_handle_422_response_increases_min_se() {
        let config = SessionTimerConfig {
            session_expires: 1800,
            min_se: 90,
            ..Default::default()
        };
        let mut timer = SessionTimer::new(config);

        let result = timer.handle_422_response(180);
        assert_eq!(result.min_se, 180);
        assert_eq!(result.session_expires, 1800);
        assert!(result.should_include_min_se_header);
    }

    #[test]
    fn test_handle_422_response_bumps_session_expires() {
        let config = SessionTimerConfig {
            session_expires: 120,
            min_se: 90,
            ..Default::default()
        };
        let mut timer = SessionTimer::new(config);

        let result = timer.handle_422_response(300);
        assert_eq!(result.min_se, 300);
        assert_eq!(result.session_expires, 300);
        assert!(result.should_include_min_se_header);
    }

    #[test]
    fn test_handle_422_response_no_change_when_lower() {
        let config = SessionTimerConfig {
            session_expires: 1800,
            min_se: 200,
            ..Default::default()
        };
        let mut timer = SessionTimer::new(config);

        let result = timer.handle_422_response(90);
        assert_eq!(result.min_se, 200);
        assert_eq!(result.session_expires, 1800);
        assert!(!result.should_include_min_se_header);
    }

    #[test]
    fn test_handle_422_result_should_include_min_se_header() {
        let config = SessionTimerConfig {
            session_expires: 1800,
            min_se: 90,
            ..Default::default()
        };
        let mut timer = SessionTimer::new(config);

        // Remote requires higher Min-SE -> should_include_min_se_header = true
        let result = timer.handle_422_response(180);
        assert!(result.should_include_min_se_header);

        // Remote requires same or lower -> should_include_min_se_header = false
        let result = timer.handle_422_response(180);
        assert!(!result.should_include_min_se_header);
    }

    // === Bug #63: process_response handles missing Session-Expires ===

    #[test]
    fn test_process_response_with_valid_header() {
        let mut timer = SessionTimer::new(SessionTimerConfig::default());

        let (se, role) = timer.process_response(Some("900;refresher=uac"), true);
        assert_eq!(se, 900);
        assert_eq!(role, RefreshRole::Local);
        assert!(timer.is_active());
    }

    #[test]
    fn test_process_response_missing_header_defaults() {
        let mut timer = SessionTimer::new(SessionTimerConfig::default());

        // Bug #63: Remote omits Session-Expires -> default 1800s, Local refresher
        let (se, role) = timer.process_response(None, true);
        assert_eq!(se, 1800);
        assert_eq!(role, RefreshRole::Local);
        assert!(timer.is_active());
    }

    #[test]
    fn test_process_response_unparseable_header_defaults() {
        let mut timer = SessionTimer::new(SessionTimerConfig::default());

        // Malformed header -> fall back to 1800s
        let (se, role) = timer.process_response(Some("invalid"), true);
        assert_eq!(se, 1800);
        assert_eq!(role, RefreshRole::Local);
        assert!(timer.is_active());
    }

    #[test]
    fn test_process_response_without_refresher() {
        let mut timer = SessionTimer::new(SessionTimerConfig::default());

        // No refresher specified -> use preferred_role from config (Local)
        let (se, role) = timer.process_response(Some("600"), true);
        assert_eq!(se, 600);
        assert_eq!(role, RefreshRole::Local);
        assert!(timer.is_active());
    }
}
