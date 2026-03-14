//! Call state machine
//!
//! Defines the state machine for SIP calls.

use std::time::Instant;

/// Unified call state enum used by both the session manager and SIP engine.
///
/// Contains internal states (Initializing, Calling, Answered, Terminating)
/// used by the session manager, SIP engine states (Trying, EarlyMedia, Hold)
/// for tracking call progression, and terminal states (Terminated, Failed, Ended).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    /// Initial state - setting up
    Initializing,
    /// INVITE sent, waiting for response (100 Trying received or no response yet)
    Trying,
    /// INVITE sent, processing (internal session manager state)
    Calling,
    /// 180 Ringing received
    Ringing,
    /// 183 Session Progress with SDP - early media available (ringback, IVR)
    EarlyMedia,
    /// 200 OK received, ACK sent
    Answered,
    /// Media established, call active
    Active,
    /// On hold (local or remote, RFC 6337)
    Hold,
    /// BYE sent or received
    Terminating,
    /// Call ended normally (internal)
    Terminated,
    /// Call ended (exposed to Python)
    Ended,
    /// Call failed
    Failed,
}

impl CallState {
    /// Check if the call is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self, CallState::Terminated | CallState::Failed | CallState::Ended)
    }

    /// Check if media can be sent/received
    pub fn can_media(&self) -> bool {
        matches!(self, CallState::Active | CallState::Answered | CallState::EarlyMedia | CallState::Hold)
    }

    /// Get human-readable state name
    pub fn as_str(&self) -> &'static str {
        match self {
            CallState::Initializing => "initializing",
            CallState::Trying => "trying",
            CallState::Calling => "calling",
            CallState::Ringing => "ringing",
            CallState::EarlyMedia => "early_media",
            CallState::Answered => "answered",
            CallState::Active => "active",
            CallState::Hold => "hold",
            CallState::Terminating => "terminating",
            CallState::Terminated => "terminated",
            CallState::Ended => "ended",
            CallState::Failed => "failed",
        }
    }
}

impl Default for CallState {
    fn default() -> Self {
        CallState::Initializing
    }
}

/// Call direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallDirection {
    /// Outbound call (we initiated)
    Outbound,
    /// Inbound call (we received)
    Inbound,
}

/// Call timing information
#[derive(Debug, Clone)]
pub struct CallTiming {
    /// When the call was created
    pub created_at: Instant,
    /// When ringing started
    pub ringing_at: Option<Instant>,
    /// When the call was answered
    pub answered_at: Option<Instant>,
    /// When the call ended
    pub ended_at: Option<Instant>,
}

impl Default for CallTiming {
    fn default() -> Self {
        Self {
            created_at: Instant::now(),
            ringing_at: None,
            answered_at: None,
            ended_at: None,
        }
    }
}

impl CallTiming {
    /// Get call setup time (creation to answer)
    pub fn setup_time_ms(&self) -> Option<u64> {
        self.answered_at
            .map(|answered| (answered - self.created_at).as_millis() as u64)
    }

    /// Get call duration (answer to end)
    pub fn duration_ms(&self) -> Option<u64> {
        match (self.answered_at, self.ended_at) {
            (Some(answered), Some(ended)) => Some((ended - answered).as_millis() as u64),
            _ => None,
        }
    }

    /// Get ring time (ringing to answer)
    pub fn ring_time_ms(&self) -> Option<u64> {
        match (self.ringing_at, self.answered_at) {
            (Some(ringing), Some(answered)) => Some((answered - ringing).as_millis() as u64),
            _ => None,
        }
    }
}

/// State transition validator
pub struct StateValidator;

impl StateValidator {
    /// Check if a state transition is valid
    pub fn can_transition(from: CallState, to: CallState) -> bool {
        use CallState::*;

        matches!(
            (from, to),
            // Normal outbound call flow
            (Initializing, Calling)
                | (Initializing, Trying)
                | (Calling, Ringing)
                | (Calling, EarlyMedia)
                | (Calling, Answered)
                | (Calling, Failed)
                | (Calling, Terminating)
                | (Calling, Terminated)
                | (Calling, Ended)
                | (Trying, Ringing)
                | (Trying, EarlyMedia)
                | (Trying, Answered)
                | (Trying, Active)
                | (Trying, Failed)
                | (Trying, Terminating)
                | (Trying, Terminated)
                | (Trying, Ended)
                | (Ringing, EarlyMedia)
                | (Ringing, Answered)
                | (Ringing, Active)
                | (Ringing, Failed)
                | (Ringing, Terminating)
                | (Ringing, Terminated)
                | (Ringing, Ended)
                | (EarlyMedia, Ringing)
                | (EarlyMedia, Answered)
                | (EarlyMedia, Active)
                | (EarlyMedia, Failed)
                | (EarlyMedia, Terminating)
                | (EarlyMedia, Terminated)
                | (EarlyMedia, Ended)
                | (Answered, Active)
                | (Answered, Failed)
                | (Answered, Terminating)
                | (Answered, Terminated)
                | (Answered, Ended)
                | (Active, Hold)
                | (Active, Terminating)
                | (Active, Terminated)
                | (Active, Ended)
                | (Active, Failed)
                | (Hold, Active)
                | (Hold, Terminating)
                | (Hold, Terminated)
                | (Hold, Ended)
                | (Hold, Failed)
                | (Terminating, Terminated)
                | (Terminating, Ended)
                | (Terminating, Failed)
                // Normal inbound call flow
                | (Initializing, Ringing)
                | (Initializing, Failed)
                | (Initializing, Ended)
                // Terminal state re-entry (Failed->Terminated)
                | (Failed, Terminated)
                | (Failed, Ended)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_state_terminal() {
        assert!(!CallState::Active.is_terminal());
        assert!(CallState::Terminated.is_terminal());
        assert!(CallState::Failed.is_terminal());
    }

    #[test]
    fn test_call_state_can_media() {
        assert!(CallState::Active.can_media());
        assert!(CallState::Answered.can_media());
        assert!(!CallState::Ringing.can_media());
        assert!(!CallState::Terminated.can_media());
    }

    #[test]
    fn test_valid_transitions() {
        assert!(StateValidator::can_transition(
            CallState::Initializing,
            CallState::Calling
        ));
        assert!(StateValidator::can_transition(
            CallState::Calling,
            CallState::Ringing
        ));
        assert!(StateValidator::can_transition(
            CallState::Ringing,
            CallState::Answered
        ));
        assert!(StateValidator::can_transition(
            CallState::Active,
            CallState::Terminating
        ));
    }

    #[test]
    fn test_invalid_transitions() {
        assert!(!StateValidator::can_transition(
            CallState::Terminated,
            CallState::Active
        ));
        assert!(!StateValidator::can_transition(
            CallState::Initializing,
            CallState::Active
        ));
    }

    // P1-STATE-2: Unified CallState includes all states
    #[test]
    fn test_unified_call_state_has_all_variants() {
        // Verify all variants exist and are distinct
        let states = vec![
            CallState::Initializing,
            CallState::Trying,
            CallState::Calling,
            CallState::Ringing,
            CallState::EarlyMedia,
            CallState::Answered,
            CallState::Active,
            CallState::Hold,
            CallState::Terminating,
            CallState::Terminated,
            CallState::Ended,
            CallState::Failed,
        ];
        assert_eq!(states.len(), 12);
        // Verify all state names
        assert_eq!(CallState::Trying.as_str(), "trying");
        assert_eq!(CallState::EarlyMedia.as_str(), "early_media");
        assert_eq!(CallState::Hold.as_str(), "hold");
        assert_eq!(CallState::Ended.as_str(), "ended");
    }

    #[test]
    fn test_terminal_states() {
        assert!(CallState::Terminated.is_terminal());
        assert!(CallState::Failed.is_terminal());
        assert!(CallState::Ended.is_terminal());
        assert!(!CallState::Active.is_terminal());
        assert!(!CallState::Hold.is_terminal());
    }

    #[test]
    fn test_can_media_states() {
        assert!(CallState::Active.can_media());
        assert!(CallState::Answered.can_media());
        assert!(CallState::EarlyMedia.can_media());
        assert!(CallState::Hold.can_media());
        assert!(!CallState::Ringing.can_media());
        assert!(!CallState::Trying.can_media());
        assert!(!CallState::Terminated.can_media());
    }

    // P1-STATE-3: Missing transitions are now present
    #[test]
    fn test_p1_state3_missing_transitions() {
        // Ringing -> Terminated
        assert!(StateValidator::can_transition(
            CallState::Ringing,
            CallState::Terminated
        ));
        // Calling -> Terminated
        assert!(StateValidator::can_transition(
            CallState::Calling,
            CallState::Terminated
        ));
        // Terminating -> Failed
        assert!(StateValidator::can_transition(
            CallState::Terminating,
            CallState::Failed
        ));
        // Failed -> Terminated
        assert!(StateValidator::can_transition(
            CallState::Failed,
            CallState::Terminated
        ));
        // EarlyMedia transitions
        assert!(StateValidator::can_transition(
            CallState::EarlyMedia,
            CallState::Active
        ));
        assert!(StateValidator::can_transition(
            CallState::EarlyMedia,
            CallState::Ended
        ));
        // Hold transitions
        assert!(StateValidator::can_transition(
            CallState::Active,
            CallState::Hold
        ));
        assert!(StateValidator::can_transition(
            CallState::Hold,
            CallState::Active
        ));
        assert!(StateValidator::can_transition(
            CallState::Hold,
            CallState::Ended
        ));
    }

    #[test]
    fn test_timing() {
        let mut timing = CallTiming::default();
        std::thread::sleep(std::time::Duration::from_millis(10));
        timing.answered_at = Some(Instant::now());
        std::thread::sleep(std::time::Duration::from_millis(10));
        timing.ended_at = Some(Instant::now());

        assert!(timing.setup_time_ms().unwrap() >= 10);
        assert!(timing.duration_ms().unwrap() >= 10);
    }
}
