//! Call state machine
//!
//! Defines the state machine for SIP calls.

use std::time::Instant;

/// Call state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    /// Initial state - setting up
    Initializing,
    /// INVITE sent, waiting for response
    Calling,
    /// 180 Ringing received
    Ringing,
    /// 200 OK received, ACK sent
    Answered,
    /// Media established, call active
    Active,
    /// BYE sent or received
    Terminating,
    /// Call ended
    Terminated,
    /// Call failed
    Failed,
}

impl CallState {
    /// Check if the call is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self, CallState::Terminated | CallState::Failed)
    }

    /// Check if media can be sent/received
    pub fn can_media(&self) -> bool {
        matches!(self, CallState::Active | CallState::Answered)
    }

    /// Get human-readable state name
    pub fn as_str(&self) -> &'static str {
        match self {
            CallState::Initializing => "initializing",
            CallState::Calling => "calling",
            CallState::Ringing => "ringing",
            CallState::Answered => "answered",
            CallState::Active => "active",
            CallState::Terminating => "terminating",
            CallState::Terminated => "terminated",
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
                | (Calling, Ringing)
                | (Calling, Answered)
                | (Calling, Failed)
                | (Calling, Terminating)
                | (Ringing, Answered)
                | (Ringing, Failed)
                | (Ringing, Terminating)
                | (Answered, Active)
                | (Answered, Failed)
                | (Answered, Terminating)
                | (Active, Terminating)
                | (Active, Failed)
                | (Terminating, Terminated)
                // Normal inbound call flow
                | (Initializing, Ringing)
                | (Initializing, Failed)
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
