//! Call events
//!
//! Defines events emitted during call lifecycle.

use super::state::CallState;
use serde::{Deserialize, Serialize};

/// Call event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CallEvent {
    /// Incoming call received
    Incoming {
        call_id: String,
        from: String,
        to: String,
        provider_id: String,
    },

    /// Outbound call initiated
    Calling {
        call_id: String,
        to: String,
        from: String,
        provider_id: String,
    },

    /// Call is ringing
    Ringing { call_id: String },

    /// Call was answered
    Answered { call_id: String },

    /// Media is ready (RTP established)
    MediaReady { call_id: String },

    /// Call state changed
    StateChanged {
        call_id: String,
        old_state: String,
        new_state: String,
    },

    /// Call ended normally
    Ended {
        call_id: String,
        reason: String,
        duration_ms: Option<u64>,
    },

    /// Call failed
    Failed { call_id: String, error: String },

    /// DTMF digit received
    DtmfReceived { call_id: String, digit: char },

    /// Audio received (for debugging/monitoring)
    AudioReceived {
        call_id: String,
        samples: usize,
        timestamp: u32,
    },
}

impl CallEvent {
    /// Get the call ID for this event
    pub fn call_id(&self) -> &str {
        match self {
            CallEvent::Incoming { call_id, .. } => call_id,
            CallEvent::Calling { call_id, .. } => call_id,
            CallEvent::Ringing { call_id } => call_id,
            CallEvent::Answered { call_id } => call_id,
            CallEvent::MediaReady { call_id } => call_id,
            CallEvent::StateChanged { call_id, .. } => call_id,
            CallEvent::Ended { call_id, .. } => call_id,
            CallEvent::Failed { call_id, .. } => call_id,
            CallEvent::DtmfReceived { call_id, .. } => call_id,
            CallEvent::AudioReceived { call_id, .. } => call_id,
        }
    }

    /// Get the event type name
    pub fn event_type(&self) -> &'static str {
        match self {
            CallEvent::Incoming { .. } => "incoming",
            CallEvent::Calling { .. } => "calling",
            CallEvent::Ringing { .. } => "ringing",
            CallEvent::Answered { .. } => "answered",
            CallEvent::MediaReady { .. } => "media_ready",
            CallEvent::StateChanged { .. } => "state_changed",
            CallEvent::Ended { .. } => "ended",
            CallEvent::Failed { .. } => "failed",
            CallEvent::DtmfReceived { .. } => "dtmf_received",
            CallEvent::AudioReceived { .. } => "audio_received",
        }
    }

    /// Create a state changed event
    pub fn state_changed(call_id: &str, old: CallState, new: CallState) -> Self {
        CallEvent::StateChanged {
            call_id: call_id.to_string(),
            old_state: old.as_str().to_string(),
            new_state: new.as_str().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_call_id() {
        let event = CallEvent::Ringing {
            call_id: "test-123".to_string(),
        };
        assert_eq!(event.call_id(), "test-123");
    }

    #[test]
    fn test_event_type() {
        let event = CallEvent::Answered {
            call_id: "test".to_string(),
        };
        assert_eq!(event.event_type(), "answered");
    }

    #[test]
    fn test_state_changed_event() {
        let event = CallEvent::state_changed("call-1", CallState::Ringing, CallState::Answered);
        if let CallEvent::StateChanged {
            old_state,
            new_state,
            ..
        } = event
        {
            assert_eq!(old_state, "ringing");
            assert_eq!(new_state, "answered");
        } else {
            panic!("Wrong event type");
        }
    }

    #[test]
    fn test_event_serialization() {
        let event = CallEvent::Incoming {
            call_id: "abc123".to_string(),
            from: "+14155551234".to_string(),
            to: "+14155550000".to_string(),
            provider_id: "plivo".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"incoming\""));
        assert!(json.contains("\"call_id\":\"abc123\""));
    }
}
