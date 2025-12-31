//! Python event types
//!
//! Wraps CallEvent for Python consumption.

use crate::sip::engine::CallEvent as RustCallEvent;
use pyo3::prelude::*;

/// Call event for Python
#[pyclass(name = "CallEvent")]
#[derive(Clone)]
pub struct PyCallEvent {
    #[pyo3(get)]
    pub event_type: String,
    #[pyo3(get)]
    pub call_id: String,
    #[pyo3(get)]
    pub from_uri: Option<String>,
    #[pyo3(get)]
    pub to_uri: Option<String>,
    #[pyo3(get)]
    pub reason: Option<String>,
    #[pyo3(get)]
    pub error: Option<String>,
    /// SDP body (for early_media and reinvite events)
    #[pyo3(get)]
    pub sdp: Option<String>,
    /// DTMF digit (for dtmf_received events)
    #[pyo3(get)]
    pub digit: Option<String>,
    /// DTMF duration in ms (for dtmf_received events)
    #[pyo3(get)]
    pub duration: Option<u32>,
}

#[pymethods]
impl PyCallEvent {
    fn __repr__(&self) -> String {
        format!(
            "CallEvent(type='{}', call_id='{}')",
            self.event_type, self.call_id
        )
    }

    /// Check if this is an incoming call event
    fn is_incoming(&self) -> bool {
        self.event_type == "incoming"
    }

    /// Check if this is a ringing event (180 Ringing)
    fn is_ringing(&self) -> bool {
        self.event_type == "ringing"
    }

    /// Check if this is an early media event (183 Session Progress)
    fn is_early_media(&self) -> bool {
        self.event_type == "early_media"
    }

    /// Check if this is an answered event (200 OK)
    fn is_answered(&self) -> bool {
        self.event_type == "answered"
    }

    /// Check if this is an audio ready event
    fn is_audio_ready(&self) -> bool {
        self.event_type == "audio_ready"
    }

    /// Check if this is a DTMF received event
    fn is_dtmf(&self) -> bool {
        self.event_type == "dtmf_received"
    }

    /// Check if this is a re-INVITE event
    fn is_reinvite(&self) -> bool {
        self.event_type == "reinvite"
    }

    /// Check if this is a hangup event
    fn is_hangup(&self) -> bool {
        self.event_type == "hangup"
    }

    /// Check if this is an error event
    fn is_error(&self) -> bool {
        self.event_type == "error"
    }
}

impl From<RustCallEvent> for PyCallEvent {
    fn from(event: RustCallEvent) -> Self {
        match event {
            RustCallEvent::Incoming { call_id, from, to } => PyCallEvent {
                event_type: "incoming".to_string(),
                call_id,
                from_uri: Some(from),
                to_uri: Some(to),
                reason: None,
                error: None,
                sdp: None,
                digit: None,
                duration: None,
            },
            RustCallEvent::Ringing { call_id } => PyCallEvent {
                event_type: "ringing".to_string(),
                call_id,
                from_uri: None,
                to_uri: None,
                reason: None,
                error: None,
                sdp: None,
                digit: None,
                duration: None,
            },
            RustCallEvent::EarlyMedia { call_id, sdp } => PyCallEvent {
                event_type: "early_media".to_string(),
                call_id,
                from_uri: None,
                to_uri: None,
                reason: None,
                error: None,
                sdp,
                digit: None,
                duration: None,
            },
            RustCallEvent::Answered { call_id } => PyCallEvent {
                event_type: "answered".to_string(),
                call_id,
                from_uri: None,
                to_uri: None,
                reason: None,
                error: None,
                sdp: None,
                digit: None,
                duration: None,
            },
            RustCallEvent::AudioReady { call_id } => PyCallEvent {
                event_type: "audio_ready".to_string(),
                call_id,
                from_uri: None,
                to_uri: None,
                reason: None,
                error: None,
                sdp: None,
                digit: None,
                duration: None,
            },
            RustCallEvent::DtmfReceived { call_id, digit, duration } => PyCallEvent {
                event_type: "dtmf_received".to_string(),
                call_id,
                from_uri: None,
                to_uri: None,
                reason: None,
                error: None,
                sdp: None,
                digit: Some(digit.to_string()),
                duration: Some(duration),
            },
            RustCallEvent::ReInvite { call_id, sdp } => PyCallEvent {
                event_type: "reinvite".to_string(),
                call_id,
                from_uri: None,
                to_uri: None,
                reason: None,
                error: None,
                sdp,
                digit: None,
                duration: None,
            },
            RustCallEvent::Hangup { call_id, reason } => PyCallEvent {
                event_type: "hangup".to_string(),
                call_id,
                from_uri: None,
                to_uri: None,
                reason: Some(reason),
                error: None,
                sdp: None,
                digit: None,
                duration: None,
            },
            RustCallEvent::Error { call_id, error } => PyCallEvent {
                event_type: "error".to_string(),
                call_id,
                from_uri: None,
                to_uri: None,
                reason: None,
                error: Some(error),
                sdp: None,
                digit: None,
                duration: None,
            },
        }
    }
}

/// Call state enum for Python (simplified - 5 states)
#[pyclass(name = "CallState", eq, eq_int)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PyCallState {
    /// 180 Ringing - call is ringing, no media yet
    Ringing = 0,
    /// 183 Session Progress with SDP - early media available
    EarlyMedia = 1,
    /// 200 OK - call answered and connected
    Active = 2,
    /// On hold (local or remote)
    Hold = 3,
    /// Call ended
    Ended = 4,
}

impl From<crate::sip::engine::CallState> for PyCallState {
    fn from(state: crate::sip::engine::CallState) -> Self {
        use crate::sip::engine::CallState;
        match state {
            CallState::Ringing => PyCallState::Ringing,
            CallState::EarlyMedia => PyCallState::EarlyMedia,
            CallState::Active => PyCallState::Active,
            CallState::Hold => PyCallState::Hold,
            CallState::Ended => PyCallState::Ended,
        }
    }
}
