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
    /// Transfer target URI (for transfer_initiated, refer_received events)
    #[pyo3(get)]
    pub target: Option<String>,
    /// Status code (for transfer_progress events)
    #[pyo3(get)]
    pub status_code: Option<u16>,
    /// Whether a transfer completed (for transfer_progress events)
    #[pyo3(get)]
    pub completed: Option<bool>,
    /// Redirect target URIs (for redirected events)
    #[pyo3(get)]
    pub targets: Option<Vec<String>>,
    /// Registration/gateway state string (for registration_changed, gateway_health events)
    #[pyo3(get)]
    pub state: Option<String>,
    /// Server address (for gateway_health events)
    #[pyo3(get)]
    pub server: Option<String>,
    /// Health flag (for gateway_health events)
    #[pyo3(get)]
    pub healthy: Option<bool>,
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

    fn is_transfer_initiated(&self) -> bool {
        self.event_type == "transfer_initiated"
    }
    fn is_transfer_progress(&self) -> bool {
        self.event_type == "transfer_progress"
    }
    fn is_transfer_failed(&self) -> bool {
        self.event_type == "transfer_failed"
    }
    fn is_refer_received(&self) -> bool {
        self.event_type == "refer_received"
    }
    fn is_cancelled(&self) -> bool {
        self.event_type == "cancelled"
    }
    fn is_redirected(&self) -> bool {
        self.event_type == "redirected"
    }
    fn is_media_timeout(&self) -> bool {
        self.event_type == "media_timeout"
    }
    fn is_registration_changed(&self) -> bool {
        self.event_type == "registration_changed"
    }
    fn is_gateway_health(&self) -> bool {
        self.event_type == "gateway_health"
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
                target: None,
                status_code: None,
                completed: None,
                targets: None,
                state: None,
                server: None,
                healthy: None,
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
                target: None,
                status_code: None,
                completed: None,
                targets: None,
                state: None,
                server: None,
                healthy: None,
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
                target: None,
                status_code: None,
                completed: None,
                targets: None,
                state: None,
                server: None,
                healthy: None,
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
                target: None,
                status_code: None,
                completed: None,
                targets: None,
                state: None,
                server: None,
                healthy: None,
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
                target: None,
                status_code: None,
                completed: None,
                targets: None,
                state: None,
                server: None,
                healthy: None,
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
                target: None,
                status_code: None,
                completed: None,
                targets: None,
                state: None,
                server: None,
                healthy: None,
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
                target: None,
                status_code: None,
                completed: None,
                targets: None,
                state: None,
                server: None,
                healthy: None,
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
                target: None,
                status_code: None,
                completed: None,
                targets: None,
                state: None,
                server: None,
                healthy: None,
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
                target: None,
                status_code: None,
                completed: None,
                targets: None,
                state: None,
                server: None,
                healthy: None,
            },
            RustCallEvent::TransferInitiated { call_id, target } => PyCallEvent {
                event_type: "transfer_initiated".to_string(),
                call_id,
                from_uri: None, to_uri: None, reason: None, error: None,
                sdp: None, digit: None, duration: None,
                target: Some(target),
                status_code: None, completed: None, targets: None,
                state: None, server: None, healthy: None,
            },
            RustCallEvent::TransferProgress { call_id, status_code, reason, completed } => PyCallEvent {
                event_type: "transfer_progress".to_string(),
                call_id,
                from_uri: None, to_uri: None, reason: Some(reason), error: None,
                sdp: None, digit: None, duration: None,
                target: None,
                status_code: Some(status_code), completed: Some(completed), targets: None,
                state: None, server: None, healthy: None,
            },
            RustCallEvent::TransferFailed { call_id, error } => PyCallEvent {
                event_type: "transfer_failed".to_string(),
                call_id,
                from_uri: None, to_uri: None, reason: None, error: Some(error),
                sdp: None, digit: None, duration: None,
                target: None,
                status_code: None, completed: None, targets: None,
                state: None, server: None, healthy: None,
            },
            RustCallEvent::ReferReceived { call_id, refer_to } => PyCallEvent {
                event_type: "refer_received".to_string(),
                call_id,
                from_uri: None, to_uri: None, reason: None, error: None,
                sdp: None, digit: None, duration: None,
                target: Some(refer_to),
                status_code: None, completed: None, targets: None,
                state: None, server: None, healthy: None,
            },
            RustCallEvent::Cancelled { call_id } => PyCallEvent {
                event_type: "cancelled".to_string(),
                call_id,
                from_uri: None, to_uri: None, reason: None, error: None,
                sdp: None, digit: None, duration: None,
                target: None,
                status_code: None, completed: None, targets: None,
                state: None, server: None, healthy: None,
            },
            RustCallEvent::Redirected { call_id, targets } => PyCallEvent {
                event_type: "redirected".to_string(),
                call_id,
                from_uri: None, to_uri: None, reason: None, error: None,
                sdp: None, digit: None, duration: None,
                target: None,
                status_code: None, completed: None, targets: Some(targets),
                state: None, server: None, healthy: None,
            },
            RustCallEvent::MediaTimeout { call_id } => PyCallEvent {
                event_type: "media_timeout".to_string(),
                call_id,
                from_uri: None, to_uri: None, reason: None, error: None,
                sdp: None, digit: None, duration: None,
                target: None,
                status_code: None, completed: None, targets: None,
                state: None, server: None, healthy: None,
            },
            RustCallEvent::RegistrationChanged { state, error } => PyCallEvent {
                event_type: "registration_changed".to_string(),
                call_id: String::new(),
                from_uri: None, to_uri: None, reason: None, error,
                sdp: None, digit: None, duration: None,
                target: None,
                status_code: None, completed: None, targets: None,
                state: Some(state), server: None, healthy: None,
            },
            RustCallEvent::GatewayHealth { server, healthy } => PyCallEvent {
                event_type: "gateway_health".to_string(),
                call_id: String::new(),
                from_uri: None, to_uri: None, reason: None, error: None,
                sdp: None, digit: None, duration: None,
                target: None,
                status_code: None, completed: None, targets: None,
                state: None, server: Some(server), healthy: Some(healthy),
            },
        }
    }
}

/// Call state enum for Python (simplified - 6 states)
#[pyclass(name = "CallState", eq, eq_int)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PyCallState {
    /// INVITE sent, waiting for response (Bug #54)
    Trying = 0,
    /// 180 Ringing - call is ringing, no media yet
    Ringing = 1,
    /// 183 Session Progress with SDP - early media available
    EarlyMedia = 2,
    /// 200 OK - call answered and connected
    Active = 3,
    /// On hold (local or remote)
    Hold = 4,
    /// Call ended
    Ended = 5,
}

impl From<crate::sip::engine::CallState> for PyCallState {
    fn from(state: crate::sip::engine::CallState) -> Self {
        use crate::sip::engine::CallState;
        match state {
            // Direct mappings
            CallState::Trying => PyCallState::Trying,
            CallState::Ringing => PyCallState::Ringing,
            CallState::EarlyMedia => PyCallState::EarlyMedia,
            CallState::Active => PyCallState::Active,
            CallState::Hold => PyCallState::Hold,
            CallState::Ended => PyCallState::Ended,
            // Internal states mapped to closest Python equivalent
            CallState::Initializing | CallState::Calling => PyCallState::Trying,
            CallState::Answered => PyCallState::Active,
            CallState::Terminating | CallState::Terminated | CallState::Failed => {
                PyCallState::Ended
            }
        }
    }
}
