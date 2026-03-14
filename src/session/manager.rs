//! Session manager
//!
//! Manages multiple concurrent call sessions.

use super::events::CallEvent;
use super::state::{CallDirection, CallState, CallTiming, StateValidator};
use crate::provider::{ProviderConfig, ProviderRouter};
use crate::rtp::RtpEngine;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::broadcast;

/// A call session
pub struct CallSession {
    /// Unique call identifier
    pub call_id: String,
    /// Current state
    pub state: CallState,
    /// Call direction
    pub direction: CallDirection,
    /// Provider used for this call
    pub provider_id: String,
    /// RTP engine for media
    pub rtp_engine: Option<Arc<RtpEngine>>,
    /// Remote party
    pub remote_party: String,
    /// Local party (caller ID)
    pub local_party: String,
    /// Timing information
    pub timing: CallTiming,
    /// Local SDP
    pub local_sdp: Option<String>,
    /// Remote SDP
    pub remote_sdp: Option<String>,
}

impl CallSession {
    /// Create a new outbound call session
    pub fn new_outbound(
        call_id: &str,
        to: &str,
        from: &str,
        provider_id: &str,
    ) -> Self {
        Self {
            call_id: call_id.to_string(),
            state: CallState::Initializing,
            direction: CallDirection::Outbound,
            provider_id: provider_id.to_string(),
            rtp_engine: None,
            remote_party: to.to_string(),
            local_party: from.to_string(),
            timing: CallTiming::default(),
            local_sdp: None,
            remote_sdp: None,
        }
    }

    /// Create a new inbound call session
    pub fn new_inbound(
        call_id: &str,
        from: &str,
        to: &str,
        provider_id: &str,
    ) -> Self {
        Self {
            call_id: call_id.to_string(),
            state: CallState::Ringing,
            direction: CallDirection::Inbound,
            provider_id: provider_id.to_string(),
            rtp_engine: None,
            remote_party: from.to_string(),
            local_party: to.to_string(),
            timing: CallTiming::default(),
            local_sdp: None,
            remote_sdp: None,
        }
    }

    /// Set the RTP engine
    pub fn set_rtp_engine(&mut self, engine: Arc<RtpEngine>) {
        self.rtp_engine = Some(engine);
    }

    /// Update call state
    pub fn set_state(&mut self, state: CallState) {
        use std::time::Instant;

        match state {
            CallState::Ringing => {
                self.timing.ringing_at = Some(Instant::now());
            }
            CallState::Answered | CallState::Active => {
                if self.timing.answered_at.is_none() {
                    self.timing.answered_at = Some(Instant::now());
                }
            }
            CallState::Terminated | CallState::Failed | CallState::Ended => {
                self.timing.ended_at = Some(Instant::now());
            }
            _ => {}
        }

        self.state = state;
    }
}

/// Session manager for handling multiple calls
pub struct SessionManager {
    /// Active sessions
    sessions: DashMap<String, Arc<parking_lot::Mutex<CallSession>>>,
    /// Provider router
    router: Arc<ProviderRouter>,
    /// Event broadcaster
    event_tx: broadcast::Sender<CallEvent>,
}

impl SessionManager {
    /// Create a new session manager
    ///
    /// P2-STATE-4: Broadcast channel capacity increased to 4096 to prevent
    /// dropped events under high call volume.
    pub fn new(router: Arc<ProviderRouter>) -> Self {
        let (event_tx, _) = broadcast::channel(4096);
        Self {
            sessions: DashMap::new(),
            router,
            event_tx,
        }
    }

    /// Subscribe to call events
    pub fn subscribe(&self) -> broadcast::Receiver<CallEvent> {
        self.event_tx.subscribe()
    }

    /// Add a session
    pub fn add_session(&self, session: CallSession) {
        let call_id = session.call_id.clone();
        self.sessions.insert(call_id, Arc::new(parking_lot::Mutex::new(session)));
    }

    /// Get a session by call ID
    pub fn get_session(&self, call_id: &str) -> Option<Arc<parking_lot::Mutex<CallSession>>> {
        self.sessions.get(call_id).map(|s| s.clone())
    }

    /// Remove a session
    ///
    /// P2-STATE-6: Performs resource cleanup before removing the session.
    /// Stops the RTP engine (if running) and releases any allocated ports.
    pub fn remove_session(&self, call_id: &str) -> Option<Arc<parking_lot::Mutex<CallSession>>> {
        if let Some((_, session)) = self.sessions.remove(call_id) {
            // P2-STATE-6: Clean up RTP engine resources
            let sess = session.lock();
            if let Some(ref rtp) = sess.rtp_engine {
                rtp.stop();
            }
            drop(sess);
            Some(session)
        } else {
            None
        }
    }

    /// Get all active call IDs
    pub fn active_calls(&self) -> Vec<String> {
        self.sessions.iter().map(|e| e.key().clone()).collect()
    }

    /// Get number of active calls
    pub fn active_call_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get the router
    pub fn router(&self) -> &Arc<ProviderRouter> {
        &self.router
    }

    /// Emit an event
    pub fn emit(&self, event: CallEvent) {
        let _ = self.event_tx.send(event);
    }

    /// Update session state and emit event
    ///
    /// P1-STATE-1: Validates the transition using `StateValidator::can_transition`
    /// and logs a warning on invalid transitions.
    pub fn update_state(&self, call_id: &str, new_state: CallState) {
        if let Some(session) = self.get_session(call_id) {
            let mut sess = session.lock();
            let old_state = sess.state;

            // P1-STATE-1: Validate transition
            if !StateValidator::can_transition(old_state, new_state) {
                tracing::warn!(
                    call_id = call_id,
                    from = old_state.as_str(),
                    to = new_state.as_str(),
                    "invalid state transition"
                );
            }

            sess.set_state(new_state);

            self.emit(CallEvent::state_changed(call_id, old_state, new_state));
        }
    }

    /// Route and get provider for a destination
    pub fn route(&self, destination: &str) -> Option<ProviderConfig> {
        self.router.route(destination)
    }
}

/// Manager handle type
pub type ManagerHandle = Arc<SessionManager>;

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_manager() -> SessionManager {
        let router = Arc::new(ProviderRouter::new());
        router.add_provider(
            ProviderConfig::new("test", "sip.test.com", "u", "p")
        );
        SessionManager::new(router)
    }

    #[test]
    fn test_add_get_session() {
        let manager = setup_manager();

        let session = CallSession::new_outbound(
            "call-1",
            "+14155551234",
            "+14155550000",
            "test",
        );

        manager.add_session(session);

        let retrieved = manager.get_session("call-1");
        assert!(retrieved.is_some());

        let sess = retrieved.unwrap();
        assert_eq!(sess.lock().call_id, "call-1");
    }

    #[test]
    fn test_remove_session() {
        let manager = setup_manager();

        let session = CallSession::new_outbound("call-1", "to", "from", "test");
        manager.add_session(session);

        assert_eq!(manager.active_call_count(), 1);

        manager.remove_session("call-1");

        assert_eq!(manager.active_call_count(), 0);
        assert!(manager.get_session("call-1").is_none());
    }

    #[test]
    fn test_active_calls() {
        let manager = setup_manager();

        manager.add_session(CallSession::new_outbound("call-1", "to", "from", "test"));
        manager.add_session(CallSession::new_outbound("call-2", "to", "from", "test"));

        let active = manager.active_calls();
        assert_eq!(active.len(), 2);
        assert!(active.contains(&"call-1".to_string()));
        assert!(active.contains(&"call-2".to_string()));
    }

    #[test]
    fn test_state_update() {
        let manager = setup_manager();

        let session = CallSession::new_outbound("call-1", "to", "from", "test");
        manager.add_session(session);

        manager.update_state("call-1", CallState::Ringing);

        let sess = manager.get_session("call-1").unwrap();
        assert_eq!(sess.lock().state, CallState::Ringing);
    }

    #[test]
    fn test_event_subscription() {
        let manager = setup_manager();
        let mut rx = manager.subscribe();

        manager.emit(CallEvent::Ringing {
            call_id: "test".to_string(),
        });

        // Event should be received
        let event = rx.try_recv();
        assert!(event.is_ok());
    }
}
