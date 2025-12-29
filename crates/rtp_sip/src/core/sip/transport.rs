//! SipTransport - implements Transport trait for SIP/RTP via mod_sofia
//!
//! Provides a high-level async interface for:
//! - Making outbound calls
//! - Receiving inbound calls
//! - Managing call sessions with audio

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::{broadcast, Mutex, RwLock};
use tracing::{debug, info, warn};

use crate::core::error::{Error, Result};
use crate::core::runtime::Runtime;
use crate::core::sip::config::{SipConfig, TrunkConfig};
use crate::core::sip::session::SipSession;

/// Events emitted by the transport
#[derive(Debug, Clone)]
pub enum TransportEvent {
    /// New inbound call received
    InboundCall {
        uuid: String,
        caller_id: Option<String>,
        destination: Option<String>,
    },
    /// Call answered
    CallAnswered { uuid: String },
    /// Call hung up
    CallHungup { uuid: String, cause: String },
    /// Transport started
    Started,
    /// Transport stopped
    Stopped,
}

/// SIP transport using embedded FreeSWITCH with mod_sofia
///
/// This transport uses media bugs to capture/inject audio,
/// which works correctly with mod_sofia's internal RTP management.
pub struct SipTransport {
    config: SipConfig,
    /// Registered trunks
    trunks: RwLock<HashMap<String, TrunkConfig>>,
    /// Active sessions by UUID
    sessions: RwLock<HashMap<String, Arc<Mutex<SipSession>>>>,
    /// Running flag
    running: AtomicBool,
    /// Event broadcaster
    event_tx: broadcast::Sender<TransportEvent>,
    /// Event receiver (kept to prevent channel from closing)
    _event_rx: broadcast::Receiver<TransportEvent>,
}

impl SipTransport {
    /// Create a new SIP transport
    pub fn new(config: SipConfig) -> Result<Self> {
        config.validate()?;

        let (event_tx, event_rx) = broadcast::channel(100);

        Ok(Self {
            config,
            trunks: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            running: AtomicBool::new(false),
            event_tx,
            _event_rx: event_rx,
        })
    }

    /// Start the transport
    ///
    /// Initializes FreeSWITCH in SIP mode.
    ///
    /// Note: Once SIP mode is initialized, you cannot use RTP-only mode
    /// in the same process. Restart required to switch modes.
    pub async fn start(&self) -> Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(Error::Sip("Transport already running".to_string()));
        }

        info!(
            "Starting SIP transport on {}:{}",
            self.config.local_ip, self.config.local_port
        );

        // Initialize FreeSWITCH in SIP mode (locks this process to SIP mode)
        Runtime::ensure_sip_mode()?;

        // TODO: Configure sofia SIP profile with our local_ip/port
        // For now, we rely on the FreeSWITCH config files

        let _ = self.event_tx.send(TransportEvent::Started);
        info!("SIP transport started");

        Ok(())
    }

    /// Stop the transport
    pub async fn stop(&self) -> Result<()> {
        if !self.running.swap(false, Ordering::SeqCst) {
            return Ok(());
        }

        info!("Stopping SIP transport");

        // Hangup all active sessions
        {
            let sessions = self.sessions.read().await;
            for (uuid, session) in sessions.iter() {
                let mut session = session.lock().await;
                if let Err(e) = session.hangup(None).await {
                    warn!("Error hanging up session {}: {}", uuid, e);
                }
            }
        }

        // Clear sessions
        {
            let mut sessions = self.sessions.write().await;
            sessions.clear();
        }

        // Clear trunks
        {
            let mut trunks = self.trunks.write().await;
            trunks.clear();
        }

        let _ = self.event_tx.send(TransportEvent::Stopped);
        info!("SIP transport stopped");

        Ok(())
    }

    /// Add a SIP trunk for outbound calls
    pub async fn add_trunk(&self, trunk: TrunkConfig) -> Result<()> {
        trunk.validate()?;

        let name = trunk.name.clone();
        info!("Adding trunk: {} -> {}:{}", name, trunk.host, trunk.port);

        // TODO: Create sofia gateway via FS API or config
        // For now, we assume the gateway is configured in sofia.conf.xml

        let mut trunks = self.trunks.write().await;
        trunks.insert(name, trunk);

        Ok(())
    }

    /// Remove a SIP trunk
    pub async fn remove_trunk(&self, name: &str) -> Result<()> {
        let mut trunks = self.trunks.write().await;
        if trunks.remove(name).is_some() {
            info!("Removed trunk: {}", name);
            Ok(())
        } else {
            Err(Error::Sip(format!("Trunk not found: {}", name)))
        }
    }

    /// Make an outbound call
    ///
    /// Returns a SipSession for the connected call.
    pub async fn dial(
        &self,
        destination: &str,
        trunk_name: &str,
        timeout_sec: Option<u32>,
        caller_id_name: Option<&str>,
        caller_id_number: Option<&str>,
    ) -> Result<Arc<Mutex<SipSession>>> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(Error::Sip("Transport not running".to_string()));
        }

        // Get trunk config
        let trunk = {
            let trunks = self.trunks.read().await;
            trunks
                .get(trunk_name)
                .cloned()
                .ok_or_else(|| Error::Sip(format!("Trunk not found: {}", trunk_name)))?
        };

        let dial_string = trunk.dial_string(destination);
        let timeout = timeout_sec.unwrap_or(60);

        // Resolve caller ID
        let cid_name = caller_id_name
            .or(trunk.caller_id_name.as_deref())
            .unwrap_or("rtp_sip")
            .to_string();
        let cid_number = caller_id_number
            .or(trunk.caller_id_number.as_deref())
            .unwrap_or("0000000000")
            .to_string();

        info!(
            "Dialing {} via {} (timeout: {}s, CID: {} <{}>)",
            destination, trunk_name, timeout, cid_name, cid_number
        );

        // Use libfs worker to originate the call
        let worker = crate::core::libfs_worker::LibFsWorker::get()?;
        let session_handle = worker
            .sip_originate(dial_string, timeout, cid_name, cid_number)
            .await?;

        // Create SipSession from the session
        let uuid = unsafe {
            let uuid_ptr = libfs_sys::switch_core_session_get_uuid(session_handle.session);
            libfs_sys::cstr_to_string(uuid_ptr)
                .ok_or_else(|| Error::Session("Failed to get UUID".to_string()))?
        };

        let mut session = unsafe { SipSession::from_session(session_handle.session)? };

        // Start audio processing
        session.start_audio().await?;

        let session = Arc::new(Mutex::new(session));

        // Track the session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(uuid.clone(), session.clone());
        }

        info!("Call {} connected to {}", uuid, destination);

        let _ = self.event_tx.send(TransportEvent::CallAnswered { uuid });

        Ok(session)
    }

    /// Handle an inbound call
    ///
    /// Called by the event handler when a new call arrives.
    pub async fn handle_inbound_call(&self, uuid: &str) -> Result<Arc<Mutex<SipSession>>> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(Error::Sip("Transport not running".to_string()));
        }

        info!("Handling inbound call: {}", uuid);

        // Create SipSession
        let session = SipSession::from_uuid(uuid)?;

        let caller_id = session.caller_id();
        let destination = session.destination();

        let session = Arc::new(Mutex::new(session));

        // Track the session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(uuid.to_string(), session.clone());
        }

        // Emit event
        let _ = self.event_tx.send(TransportEvent::InboundCall {
            uuid: uuid.to_string(),
            caller_id,
            destination,
        });

        Ok(session)
    }

    /// Get a session by UUID
    pub async fn get_session(&self, uuid: &str) -> Option<Arc<Mutex<SipSession>>> {
        let sessions = self.sessions.read().await;
        sessions.get(uuid).cloned()
    }

    /// Remove a session (called on hangup)
    pub async fn remove_session(&self, uuid: &str) {
        let mut sessions = self.sessions.write().await;
        if sessions.remove(uuid).is_some() {
            debug!("Session {} removed from transport", uuid);
            let _ = self.event_tx.send(TransportEvent::CallHungup {
                uuid: uuid.to_string(),
                cause: "normal_clearing".to_string(),
            });
        }
    }

    /// Subscribe to transport events
    pub fn subscribe(&self) -> broadcast::Receiver<TransportEvent> {
        self.event_tx.subscribe()
    }

    /// Check if transport is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get list of active session UUIDs
    pub async fn list_sessions(&self) -> Vec<String> {
        let sessions = self.sessions.read().await;
        sessions.keys().cloned().collect()
    }
}

impl Drop for SipTransport {
    fn drop(&mut self) {
        if self.running.load(Ordering::SeqCst) {
            self.running.store(false, Ordering::SeqCst);
            debug!("SipTransport dropped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_new() {
        let config = SipConfig::default();
        let transport = SipTransport::new(config);
        assert!(transport.is_ok());
    }
}
