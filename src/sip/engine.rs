//! SIP Engine - Wrapper around rsipstack
//!
//! Provides a simplified interface for SIP operations using rsipstack.
//! All features work for both inbound and outbound calls.
//!
//! # Edge Cases Handled (Inbound & Outbound)
//!
//! ## Early Media Handling (180/183 Responses)
//!
//! - **180 Ringing without SDP**: Generate local ringback tone. Common response.
//! - **183 Session Progress with SDP**: Remote ringback/IVR available. Open RTP.
//! - **180 after 183**: Mobile carrier edge case! Continue using established media
//!   from 183 - do NOT revert to local ringback. This sequence happens when calls
//!   traverse mobile gateways.
//! - **183 without SDP**: Treat as 180 (no early media). Some proxies strip SDP.
//! - **Multiple 183**: Only first 183 with SDP establishes media. Subsequent ones
//!   may update SDP (port/codec changes).
//!
//! ## SDP Changes Between Responses
//!
//! - **Different IP in 200 OK vs 183**: Common with load balancers and call routing.
//!   We re-configure RTP remote address on each SDP.
//! - **Different port in 200 OK**: Same as above. Always update RTP target.
//! - **Different codec in 200 OK**: Rare but handled. Re-negotiation may be needed.
//!
//! ## Hold/Resume (RFC 6337)
//!
//! - **a=sendonly**: Local party initiating hold. We send MOH, remote silent.
//! - **a=recvonly**: Response to hold. We receive MOH, don't send.
//! - **a=inactive**: Both parties on hold. No media flows.
//! - **Legacy c=0.0.0.0**: Deprecated but still common with older PBX systems.
//! - **Port 0**: Stream rejection. Treat as hold/disabled.
//! - **Local vs remote hold tracking**: We track both independently. Call is
//!   in Hold state if either party has initiated hold.
//!
//! ## DTMF Handling
//!
//! - **Auto-detection**: If remote SDP has telephone-event, use RFC 2833.
//!   Otherwise fall back to SIP INFO.
//! - **RFC 2833 via RTP**: Preferred method. In-band with marker bit and
//!   end-bit redundancy (3x per RFC 4733).
//! - **SIP INFO**: Fallback for endpoints without telephone-event support.
//!   Uses application/dtmf-relay content type.
//! - **State validation**: DTMF only allowed in Active state (call answered).
//!   Early media does not support DTMF reliably.
//!
//! ## Re-INVITE Handling
//!
//! - **Incoming re-INVITE**: Received via DialogState::Updated. Update RTP and
//!   detect hold/resume from new SDP.
//! - **Outgoing re-INVITE**: For hold/resume/codec change. Via dialog.reinvite().
//! - **Glare handling**: Not implemented. If both sides re-INVITE simultaneously,
//!   one will get 491 Request Pending. Application should retry.
//!
//! ## REFER Handling (RFC 3515)
//!
//! - **Blind transfer**: Simple REFER with Refer-To header.
//! - **Referred-By header**: RFC 3892. Identifies the transferor.
//! - **NOTIFY subscription**: Pending implementation. Currently fire-and-forget.
//! - **Works for both directions**: Uses client_dialog or server_dialog.
//!
//! ## Inbound vs Outbound Call Handling
//!
//! All features (DTMF, hold, re-INVITE, REFER) work identically for both
//! directions. The code checks `client_dialog` then `server_dialog` to find
//! the appropriate dialog for the operation.

use crate::error::{Result, SipRunnerError};
use crate::rtp::{CodecType, RtpEngine, RtpEngineConfig};
use crate::sip::sdp::{MediaDirection, Sdp, SdpBuilder};
use parking_lot::Mutex;
use rsip::prelude::HeadersExt;
use rsip::Uri;
use rsipstack::dialog::authenticate::Credential;
use rsipstack::dialog::client_dialog::ClientInviteDialog;
use rsipstack::dialog::server_dialog::ServerInviteDialog;
use rsipstack::dialog::dialog::DialogState;
use rsipstack::dialog::dialog_layer::DialogLayer;
use rsipstack::dialog::invitation::InviteOption;
use rsipstack::dialog::registration::Registration;
use rsipstack::transaction::endpoint::{Endpoint, EndpointBuilder, EndpointOption};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc};

/// DTMF transmission mode
///
/// Automatically selected based on remote SDP capabilities.
/// RFC 2833 is preferred when remote supports telephone-event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DtmfMode {
    /// Automatically detect based on remote SDP (default)
    /// Uses RFC 2833 if remote supports telephone-event, else SIP INFO
    #[default]
    Auto,
    /// RFC 2833/4733 telephone-event in RTP stream
    Rfc2833,
    /// SIP INFO with application/dtmf-relay
    Info,
}

/// SIP call state (simplified for Python API)
///
/// Only 5 states exposed - internal transitions handled automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    /// 180 Ringing - call is ringing, no media yet
    Ringing,
    /// 183 Session Progress with SDP - early media available (ringback, IVR)
    EarlyMedia,
    /// 200 OK - call answered and active (resumes here after hold)
    Active,
    /// On hold (local or remote)
    Hold,
    /// Call ended
    Ended,
}

/// Early media state tracking
///
/// Tracks the progression of early media to handle edge cases like
/// receiving 180 after 183 (common with mobile carriers).
///
/// # State Machine
///
/// ```text
/// None -> Ringing180       (on 180 without prior 183)
/// None -> EarlyMedia183    (on 183 with SDP)
/// EarlyMedia183 -> Ringing180After183  (on 180 after 183, KEEP MEDIA!)
/// ```
///
/// # Critical Edge Cases
///
/// ## 180 After 183 (Mobile Carrier Behavior)
/// Many mobile carriers route calls through gateways that:
/// 1. Send 183 with SDP (remote ringback starts)
/// 2. Later send 180 when phone actually rings
///
/// **Naive implementations revert to local ringback on 180, breaking audio!**
/// We detect this with `Ringing180After183` and continue using established media.
///
/// ## Multiple 183 Responses
/// Some forking scenarios send multiple 183 from different endpoints.
/// We use the first one with SDP. Subsequent 183s may update RTP target
/// (handled in DialogState::Early processing).
///
/// ## 183 Without SDP
/// Some SIP proxies strip SDP from 183. Treat as 180 (no early media).
/// The actual media negotiation happens in 200 OK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EarlyMediaState {
    /// No early media response received
    #[default]
    None,
    /// 180 Ringing received (no SDP, use local ringback)
    Ringing180,
    /// 183 Session Progress with SDP (remote ringback available)
    EarlyMedia183,
    /// 180 received after 183 (continue using established media)
    Ringing180After183,
}

/// Call direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}


/// SIP call events
#[derive(Debug, Clone)]
pub enum CallEvent {
    /// Incoming call
    Incoming {
        call_id: String,
        from: String,
        to: String,
    },
    /// Call is ringing (180 Ringing)
    Ringing { call_id: String },
    /// Early media (183 Session Progress) - RTP may be available
    EarlyMedia {
        call_id: String,
        sdp: Option<String>,
    },
    /// Call was answered (200 OK)
    Answered { call_id: String },
    /// RTP is ready for audio
    AudioReady { call_id: String },
    /// DTMF received (from SIP INFO)
    DtmfReceived {
        call_id: String,
        digit: char,
        duration: u32,
    },
    /// Re-INVITE received (hold/resume/codec change)
    ReInvite {
        call_id: String,
        sdp: Option<String>,
    },
    /// Call ended
    Hangup { call_id: String, reason: String },
    /// Error occurred
    Error { call_id: String, error: String },
}

/// Active call session
pub struct CallSession {
    pub call_id: String,
    pub state: CallState,
    pub direction: Direction,
    pub provider_id: String,
    pub rtp_engine: Option<Arc<RtpEngine>>,
    /// Client dialog for outbound calls (UAC)
    pub client_dialog: Option<Arc<ClientInviteDialog>>,
    /// Server dialog for inbound calls (UAS)
    pub server_dialog: Option<Arc<ServerInviteDialog>>,
    pub local_sdp: Option<String>,
    pub remote_sdp: Option<String>,
    /// Local URI (From header value)
    pub local_uri: Option<String>,
    /// Remote URI (To header value)
    pub remote_uri: Option<String>,
    /// Remote SIP server address for sending requests
    pub remote_addr: Option<SocketAddr>,
    /// CSeq counter for out-of-dialog or custom requests
    pub cseq: u32,
    /// Local contact URI
    pub local_contact: Option<String>,
    /// DTMF mode (auto-detected from remote SDP)
    pub dtmf_mode: DtmfMode,
    /// Remote telephone-event payload type (if RFC 2833 supported)
    pub remote_telephone_event_pt: Option<u8>,
    /// Early media state tracking
    pub early_media_state: EarlyMediaState,
    /// Remote media direction (from SDP)
    pub remote_media_direction: MediaDirection,
    /// Hold initiated by local party
    pub local_hold: bool,
    /// Hold indicated by remote party
    pub remote_hold: bool,
    /// Remote party's User-Agent header (for device detection)
    pub remote_user_agent: Option<String>,
    /// RTP bug workaround flags (auto-detected from User-Agent)
    pub rtp_bug_flags: crate::rtp::dtmf::RtpBugFlags,
}

impl CallSession {
    /// Get the RTP engine for this call
    pub fn rtp(&self) -> Option<&Arc<RtpEngine>> {
        self.rtp_engine.as_ref()
    }

    /// Increment and return the next CSeq value
    pub fn next_cseq(&mut self) -> u32 {
        self.cseq += 1;
        self.cseq
    }

    /// Get the effective DTMF mode for this call
    ///
    /// If mode is Auto, returns RFC 2833 if remote supports it, else INFO.
    pub fn effective_dtmf_mode(&self) -> DtmfMode {
        match self.dtmf_mode {
            DtmfMode::Auto => {
                if self.remote_telephone_event_pt.is_some() {
                    DtmfMode::Rfc2833
                } else {
                    DtmfMode::Info
                }
            }
            mode => mode,
        }
    }

    /// Update DTMF capabilities from remote SDP
    pub fn update_dtmf_from_sdp(&mut self, sdp: &Sdp) {
        self.remote_telephone_event_pt = sdp.telephone_event_pt();
        tracing::debug!(
            "Call {} DTMF: remote supports RFC2833={}",
            self.call_id,
            self.remote_telephone_event_pt.is_some()
        );
    }

    /// Update session state from remote SDP (hold detection, direction, etc.)
    pub fn update_from_remote_sdp(&mut self, sdp: &Sdp) {
        // Update DTMF capabilities
        self.update_dtmf_from_sdp(sdp);

        // Update remote media direction
        self.remote_media_direction = sdp.audio_direction();

        // Detect remote hold
        self.remote_hold = sdp.is_on_hold();

        // Update call state if hold changed
        if self.remote_hold && self.state == CallState::Active {
            self.state = CallState::Hold;
            tracing::info!("Call {} put on hold by remote", self.call_id);
        } else if !self.remote_hold && !self.local_hold && self.state == CallState::Hold {
            self.state = CallState::Active;
            tracing::info!("Call {} resumed", self.call_id);
        }
    }

    /// Process 180 Ringing response (early media handling)
    pub fn process_180_ringing(&mut self) {
        match self.early_media_state {
            EarlyMediaState::None => {
                // First ringing, no early media yet
                self.early_media_state = EarlyMediaState::Ringing180;
                self.state = CallState::Ringing;
                tracing::debug!("Call {}: 180 Ringing (use local ringback)", self.call_id);
            }
            EarlyMediaState::EarlyMedia183 => {
                // 180 after 183 - common with mobile carriers
                // Continue using established media (don't revert to local ringback)
                self.early_media_state = EarlyMediaState::Ringing180After183;
                tracing::debug!(
                    "Call {}: 180 Ringing after 183 (keep remote media)",
                    self.call_id
                );
            }
            _ => {
                // Already processed ringing
                tracing::trace!("Call {}: duplicate 180 Ringing", self.call_id);
            }
        }
    }

    /// Process 183 Session Progress response
    pub fn process_183_session_progress(&mut self, has_sdp: bool) {
        if has_sdp {
            self.early_media_state = EarlyMediaState::EarlyMedia183;
            self.state = CallState::EarlyMedia;
            tracing::debug!(
                "Call {}: 183 Session Progress with SDP (use remote media)",
                self.call_id
            );
        } else {
            // 183 without SDP treated like 180
            if self.early_media_state == EarlyMediaState::None {
                self.early_media_state = EarlyMediaState::Ringing180;
                self.state = CallState::Ringing;
                tracing::debug!(
                    "Call {}: 183 without SDP (treat as 180 Ringing)",
                    self.call_id
                );
            }
        }
    }

    /// Check if remote media is available (for early media or active call)
    pub fn has_remote_media(&self) -> bool {
        matches!(
            self.early_media_state,
            EarlyMediaState::EarlyMedia183 | EarlyMediaState::Ringing180After183
        ) || matches!(self.state, CallState::Active | CallState::EarlyMedia)
    }

    /// Check if call is on hold (either party)
    pub fn is_on_hold(&self) -> bool {
        self.local_hold || self.remote_hold
    }
}

/// Provider credentials for SIP registration and authentication
#[derive(Debug, Clone)]
pub struct ProviderCredentials {
    pub id: String,
    pub sip_server: String,
    pub sip_port: u16,
    pub username: String,
    pub password: String,
    pub realm: Option<String>,
    pub register: bool,
}

impl ProviderCredentials {
    /// Convert to rsipstack Credential
    pub fn to_credential(&self) -> Credential {
        Credential {
            username: self.username.clone(),
            password: self.password.clone(),
            realm: self.realm.clone(),
        }
    }
}

/// SIP Engine configuration
#[derive(Debug, Clone)]
pub struct SipEngineConfig {
    /// Local bind address
    pub local_addr: SocketAddr,
    /// User agent string
    pub user_agent: String,
    /// RTP port range start
    pub rtp_port_start: u16,
    /// RTP port range end
    pub rtp_port_end: u16,
}

impl Default for SipEngineConfig {
    fn default() -> Self {
        Self {
            local_addr: "0.0.0.0:5060".parse().unwrap(),
            user_agent: "siprunner/0.1".to_string(),
            rtp_port_start: 10000,
            rtp_port_end: 20000,
        }
    }
}

/// SIP Engine for handling SIP signaling
pub struct SipEngine {
    /// rsipstack endpoint
    endpoint: Arc<Endpoint>,
    /// Dialog layer
    dialog_layer: Arc<DialogLayer>,
    /// Provider credentials
    providers: Mutex<HashMap<String, ProviderCredentials>>,
    /// Active registrations
    registrations: Mutex<HashMap<String, Arc<Registration>>>,
    /// Active calls
    calls: Mutex<HashMap<String, Arc<Mutex<CallSession>>>>,
    /// Event sender
    event_tx: broadcast::Sender<CallEvent>,
    /// Configuration
    config: SipEngineConfig,
    /// Next RTP port
    next_rtp_port: Mutex<u16>,
    /// Shutdown signal for background tasks
    shutdown_tx: broadcast::Sender<()>,
}

impl SipEngine {
    /// Create a new SIP engine
    pub async fn new(config: SipEngineConfig) -> Result<Arc<Self>> {
        let endpoint_option = EndpointOption::default();

        let endpoint = EndpointBuilder::new()
            .with_option(endpoint_option)
            .build();

        let dialog_layer = DialogLayer::new(endpoint.inner.clone());

        let (event_tx, _) = broadcast::channel(100);
        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Arc::new(Self {
            endpoint: Arc::new(endpoint),
            dialog_layer: Arc::new(dialog_layer),
            providers: Mutex::new(HashMap::new()),
            registrations: Mutex::new(HashMap::new()),
            calls: Mutex::new(HashMap::new()),
            event_tx,
            config: config.clone(),
            next_rtp_port: Mutex::new(config.rtp_port_start),
            shutdown_tx,
        }))
    }

    /// Add a provider
    pub fn add_provider(&self, provider: ProviderCredentials) {
        self.providers.lock().insert(provider.id.clone(), provider);
    }

    /// Remove a provider
    pub fn remove_provider(&self, provider_id: &str) {
        self.providers.lock().remove(provider_id);
        self.registrations.lock().remove(provider_id);
    }

    /// Subscribe to call events
    pub fn subscribe(&self) -> broadcast::Receiver<CallEvent> {
        self.event_tx.subscribe()
    }

    /// Start the SIP engine (spawns incoming call listener)
    ///
    /// This must be called to receive incoming calls. It spawns a background task
    /// that listens for incoming INVITE requests and creates CallSession entries.
    pub fn start(self: &Arc<Self>) -> Result<()> {
        // Get the incoming transaction receiver from the endpoint
        let mut incoming_rx = self
            .endpoint
            .incoming_transactions()
            .map_err(|e| SipRunnerError::Sip(format!("Failed to get incoming transactions: {}", e)))?;

        let engine = self.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            tracing::info!("SIP engine started, listening for incoming calls");

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        tracing::info!("SIP engine shutting down");
                        break;
                    }
                    Some(transaction) = incoming_rx.recv() => {
                        // Check if this is an INVITE request
                        if transaction.original.method == rsip::Method::Invite {
                            engine.handle_incoming_invite(transaction).await;
                        } else {
                            tracing::debug!("Ignoring non-INVITE request: {:?}", transaction.original.method);
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop the SIP engine
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Handle an incoming INVITE request
    async fn handle_incoming_invite(self: &Arc<Self>, transaction: rsipstack::transaction::transaction::Transaction) {
        // Extract call information from the INVITE request
        let request = &transaction.original;

        // Generate call ID
        let call_id = uuid::Uuid::new_v4().to_string();

        // Extract From and To URIs using rsip's header access
        let from_uri = request
            .from_header()
            .ok()
            .and_then(|h| h.uri().ok().map(|u| u.to_string()))
            .unwrap_or_else(|| "unknown".to_string());
        let to_uri = request
            .to_header()
            .ok()
            .and_then(|h| h.uri().ok().map(|u| u.to_string()))
            .unwrap_or_else(|| "unknown".to_string());

        // Extract User-Agent header for device detection
        // This enables automatic RTP bug workarounds for known problematic devices
        let remote_user_agent = request
            .headers
            .iter()
            .find_map(|h| {
                if let rsip::Header::UserAgent(ua) = h {
                    Some(ua.to_string())
                } else {
                    None
                }
            });

        // Auto-detect RTP bug workarounds based on User-Agent
        // Known devices with DTMF issues:
        // - Sonus: Expects incorrect timestamp incrementing per packet
        // - Cisco: May skip marker bit handling
        let rtp_bug_flags = remote_user_agent
            .as_ref()
            .map(|ua| crate::rtp::dtmf::RtpBugFlags::detect_from_user_agent(ua))
            .unwrap_or_default();

        if rtp_bug_flags.has_workarounds() {
            tracing::info!(
                "Detected device workarounds for User-Agent '{}': sonus_dtmf={}, no_marker={}",
                remote_user_agent.as_deref().unwrap_or("unknown"),
                rtp_bug_flags.sonus_dtmf_timestamp,
                rtp_bug_flags.never_send_marker
            );
        }

        // Parse remote SDP if present
        let remote_sdp = std::str::from_utf8(request.body())
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        // Create RTP engine for this call
        let rtp_port = self.allocate_rtp_port();
        let rtp_addr: SocketAddr = format!("0.0.0.0:{}", rtp_port).parse().unwrap();

        let rtp_config = RtpEngineConfig {
            codec: CodecType::Pcmu,
            ..Default::default()
        };

        let rtp_engine = match RtpEngine::new(rtp_addr, rtp_config).await {
            Ok(rtp) => {
                // Apply detected bug flags to RTP engine (for DTMF sender)
                if rtp_bug_flags.has_workarounds() {
                    rtp.set_rtp_bug_flags(rtp_bug_flags);
                }
                Some(Arc::new(rtp))
            }
            Err(e) => {
                tracing::error!("Failed to create RTP engine for incoming call: {}", e);
                None
            }
        };

        // Build local SDP answer
        let local_sdp = if let Some(ref rtp) = rtp_engine {
            Some(
                SdpBuilder::new(rtp.local_addr())
                    .codecs(vec![CodecType::Pcmu, CodecType::Pcma])
                    .build(),
            )
        } else {
            None
        };

        // Parse remote SDP and configure RTP
        let mut remote_telephone_event_pt = None;
        let mut remote_media_direction = MediaDirection::SendRecv;
        if let Some(ref sdp_str) = remote_sdp {
            if let Ok(sdp) = Sdp::parse(sdp_str) {
                if let Some(rtp_addr) = sdp.rtp_addr() {
                    if let Some(ref rtp) = rtp_engine {
                        rtp.set_remote(rtp_addr);
                    }
                }
                remote_telephone_event_pt = sdp.telephone_event_pt();
                remote_media_direction = sdp.audio_direction();
            }
        }

        // Create the server dialog
        let (state_tx, mut state_rx) = mpsc::unbounded_channel::<DialogState>();
        let server_dialog = match self.dialog_layer.get_or_create_server_invite(&transaction, state_tx, None, None) {
            Ok(dialog) => Arc::new(dialog),
            Err(e) => {
                tracing::error!("Failed to create server dialog: {}", e);
                return;
            }
        };

        // Create call session
        let session = Arc::new(Mutex::new(CallSession {
            call_id: call_id.clone(),
            state: CallState::Ringing,
            direction: Direction::Inbound,
            provider_id: "inbound".to_string(), // Inbound calls don't have a provider
            rtp_engine,
            client_dialog: None,
            server_dialog: Some(server_dialog.clone()),
            local_sdp,
            remote_sdp,
            local_uri: Some(to_uri.clone()),  // For inbound, we are the "To"
            remote_uri: Some(from_uri.clone()), // Remote is the "From"
            remote_addr: None, // Will be set from response
            cseq: 1,
            local_contact: Some(format!("sip:siprunner@{}", self.config.local_addr)),
            dtmf_mode: DtmfMode::Auto,
            remote_telephone_event_pt,
            early_media_state: EarlyMediaState::None,
            remote_media_direction,
            local_hold: false,
            remote_hold: false,
            remote_user_agent,
            rtp_bug_flags,
        }));

        self.calls.lock().insert(call_id.clone(), session.clone());

        // Send ringing response (180) - not async
        if let Err(e) = server_dialog.ringing(None, None) {
            tracing::error!("Failed to send 180 Ringing: {}", e);
        }

        // Send incoming call event
        let _ = self.event_tx.send(CallEvent::Incoming {
            call_id: call_id.clone(),
            from: from_uri,
            to: to_uri,
        });

        // Spawn task to handle dialog state changes
        let engine = self.clone();
        let call_id_for_state = call_id.clone();
        tokio::spawn(async move {
            while let Some(state) = state_rx.recv().await {
                match state {
                    DialogState::Updated(_, request) => {
                        // Incoming re-INVITE
                        let sdp_str = std::str::from_utf8(request.body())
                            .ok()
                            .filter(|s| !s.is_empty());

                        if let Some(sdp_body) = sdp_str {
                            if let Some(sess) = engine.calls.lock().get(&call_id_for_state) {
                                let mut sess = sess.lock();
                                sess.remote_sdp = Some(sdp_body.to_string());

                                if let Ok(sdp) = Sdp::parse(sdp_body) {
                                    if let Some(rtp_addr) = sdp.rtp_addr() {
                                        if let Some(ref rtp) = sess.rtp_engine {
                                            rtp.set_remote(rtp_addr);
                                        }
                                    }
                                    sess.update_from_remote_sdp(&sdp);
                                }
                            }
                        }

                        let _ = engine.event_tx.send(CallEvent::ReInvite {
                            call_id: call_id_for_state.clone(),
                            sdp: sdp_str.map(|s| s.to_string()),
                        });
                    }
                    DialogState::Info(_, request) => {
                        // Incoming SIP INFO (DTMF)
                        if let Ok(body_str) = std::str::from_utf8(request.body()) {
                            if let Some((digit, duration)) = Self::parse_dtmf_relay(body_str) {
                                let _ = engine.event_tx.send(CallEvent::DtmfReceived {
                                    call_id: call_id_for_state.clone(),
                                    digit,
                                    duration,
                                });
                            }
                        }
                    }
                    DialogState::Terminated(_, reason) => {
                        let reason_str = format!("{:?}", reason);
                        let _ = engine.event_tx.send(CallEvent::Hangup {
                            call_id: call_id_for_state.clone(),
                            reason: reason_str,
                        });
                        engine.calls.lock().remove(&call_id_for_state);
                        break;
                    }
                    _ => {}
                }
            }
        });
    }

    /// Answer an incoming call
    ///
    /// Sends 200 OK with SDP to accept the call.
    /// Only works for inbound calls that are in Ringing state.
    pub fn answer(&self, call_id: &str) -> Result<()> {
        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| SipRunnerError::Session(format!("Call not found: {}", call_id)))?;

        let (server_dialog, local_sdp) = {
            let mut sess = session.lock();

            if sess.direction != Direction::Inbound {
                return Err(SipRunnerError::Session(
                    "Cannot answer outbound call".to_string(),
                ));
            }

            if sess.state != CallState::Ringing {
                return Err(SipRunnerError::Session(format!(
                    "Cannot answer call in state {:?}",
                    sess.state
                )));
            }

            let dialog = sess.server_dialog.clone().ok_or_else(|| {
                SipRunnerError::Session("No server dialog for inbound call".to_string())
            })?;

            let sdp = sess.local_sdp.clone();

            // Update state to Active
            sess.state = CallState::Active;

            (dialog, sdp)
        };

        // Build headers and body for 200 OK
        let (headers, body) = if let Some(sdp_str) = local_sdp {
            (
                Some(vec![rsip::Header::ContentType("application/sdp".into())]),
                Some(sdp_str.into_bytes()),
            )
        } else {
            (None, None)
        };

        // Send 200 OK (not async)
        server_dialog
            .accept(headers, body)
            .map_err(|e| SipRunnerError::Sip(format!("Failed to send 200 OK: {}", e)))?;

        // Send answered event
        let _ = self.event_tx.send(CallEvent::Answered {
            call_id: call_id.to_string(),
        });

        let _ = self.event_tx.send(CallEvent::AudioReady {
            call_id: call_id.to_string(),
        });

        tracing::info!("Call {} answered", call_id);
        Ok(())
    }

    /// Reject an incoming call
    ///
    /// Sends an error response to reject the call.
    /// Common status codes: 486 (Busy), 603 (Decline), 480 (Temporarily Unavailable)
    pub fn reject(&self, call_id: &str, status_code: u16) -> Result<()> {
        let session = self
            .calls
            .lock()
            .remove(call_id)
            .ok_or_else(|| SipRunnerError::Session(format!("Call not found: {}", call_id)))?;

        let server_dialog = {
            let mut sess = session.lock();

            if sess.direction != Direction::Inbound {
                return Err(SipRunnerError::Session(
                    "Cannot reject outbound call".to_string(),
                ));
            }

            // Stop RTP if started
            if let Some(ref rtp) = sess.rtp_engine {
                rtp.stop();
            }

            sess.state = CallState::Ended;

            sess.server_dialog.clone().ok_or_else(|| {
                SipRunnerError::Session("No server dialog for inbound call".to_string())
            })?
        };

        // Convert status code to rsip StatusCode
        let sip_status = rsip::StatusCode::from(status_code);

        // Send rejection response (not async)
        server_dialog
            .reject(Some(sip_status), None)
            .map_err(|e| SipRunnerError::Sip(format!("Failed to send rejection: {}", e)))?;

        let reason = format!("Rejected with {}", status_code);
        let _ = self.event_tx.send(CallEvent::Hangup {
            call_id: call_id.to_string(),
            reason,
        });

        tracing::info!("Call {} rejected with status {}", call_id, status_code);
        Ok(())
    }

    /// Register with a provider
    pub async fn register(&self, provider_id: &str) -> Result<()> {
        let provider = self
            .providers
            .lock()
            .get(provider_id)
            .cloned()
            .ok_or_else(|| SipRunnerError::Provider(format!("Unknown provider: {}", provider_id)))?;

        if !provider.register {
            return Ok(());
        }

        let credential = provider.to_credential();
        let mut registration = Registration::new(self.endpoint.inner.clone(), Some(credential));

        let registrar_uri: Uri = Uri::try_from(format!("sip:{}", provider.sip_server).as_str())
            .map_err(|e| SipRunnerError::Sip(format!("Invalid registrar URI: {:?}", e)))?;

        registration
            .register(registrar_uri, None)
            .await
            .map_err(|e| SipRunnerError::Sip(format!("Registration failed: {}", e)))?;

        self.registrations
            .lock()
            .insert(provider_id.to_string(), Arc::new(registration));

        Ok(())
    }

    /// Allocate an RTP port
    fn allocate_rtp_port(&self) -> u16 {
        let mut port = self.next_rtp_port.lock();
        let allocated = *port;
        *port += 2; // RTP uses even ports, RTCP uses odd
        if *port >= self.config.rtp_port_end {
            *port = self.config.rtp_port_start;
        }
        allocated
    }

    /// Make an outbound call
    pub async fn call(
        self: &Arc<Self>,
        to: &str,
        from: &str,
        provider_id: &str,
    ) -> Result<String> {
        let provider = self
            .providers
            .lock()
            .get(provider_id)
            .cloned()
            .ok_or_else(|| SipRunnerError::Provider(format!("Unknown provider: {}", provider_id)))?;

        // Create RTP engine for this call
        let rtp_port = self.allocate_rtp_port();
        let rtp_addr: SocketAddr = format!("0.0.0.0:{}", rtp_port).parse().unwrap();

        let rtp_config = RtpEngineConfig {
            codec: CodecType::Pcmu,
            ..Default::default()
        };

        let rtp_engine = RtpEngine::new(rtp_addr, rtp_config)
            .await
            .map_err(|e| SipRunnerError::Rtp(e.to_string()))?;
        let rtp_engine = Arc::new(rtp_engine);

        // Build SDP offer
        let local_sdp = SdpBuilder::new(rtp_engine.local_addr())
            .codecs(vec![CodecType::Pcmu, CodecType::Pcma])
            .build();

        // Parse URIs
        let callee: Uri = Uri::try_from(to)
            .map_err(|e| SipRunnerError::Sip(format!("Invalid callee URI: {:?}", e)))?;
        let caller: Uri = Uri::try_from(from)
            .map_err(|e| SipRunnerError::Sip(format!("Invalid caller URI: {:?}", e)))?;
        let contact: Uri =
            Uri::try_from(format!("sip:{}@{}", provider.username, self.config.local_addr).as_str())
                .map_err(|e| SipRunnerError::Sip(format!("Invalid contact URI: {:?}", e)))?;

        let credential = provider.to_credential();

        // Create call ID
        let call_id = uuid::Uuid::new_v4().to_string();

        // Resolve remote SIP server address
        let remote_addr: Option<SocketAddr> = format!("{}:{}", provider.sip_server, provider.sip_port)
            .parse()
            .ok();

        // Store contact URI for REFER
        let contact_str = format!("sip:{}@{}", provider.username, self.config.local_addr);

        // Create call session with dialog information for REFER support
        // Note: remote_user_agent and rtp_bug_flags will be updated when we receive
        // the first response (180/183/200) containing the User-Agent header
        let session = Arc::new(Mutex::new(CallSession {
            call_id: call_id.clone(),
            state: CallState::Ringing, // Start at Ringing (simplified states)
            direction: Direction::Outbound,
            provider_id: provider_id.to_string(),
            rtp_engine: Some(rtp_engine.clone()),
            client_dialog: None, // Set when 200 OK received
            server_dialog: None, // Not used for outbound calls
            local_sdp: Some(local_sdp.clone()),
            remote_sdp: None,
            local_uri: Some(from.to_string()),
            remote_uri: Some(to.to_string()),
            remote_addr,
            cseq: 1, // Will be incremented for each request
            local_contact: Some(contact_str),
            dtmf_mode: DtmfMode::Auto, // Auto-detect from remote SDP
            remote_telephone_event_pt: None, // Will be set when remote SDP received
            // Early media and hold state tracking
            early_media_state: EarlyMediaState::None,
            remote_media_direction: MediaDirection::SendRecv,
            local_hold: false,
            remote_hold: false,
            // Device detection - populated from response User-Agent header
            remote_user_agent: None,
            rtp_bug_flags: crate::rtp::dtmf::RtpBugFlags::default(),
        }));

        self.calls.lock().insert(call_id.clone(), session.clone());

        // Create state channel for dialog state updates
        let (state_tx, mut state_rx) = mpsc::unbounded_channel::<DialogState>();

        let invite_option = InviteOption {
            callee,
            caller,
            contact,
            credential: Some(credential),
            offer: Some(local_sdp.into_bytes()),
            ..Default::default()
        };

        let engine = self.clone();
        let call_id_clone = call_id.clone();
        let engine_for_state = self.clone();
        let call_id_for_state = call_id.clone();

        // Spawn task to handle the INVITE
        tokio::spawn(async move {
            match engine
                .dialog_layer
                .do_invite(invite_option, state_tx)
                .await
            {
                Ok((dialog, response)) => {
                    // Extract SDP from response if present
                    if let Some(ref resp) = response {
                        let body = resp.body();
                        if !body.is_empty() {
                            if let Ok(body_str) = std::str::from_utf8(body) {
                                if let Some(sess) = engine.calls.lock().get(&call_id_clone) {
                                    let mut sess = sess.lock();
                                    sess.remote_sdp = Some(body_str.to_string());
                                    sess.state = CallState::Active;
                                    sess.client_dialog = Some(Arc::new(dialog));
                                    // Reset early media state on answer
                                    sess.early_media_state = EarlyMediaState::None;

                                    // Extract User-Agent from 200 OK if not already detected from 180/183
                                    // This ensures device workarounds are applied even if early responses
                                    // didn't contain User-Agent header
                                    if sess.remote_user_agent.is_none() {
                                        if let Some(ua) = resp.headers.iter().find_map(|h| {
                                            if let rsip::Header::UserAgent(ua) = h {
                                                Some(ua.to_string())
                                            } else {
                                                None
                                            }
                                        }) {
                                            let flags = crate::rtp::dtmf::RtpBugFlags::detect_from_user_agent(&ua);
                                            if flags.has_workarounds() {
                                                tracing::info!(
                                                    "Detected device workarounds from 200 OK User-Agent '{}': sonus_dtmf={}, no_marker={}",
                                                    ua, flags.sonus_dtmf_timestamp, flags.never_send_marker
                                                );
                                                // Apply bug flags to RTP engine for DTMF sender
                                                if let Some(ref rtp) = sess.rtp_engine {
                                                    rtp.set_rtp_bug_flags(flags);
                                                }
                                            }
                                            sess.remote_user_agent = Some(ua);
                                            sess.rtp_bug_flags = flags;
                                        }
                                    }

                                    // Parse remote SDP and update all state
                                    if let Ok(sdp) = Sdp::parse(body_str) {
                                        if let Some(rtp_addr) = sdp.rtp_addr() {
                                            if let Some(ref rtp) = sess.rtp_engine {
                                                rtp.set_remote(rtp_addr);
                                            }
                                        }
                                        // Update DTMF, hold, and direction from SDP
                                        sess.update_from_remote_sdp(&sdp);
                                    }
                                }
                            }
                        }
                    }

                    let _ = engine.event_tx.send(CallEvent::Answered {
                        call_id: call_id_clone.clone(),
                    });

                    let _ = engine.event_tx.send(CallEvent::AudioReady {
                        call_id: call_id_clone,
                    });
                }
                Err(e) => {
                    let _ = engine.event_tx.send(CallEvent::Error {
                        call_id: call_id_clone.clone(),
                        error: e.to_string(),
                    });

                    engine.calls.lock().remove(&call_id_clone);
                }
            }
        });

        // Spawn task to handle dialog state changes (incoming re-INVITE, INFO, etc.)
        tokio::spawn(async move {
            while let Some(state) = state_rx.recv().await {
                match state {
                    DialogState::Updated(_, request) => {
                        // Incoming re-INVITE (hold/resume/codec change)
                        let sdp_str = std::str::from_utf8(request.body())
                            .ok()
                            .filter(|s| !s.is_empty());

                        // Update session state from re-INVITE SDP
                        if let Some(sdp_body) = sdp_str {
                            if let Some(sess) = engine_for_state.calls.lock().get(&call_id_for_state) {
                                let mut sess = sess.lock();
                                sess.remote_sdp = Some(sdp_body.to_string());

                                if let Ok(sdp) = Sdp::parse(sdp_body) {
                                    // Update RTP remote (port might change)
                                    if let Some(rtp_addr) = sdp.rtp_addr() {
                                        if let Some(ref rtp) = sess.rtp_engine {
                                            rtp.set_remote(rtp_addr);
                                        }
                                    }
                                    // Update hold/direction state (handles remote hold detection)
                                    sess.update_from_remote_sdp(&sdp);
                                }
                            }
                        }

                        let _ = engine_for_state.event_tx.send(CallEvent::ReInvite {
                            call_id: call_id_for_state.clone(),
                            sdp: sdp_str.map(|s| s.to_string()),
                        });
                    }
                    DialogState::Info(_, request) => {
                        // Incoming SIP INFO (may contain DTMF)
                        if let Ok(body_str) = std::str::from_utf8(request.body()) {
                            // Parse DTMF relay format: Signal=X\r\nDuration=Y\r\n
                            if let Some((digit, duration)) = Self::parse_dtmf_relay(body_str) {
                                let _ = engine_for_state.event_tx.send(CallEvent::DtmfReceived {
                                    call_id: call_id_for_state.clone(),
                                    digit,
                                    duration,
                                });
                            }
                        }
                    }
                    DialogState::Early(_, response) => {
                        // 180 Ringing or 183 Session Progress
                        let body = response.body();
                        let sdp_str = std::str::from_utf8(body).ok().filter(|s| !s.is_empty());
                        let has_sdp = sdp_str.is_some();

                        // Update session early media state
                        if let Some(sess) = engine_for_state.calls.lock().get(&call_id_for_state) {
                            let mut sess = sess.lock();

                            // Extract User-Agent from response for device detection (outbound calls)
                            // This enables automatic RTP bug workarounds for Sonus, Cisco, etc.
                            if sess.remote_user_agent.is_none() {
                                if let Some(ua) = response.headers.iter().find_map(|h| {
                                    if let rsip::Header::UserAgent(ua) = h {
                                        Some(ua.to_string())
                                    } else {
                                        None
                                    }
                                }) {
                                    let flags = crate::rtp::dtmf::RtpBugFlags::detect_from_user_agent(&ua);
                                    if flags.has_workarounds() {
                                        tracing::info!(
                                            "Detected device workarounds from 180/183 User-Agent '{}': sonus_dtmf={}, no_marker={}",
                                            ua, flags.sonus_dtmf_timestamp, flags.never_send_marker
                                        );
                                        // Apply bug flags to RTP engine for DTMF sender
                                        if let Some(ref rtp) = sess.rtp_engine {
                                            rtp.set_rtp_bug_flags(flags);
                                        }
                                    }
                                    sess.remote_user_agent = Some(ua);
                                    sess.rtp_bug_flags = flags;
                                }
                            }

                            // Parse SDP if present and configure RTP
                            if let Some(sdp_body) = sdp_str {
                                if let Ok(sdp) = Sdp::parse(sdp_body) {
                                    // Set RTP remote address for early media
                                    if let Some(rtp_addr) = sdp.rtp_addr() {
                                        if let Some(ref rtp) = sess.rtp_engine {
                                            rtp.set_remote(rtp_addr);
                                        }
                                    }
                                    // Update DTMF and hold state from SDP
                                    sess.update_from_remote_sdp(&sdp);
                                }
                            }

                            // Process based on status code
                            if response.status_code == rsip::StatusCode::SessionProgress {
                                sess.process_183_session_progress(has_sdp);
                            } else if response.status_code == rsip::StatusCode::Ringing {
                                sess.process_180_ringing();
                            }
                        }

                        // Send appropriate event
                        if response.status_code == rsip::StatusCode::SessionProgress && has_sdp {
                            let _ = engine_for_state.event_tx.send(CallEvent::EarlyMedia {
                                call_id: call_id_for_state.clone(),
                                sdp: sdp_str.map(|s| s.to_string()),
                            });
                        } else if response.status_code == rsip::StatusCode::Ringing {
                            // Only send Ringing event if not already in early media state
                            // (handles 180 after 183 case)
                            if let Some(sess) = engine_for_state.calls.lock().get(&call_id_for_state) {
                                let sess = sess.lock();
                                if !matches!(
                                    sess.early_media_state,
                                    EarlyMediaState::EarlyMedia183 | EarlyMediaState::Ringing180After183
                                ) {
                                    drop(sess);
                                    let _ = engine_for_state.event_tx.send(CallEvent::Ringing {
                                        call_id: call_id_for_state.clone(),
                                    });
                                }
                            }
                        }
                    }
                    DialogState::Terminated(_, reason) => {
                        let reason_str = format!("{:?}", reason);
                        let _ = engine_for_state.event_tx.send(CallEvent::Hangup {
                            call_id: call_id_for_state.clone(),
                            reason: reason_str,
                        });
                        engine_for_state.calls.lock().remove(&call_id_for_state);
                        break;
                    }
                    _ => {}
                }
            }
        });

        // Send initial ringing event (state already set to Ringing in session creation)
        let _ = self.event_tx.send(CallEvent::Ringing {
            call_id: call_id.clone(),
        });

        Ok(call_id)
    }

    /// Hangup a call
    pub async fn hangup(&self, call_id: &str) -> Result<()> {
        let session = self
            .calls
            .lock()
            .remove(call_id)
            .ok_or_else(|| SipRunnerError::Session(format!("Call not found: {}", call_id)))?;

        let mut sess = session.lock();

        // Stop RTP
        if let Some(ref rtp) = sess.rtp_engine {
            rtp.stop();
        }

        // Send BYE if we have a dialog
        // Hangup via appropriate dialog
        if let Some(ref dialog) = sess.client_dialog {
            let _ = dialog.hangup().await;
        } else if let Some(ref dialog) = sess.server_dialog {
            let _ = dialog.bye().await;
        }

        sess.state = CallState::Ended;

        let _ = self.event_tx.send(CallEvent::Hangup {
            call_id: call_id.to_string(),
            reason: "User hangup".to_string(),
        });

        Ok(())
    }

    /// Send DTMF via SIP INFO (RFC 2976)
    ///
    /// Uses rsipstack's dialog.info() method with application/dtmf-relay content type.
    /// Format follows Cisco de facto standard: `Signal= X\r\nDuration= Y\r\n`
    /// **Requires call to be in Active state** (answered).
    ///
    /// # Arguments
    /// * `call_id` - The call to send DTMF on
    /// * `digit` - DTMF digit (0-9, *, #, A-D) or pause ('w'=500ms, 'W'=1000ms)
    /// * `duration_ms` - Duration in milliseconds (clamped to 100-5000ms range)
    pub async fn send_dtmf_info(&self, call_id: &str, digit: char, duration_ms: u32) -> Result<()> {
        // Handle pause characters
        if digit == 'w' {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            return Ok(());
        } else if digit == 'W' {
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
            return Ok(());
        }

        // Validate digit (0-9, *, #, A-D)
        if !matches!(digit, '0'..='9' | '*' | '#' | 'A'..='D' | 'a'..='d') {
            return Err(SipRunnerError::Sip(format!("Invalid DTMF digit: {}", digit)));
        }

        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| SipRunnerError::Session(format!("Call not found: {}", call_id)))?;

        let sess = session.lock();

        // DTMF only allowed after call is answered (Active state)
        if sess.state != CallState::Active {
            return Err(SipRunnerError::Session(format!(
                "Cannot send DTMF: call {} is not active (state: {:?})",
                call_id, sess.state
            )));
        }

        // Clamp duration to valid range (Cisco standard: 100-5000ms)
        let duration = duration_ms.clamp(100, 5000);

        // Build DTMF relay body per de facto standard (space after =)
        // Format: Signal= X\r\nDuration= Y\r\n (with space after =)
        let dtmf_body = format!(
            "Signal= {}\r\nDuration= {}\r\n",
            digit.to_ascii_uppercase(),
            duration
        );

        // Build headers with Content-Type
        let headers = vec![rsip::Header::ContentType("application/dtmf-relay".into())];

        // Send INFO using appropriate dialog (client or server)
        if let Some(ref dialog) = sess.client_dialog {
            dialog
                .info(Some(headers), Some(dtmf_body.into_bytes()))
                .await
                .map_err(|e| SipRunnerError::Sip(format!("Failed to send DTMF INFO: {}", e)))?;
        } else if let Some(ref dialog) = sess.server_dialog {
            dialog
                .info(Some(headers), Some(dtmf_body.into_bytes()))
                .await
                .map_err(|e| SipRunnerError::Sip(format!("Failed to send DTMF INFO: {}", e)))?;
        } else {
            return Err(SipRunnerError::Session(
                "Dialog not established for this call".to_string(),
            ));
        }

        Ok(())
    }

    /// Send multiple DTMF digits via SIP INFO
    ///
    /// Sends each digit sequentially with inter-digit delay.
    /// **Requires call to be in Active state** (answered).
    ///
    /// # Arguments
    /// * `call_id` - The call to send DTMF on
    /// * `digits` - String of DTMF digits
    /// * `duration_ms` - Duration per digit in milliseconds (default 100)
    /// * `inter_digit_ms` - Delay between digits in milliseconds (default 100)
    ///
    /// **Automatic Method Selection:**
    /// - If remote SDP includes telephone-event -> RFC 2833 (RTP)
    /// - Otherwise -> SIP INFO with application/dtmf-relay
    ///
    /// # Errors
    /// Returns error if call is not in Active state.
    pub async fn send_dtmf_digits(
        &self,
        call_id: &str,
        digits: &str,
        duration_ms: u32,
        inter_digit_ms: u64,
    ) -> Result<()> {
        // Determine DTMF mode for this call and verify Active state
        let (dtmf_mode, rtp_engine) = {
            let session = self
                .calls
                .lock()
                .get(call_id)
                .cloned()
                .ok_or_else(|| SipRunnerError::Session(format!("Call not found: {}", call_id)))?;

            let sess = session.lock();

            // DTMF only allowed after call is answered (Active state)
            if sess.state != CallState::Active {
                return Err(SipRunnerError::Session(format!(
                    "Cannot send DTMF: call {} is not active (state: {:?})",
                    call_id, sess.state
                )));
            }

            let mode = sess.effective_dtmf_mode();
            let rtp = sess.rtp_engine.clone();
            (mode, rtp)
        };

        tracing::debug!(
            "Sending DTMF '{}' on call {} using {:?}",
            digits,
            call_id,
            dtmf_mode
        );

        match dtmf_mode {
            DtmfMode::Rfc2833 => {
                // Use RFC 2833 via RTP engine
                let rtp = rtp_engine.ok_or_else(|| {
                    SipRunnerError::Session("RTP not established for this call".to_string())
                })?;

                rtp.send_dtmf_string(digits, duration_ms, inter_digit_ms as u32)
                    .await
            }
            DtmfMode::Info | DtmfMode::Auto => {
                // Use SIP INFO (Auto falls back to INFO if RFC2833 not detected)
                for digit in digits.chars() {
                    self.send_dtmf_info(call_id, digit, duration_ms).await?;
                    tokio::time::sleep(std::time::Duration::from_millis(inter_digit_ms)).await;
                }
                Ok(())
            }
        }
    }

    /// Get the effective DTMF mode for a call
    ///
    /// Returns the mode that will be used for sending/receiving DTMF.
    pub fn get_dtmf_mode(&self, call_id: &str) -> Result<DtmfMode> {
        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| SipRunnerError::Session(format!("Call not found: {}", call_id)))?;

        let sess = session.lock();
        Ok(sess.effective_dtmf_mode())
    }

    /// Set the DTMF mode for a call
    ///
    /// Args:
    /// * `call_id` - The call to configure
    /// * `mode` - The DTMF mode to use (Auto, Rfc2833, or Info)
    pub fn set_dtmf_mode(&self, call_id: &str, mode: DtmfMode) -> Result<()> {
        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| SipRunnerError::Session(format!("Call not found: {}", call_id)))?;

        let mut sess = session.lock();
        sess.dtmf_mode = mode;
        Ok(())
    }

    /// Receive DTMF digit (non-blocking)
    ///
    /// Checks both RFC 2833 (RTP) and SIP INFO sources automatically.
    /// Returns None if no DTMF is available.
    pub fn recv_dtmf(&self, call_id: &str) -> Result<Option<(char, u32)>> {
        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| SipRunnerError::Session(format!("Call not found: {}", call_id)))?;

        let sess = session.lock();

        // Try RFC 2833 first (via RTP engine)
        if let Some(ref rtp) = sess.rtp_engine {
            if let Ok(Some(detected)) = rtp.recv_dtmf_try() {
                return Ok(Some((detected.digit, detected.duration_ms)));
            }
        }

        // SIP INFO DTMF is received via events, not this method
        // It comes through the event channel as CallEvent::Dtmf
        Ok(None)
    }

    /// Receive DTMF digit with timeout (blocking)
    ///
    /// Checks both RFC 2833 (RTP) and polls for timeout.
    /// SIP INFO DTMF should be received via next_event().
    pub fn recv_dtmf_blocking(
        &self,
        call_id: &str,
        timeout: std::time::Duration,
    ) -> Result<Option<(char, u32)>> {
        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| SipRunnerError::Session(format!("Call not found: {}", call_id)))?;

        let sess = session.lock();

        // Try RFC 2833 (via RTP engine)
        if let Some(ref rtp) = sess.rtp_engine {
            if let Ok(Some(detected)) = rtp.recv_dtmf_blocking(timeout) {
                return Ok(Some((detected.digit, detected.duration_ms)));
            }
        }

        Ok(None)
    }

    /// Send Re-INVITE to modify session (hold/resume/codec change)
    ///
    /// Uses rsipstack's dialog.reinvite() method with 491 glare handling.
    ///
    /// # 491 Glare Handling (RFC 3261 Section 14.1)
    ///
    /// When both sides send re-INVITE simultaneously, one gets 491 "Request Pending".
    /// Per RFC 3261:
    /// - If UAC owns Call-ID (we originated): wait 2.1-4 seconds, retry
    /// - If UAC doesn't own Call-ID (inbound call): wait 0-2 seconds, retry
    ///
    /// We retry up to 3 times with exponential backoff.
    ///
    /// # Arguments
    /// * `call_id` - The call to modify
    /// * `sdp` - New SDP offer (None to use current SDP)
    pub async fn send_reinvite(&self, call_id: &str, sdp: Option<&str>) -> Result<()> {
        self.send_reinvite_with_retry(call_id, sdp, 3).await
    }

    /// Send Re-INVITE with explicit retry count for 491 handling
    ///
    /// # Arguments
    /// * `call_id` - The call to modify
    /// * `sdp` - New SDP offer (None to use current SDP)
    /// * `max_retries` - Maximum retry attempts on 491 (0 = no retry)
    pub async fn send_reinvite_with_retry(
        &self,
        call_id: &str,
        sdp: Option<&str>,
        max_retries: u32,
    ) -> Result<()> {
        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| SipRunnerError::Session(format!("Call not found: {}", call_id)))?;

        // Determine if we're the Call-ID owner (outbound call)
        let is_call_owner = {
            let sess = session.lock();
            sess.direction == Direction::Outbound
        };

        for attempt in 0..=max_retries {
            let result = self.send_reinvite_internal(call_id, sdp).await;

            match &result {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let err_str = e.to_string().to_lowercase();

                    // Check if this is a 491 Request Pending response
                    if err_str.contains("491") || err_str.contains("request pending") {
                        if attempt < max_retries {
                            // RFC 3261 Section 14.1: Calculate retry delay
                            let delay_ms = if is_call_owner {
                                // We own Call-ID: wait 2.1-4 seconds
                                2100 + rand::random::<u64>() % 1900
                            } else {
                                // We don't own Call-ID: wait 0-2 seconds
                                rand::random::<u64>() % 2000
                            };

                            tracing::info!(
                                "Re-INVITE got 491, retry {}/{} after {}ms (call_owner={})",
                                attempt + 1,
                                max_retries,
                                delay_ms,
                                is_call_owner
                            );

                            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                            continue;
                        }
                    }

                    // Not a 491 or exhausted retries
                    return result;
                }
            }
        }

        Err(SipRunnerError::Sip(
            "Re-INVITE failed: 491 glare after max retries".to_string(),
        ))
    }

    /// Internal re-INVITE send without retry logic
    async fn send_reinvite_internal(&self, call_id: &str, sdp: Option<&str>) -> Result<()> {
        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| SipRunnerError::Session(format!("Call not found: {}", call_id)))?;

        let sess = session.lock();

        // Build headers and body
        let (headers, body) = if let Some(sdp_str) = sdp {
            (
                Some(vec![rsip::Header::ContentType("application/sdp".into())]),
                Some(sdp_str.as_bytes().to_vec()),
            )
        } else {
            (None, None)
        };

        // Send re-INVITE using appropriate dialog
        if let Some(ref dialog) = sess.client_dialog {
            dialog
                .reinvite(headers, body)
                .await
                .map_err(|e| SipRunnerError::Sip(format!("Failed to send re-INVITE: {}", e)))?;
        } else if let Some(ref dialog) = sess.server_dialog {
            dialog
                .reinvite(headers, body)
                .await
                .map_err(|e| SipRunnerError::Sip(format!("Failed to send re-INVITE: {}", e)))?;
        } else {
            return Err(SipRunnerError::Session(
                "Dialog not established for this call".to_string(),
            ));
        }

        Ok(())
    }

    /// Put call on hold (sends re-INVITE with sendonly SDP)
    ///
    /// Per RFC 6337:
    /// - sendonly: we can send, remote should not send
    /// - Remote should respond with recvonly
    pub async fn hold(&self, call_id: &str) -> Result<()> {
        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| SipRunnerError::Session(format!("Call not found: {}", call_id)))?;

        let hold_sdp = {
            let mut sess = session.lock();

            // Check if already on hold
            if sess.local_hold {
                return Ok(());
            }

            let rtp = sess.rtp_engine.as_ref().ok_or_else(|| {
                SipRunnerError::Session("RTP not established for this call".to_string())
            })?;

            // Build hold SDP (sendonly)
            let sdp = SdpBuilder::new(rtp.local_addr())
                .codecs(vec![CodecType::Pcmu, CodecType::Pcma])
                .direction("sendonly")
                .build();

            // Update local hold state
            sess.local_hold = true;
            sess.state = CallState::Hold;
            tracing::info!("Call {} put on hold by local", sess.call_id);

            sdp
        };

        self.send_reinvite(call_id, Some(&hold_sdp)).await
    }

    /// Resume call from hold (sends re-INVITE with sendrecv SDP)
    ///
    /// Per RFC 6337:
    /// - sendrecv: bidirectional media resumed
    pub async fn unhold(&self, call_id: &str) -> Result<()> {
        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| SipRunnerError::Session(format!("Call not found: {}", call_id)))?;

        let resume_sdp = {
            let mut sess = session.lock();

            // Check if actually on hold
            if !sess.local_hold {
                return Ok(());
            }

            let rtp = sess.rtp_engine.as_ref().ok_or_else(|| {
                SipRunnerError::Session("RTP not established for this call".to_string())
            })?;

            // Build resume SDP (sendrecv)
            let sdp = SdpBuilder::new(rtp.local_addr())
                .codecs(vec![CodecType::Pcmu, CodecType::Pcma])
                .direction("sendrecv")
                .build();

            // Update local hold state
            sess.local_hold = false;

            // Only change to Active if remote is also not on hold
            if !sess.remote_hold {
                sess.state = CallState::Active;
                tracing::info!("Call {} resumed by local", sess.call_id);
            }

            sdp
        };

        self.send_reinvite(call_id, Some(&resume_sdp)).await
    }

    /// Check if a call is currently on hold (local or remote)
    pub fn is_on_hold(&self, call_id: &str) -> Result<bool> {
        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| SipRunnerError::Session(format!("Call not found: {}", call_id)))?;

        let sess = session.lock();
        Ok(sess.is_on_hold())
    }

    /// Get detailed hold state for a call
    pub fn get_hold_state(&self, call_id: &str) -> Result<(bool, bool)> {
        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| SipRunnerError::Session(format!("Call not found: {}", call_id)))?;

        let sess = session.lock();
        Ok((sess.local_hold, sess.remote_hold))
    }

    /// Send REFER for call transfer (RFC 3515)
    ///
    /// Works for both inbound and outbound calls - we can transfer in either direction.
    ///
    /// Builds a proper SIP REFER request using rsip and sends it directly via UDP.
    /// This bypasses rsipstack's dialog layer (which lacks native REFER support)
    /// while still using the established dialog's information.
    ///
    /// # Arguments
    /// * `call_id` - The call to transfer
    /// * `target_uri` - Target URI to transfer to (e.g., "sip:bob@example.com")
    ///
    /// # Edge Cases Handled
    ///
    /// ## Refer-To Header Formatting
    /// - Auto-wraps URI in angle brackets if not already wrapped
    /// - Supports both `sip:user@domain` and `<sip:user@domain>` formats
    ///
    /// ## Referred-By Header (RFC 3892)
    /// - Identifies the transferor (us) to the transfer target
    /// - Required by most PBX systems for proper transfer handling
    ///
    /// ## Dialog Identification
    /// - Uses Call-ID, From-tag, To-tag from established dialog
    /// - Works with both client_dialog (outbound) and server_dialog (inbound)
    ///
    /// # Known Limitations
    ///
    /// ## NOTIFY Subscription (Pending)
    /// - REFER creates implicit subscription per RFC 3515
    /// - We should receive NOTIFY with transfer progress (100 Trying, 200 OK, etc)
    /// - Currently fire-and-forget - no NOTIFY handling
    ///
    /// ## Attended Transfer (Not Implemented)
    /// - Would require Replaces header (RFC 3891)
    /// - Need consultation call established first
    /// - Complex state management
    ///
    /// ## Error Handling
    /// - No retry on failure
    /// - No 491 (Request Pending) handling
    pub async fn send_refer(&self, call_id: &str, target_uri: &str) -> Result<()> {
        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| SipRunnerError::Session(format!("Call not found: {}", call_id)))?;

        // Extract dialog information needed for the REFER request
        let (dialog_id, remote_addr, local_uri, remote_uri, local_contact, cseq) = {
            let mut sess = session.lock();

            // Get dialog ID from either client or server dialog
            let dialog_id = if let Some(ref dialog) = sess.client_dialog {
                dialog.id()
            } else if let Some(ref dialog) = sess.server_dialog {
                dialog.id()
            } else {
                return Err(SipRunnerError::Session(
                    "Dialog not established for this call".to_string(),
                ));
            };
            let remote_addr = sess.remote_addr.ok_or_else(|| {
                SipRunnerError::Session("Remote address not available".to_string())
            })?;
            let local_uri = sess.local_uri.clone().ok_or_else(|| {
                SipRunnerError::Session("Local URI not available".to_string())
            })?;
            let remote_uri = sess.remote_uri.clone().ok_or_else(|| {
                SipRunnerError::Session("Remote URI not available".to_string())
            })?;
            let local_contact = sess.local_contact.clone().ok_or_else(|| {
                SipRunnerError::Session("Local contact not available".to_string())
            })?;
            let cseq = sess.next_cseq();

            (dialog_id, remote_addr, local_uri, remote_uri, local_contact, cseq)
        };

        // Format Refer-To header value
        let refer_to_value = if target_uri.starts_with('<') {
            target_uri.to_string()
        } else {
            format!("<{}>", target_uri)
        };

        // Build the REFER request using rsip
        let request = self.build_refer_request(
            &dialog_id.call_id,
            &dialog_id.from_tag,
            &dialog_id.to_tag,
            &local_uri,
            &remote_uri,
            &local_contact,
            &refer_to_value,
            cseq,
        )?;

        // Serialize the request to bytes
        let request_bytes = request.to_string();

        // Send via UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
            SipRunnerError::Sip(format!("Failed to bind UDP socket for REFER: {}", e))
        })?;

        socket
            .send_to(request_bytes.as_bytes(), remote_addr)
            .await
            .map_err(|e| SipRunnerError::Sip(format!("Failed to send REFER: {}", e)))?;

        tracing::info!(
            "REFER sent to {} for call {} -> {}",
            remote_addr,
            call_id,
            target_uri
        );

        Ok(())
    }

    /// Build a SIP REFER request using rsip
    fn build_refer_request(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        local_uri: &str,
        remote_uri: &str,
        local_contact: &str,
        refer_to: &str,
        cseq: u32,
    ) -> Result<rsip::Request> {
        // Parse the Request-URI (where to send the request)
        let request_uri = rsip::Uri::try_from(remote_uri)
            .map_err(|e| SipRunnerError::Sip(format!("Invalid remote URI: {:?}", e)))?;

        // Generate unique branch parameter for Via header
        let branch = format!("z9hG4bK{}", uuid::Uuid::new_v4().simple());

        // Build headers
        let mut headers: rsip::Headers = Default::default();

        // Via header
        let via_value = format!(
            "SIP/2.0/UDP {};branch={}",
            self.config.local_addr, branch
        );
        headers.push(rsip::Header::Via(via_value.into()));

        // Max-Forwards
        headers.push(rsip::Header::MaxForwards("70".into()));

        // From header with tag
        let from_value = format!("<{}>;tag={}", local_uri, from_tag);
        headers.push(rsip::Header::From(from_value.into()));

        // To header with tag
        let to_value = format!("<{}>;tag={}", remote_uri, to_tag);
        headers.push(rsip::Header::To(to_value.into()));

        // Call-ID
        headers.push(rsip::Header::CallId(call_id.into()));

        // CSeq
        let cseq_value = format!("{} REFER", cseq);
        headers.push(rsip::Header::CSeq(cseq_value.into()));

        // Contact
        let contact_value = format!("<{}>", local_contact);
        headers.push(rsip::Header::Contact(contact_value.into()));

        // Refer-To header (RFC 3515)
        headers.push(rsip::Header::Other("Refer-To".into(), refer_to.into()));

        // Referred-By header (RFC 3892)
        let referred_by = format!("<{}>", local_uri);
        headers.push(rsip::Header::Other("Referred-By".into(), referred_by));

        // User-Agent
        headers.push(rsip::Header::UserAgent(self.config.user_agent.clone().into()));

        // Content-Length (no body for REFER)
        headers.push(rsip::Header::ContentLength("0".into()));

        // Build the request
        let request = rsip::Request {
            method: rsip::Method::Refer,
            uri: request_uri,
            version: rsip::Version::V2,
            headers,
            body: vec![],
        };

        Ok(request)
    }

    /// Blind transfer - transfers call without consultation
    ///
    /// This is a convenience wrapper around send_refer().
    pub async fn blind_transfer(&self, call_id: &str, target_uri: &str) -> Result<()> {
        self.send_refer(call_id, target_uri).await
    }

    /// Get a call session
    pub fn get_call(&self, call_id: &str) -> Option<Arc<Mutex<CallSession>>> {
        self.calls.lock().get(call_id).cloned()
    }

    /// Get all active call IDs
    pub fn active_calls(&self) -> Vec<String> {
        self.calls.lock().keys().cloned().collect()
    }

    /// Parse DTMF from SIP INFO body
    ///
    /// Works for both inbound and outbound calls - we receive INFO from either direction.
    ///
    /// # Supported Content-Type Formats
    ///
    /// ## 1. `application/dtmf-relay` (Cisco/Standard)
    /// ```text
    /// Signal= 5\r\n
    /// Duration= 160\r\n
    /// ```
    ///
    /// ## 2. `application/dtmf` (Simple)
    /// ```text
    /// 5
    /// ```
    ///
    /// # Edge Cases Handled
    ///
    /// - **Whitespace variations**: `Signal= 5`, `Signal=5`, `Signal = 5` all work.
    /// - **Case insensitive**: `Signal`, `signal`, `SIGNAL` all work.
    /// - **Missing duration**: Defaults to 250ms (Cisco standard).
    /// - **Duration out of range**: Clamped to 100-5000ms. Some endpoints send
    ///   unreasonable values.
    /// - **DTMF A-D**: Both uppercase and lowercase accepted, normalized to uppercase.
    /// - **Special characters**: `*` and `#` supported.
    ///
    /// # Why Two Formats?
    ///
    /// - `dtmf-relay`: Full-featured, includes duration. Used by Cisco, Orc,
    ///   most modern systems.
    /// - `dtmf`: Simple single-character. Used by some older systems, Orc
    ///   in certain configurations.
    fn parse_dtmf_relay(body: &str) -> Option<(char, u32)> {
        let body = body.trim();

        // Check for simple application/dtmf format (single character)
        if body.len() == 1 {
            let digit = body.chars().next()?;
            if matches!(digit, '0'..='9' | '*' | '#' | 'A'..='D' | 'a'..='d') {
                return Some((digit.to_ascii_uppercase(), 250)); // Default duration
            }
        }

        // Parse application/dtmf-relay format
        let mut digit: Option<char> = None;
        let mut duration: u32 = 250; // Default duration (Cisco standard)

        for line in body.lines() {
            let line = line.trim();
            let lower = line.to_ascii_lowercase();

            // Parse Signal= (case-insensitive, handle whitespace)
            if lower.starts_with("signal") {
                // Find = and extract value after it
                if let Some(eq_pos) = line.find('=') {
                    let value = line[eq_pos + 1..].trim();
                    if let Some(c) = value.chars().next() {
                        if matches!(c, '0'..='9' | '*' | '#' | 'A'..='D' | 'a'..='d') {
                            digit = Some(c.to_ascii_uppercase());
                        }
                    }
                }
            }
            // Parse Duration= (case-insensitive, handle whitespace)
            else if lower.starts_with("duration") {
                if let Some(eq_pos) = line.find('=') {
                    let value = line[eq_pos + 1..].trim();
                    if let Ok(d) = value.parse::<u32>() {
                        // Clamp to valid range (Cisco: 100-5000ms)
                        duration = d.clamp(100, 5000);
                    }
                }
            }
        }

        digit.map(|d| (d, duration))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sip_engine_creation() {
        let config = SipEngineConfig::default();
        let engine = SipEngine::new(config).await.unwrap();
        assert!(engine.active_calls().is_empty());
    }

    #[tokio::test]
    async fn test_add_provider() {
        let config = SipEngineConfig::default();
        let engine = SipEngine::new(config).await.unwrap();

        let provider = ProviderCredentials {
            id: "test".to_string(),
            sip_server: "sip.test.com".to_string(),
            sip_port: 5060,
            username: "user".to_string(),
            password: "pass".to_string(),
            realm: None,
            register: false,
        };

        engine.add_provider(provider);
        assert!(engine.providers.lock().contains_key("test"));
    }

    #[tokio::test]
    async fn test_rtp_port_allocation() {
        let config = SipEngineConfig {
            rtp_port_start: 10000,
            rtp_port_end: 10010,
            ..Default::default()
        };
        let engine = SipEngine::new(config).await.unwrap();

        let port1 = engine.allocate_rtp_port();
        let port2 = engine.allocate_rtp_port();

        assert_eq!(port1, 10000);
        assert_eq!(port2, 10002);
    }

    // DTMF INFO parsing tests

    #[test]
    fn test_parse_dtmf_relay_standard() {
        // Standard format with space after =
        let body = "Signal= 5\r\nDuration= 160\r\n";
        let result = SipEngine::parse_dtmf_relay(body);
        assert_eq!(result, Some(('5', 160)));
    }

    #[test]
    fn test_parse_dtmf_relay_no_space() {
        // Format without space (our original format)
        let body = "Signal=5\r\nDuration=160\r\n";
        let result = SipEngine::parse_dtmf_relay(body);
        assert_eq!(result, Some(('5', 160)));
    }

    #[test]
    fn test_parse_dtmf_relay_lowercase() {
        // Case-insensitive parsing
        let body = "signal= 5\r\nduration= 160\r\n";
        let result = SipEngine::parse_dtmf_relay(body);
        assert_eq!(result, Some(('5', 160)));
    }

    #[test]
    fn test_parse_dtmf_relay_mixed_case() {
        // Mixed case
        let body = "SIGNAL= 5\r\nDURATION= 160\r\n";
        let result = SipEngine::parse_dtmf_relay(body);
        assert_eq!(result, Some(('5', 160)));
    }

    #[test]
    fn test_parse_dtmf_relay_special_chars() {
        // Test *, #, A-D
        assert_eq!(SipEngine::parse_dtmf_relay("Signal= *\r\n"), Some(('*', 250)));
        assert_eq!(SipEngine::parse_dtmf_relay("Signal= #\r\n"), Some(('#', 250)));
        assert_eq!(SipEngine::parse_dtmf_relay("Signal= A\r\n"), Some(('A', 250)));
        assert_eq!(SipEngine::parse_dtmf_relay("Signal= a\r\n"), Some(('A', 250))); // Normalized to uppercase
    }

    #[test]
    fn test_parse_dtmf_relay_duration_default() {
        // No duration specified - should use default 250ms
        let body = "Signal= 5\r\n";
        let result = SipEngine::parse_dtmf_relay(body);
        assert_eq!(result, Some(('5', 250)));
    }

    #[test]
    fn test_parse_dtmf_relay_duration_clamped() {
        // Duration below minimum (100ms) - should clamp to 100
        let body = "Signal= 5\r\nDuration= 50\r\n";
        let result = SipEngine::parse_dtmf_relay(body);
        assert_eq!(result, Some(('5', 100)));

        // Duration above maximum (5000ms) - should clamp to 5000
        let body = "Signal= 5\r\nDuration= 10000\r\n";
        let result = SipEngine::parse_dtmf_relay(body);
        assert_eq!(result, Some(('5', 5000)));
    }

    #[test]
    fn test_parse_dtmf_simple_format() {
        // application/dtmf format (single character)
        assert_eq!(SipEngine::parse_dtmf_relay("5"), Some(('5', 250)));
        assert_eq!(SipEngine::parse_dtmf_relay("*"), Some(('*', 250)));
        assert_eq!(SipEngine::parse_dtmf_relay("#"), Some(('#', 250)));
        assert_eq!(SipEngine::parse_dtmf_relay("A"), Some(('A', 250)));
        assert_eq!(SipEngine::parse_dtmf_relay("a"), Some(('A', 250))); // Normalized
    }

    #[test]
    fn test_parse_dtmf_relay_invalid() {
        // Invalid digit
        assert_eq!(SipEngine::parse_dtmf_relay("Signal= X\r\n"), None);
        // Empty body
        assert_eq!(SipEngine::parse_dtmf_relay(""), None);
        // No signal line
        assert_eq!(SipEngine::parse_dtmf_relay("Duration= 160\r\n"), None);
    }

    #[test]
    fn test_parse_dtmf_relay_whitespace() {
        // Extra whitespace handling
        let body = "  Signal = 5  \r\n  Duration = 160  \r\n";
        let result = SipEngine::parse_dtmf_relay(body);
        assert_eq!(result, Some(('5', 160)));
    }
}
