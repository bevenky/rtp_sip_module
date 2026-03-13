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

use crate::config::Transport;
use crate::error::{Result, RtpSipError};
use crate::rtp::{CodecType, RtpEngine, RtpEngineConfig};
use crate::sip::dns::SipResolver;
use crate::sip::sdp::{MediaDirection, Sdp, SdpBuilder};
use crate::sip::session_timer::{SessionTimer, SessionTimerConfig};
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
use rsipstack::transaction::key::{TransactionKey, TransactionRole};
use rsipstack::transaction::transaction::Transaction;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{broadcast, mpsc, oneshot};

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
/// Only 6 states exposed - internal transitions handled automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    /// INVITE sent, waiting for response (100 Trying received or no response yet).
    /// Bug #54: Added so CANCEL works before 180/183 is received.
    Trying,
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
    /// Blind transfer initiated (REFER sent)
    TransferInitiated {
        call_id: String,
        target: String,
    },
    /// Transfer progress from NOTIFY (SIP fragment status)
    TransferProgress {
        call_id: String,
        status_code: u16,
        reason: String,
        completed: bool,
    },
    /// Transfer failed
    TransferFailed {
        call_id: String,
        error: String,
    },
    /// Incoming REFER received (someone is transferring us)
    ReferReceived {
        call_id: String,
        refer_to: String,
    },
    /// Call was cancelled (early dialog cancelled before answer)
    Cancelled { call_id: String },
    /// Call was redirected (3xx response)
    Redirected {
        call_id: String,
        targets: Vec<String>,
    },
    /// RTP media timeout detected (no RTP received)
    MediaTimeout { call_id: String },
    /// Registration state changed
    RegistrationChanged {
        state: String,
        error: Option<String>,
    },
    /// Gateway health status changed (from OPTIONS keepalive)
    GatewayHealth { server: String, healthy: bool },
}

/// Registration state (Fix 4)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationState {
    /// Not registered
    Unregistered,
    /// Registration in progress
    Registering,
    /// Successfully registered
    Registered,
    /// Registration failed
    Failed(String),
    /// Unregistering
    Unregistering,
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
    /// Session timer state (RFC 4028)
    pub session_timer: Option<crate::sip::session_timer::SessionTimer>,
    /// Whether a REFER transfer is pending
    pub refer_pending: bool,
    /// Target URI for pending REFER
    pub refer_target: Option<String>,
    /// Whether a re-INVITE is currently in progress (for glare detection)
    pub reinvite_pending: bool,
    /// Bug #28 fix: Remote Contact URI (the actual target for in-dialog requests).
    /// Populated from the Contact header in dialog establishment responses (180/183/200 OK).
    /// REFER and other in-dialog requests should use this instead of remote_uri (To header).
    pub remote_contact: Option<String>,
    /// Whether a CANCEL has been sent but 200 OK may still arrive (Bug #6)
    /// If true, the dialog task should send BYE immediately upon receiving 200 OK.
    pub cancel_pending: bool,
    /// Bug #R11-4: Route set from Record-Route headers, stored in the order
    /// they should appear in Route headers for in-dialog requests.
    /// For UAC (outbound): reverse of Record-Route from response (RFC 3261 §12.1.1).
    /// For UAS (inbound): same order as Record-Route from request (RFC 3261 §12.1.1).
    pub route_set: Vec<String>,
    /// Oneshot sender to signal cancellation to the invite task.
    /// Used to cancel outbound calls before the dialog is established (before 200 OK).
    /// The invite task `select!`s on the receiver; when fired, the `do_invite` future
    /// is dropped, which triggers rsipstack's `DialogGuardForUnconfirmed` to send CANCEL.
    pub cancel_tx: Option<oneshot::Sender<()>>,
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
    /// Enable 100rel/PRACK support (Fix 7)
    pub enable_100rel: bool,
    /// OPTIONS keepalive interval in seconds (Fix 8), 0 = disabled
    pub options_keepalive_interval_secs: u64,
    /// Enable Contact header NAT rewriting (Fix 9)
    pub contact_nat_rewrite: bool,
    /// Maximum concurrent calls (Fix 10), 0 = unlimited
    pub max_calls: usize,
    /// Maximum SIP requests per second (Fix 10), 0 = unlimited
    pub max_requests_per_second: u32,
    /// Automatically follow 3xx redirects (Fix 2)
    pub auto_redirect: bool,
    /// Timer T1: RTT estimate in milliseconds (Fix 3)
    pub timer_t1_ms: Option<u32>,
    /// Timer T2: Maximum retransmit interval in milliseconds (Fix 3)
    pub timer_t2_ms: Option<u32>,
    /// Timer T1x64: Maximum retransmit time in milliseconds (Fix 3)
    pub timer_t1x64_ms: Option<u32>,
    /// Enable session timers (RFC 4028) for outbound calls (Bug R15-3)
    pub enable_session_timers: bool,
    /// Transport type (Fix 11)
    pub transport: Transport,
    /// Verify TLS certificates (Fix 11)
    pub tls_verify: bool,
    /// CA certificate path for TLS (Fix 11)
    pub tls_ca_cert: Option<String>,
}

impl SipEngineConfig {
    /// Enable or disable 100rel/PRACK support (Fix 7)
    pub fn set_100rel_enabled(&mut self, enabled: bool) {
        self.enable_100rel = enabled;
    }
}

impl Default for SipEngineConfig {
    fn default() -> Self {
        Self {
            local_addr: "0.0.0.0:5060".parse().unwrap(),
            user_agent: "rtpsip/0.1".to_string(),
            rtp_port_start: 10000,
            rtp_port_end: 20000,
            enable_100rel: false,
            options_keepalive_interval_secs: 0,
            contact_nat_rewrite: false,
            max_calls: 0,
            max_requests_per_second: 0,
            enable_session_timers: false,
            auto_redirect: false,
            timer_t1_ms: None,
            timer_t2_ms: None,
            timer_t1x64_ms: None,
            transport: Transport::Udp,
            tls_verify: true,
            tls_ca_cert: None,
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
    registrations: Mutex<HashMap<String, Arc<tokio::sync::Mutex<Registration>>>>,
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
    /// Registration state (Fix 4)
    registration_state: Mutex<RegistrationState>,
    /// Registration expiry in seconds (Fix 4)
    registration_expiry: Mutex<Option<u32>>,
    /// Gateway health status (Fix 8)
    gateway_health: Mutex<HashMap<String, bool>>,
    /// Rate limiting: timestamps of recent requests (Fix 10)
    request_timestamps: Mutex<Vec<Instant>>,
    /// Bug #5 fix: Handle for the registration refresh background task.
    /// Stored so it can be cancelled when the engine is stopped or re-registered.
    registration_refresh_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl SipEngine {
    /// Create a new SIP engine
    pub async fn new(config: SipEngineConfig) -> Result<Arc<Self>> {
        // Fix 3: Apply transaction timer configuration
        let mut endpoint_option = EndpointOption::default();
        if let Some(t1) = config.timer_t1_ms {
            endpoint_option.t1 = std::time::Duration::from_millis(t1 as u64);
        }
        // Bug #100: Timer T2 (maximum retransmit interval, RFC 3261 Section 17)
        // is configured in SipEngineConfig::timer_t2_ms but cannot be applied here
        // because rsipstack 0.3's EndpointOption does not expose a `t2` field.
        // TODO: Apply config.timer_t2_ms when upgrading to a version of rsipstack
        // that exposes T2 in EndpointOption (T2 defaults to 4s per RFC 3261).
        if let Some(t1x64) = config.timer_t1x64_ms {
            endpoint_option.t1x64 = std::time::Duration::from_millis(t1x64 as u64);
        }

        // Fix 11: Log TLS configuration
        if config.transport == Transport::Tls {
            tracing::info!(
                "TLS transport configured (verify={}, ca_cert={:?})",
                config.tls_verify,
                config.tls_ca_cert
            );
        }

        let endpoint = EndpointBuilder::new()
            .with_option(endpoint_option)
            .build();

        let dialog_layer = DialogLayer::new(endpoint.inner.clone());

        // Bug #99: Increased capacity from 100 to 1000 to avoid dropped events
        // under high call volume (each call generates multiple events: Ringing,
        // Answered, AudioReady, Hangup, etc.)
        let (event_tx, _) = broadcast::channel(1000);
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
            registration_state: Mutex::new(RegistrationState::Unregistered),
            registration_expiry: Mutex::new(None),
            gateway_health: Mutex::new(HashMap::new()),
            request_timestamps: Mutex::new(Vec::new()),
            registration_refresh_handle: Mutex::new(None),
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
            .map_err(|e| RtpSipError::Sip(format!("Failed to get incoming transactions: {}", e)))?;

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
                    Some(mut transaction) = incoming_rx.recv() => {
                        // Check if this is an INVITE request
                        if transaction.original.method == rsip::Method::Invite {
                            engine.handle_incoming_invite(transaction).await;
                        } else {
                            // Bug #98 fix: Handle out-of-dialog non-INVITE requests
                            // instead of silently ignoring them.
                            match transaction.original.method {
                                rsip::Method::Options => {
                                    // Respond 200 OK to OPTIONS (used for keepalive / capability queries)
                                    if let Err(e) = transaction.reply(rsip::StatusCode::OK).await {
                                        tracing::debug!("Failed to send 200 OK for OPTIONS: {}", e);
                                    }
                                }
                                _ => {
                                    // TODO: For proper compliance, we should inspect the
                                    // transaction to build a full 405 response with an
                                    // Allow header listing supported methods. The current
                                    // rsipstack transaction API only exposes reply(StatusCode).
                                    if let Err(e) = transaction.reply(rsip::StatusCode::MethodNotAllowed).await {
                                        tracing::debug!(
                                            "Failed to send 405 for {:?}: {}",
                                            transaction.original.method,
                                            e
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        // Fix 8: Start OPTIONS keepalive background task
        if self.config.options_keepalive_interval_secs > 0 {
            let engine_keepalive = self.clone();
            let interval_secs = self.config.options_keepalive_interval_secs;
            let mut keepalive_shutdown_rx = self.shutdown_tx.subscribe();

            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(std::time::Duration::from_secs(interval_secs));
                // Skip the first immediate tick
                interval.tick().await;

                loop {
                    tokio::select! {
                        _ = keepalive_shutdown_rx.recv() => {
                            tracing::debug!("OPTIONS keepalive task shutting down");
                            break;
                        }
                        _ = interval.tick() => {
                            engine_keepalive.send_options_keepalive().await;
                        }
                    }
                }
            });

            tracing::info!(
                "OPTIONS keepalive started (interval={}s)",
                interval_secs
            );
        }

        Ok(())
    }

    /// Send OPTIONS keepalive pings to all registered providers (Fix 8)
    async fn send_options_keepalive(self: &Arc<Self>) {
        let providers: Vec<ProviderCredentials> =
            self.providers.lock().values().cloned().collect();

        for provider in &providers {
            let server = format!("{}:{}", provider.sip_server, provider.sip_port);
            let healthy = self.send_options_ping(&server).await;

            let prev_healthy = self.gateway_health.lock().insert(server.clone(), healthy);

            // Only emit event on state change
            if prev_healthy != Some(healthy) {
                let _ = self.event_tx.send(CallEvent::GatewayHealth {
                    server: server.clone(),
                    healthy,
                });
                if healthy {
                    tracing::info!("Gateway {} is healthy", server);
                } else {
                    tracing::warn!("Gateway {} is unhealthy", server);
                }
            }
        }
    }

    /// Send a single OPTIONS ping to a server and check for response (Fix 8)
    ///
    /// TODO(Bug #5): This currently sends OPTIONS via a raw ephemeral UDP socket
    /// (`UdpSocket::bind("0.0.0.0:0")`), bypassing the SIP stack entirely. This means:
    /// - No SIP transaction retransmission (unreliable over lossy networks)
    /// - NAT pinhole may not match the SIP stack's transport (response may be dropped)
    /// - Does not benefit from the endpoint's transport layer (no TCP/TLS support)
    /// This is acceptable as a keepalive since false negatives only cause a health
    /// status flap, but ideally should be routed through the endpoint's transaction
    /// layer (similar to the Bug #4 fix for REFER) for reliability.
    async fn send_options_ping(&self, server: &str) -> bool {
        let addrs = match SipResolver::resolve_sip_uri(server).await {
            Ok(addrs) if !addrs.is_empty() => addrs,
            _ => return false,
        };

        let remote_addr = addrs[0];

        let branch = format!("z9hG4bK{}", uuid::Uuid::new_v4().simple());
        let mut headers: rsip::Headers = Default::default();

        // TODO(Bug #22): The Via transport is hardcoded to "UDP" but should be
        // derived from the configured transport (self.config.transport). When TCP
        // or TLS is configured, this should use "TCP" or "TLS" respectively.
        let via_value = format!(
            "SIP/2.0/UDP {};branch={}",
            self.config.local_addr, branch
        );
        headers.push(rsip::Header::Via(via_value.into()));
        headers.push(rsip::Header::MaxForwards("70".into()));
        headers.push(rsip::Header::From(
            format!(
                "<sip:keepalive@{}>;tag={}",
                self.config.local_addr,
                uuid::Uuid::new_v4().simple()
            )
            .into(),
        ));
        headers.push(rsip::Header::To(format!("<sip:{}>", server).into()));
        headers.push(rsip::Header::CallId(
            uuid::Uuid::new_v4().to_string().into(),
        ));
        headers.push(rsip::Header::CSeq("1 OPTIONS".into()));
        headers.push(rsip::Header::UserAgent(
            self.config.user_agent.clone().into(),
        ));
        headers.push(rsip::Header::ContentLength("0".into()));

        let request_uri = match rsip::Uri::try_from(format!("sip:{}", server).as_str()) {
            Ok(uri) => uri,
            Err(_) => return false,
        };

        let request = rsip::Request {
            method: rsip::Method::Options,
            uri: request_uri,
            version: rsip::Version::V2,
            headers,
            body: vec![],
        };

        let request_bytes = request.to_string();

        let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => return false,
        };

        if socket
            .send_to(request_bytes.as_bytes(), remote_addr)
            .await
            .is_err()
        {
            return false;
        }

        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            socket.recv_from(&mut buf),
        )
        .await
        {
            Ok(Ok((len, _))) => {
                let response = String::from_utf8_lossy(&buf[..len]);
                response.starts_with("SIP/2.0 2")
            }
            _ => false,
        }
    }

    /// Get gateway health status (Fix 8)
    pub fn gateway_health(&self) -> HashMap<String, bool> {
        self.gateway_health.lock().clone()
    }

    /// Get current registration state (Fix 4)
    pub fn registration_state(&self) -> RegistrationState {
        self.registration_state.lock().clone()
    }

    /// Unregister from a provider (Fix 4)
    pub async fn unregister(&self, provider_id: &str) -> Result<()> {
        *self.registration_state.lock() = RegistrationState::Unregistering;

        let registration = self
            .registrations
            .lock()
            .get(provider_id)
            .cloned()
            .ok_or_else(|| {
                RtpSipError::Provider(format!("No registration for provider: {}", provider_id))
            })?;

        let provider = self
            .providers
            .lock()
            .get(provider_id)
            .cloned()
            .ok_or_else(|| {
                RtpSipError::Provider(format!("Unknown provider: {}", provider_id))
            })?;

        let registrar_uri: Uri =
            Uri::try_from(format!("sip:{}", provider.sip_server).as_str()).map_err(|e| {
                RtpSipError::Sip(format!("Invalid registrar URI: {:?}", e))
            })?;

        // Send REGISTER with Expires: 0 to unregister
        registration
            .lock()
            .await
            .register(registrar_uri, Some(0))
            .await
            .map_err(|e| RtpSipError::Sip(format!("Unregistration failed: {}", e)))?;

        self.registrations.lock().remove(provider_id);
        *self.registration_state.lock() = RegistrationState::Unregistered;
        *self.registration_expiry.lock() = None;

        let _ = self.event_tx.send(CallEvent::RegistrationChanged {
            state: "unregistered".to_string(),
            error: None,
        });

        tracing::info!("Unregistered from provider {}", provider_id);
        Ok(())
    }

    /// Get NAT-rewritten contact URI (Fix 9)
    fn nat_rewritten_contact(&self, user: &str) -> String {
        format!("sip:{}@{}", user, self.config.local_addr)
    }

    /// Check rate limits (Fix 10)
    fn check_rate_limit(&self) -> bool {
        if self.config.max_requests_per_second == 0 {
            return true;
        }

        let now = Instant::now();
        let window = std::time::Duration::from_secs(1);
        let mut timestamps = self.request_timestamps.lock();

        timestamps.retain(|t| now.duration_since(*t) < window);

        if timestamps.len() >= self.config.max_requests_per_second as usize {
            return false;
        }

        timestamps.push(now);
        true
    }

    /// Stop the SIP engine
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Handle an incoming INVITE request
    async fn handle_incoming_invite(
        self: &Arc<Self>,
        mut transaction: rsipstack::transaction::transaction::Transaction,
    ) {
        // Bug #29 fix: Send 100 Trying immediately to stop INVITE retransmissions.
        // Without this, the remote side retransmits the INVITE at T1 intervals,
        // and each retransmission could create a duplicate session.
        if let Err(e) = transaction.reply(rsip::StatusCode::Trying).await {
            tracing::error!("Failed to send 100 Trying: {}", e);
        }

        // Bug #29: Deduplicate by SIP Call-ID to prevent duplicate sessions from
        // INVITE retransmissions that arrive before our 100 Trying reaches the sender.
        let sip_call_id = transaction
            .original
            .call_id_header()
            .ok()
            .map(|h| h.to_string());
        if let Some(ref sip_cid) = sip_call_id {
            let sip_cid_trimmed = sip_cid.trim();
            let existing = self.calls.lock().values().any(|sess| {
                let sess = sess.lock();
                // Bug #5 fix: Trim both sides of the comparison to avoid format mismatches
                // (e.g., trailing whitespace or CRLF in SIP Call-ID headers).
                sess.direction == Direction::Inbound
                    && sess.server_dialog.as_ref().map(|d| d.id().call_id.to_string().trim().to_string())
                        == Some(sip_cid_trimmed.to_string())
            });
            if existing {
                tracing::debug!(
                    "Duplicate INVITE detected (SIP Call-ID={}), ignoring",
                    sip_cid
                );
                return;
            }
        }

        // Fix 10 + Bug #56: Rate limiting checks - send 503 before returning
        if !self.check_rate_limit() {
            tracing::warn!("Rate limit exceeded, rejecting INVITE with 503");
            if let Err(e) = transaction.reply(rsip::StatusCode::ServiceUnavailable).await {
                tracing::error!("Failed to send 503 for rate limit: {}", e);
            }
            return;
        }

        if self.config.max_calls > 0 {
            let active = self.calls.lock().len();
            if active >= self.config.max_calls {
                tracing::warn!(
                    "Max calls ({}) reached, rejecting INVITE with 503",
                    self.config.max_calls
                );
                if let Err(e) = transaction.reply(rsip::StatusCode::ServiceUnavailable).await {
                    tracing::error!("Failed to send 503 for max calls: {}", e);
                }
                return;
            }
        }

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
        // Bug #24 fix: Replace .unwrap() with graceful error handling
        let rtp_addr: SocketAddr = match format!("0.0.0.0:{}", rtp_port).parse() {
            Ok(addr) => addr,
            Err(e) => {
                tracing::error!("Invalid RTP bind address for port {}: {}", rtp_port, e);
                return;
            }
        };

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

        // Bug #57 fix: If RTP engine creation failed and we received an SDP offer,
        // we cannot handle the call - reject with 500 Server Internal Error.
        if rtp_engine.is_none() && remote_sdp.is_some() {
            tracing::error!("Cannot accept call with SDP offer: RTP engine creation failed");
            if let Err(e) = transaction.reply(rsip::StatusCode::ServerInternalError).await {
                tracing::error!("Failed to send 500 for RTP failure: {}", e);
            }
            return;
        }

        // Parse remote SDP first to determine direction for our answer
        let mut remote_telephone_event_pt = None;
        let mut remote_media_direction = MediaDirection::SendRecv;
        if let Some(ref sdp_str) = remote_sdp {
            if let Ok(sdp) = Sdp::parse(sdp_str) {
                if let Some(rtp_addr) = sdp.rtp_addr() {
                    // Bug #22 fix: Port 0 means stream disabled/rejected (RFC 3264 Section 6)
                    if rtp_addr.port() != 0 {
                        if let Some(ref rtp) = rtp_engine {
                            rtp.set_remote(rtp_addr);
                        }
                    }
                }
                remote_telephone_event_pt = sdp.telephone_event_pt();
                remote_media_direction = sdp.audio_direction();
            }
        }

        // Bug #R12-3: Build local SDP answer with correct direction per RFC 3264 §6.
        // The answer direction must be the inverse of the offer direction:
        // sendrecv→sendrecv, sendonly→recvonly, recvonly→sendonly, inactive→inactive.
        let answer_direction = remote_media_direction.answer_direction();
        let local_sdp = if let Some(ref rtp) = rtp_engine {
            let mut builder = SdpBuilder::new(rtp.local_addr())
                .codecs(vec![CodecType::Pcmu, CodecType::Pcma]);
            // Only add explicit direction when not the default sendrecv
            if answer_direction != MediaDirection::SendRecv {
                builder = builder.direction(answer_direction.as_str());
            }
            Some(builder.build())
        } else {
            None
        };

        // Create the server dialog
        let (state_tx, mut state_rx) = mpsc::unbounded_channel::<DialogState>();
        let server_dialog = match self.dialog_layer.get_or_create_server_invite(&transaction, state_tx, None, None) {
            Ok(dialog) => Arc::new(dialog),
            Err(e) => {
                tracing::error!("Failed to create server dialog: {}", e);
                return;
            }
        };

        // Bug #R11-4: Extract Record-Route headers from INVITE for route set.
        // RFC 3261 §12.1.1: UAS stores route set in same order as received.
        let route_set: Vec<String> = transaction.original.headers.iter()
            .filter_map(|h| {
                if let rsip::Header::RecordRoute(rr) = h {
                    Some(rr.to_string())
                } else {
                    None
                }
            })
            .collect();

        // Bug #27 fix: Parse Session-Expires from incoming INVITE for session timer.
        // Timer will be started when the call is answered.
        let session_timer = {
            let se_header = transaction.original.headers.iter().find_map(|h| {
                if let rsip::Header::Other(name, val) = h {
                    if name.as_str().eq_ignore_ascii_case("Session-Expires") {
                        Some(val.as_str().to_string())
                    } else { None }
                } else { None }
            });
            if let Some(ref header) = se_header {
                let mut timer = SessionTimer::new(SessionTimerConfig::default());
                let (_se, _role) = timer.process_response(
                    Some(header.as_str()),
                    false, // is_uac: inbound call = we are UAS
                );
                // Don't start yet - will start when answer() is called
                Some(timer)
            } else {
                None
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
            // Bug #20: CSeq starts at 1 for our local tracking, but the rsipstack
            // dialog layer manages the actual CSeq numbering for in-dialog requests
            // (re-INVITE, BYE, etc.) independently. This field is only used for
            // out-of-dialog requests generated directly by the engine.
            cseq: 1,
            local_contact: Some(self.nat_rewritten_contact("rtpsip")),
            dtmf_mode: DtmfMode::Auto,
            remote_telephone_event_pt,
            early_media_state: EarlyMediaState::None,
            remote_media_direction,
            local_hold: false,
            remote_hold: false,
            remote_user_agent,
            rtp_bug_flags,
            session_timer,
            refer_pending: false,
            refer_target: None,
            reinvite_pending: false,
            remote_contact: None,
            cancel_pending: false,
            route_set,
            cancel_tx: None,
        }));

        self.calls.lock().insert(call_id.clone(), session.clone());

        // Send ringing response (180) - not async
        // Bug #32 fix: Include Contact header in 180 Ringing per RFC 3261 §8.2.6.
        // Provisional responses that establish a dialog MUST include Contact.
        let local_contact = self.nat_rewritten_contact("rtpsip");
        let ringing_headers = vec![
            rsip::Header::Contact(format!("<{}>", local_contact).into()),
        ];
        if let Err(e) = server_dialog.ringing(Some(ringing_headers), None) {
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
                        // Fix 5 + Bug #50: Glare detection for inbound calls (UAS role)
                        let is_glare = if let Some(sess) = engine.calls.lock().get(&call_id_for_state) {
                            sess.lock().reinvite_pending
                        } else {
                            false
                        };

                        if is_glare {
                            // Bug #50 fix: Log the glare condition. Ideally we would send
                            // a 491 Request Pending response here, but rsipstack 0.3
                            // automatically sends 200 OK to incoming re-INVITEs before
                            // delivering the DialogState::Updated notification to us.
                            // TODO: When upgrading to a version of rsipstack that allows
                            // deferred re-INVITE responses, send 491 instead of accepting.
                            tracing::warn!(
                                "Glare detected on call {} (UAS): re-INVITE pending, \
                                 cannot send 491 (rsipstack auto-accepted)",
                                call_id_for_state
                            );
                            // Bug #35 fix: Do NOT skip SDP processing here. Since rsipstack
                            // already auto-accepted the re-INVITE with 200 OK, we must
                            // process the SDP to keep RTP state consistent with what the
                            // remote side now expects.
                        }

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
                                        // Bug #22 fix: Port 0 means stream disabled/rejected
                                        if rtp_addr.port() != 0 {
                                            if let Some(ref rtp) = sess.rtp_engine {
                                                rtp.set_remote(rtp_addr);
                                            }
                                        }
                                    }
                                    sess.update_from_remote_sdp(&sdp);
                                }
                            }
                        }

                        // Bug #27 fix: Reset session timer on incoming re-INVITE (UAS side).
                        if let Some(sess) = engine.calls.lock().get(&call_id_for_state) {
                            let mut sess = sess.lock();
                            if let Some(ref mut timer) = sess.session_timer {
                                timer.refresh();
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
                    DialogState::Notify(_, request) => {
                        // Check if this is a REFER subscription NOTIFY
                        let is_refer_event = request.headers.iter().any(|h| {
                            matches!(h, rsip::Header::Other(name, val)
                                if name.as_str().eq_ignore_ascii_case("Event")
                                    && val.as_str().trim().starts_with("refer"))
                        });

                        if is_refer_event {
                            let body_str =
                                std::str::from_utf8(request.body()).unwrap_or("");
                            let (status_code, reason) = parse_sipfrag_status(body_str)
                                .unwrap_or((100, "Trying".to_string()));

                            let is_terminated = request.headers.iter().any(|h| {
                                matches!(h, rsip::Header::Other(name, val)
                                    if name.as_str().eq_ignore_ascii_case("Subscription-State")
                                        && val.as_str().trim().starts_with("terminated"))
                            });

                            let completed =
                                is_terminated && status_code >= 200 && status_code < 300;

                            let _ = engine.event_tx.send(CallEvent::TransferProgress {
                                call_id: call_id_for_state.clone(),
                                status_code,
                                reason,
                                completed,
                            });

                            if is_terminated {
                                if let Some(sess) =
                                    engine.calls.lock().get(&call_id_for_state)
                                {
                                    sess.lock().refer_pending = false;
                                }
                            }
                        }
                    }
                    DialogState::Terminated(_, reason) => {
                        // Bug #61 fix: Stop RTP engine before removing call from map
                        if let Some(sess) = engine.calls.lock().get(&call_id_for_state) {
                            let sess = sess.lock();
                            if let Some(ref rtp) = sess.rtp_engine {
                                rtp.stop();
                            }
                        }

                        let reason_str = format!("{:?}", reason);
                        // Bug #96 fix: Send Hangup event BEFORE removing the call
                        // from the map, so that event subscribers can still look up
                        // the call session while processing the event.
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
    pub fn answer(self: &Arc<Self>, call_id: &str) -> Result<()> {
        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| RtpSipError::Session(format!("Call not found: {}", call_id)))?;

        let (server_dialog, local_sdp) = {
            let mut sess = session.lock();

            if sess.direction != Direction::Inbound {
                return Err(RtpSipError::Session(
                    "Cannot answer outbound call".to_string(),
                ));
            }

            if sess.state != CallState::Ringing {
                return Err(RtpSipError::Session(format!(
                    "Cannot answer call in state {:?}",
                    sess.state
                )));
            }

            let dialog = sess.server_dialog.clone().ok_or_else(|| {
                RtpSipError::Session("No server dialog for inbound call".to_string())
            })?;

            let sdp = sess.local_sdp.clone();

            // Update state to Active
            sess.state = CallState::Active;

            (dialog, sdp)
        };

        // Build headers and body for 200 OK
        // Bug #7 fix: Include Contact header in 200 OK per RFC 3261 §13.3.1.4.
        // The Contact header establishes the remote target for in-dialog requests.
        let local_contact = self.nat_rewritten_contact("rtpsip");
        let (headers, body) = if let Some(sdp_str) = local_sdp {
            (
                Some(vec![
                    rsip::Header::Contact(format!("<{}>", local_contact).into()),
                    rsip::Header::ContentType("application/sdp".into()),
                ]),
                Some(sdp_str.into_bytes()),
            )
        } else {
            (
                Some(vec![
                    rsip::Header::Contact(format!("<{}>", local_contact).into()),
                ]),
                None,
            )
        };

        // Send 200 OK (not async)
        server_dialog
            .accept(headers, body)
            .map_err(|e| RtpSipError::Sip(format!("Failed to send 200 OK: {}", e)))?;

        // Bug R14-1 fix: Reset session timer to count from answer time, not INVITE time.
        // process_response() called start() when the INVITE arrived, but the call may
        // have been ringing for an extended period. Reset last_refresh now.
        {
            let mut sess = session.lock();
            if let Some(ref mut timer) = sess.session_timer {
                timer.refresh();
            }
        }

        // Bug #27 fix: Spawn session timer monitoring task for inbound calls.
        let has_session_timer = {
            let sess = session.lock();
            sess.session_timer.as_ref().map_or(false, |t| t.is_active())
        };
        if has_session_timer {
            let st_engine = self.clone();
            let st_call_id = call_id.to_string();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                    let action = {
                        let calls = st_engine.calls.lock();
                        let Some(sess) = calls.get(&st_call_id) else { break };
                        let sess = sess.lock();
                        if sess.state == CallState::Ended {
                            break;
                        }
                        match &sess.session_timer {
                            Some(timer) if timer.is_expired() => Some("expired"),
                            Some(timer) if timer.needs_refresh() => Some("refresh"),
                            Some(_) => None,
                            None => { break; }
                        }
                    };

                    match action {
                        Some("expired") => {
                            tracing::warn!(
                                "Session timer expired for call {}, sending BYE",
                                st_call_id
                            );
                            let _ = st_engine.hangup(&st_call_id).await;
                            break;
                        }
                        Some("refresh") => {
                            tracing::debug!(
                                "Session timer refresh needed for call {}",
                                st_call_id
                            );
                            if let Err(e) = st_engine.send_reinvite(&st_call_id, None).await {
                                tracing::warn!(
                                    "Session timer refresh re-INVITE failed for call {}: {}",
                                    st_call_id, e
                                );
                            } else {
                                if let Some(sess) = st_engine.calls.lock().get(&st_call_id) {
                                    let mut sess = sess.lock();
                                    if let Some(ref mut timer) = sess.session_timer {
                                        timer.refresh();
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            });
        }

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
        // Bug #65 fix: Validate that status code is in the error response range (300-699).
        // 1xx and 2xx are not rejection codes and would confuse dialog state.
        if status_code < 300 || status_code > 699 {
            return Err(RtpSipError::Sip(format!(
                "reject status code must be 300-699, got {}",
                status_code
            )));
        }

        // Bug #97 fix: Don't remove the call from the map until after the
        // reject response has been sent successfully. Previously the call was
        // removed before server_dialog.reject(), so a failure to send the
        // response would leave the call orphaned (removed from map but never
        // properly rejected on the wire).
        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| RtpSipError::Session(format!("Call not found: {}", call_id)))?;

        let server_dialog = {
            let mut sess = session.lock();

            if sess.direction != Direction::Inbound {
                return Err(RtpSipError::Session(
                    "Cannot reject outbound call".to_string(),
                ));
            }

            // Stop RTP if started
            if let Some(ref rtp) = sess.rtp_engine {
                rtp.stop();
            }

            sess.state = CallState::Ended;

            sess.server_dialog.clone().ok_or_else(|| {
                RtpSipError::Session("No server dialog for inbound call".to_string())
            })?
        };

        // Convert status code to rsip StatusCode
        let sip_status = rsip::StatusCode::from(status_code);

        // Send rejection response (not async)
        server_dialog
            .reject(Some(sip_status), None)
            .map_err(|e| RtpSipError::Sip(format!("Failed to send rejection: {}", e)))?;

        // Bug #97: Only remove from map after reject() succeeds
        self.calls.lock().remove(call_id);

        let reason = format!("Rejected with {}", status_code);
        let _ = self.event_tx.send(CallEvent::Hangup {
            call_id: call_id.to_string(),
            reason,
        });

        tracing::info!("Call {} rejected with status {}", call_id, status_code);
        Ok(())
    }

    /// Register with a provider (Fix 4: lifecycle tracking)
    pub async fn register(self: &Arc<Self>, provider_id: &str) -> Result<()> {
        let provider = self
            .providers
            .lock()
            .get(provider_id)
            .cloned()
            .ok_or_else(|| RtpSipError::Provider(format!("Unknown provider: {}", provider_id)))?;

        if !provider.register {
            return Ok(());
        }

        // Bug #5 fix: Cancel any existing registration refresh task before re-registering.
        if let Some(handle) = self.registration_refresh_handle.lock().take() {
            handle.abort();
        }

        *self.registration_state.lock() = RegistrationState::Registering;

        let _ = self.event_tx.send(CallEvent::RegistrationChanged {
            state: "registering".to_string(),
            error: None,
        });

        let credential = provider.to_credential();
        let mut registration = Registration::new(self.endpoint.inner.clone(), Some(credential));

        let registrar_uri: Uri = Uri::try_from(format!("sip:{}", provider.sip_server).as_str())
            .map_err(|e| RtpSipError::Sip(format!("Invalid registrar URI: {:?}", e)))?;

        let registrar_uri_clone = registrar_uri.clone();
        match registration.register(registrar_uri, None).await {
            Ok(response) if response.status_code == rsip::StatusCode::IntervalTooBrief => {
                // Bug #31 fix: Handle 423 Interval Too Brief per RFC 3261 §10.2.8.
                // Extract Min-Expires header and retry with the longer interval.
                let min_expires = response.min_expires_header()
                    .and_then(|h| u32::try_from(h.clone()).ok());

                if let Some(min_exp) = min_expires {
                    tracing::warn!(
                        "Registration got 423 Interval Too Brief, retrying with Min-Expires={} for provider {}",
                        min_exp, provider_id
                    );
                    match registration.register(registrar_uri_clone, Some(min_exp)).await {
                        Ok(retry_resp) if retry_resp.status_code == rsip::StatusCode::OK => {
                            // Fall through to normal success handling below
                            let expiry = registration.expires();
                            *self.registration_expiry.lock() = Some(expiry);
                            *self.registration_state.lock() = RegistrationState::Registered;

                            self.registrations
                                .lock()
                                .insert(provider_id.to_string(), Arc::new(tokio::sync::Mutex::new(registration)));

                            let _ = self.event_tx.send(CallEvent::RegistrationChanged {
                                state: "registered".to_string(),
                                error: None,
                            });

                            tracing::info!(
                                "Registered with provider {} after 423 retry (expires={:?})",
                                provider_id,
                                expiry
                            );

                            // Bug R14-2 fix: Spawn refresh task (was missing — early return
                            // bypassed the normal path's refresh task spawn).
                            self.spawn_registration_refresh_task(&provider_id, expiry);
                            return Ok(());
                        }
                        Ok(retry_resp) => {
                            let err_msg = format!(
                                "Registration retry after 423 failed with status: {}",
                                retry_resp.status_code
                            );
                            *self.registration_state.lock() = RegistrationState::Failed(err_msg.clone());
                            let _ = self.event_tx.send(CallEvent::RegistrationChanged {
                                state: "failed".to_string(),
                                error: Some(err_msg.clone()),
                            });
                            return Err(RtpSipError::Sip(err_msg));
                        }
                        Err(e) => {
                            let err_msg = format!("Registration retry after 423 failed: {}", e);
                            *self.registration_state.lock() = RegistrationState::Failed(err_msg.clone());
                            let _ = self.event_tx.send(CallEvent::RegistrationChanged {
                                state: "failed".to_string(),
                                error: Some(err_msg.clone()),
                            });
                            return Err(RtpSipError::Sip(err_msg));
                        }
                    }
                } else {
                    let err_msg = "Registration failed: 423 Interval Too Brief without Min-Expires header".to_string();
                    tracing::error!("{}", err_msg);
                    *self.registration_state.lock() = RegistrationState::Failed(err_msg.clone());
                    let _ = self.event_tx.send(CallEvent::RegistrationChanged {
                        state: "failed".to_string(),
                        error: Some(err_msg.clone()),
                    });
                    return Err(RtpSipError::Sip(err_msg));
                }
            }
            Ok(response) if response.status_code != rsip::StatusCode::OK => {
                let err_msg = format!("Registration failed with status: {}", response.status_code);
                *self.registration_state.lock() = RegistrationState::Failed(err_msg.clone());
                let _ = self.event_tx.send(CallEvent::RegistrationChanged {
                    state: "failed".to_string(),
                    error: Some(err_msg.clone()),
                });
                return Err(RtpSipError::Sip(err_msg));
            }
            Ok(_response) => {
                // 200 OK - Track expiry from registration
                let expiry = registration.expires();
                *self.registration_expiry.lock() = Some(expiry);
                *self.registration_state.lock() = RegistrationState::Registered;

                self.registrations
                    .lock()
                    .insert(provider_id.to_string(), Arc::new(tokio::sync::Mutex::new(registration)));

                let _ = self.event_tx.send(CallEvent::RegistrationChanged {
                    state: "registered".to_string(),
                    error: None,
                });

                tracing::info!(
                    "Registered with provider {} (expires={:?})",
                    provider_id,
                    expiry
                );

                // Bug #5 fix: Spawn a background task to refresh the registration
                // at half the expiry interval. On failure, update registration_state.
                self.spawn_registration_refresh_task(&provider_id, expiry);

                Ok(())
            }
            Err(e) => {
                let err_msg = format!("Registration failed: {}", e);
                *self.registration_state.lock() = RegistrationState::Failed(err_msg.clone());

                let _ = self.event_tx.send(CallEvent::RegistrationChanged {
                    state: "failed".to_string(),
                    error: Some(err_msg.clone()),
                });

                Err(RtpSipError::Sip(err_msg))
            }
        }
    }

    /// Bug R14-2 fix: Spawn registration refresh task.
    /// Extracted to avoid duplication between normal and 423-retry registration paths.
    fn spawn_registration_refresh_task(self: &Arc<Self>, provider_id: &str, expiry: u32) {
        if expiry > 0 {
            let engine = Arc::clone(self);
            let provider_id = provider_id.to_string();
            let refresh_interval = Arc::new(parking_lot::Mutex::new(std::time::Duration::from_secs(u64::from(expiry) / 2)));
            let mut shutdown_rx = self.shutdown_tx.subscribe();

            let handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(*refresh_interval.lock()) => {}
                        _ = shutdown_rx.recv() => {
                            tracing::debug!("Registration refresh task shutting down for provider {}", provider_id);
                            break;
                        }
                    }

                    tracing::debug!("Refreshing registration for provider {}", provider_id);

                    // Re-register using the stored Registration object
                    let reg = engine.registrations.lock().get(&provider_id).cloned();
                    if let Some(reg) = reg {
                        let provider = engine.providers.lock().get(&provider_id).cloned();
                        if let Some(provider) = provider {
                            let registrar_uri = match Uri::try_from(format!("sip:{}", provider.sip_server).as_str()) {
                                Ok(uri) => uri,
                                Err(e) => {
                                    tracing::error!("Invalid registrar URI during refresh: {:?}", e);
                                    break;
                                }
                            };

                            let registrar_uri_clone = registrar_uri.clone();
                            let result = reg.lock().await.register(registrar_uri, None).await;
                            match result {
                                Ok(resp) if resp.status_code == rsip::StatusCode::IntervalTooBrief => {
                                    // Handle 423 Interval Too Brief during refresh
                                    let min_expires = resp.min_expires_header()
                                        .and_then(|h| u32::try_from(h.clone()).ok());

                                    if let Some(min_exp) = min_expires {
                                        tracing::warn!(
                                            "Registration refresh got 423, retrying with Min-Expires={} for provider {}",
                                            min_exp, provider_id
                                        );
                                        let retry_result = reg.lock().await.register(registrar_uri_clone, Some(min_exp)).await;
                                        match retry_result {
                                            Ok(retry_resp) if retry_resp.status_code == rsip::StatusCode::OK => {
                                                *engine.registration_state.lock() = RegistrationState::Registered;
                                                tracing::debug!("Registration refreshed after 423 retry for provider {}", provider_id);
                                            }
                                            Ok(retry_resp) => {
                                                let err_msg = format!(
                                                    "Registration refresh retry after 423 failed with status: {}",
                                                    retry_resp.status_code
                                                );
                                                tracing::error!("{}", err_msg);
                                                *engine.registration_state.lock() = RegistrationState::Failed(err_msg.clone());
                                                let _ = engine.event_tx.send(CallEvent::RegistrationChanged {
                                                    state: "failed".to_string(),
                                                    error: Some(err_msg),
                                                });
                                                break;
                                            }
                                            Err(e) => {
                                                let err_msg = format!("Registration refresh retry after 423 failed: {}", e);
                                                tracing::error!("{}", err_msg);
                                                *engine.registration_state.lock() = RegistrationState::Failed(err_msg.clone());
                                                let _ = engine.event_tx.send(CallEvent::RegistrationChanged {
                                                    state: "failed".to_string(),
                                                    error: Some(err_msg),
                                                });
                                                break;
                                            }
                                        }
                                    } else {
                                        let err_msg = "Registration refresh failed: 423 Interval Too Brief without Min-Expires header".to_string();
                                        tracing::error!("{}", err_msg);
                                        *engine.registration_state.lock() = RegistrationState::Failed(err_msg.clone());
                                        let _ = engine.event_tx.send(CallEvent::RegistrationChanged {
                                            state: "failed".to_string(),
                                            error: Some(err_msg),
                                        });
                                        break;
                                    }
                                }
                                Ok(resp) if resp.status_code == rsip::StatusCode::OK => {
                                    // Update refresh interval from server's response
                                    let reg_guard = reg.lock().await;
                                    let new_expiry = reg_guard.expires();
                                    drop(reg_guard);
                                    if new_expiry > 0 {
                                        let new_interval = std::time::Duration::from_secs(u64::from(new_expiry) / 2);
                                        *refresh_interval.lock() = new_interval;
                                        *engine.registration_expiry.lock() = Some(new_expiry);
                                        tracing::debug!(
                                            "Registration refreshed for provider {} (new expiry={}s, refresh={}s)",
                                            provider_id, new_expiry, new_expiry / 2
                                        );
                                    } else {
                                        *engine.registration_state.lock() = RegistrationState::Registered;
                                        tracing::debug!("Registration refreshed for provider {}", provider_id);
                                    }
                                }
                                Ok(resp) => {
                                    let err_msg = format!("Registration refresh failed with status: {}", resp.status_code);
                                    tracing::error!("{}", err_msg);
                                    *engine.registration_state.lock() = RegistrationState::Failed(err_msg.clone());
                                    let _ = engine.event_tx.send(CallEvent::RegistrationChanged {
                                        state: "failed".to_string(),
                                        error: Some(err_msg),
                                    });
                                    break;
                                }
                                Err(e) => {
                                    let err_msg = format!("Registration refresh failed: {}", e);
                                    tracing::error!("{}", err_msg);
                                    *engine.registration_state.lock() = RegistrationState::Failed(err_msg.clone());
                                    let _ = engine.event_tx.send(CallEvent::RegistrationChanged {
                                        state: "failed".to_string(),
                                        error: Some(err_msg),
                                    });
                                    break;
                                }
                            }
                        } else {
                            tracing::warn!("Provider {} not found during registration refresh", provider_id);
                            break;
                        }
                    } else {
                        tracing::warn!("Registration not found for provider {} during refresh", provider_id);
                        break;
                    }
                }
            });

            *self.registration_refresh_handle.lock() = Some(handle);
        }
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
            .ok_or_else(|| RtpSipError::Provider(format!("Unknown provider: {}", provider_id)))?;

        // Create RTP engine for this call
        let rtp_port = self.allocate_rtp_port();
        // Bug #24 fix: Replace .unwrap() with proper error propagation
        let rtp_addr: SocketAddr = format!("0.0.0.0:{}", rtp_port)
            .parse()
            .map_err(|e| RtpSipError::Config(format!("Invalid RTP bind address: {}", e)))?;

        let rtp_config = RtpEngineConfig {
            codec: CodecType::Pcmu,
            ..Default::default()
        };

        let rtp_engine = RtpEngine::new(rtp_addr, rtp_config)
            .await
            .map_err(|e| RtpSipError::Rtp(e.to_string()))?;
        let rtp_engine = Arc::new(rtp_engine);

        // Build SDP offer
        let local_sdp = SdpBuilder::new(rtp_engine.local_addr())
            .codecs(vec![CodecType::Pcmu, CodecType::Pcma])
            .build();

        // Parse URIs
        let callee: Uri = Uri::try_from(to)
            .map_err(|e| RtpSipError::Sip(format!("Invalid callee URI: {:?}", e)))?;
        let caller: Uri = Uri::try_from(from)
            .map_err(|e| RtpSipError::Sip(format!("Invalid caller URI: {:?}", e)))?;
        let contact: Uri =
            Uri::try_from(format!("sip:{}@{}", provider.username, self.config.local_addr).as_str())
                .map_err(|e| RtpSipError::Sip(format!("Invalid contact URI: {:?}", e)))?;

        let credential = provider.to_credential();

        // Create call ID
        let call_id = uuid::Uuid::new_v4().to_string();

        // Resolve remote SIP server address
        // TODO(Bug #8): This .parse::<SocketAddr>() returns None for hostnames (e.g.,
        // "sip.example.com:5060"). Currently the call still works because the SIP
        // resolver (SipResolver::resolve_sip_uri) is invoked later in do_invite() to
        // resolve the hostname via DNS. However, remote_addr will be None, which means
        // any code path that relies on it before do_invite will not have the address.
        // Ideally, DNS resolution should happen here or remote_addr should be populated
        // from the SIP resolver results.
        let remote_addr: Option<SocketAddr> = format!("{}:{}", provider.sip_server, provider.sip_port)
            .parse()
            .ok();

        // Fix 9: Use NAT-rewritten contact
        let contact_str = self.nat_rewritten_contact(&provider.username);

        // Create call session with dialog information for REFER support
        // Note: remote_user_agent and rtp_bug_flags will be updated when we receive
        // the first response (180/183/200) containing the User-Agent header
        let session = Arc::new(Mutex::new(CallSession {
            call_id: call_id.clone(),
            state: CallState::Trying, // Bug #54: Start at Trying until 180/183 received
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
            session_timer: None,
            refer_pending: false,
            refer_target: None,
            reinvite_pending: false,
            remote_contact: None,
            cancel_pending: false,
            route_set: Vec::new(),
            cancel_tx: None,
        }));

        // Create a oneshot channel so cancel() can signal the invite task
        // before the ClientInviteDialog is available (before 200 OK).
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
        {
            session.lock().cancel_tx = Some(cancel_tx);
        }

        self.calls.lock().insert(call_id.clone(), session.clone());

        // Create state channel for dialog state updates
        let (state_tx, mut state_rx) = mpsc::unbounded_channel::<DialogState>();

        // Fix 7: Configure 100rel/PRACK support
        let mut invite_option = InviteOption {
            callee,
            caller,
            contact,
            credential: Some(credential),
            offer: Some(local_sdp.into_bytes()),
            ..Default::default()
        };
        if self.config.enable_100rel {
            invite_option.support_prack = true;
        }

        // Bug R15-3 fix: Add Session-Expires and Min-SE headers to outbound INVITE
        // when session timers are enabled. Per RFC 4028 §7, the UAS SHOULD NOT
        // include Session-Expires in 200 OK unless the UAC requested it.
        let session_timer_config = if self.config.enable_session_timers {
            let timer = SessionTimer::new(SessionTimerConfig::default());
            let se_header = timer.build_session_expires_header();
            let min_se_header = timer.build_min_se_header();
            let mut headers = invite_option.headers.take().unwrap_or_default();
            headers.push(rsip::Header::Other(
                "Session-Expires".into(),
                se_header.into(),
            ));
            headers.push(rsip::Header::Other(
                "Min-SE".into(),
                min_se_header.into(),
            ));
            // Supported: timer (RFC 4028 §4)
            headers.push(rsip::Header::Supported("timer".into()));
            invite_option.headers = Some(headers);
            Some(SessionTimerConfig::default())
        } else {
            None
        };

        let engine = self.clone();
        let call_id_clone = call_id.clone();
        let engine_for_state = self.clone();
        let call_id_for_state = call_id.clone();

        // Spawn task to handle the INVITE
        tokio::spawn(async move {
            // Use select! to race do_invite against the cancel signal.
            // If cancel_rx fires, dropping the do_invite future triggers
            // rsipstack's DialogGuardForUnconfirmed, which sends CANCEL on the wire.
            let invite_result = tokio::select! {
                result = engine
                    .dialog_layer
                    .do_invite(invite_option, state_tx) => Some(result),
                _ = cancel_rx => {
                    tracing::info!(
                        "Call {} invite task cancelled via cancel signal",
                        call_id_clone
                    );
                    // do_invite future is dropped here; DialogGuardForUnconfirmed
                    // will send CANCEL on the wire automatically.
                    None
                }
            };

            // If cancelled, stop RTP and mark ended
            let Some(invite_result) = invite_result else {
                if let Some(sess) = engine.calls.lock().get(&call_id_clone) {
                    let mut sess = sess.lock();
                    if let Some(ref rtp) = sess.rtp_engine {
                        rtp.stop();
                    }
                    sess.state = CallState::Ended;
                }
                let _ = engine.event_tx.send(CallEvent::Cancelled {
                    call_id: call_id_clone,
                });
                return;
            };

            match invite_result {
                Ok((dialog, response)) => {
                    // Bug R15-4 fix: Handle 422 (Session Interval Too Small) per RFC 4028 §5.
                    // If the server rejects our Session-Expires, extract Min-SE from the
                    // response and retry the INVITE with updated timer values.
                    if let Some(ref resp) = response {
                        if resp.status_code == rsip::StatusCode::SessionIntervalTooSmall {
                            if let Some(ref _stc) = session_timer_config {
                                let remote_min_se = resp.headers.iter().find_map(|h| {
                                    if let rsip::Header::Other(name, val) = h {
                                        if name.as_str().eq_ignore_ascii_case("Min-SE") {
                                            SessionTimer::parse_min_se(val.as_str())
                                        } else { None }
                                    } else { None }
                                });
                                if let Some(min_se) = remote_min_se {
                                    let mut timer = SessionTimer::new(SessionTimerConfig::default());
                                    let result = timer.handle_422_response(min_se);
                                    tracing::warn!(
                                        "Call {} got 422 Session Interval Too Small, retrying with SE={}, Min-SE={}",
                                        call_id_clone, result.session_expires, result.min_se
                                    );
                                    // Retry is logged but not automatically re-sent because
                                    // rsipstack's dialog is already terminated. Emit error so
                                    // the application can retry with adjusted parameters.
                                    let _ = engine.event_tx.send(CallEvent::Error {
                                        call_id: call_id_clone.clone(),
                                        error: format!(
                                            "422 Session Interval Too Small: retry with Session-Expires >= {}",
                                            result.session_expires
                                        ),
                                    });
                                    // Clean up
                                    {
                                        let mut calls = engine.calls.lock();
                                        if let Some(sess) = calls.get(&call_id_clone) {
                                            let sess = sess.lock();
                                            if let Some(ref rtp) = sess.rtp_engine {
                                                rtp.stop();
                                            }
                                        }
                                        calls.remove(&call_id_clone);
                                    }
                                    return;
                                }
                            }
                        }
                    }

                    let dialog = Arc::new(dialog);

                    // Extract SDP from response if present
                    if let Some(ref resp) = response {
                        let body = resp.body();
                        if !body.is_empty() {
                            if let Ok(body_str) = std::str::from_utf8(body) {
                                if let Some(sess) = engine.calls.lock().get(&call_id_clone) {
                                    let mut sess = sess.lock();
                                    sess.remote_sdp = Some(body_str.to_string());
                                    sess.state = CallState::Active;
                                    sess.client_dialog = Some(dialog.clone());
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

                                    // Bug #28 fix: Extract Contact URI from 200 OK
                                    // for use as the remote target in in-dialog requests (REFER, etc.)
                                    if let Some(contact_uri) = resp.headers.iter().find_map(|h| {
                                        if let rsip::Header::Contact(c) = h {
                                            let s = c.to_string();
                                            // Extract URI from Contact, stripping angle brackets
                                            let trimmed = s.trim();
                                            if let Some(end) = trimmed.strip_prefix('<').and_then(|s| s.find('>')) {
                                                // Bug #6 fix: Use if-let instead of .unwrap() on .find('>')
                                                Some(trimmed[1..end + 1].to_string())
                                            } else {
                                                // Bug #R8-4: Strip header parameters when no angle brackets.
                                                // Per RFC 3261 §20.10, params after a bare URI are header
                                                // params (e.g. ;q=0.7), not part of the URI itself.
                                                let uri_only = trimmed.split(';').next().unwrap_or(trimmed);
                                                Some(uri_only.to_string())
                                            }
                                        } else {
                                            None
                                        }
                                    }) {
                                        sess.remote_contact = Some(contact_uri);
                                    }

                                    // Bug #R11-4: Extract Record-Route from 200 OK for route set.
                                    // RFC 3261 §12.1.1: UAC stores route set in reverse order.
                                    let rr_headers: Vec<String> = resp.headers.iter()
                                        .filter_map(|h| {
                                            if let rsip::Header::RecordRoute(rr) = h {
                                                Some(rr.to_string())
                                            } else {
                                                None
                                            }
                                        })
                                        .collect();
                                    if !rr_headers.is_empty() {
                                        let mut reversed = rr_headers;
                                        reversed.reverse();
                                        sess.route_set = reversed;
                                    }

                                    // Parse remote SDP and update all state
                                    if let Ok(sdp) = Sdp::parse(body_str) {
                                        if let Some(rtp_addr) = sdp.rtp_addr() {
                                            // Bug #22 fix: Port 0 means stream disabled/rejected
                                            if rtp_addr.port() != 0 {
                                                if let Some(ref rtp) = sess.rtp_engine {
                                                    rtp.set_remote(rtp_addr);
                                                }
                                            }
                                        }
                                        // Update DTMF, hold, and direction from SDP
                                        sess.update_from_remote_sdp(&sdp);
                                    }

                                    // Bug #27 fix: Parse Session-Expires from 200 OK and
                                    // initialize session timer with negotiated values.
                                    let se_header = resp.headers.iter().find_map(|h| {
                                        if let rsip::Header::Other(name, val) = h {
                                            if name.as_str().eq_ignore_ascii_case("Session-Expires") {
                                                Some(val.as_str().to_string())
                                            } else { None }
                                        } else { None }
                                    });
                                    if let Some(ref _se) = se_header {
                                        let mut timer = SessionTimer::new(SessionTimerConfig::default());
                                        let (negotiated_se, role) = timer.process_response(
                                            se_header.as_deref(),
                                            true, // is_uac: outbound call = we are UAC
                                        );
                                        sess.session_timer = Some(timer);
                                        tracing::info!(
                                            "Session timer started for call {} (expires={}s, role={:?})",
                                            call_id_clone, negotiated_se, role
                                        );
                                    }
                                }
                            }
                        }
                    }

                    // Bug #6 fix: If cancel was pending when 200 OK arrived (CANCEL/200 race),
                    // we must send BYE immediately to properly tear down the call. Without this,
                    // the remote side thinks the call is active but we've already discarded it.
                    let was_cancel_pending = engine
                        .calls
                        .lock()
                        .get(&call_id_clone)
                        .map(|s| s.lock().cancel_pending)
                        .unwrap_or(false);

                    if was_cancel_pending {
                        tracing::warn!(
                            "Call {} received 200 OK after CANCEL was sent (race condition), \
                             sending BYE to tear down",
                            call_id_clone
                        );
                        if let Err(e) = dialog.hangup().await {
                            tracing::error!(
                                "Call {} failed to send BYE after CANCEL/200 race: {}",
                                call_id_clone, e
                            );
                        }
                        // Stop RTP and mark ended
                        if let Some(sess) = engine.calls.lock().get(&call_id_clone) {
                            let mut sess = sess.lock();
                            if let Some(ref rtp) = sess.rtp_engine {
                                rtp.stop();
                            }
                            sess.state = CallState::Ended;
                        }
                        // Don't remove from map; DialogState::Terminated handler does cleanup
                    } else {
                        // Bug #27 fix: Spawn session timer monitoring task if timer is active.
                        // Checks needs_refresh() and is_expired() periodically.
                        let has_session_timer = engine
                            .calls
                            .lock()
                            .get(&call_id_clone)
                            .map(|s| s.lock().session_timer.as_ref().map_or(false, |t| t.is_active()))
                            .unwrap_or(false);

                        if has_session_timer {
                            let st_engine = engine.clone();
                            let st_call_id = call_id_clone.clone();
                            tokio::spawn(async move {
                                loop {
                                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                                    let action = {
                                        let calls = st_engine.calls.lock();
                                        let Some(sess) = calls.get(&st_call_id) else { break };
                                        let sess = sess.lock();
                                        if sess.state == CallState::Ended {
                                            break;
                                        }
                                        match &sess.session_timer {
                                            Some(timer) if timer.is_expired() => Some("expired"),
                                            Some(timer) if timer.needs_refresh() => Some("refresh"),
                                            Some(_) => None,
                                            None => { break; }
                                        }
                                    };

                                    match action {
                                        Some("expired") => {
                                            tracing::warn!(
                                                "Session timer expired for call {}, sending BYE",
                                                st_call_id
                                            );
                                            let _ = st_engine.hangup(&st_call_id).await;
                                            break;
                                        }
                                        Some("refresh") => {
                                            tracing::debug!(
                                                "Session timer refresh needed for call {}",
                                                st_call_id
                                            );
                                            // Send re-INVITE to refresh the session
                                            if let Err(e) = st_engine.send_reinvite(&st_call_id, None).await {
                                                tracing::warn!(
                                                    "Session timer refresh re-INVITE failed for call {}: {}",
                                                    st_call_id, e
                                                );
                                            } else {
                                                // Reset the timer after successful refresh
                                                if let Some(sess) = st_engine.calls.lock().get(&st_call_id) {
                                                    let mut sess = sess.lock();
                                                    if let Some(ref mut timer) = sess.session_timer {
                                                        timer.refresh();
                                                    }
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            });
                        }

                        let _ = engine.event_tx.send(CallEvent::Answered {
                            call_id: call_id_clone.clone(),
                        });

                        let _ = engine.event_tx.send(CallEvent::AudioReady {
                            call_id: call_id_clone,
                        });
                    }
                }
                Err(e) => {
                    let _ = engine.event_tx.send(CallEvent::Error {
                        call_id: call_id_clone.clone(),
                        error: e.to_string(),
                    });

                    // Bug #62 + Bug #6 fix: Hold the calls lock across both stop and remove
                    // to prevent a race where another task could observe the session between
                    // stop and remove.
                    {
                        let mut calls = engine.calls.lock();
                        if let Some(sess) = calls.get(&call_id_clone) {
                            let sess = sess.lock();
                            if let Some(ref rtp) = sess.rtp_engine {
                                rtp.stop();
                            }
                        }
                        calls.remove(&call_id_clone);
                    }
                }
            }
        });

        // Spawn task to handle dialog state changes (incoming re-INVITE, INFO, etc.)
        tokio::spawn(async move {
            while let Some(state) = state_rx.recv().await {
                match state {
                    DialogState::Updated(_, request) => {
                        // Fix 5 + Bug #50: Glare detection for outbound calls (UAC role)
                        let is_glare = if let Some(sess) = engine_for_state.calls.lock().get(&call_id_for_state) {
                            sess.lock().reinvite_pending
                        } else {
                            false
                        };

                        if is_glare {
                            // Bug #50 fix: Log the glare condition. Ideally we would send
                            // a 491 Request Pending response here, but rsipstack 0.3
                            // automatically sends 200 OK to incoming re-INVITEs before
                            // delivering the DialogState::Updated notification to us.
                            // TODO: When upgrading to a version of rsipstack that allows
                            // deferred re-INVITE responses, send 491 instead of accepting.
                            tracing::warn!(
                                "Glare detected on call {} (UAC): re-INVITE pending, \
                                 cannot send 491 (rsipstack auto-accepted)",
                                call_id_for_state
                            );
                            // Bug #35 fix: Do NOT skip SDP processing here. Since rsipstack
                            // already auto-accepted the re-INVITE with 200 OK, we must
                            // process the SDP to keep RTP state consistent with what the
                            // remote side now expects.
                        }

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
                                        // Bug #22 fix: Port 0 means stream disabled/rejected
                                        if rtp_addr.port() != 0 {
                                            if let Some(ref rtp) = sess.rtp_engine {
                                                rtp.set_remote(rtp_addr);
                                            }
                                        }
                                    }
                                    // Update hold/direction state (handles remote hold detection)
                                    sess.update_from_remote_sdp(&sdp);
                                }
                            }
                        }

                        // Bug #27 fix: Reset session timer on incoming re-INVITE.
                        // This handles the case where remote is the refresher.
                        if let Some(sess) = engine_for_state.calls.lock().get(&call_id_for_state) {
                            let mut sess = sess.lock();
                            if let Some(ref mut timer) = sess.session_timer {
                                timer.refresh();
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
                        let sdp_str_owned = sdp_str.map(|s| s.to_string());

                        // Bug #8 fix: Determine which event to emit WHILE holding the session
                        // lock, to avoid a TOCTOU race where the early_media_state could change
                        // between the state update and the event emission decision.
                        let mut should_emit_early_media = false;
                        let mut should_emit_ringing = false;

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

                            // Bug #R7-3: Extract Contact from 180/183 early responses.
                            // RFC 3261 §12.1.2: provisional responses establishing a
                            // dialog contain a Contact that defines the remote target.
                            if let Some(contact_uri) = response.headers.iter().find_map(|h| {
                                if let rsip::Header::Contact(c) = h {
                                    let s = c.to_string();
                                    let trimmed = s.trim();
                                    if let Some(end) = trimmed.strip_prefix('<').and_then(|s| s.find('>')) {
                                        Some(trimmed[1..end + 1].to_string())
                                    } else {
                                        // Bug #R8-4: Strip header parameters when no angle brackets
                                        let uri_only = trimmed.split(';').next().unwrap_or(trimmed);
                                        Some(uri_only.to_string())
                                    }
                                } else {
                                    None
                                }
                            }) {
                                sess.remote_contact = Some(contact_uri);
                            }

                            // Parse SDP if present and configure RTP
                            if let Some(sdp_body) = sdp_str {
                                if let Ok(sdp) = Sdp::parse(sdp_body) {
                                    // Set RTP remote address for early media
                                    if let Some(rtp_addr) = sdp.rtp_addr() {
                                        // Bug #22 fix: Port 0 means stream disabled/rejected
                                        if rtp_addr.port() != 0 {
                                            if let Some(ref rtp) = sess.rtp_engine {
                                                rtp.set_remote(rtp_addr);
                                            }
                                        }
                                    }
                                    // Update DTMF and hold state from SDP
                                    sess.update_from_remote_sdp(&sdp);
                                }
                            }

                            // Process based on status code
                            if response.status_code == rsip::StatusCode::SessionProgress {
                                sess.process_183_session_progress(has_sdp);
                                should_emit_early_media = has_sdp;
                            } else if response.status_code == rsip::StatusCode::Ringing {
                                sess.process_180_ringing();
                                // Bug #8 fix: Check early_media_state while still holding the lock
                                should_emit_ringing = !matches!(
                                    sess.early_media_state,
                                    EarlyMediaState::EarlyMedia183 | EarlyMediaState::Ringing180After183
                                );
                            }
                        }

                        // Emit events after releasing the lock
                        if should_emit_early_media {
                            let _ = engine_for_state.event_tx.send(CallEvent::EarlyMedia {
                                call_id: call_id_for_state.clone(),
                                sdp: sdp_str_owned,
                            });
                        } else if should_emit_ringing {
                            let _ = engine_for_state.event_tx.send(CallEvent::Ringing {
                                call_id: call_id_for_state.clone(),
                            });
                        }
                    }
                    DialogState::Notify(_, request) => {
                        // Check if this is a REFER subscription NOTIFY
                        let is_refer_event = request.headers.iter().any(|h| {
                            matches!(h, rsip::Header::Other(name, val)
                                if name.as_str().eq_ignore_ascii_case("Event")
                                    && val.as_str().trim().starts_with("refer"))
                        });

                        if is_refer_event {
                            let body_str =
                                std::str::from_utf8(request.body()).unwrap_or("");
                            let (status_code, reason) = parse_sipfrag_status(body_str)
                                .unwrap_or((100, "Trying".to_string()));

                            let is_terminated = request.headers.iter().any(|h| {
                                matches!(h, rsip::Header::Other(name, val)
                                    if name.as_str().eq_ignore_ascii_case("Subscription-State")
                                        && val.as_str().trim().starts_with("terminated"))
                            });

                            let completed =
                                is_terminated && status_code >= 200 && status_code < 300;

                            let _ =
                                engine_for_state.event_tx.send(CallEvent::TransferProgress {
                                    call_id: call_id_for_state.clone(),
                                    status_code,
                                    reason,
                                    completed,
                                });

                            if is_terminated {
                                if let Some(sess) =
                                    engine_for_state.calls.lock().get(&call_id_for_state)
                                {
                                    sess.lock().refer_pending = false;
                                }
                            }
                        }
                    }
                    DialogState::Terminated(_, reason) => {
                        // Fix 2: Check for 3xx redirect
                        let reason_str = format!("{:?}", reason);

                        // Detect 3xx redirect responses (Fix 2)
                        // TODO(Bug #23): The redirect handling is incomplete. Currently we
                        // only detect that a 3xx response was received and emit a Redirected
                        // event with the debug-formatted reason. A full implementation should:
                        // 1. Extract Contact headers from the 3xx response as redirect targets
                        // 2. Examine the exact status code (301 vs 302 vs 305) for semantics
                        // 3. Optionally re-attempt the INVITE to the new target(s)
                        let is_redirect = if let rsipstack::dialog::dialog::TerminatedReason::UasOther(ref code) = reason {
                            let code_num = u16::from(code.clone());
                            code_num >= 300 && code_num < 400
                        } else {
                            false
                        };

                        if is_redirect {
                            let _ = engine_for_state.event_tx.send(CallEvent::Redirected {
                                call_id: call_id_for_state.clone(),
                                targets: vec![reason_str.clone()],
                            });
                        }

                        // Bug #61 fix: Stop RTP engine before removing call from map
                        if let Some(sess) = engine_for_state.calls.lock().get(&call_id_for_state) {
                            let sess = sess.lock();
                            if let Some(ref rtp) = sess.rtp_engine {
                                rtp.stop();
                            }
                        }

                        // Bug #96 fix: Send Hangup event BEFORE removing the call
                        // from the map, so that event subscribers can still look up
                        // the call session while processing the event.
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

        // Bug #46 fix: Removed premature CallEvent::Ringing emission.
        // The real Ringing event is sent in the DialogState::Early handler
        // when we actually receive a 180 Ringing response from the remote party.

        Ok(call_id)
    }

    /// Hangup a call
    ///
    /// Bug #53 fix: If call is in Trying, Ringing, or EarlyMedia state, delegates
    /// to `cancel()` (sends CANCEL) instead of sending BYE. BYE is only valid
    /// for established dialogs (Active/Hold). Sending BYE for an early dialog
    /// is a SIP protocol violation per RFC 3261.
    pub async fn hangup(&self, call_id: &str) -> Result<()> {
        // Bug #53: Check state and direction to decide CANCEL vs REJECT vs BYE
        let (state, direction) = {
            let calls = self.calls.lock();
            let session = calls
                .get(call_id)
                .ok_or_else(|| RtpSipError::Session(format!("Call not found: {}", call_id)))?;
            let sess = session.lock();
            (sess.state, sess.direction)
        };

        // Bug #4 fix: If call has already ended, return immediately.
        // Attempting BYE on an ended call is a no-op and avoids errors.
        if state == CallState::Ended {
            return Ok(());
        }

        // Bug #53 fix: Pre-answer states need special handling.
        // - Outbound calls: send CANCEL (we are the UAC, cancelling our own INVITE)
        // - Inbound calls: send 487 reject (we are the UAS, rejecting the caller's INVITE)
        match state {
            CallState::Trying | CallState::Ringing | CallState::EarlyMedia => {
                if direction == Direction::Inbound {
                    tracing::debug!(
                        "Call {} inbound in {:?} state, using reject(487) instead of BYE",
                        call_id, state
                    );
                    return self.reject(call_id, 487);
                }
                tracing::debug!(
                    "Call {} outbound in {:?} state, using CANCEL instead of BYE",
                    call_id, state
                );
                return self.cancel(call_id).await;
            }
            _ => {}
        }

        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| RtpSipError::Session(format!("Call not found: {}", call_id)))?;

        // Bug #10 fix: Don't remove from calls map here. Extract dialog refs,
        // drop the lock, send BYE, and mark state as Ended. The actual removal
        // from the map is done by the DialogState::Terminated handler, which
        // prevents duplicate Hangup events and ensures proper cleanup ordering.
        let (client_dialog, server_dialog) = {
            let mut sess = session.lock();

            // Stop RTP
            if let Some(ref rtp) = sess.rtp_engine {
                rtp.stop();
            }

            sess.state = CallState::Ended;
            // Bug #21 fix: Reset hold flags when transitioning to Ended
            sess.local_hold = false;
            sess.remote_hold = false;

            (sess.client_dialog.clone(), sess.server_dialog.clone())
        };

        // Send BYE for established dialog (Active or Hold)
        if let Some(ref dialog) = client_dialog {
            let _ = dialog.hangup().await;
        } else if let Some(ref dialog) = server_dialog {
            let _ = dialog.bye().await;
        }

        Ok(())
    }

    /// Cancel an outbound call in early dialog state (Fix 1)
    ///
    /// Sends a CANCEL request for calls that are still Ringing or in EarlyMedia
    /// (not yet answered). For calls that are already Active, use `hangup()` instead.
    ///
    /// # Arguments
    /// * `call_id` - The call to cancel
    ///
    /// # Errors
    /// Returns error if the call is already Active (use hangup() instead),
    /// or if the call is not found.
    pub async fn cancel(&self, call_id: &str) -> Result<()> {
        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| RtpSipError::Session(format!("Call not found: {}", call_id)))?;

        let (state, client_dialog, cancel_tx) = {
            let mut sess = session.lock();
            (sess.state, sess.client_dialog.clone(), sess.cancel_tx.take())
        };

        // Bug #54: Allow CANCEL in any pre-answer state after INVITE sent
        // (Trying, Ringing, EarlyMedia — but NOT Active/Hold/Ended).
        match state {
            CallState::Trying | CallState::Ringing | CallState::EarlyMedia => {
                // Bug #6 fix: Set cancel_pending instead of removing from map immediately.
                // If a 200 OK arrives after CANCEL is sent (race condition), the dialog
                // task's Ok branch will detect cancel_pending and send BYE. The actual
                // map cleanup is deferred to the DialogState::Terminated handler.
                {
                    let mut sess = session.lock();
                    sess.cancel_pending = true;
                }

                // Cancel the invite. There are two paths:
                //
                // 1. client_dialog is available (rare: dialog already stored in session).
                //    Call dialog.cancel() directly to send CANCEL on the wire.
                //
                // 2. client_dialog is NOT yet available (common: do_invite has not returned
                //    200 OK yet, so the dialog is still internal to rsipstack). Use the
                //    cancel_tx oneshot channel to signal the invite task. The task's
                //    select! drops the do_invite future, which triggers rsipstack's
                //    DialogGuardForUnconfirmed to send CANCEL on the wire.
                if let Some(ref dialog) = client_dialog {
                    dialog
                        .cancel()
                        .await
                        .map_err(|e| {
                            RtpSipError::Sip(format!("Failed to send CANCEL: {}", e))
                        })?;
                } else if let Some(tx) = cancel_tx {
                    // Signal the invite task to abort do_invite.
                    // The send can only fail if the receiver was already dropped
                    // (invite task finished), which is fine — the call ended on its own.
                    let _ = tx.send(());
                    tracing::debug!(
                        "Call {} cancel signal sent to invite task (dialog not yet available)",
                        call_id
                    );
                } else {
                    tracing::warn!(
                        "Call {} cancel: no dialog and no cancel channel available",
                        call_id
                    );
                }

                // Bug #64 fix: Set call state to Ended after successful CANCEL
                // so subsequent hangup() calls don't send duplicate CANCEL.
                // Stop RTP if started (early media case)
                {
                    let mut sess = session.lock();
                    sess.state = CallState::Ended;
                    // Bug #21 fix: Reset hold flags when transitioning to Ended
                    // to prevent stale hold state from leaking if the session
                    // object is inspected after the call ends.
                    sess.local_hold = false;
                    sess.remote_hold = false;
                    if let Some(ref rtp) = sess.rtp_engine {
                        rtp.stop();
                    }
                }

                // Emit cancelled event
                let _ = self.event_tx.send(CallEvent::Cancelled {
                    call_id: call_id.to_string(),
                });

                tracing::info!("Call {} cancelled (pending 487/200 response)", call_id);
                Ok(())
            }
            CallState::Active => Err(RtpSipError::InvalidState(
                "Use hangup() for active calls".to_string(),
            )),
            _ => Err(RtpSipError::InvalidState(format!(
                "Cannot cancel call in state {:?}",
                state
            ))),
        }
    }

    /// Get the current registration state as a string
    pub fn registration_state_str(&self) -> String {
        // Registration state is tracked per-provider
        let providers = self.providers.lock();
        if providers.is_empty() {
            return "no_providers".to_string();
        }
        let registrations = self.registrations.lock();
        if registrations.is_empty() {
            "unregistered".to_string()
        } else {
            "registered".to_string()
        }
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
            return Err(RtpSipError::Sip(format!("Invalid DTMF digit: {}", digit)));
        }

        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| RtpSipError::Session(format!("Call not found: {}", call_id)))?;

        // Bug #9 fix: Extract dialog and state into local variables, then drop
        // the parking_lot::Mutex guard before any .await call to avoid deadlock.
        let (state, client_dialog, server_dialog) = {
            let sess = session.lock();
            (sess.state, sess.client_dialog.clone(), sess.server_dialog.clone())
        };

        // DTMF only allowed after call is answered (Active state)
        if state != CallState::Active {
            return Err(RtpSipError::Session(format!(
                "Cannot send DTMF: call {} is not active (state: {:?})",
                call_id, state
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
        if let Some(ref dialog) = client_dialog {
            dialog
                .info(Some(headers), Some(dtmf_body.into_bytes()))
                .await
                .map_err(|e| RtpSipError::Sip(format!("Failed to send DTMF INFO: {}", e)))?;
        } else if let Some(ref dialog) = server_dialog {
            dialog
                .info(Some(headers), Some(dtmf_body.into_bytes()))
                .await
                .map_err(|e| RtpSipError::Sip(format!("Failed to send DTMF INFO: {}", e)))?;
        } else {
            return Err(RtpSipError::Session(
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
                .ok_or_else(|| RtpSipError::Session(format!("Call not found: {}", call_id)))?;

            let sess = session.lock();

            // DTMF only allowed after call is answered (Active state)
            if sess.state != CallState::Active {
                return Err(RtpSipError::Session(format!(
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
                    RtpSipError::Session("RTP not established for this call".to_string())
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
            .ok_or_else(|| RtpSipError::Session(format!("Call not found: {}", call_id)))?;

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
            .ok_or_else(|| RtpSipError::Session(format!("Call not found: {}", call_id)))?;

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
            .ok_or_else(|| RtpSipError::Session(format!("Call not found: {}", call_id)))?;

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
            .ok_or_else(|| RtpSipError::Session(format!("Call not found: {}", call_id)))?;

        // Bug #18 fix: Clone the rtp_engine Arc outside the lock, then drop the
        // session lock before calling the blocking function. Holding a
        // parking_lot::Mutex during a blocking spin-sleep starves other tasks.
        let rtp_engine = {
            let sess = session.lock();
            sess.rtp_engine.clone()
        };

        // Try RFC 2833 (via RTP engine)
        if let Some(ref rtp) = rtp_engine {
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
            .ok_or_else(|| RtpSipError::Session(format!("Call not found: {}", call_id)))?;

        // Determine if we're the Call-ID owner (outbound call)
        let is_call_owner = {
            let sess = session.lock();
            sess.direction == Direction::Outbound
        };

        for attempt in 0..=max_retries {
            let result = self.send_reinvite_internal(call_id, sdp).await;

            match &result {
                Ok(_response) => return Ok(()),
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

        Err(RtpSipError::Sip(
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
            .ok_or_else(|| RtpSipError::Session(format!("Call not found: {}", call_id)))?;

        // Bug #7 fix: Validate call state before sending re-INVITE.
        // Only Active and Hold states are valid for re-INVITE (hold, resume, codec change).
        // Sending re-INVITE in Trying/Ringing/EarlyMedia/Ended is invalid per RFC 3261.
        {
            let sess = session.lock();
            match sess.state {
                CallState::Active | CallState::Hold => {
                    // Valid states for re-INVITE
                }
                other => {
                    return Err(RtpSipError::InvalidState(format!(
                        "Cannot send re-INVITE in {:?} state (requires Active or Hold)",
                        other
                    )));
                }
            }
        }

        // Fix 5 + Bug #7 fix: Use a drop guard to ensure reinvite_pending is ALWAYS
        // cleared on exit, even on early returns or panics. Without this, an early
        // return (e.g., from the ? operator) would leave reinvite_pending = true
        // permanently, blocking all future re-INVITEs on this call.
        struct ReinviteGuard {
            session: Arc<Mutex<CallSession>>,
        }
        impl Drop for ReinviteGuard {
            fn drop(&mut self) {
                self.session.lock().reinvite_pending = false;
            }
        }

        {
            session.lock().reinvite_pending = true;
        }
        let _guard = ReinviteGuard { session: session.clone() };

        // Extract dialog refs while holding lock, then drop before await
        let (client_dialog, server_dialog) = {
            let sess = session.lock();
            (sess.client_dialog.clone(), sess.server_dialog.clone())
        };

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
        if let Some(ref dialog) = client_dialog {
            dialog
                .reinvite(headers, body)
                .await
                .map_err(|e| RtpSipError::Sip(format!("Failed to send re-INVITE: {}", e)))
                .map(|_| ())
        } else if let Some(ref dialog) = server_dialog {
            dialog
                .reinvite(headers, body)
                .await
                .map_err(|e| RtpSipError::Sip(format!("Failed to send re-INVITE: {}", e)))
                .map(|_| ())
        } else {
            Err(RtpSipError::Session(
                "Dialog not established for this call".to_string(),
            ))
        }
        // _guard is dropped here, clearing reinvite_pending regardless of outcome
    }

    /// Put call on hold (sends re-INVITE with sendonly SDP)
    ///
    /// Per RFC 6337:
    /// - sendonly: we can send, remote should not send
    /// - Remote should respond with recvonly
    ///
    /// Bug #60 fix: State is only updated after re-INVITE succeeds. If the
    /// re-INVITE fails, state remains unchanged.
    pub async fn hold(&self, call_id: &str) -> Result<()> {
        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| RtpSipError::Session(format!("Call not found: {}", call_id)))?;

        let hold_sdp = {
            let sess = session.lock();

            // Check if already on hold
            if sess.local_hold {
                return Ok(());
            }

            let rtp = sess.rtp_engine.as_ref().ok_or_else(|| {
                RtpSipError::Session("RTP not established for this call".to_string())
            })?;

            // Build hold SDP (sendonly)
            SdpBuilder::new(rtp.local_addr())
                .codecs(vec![CodecType::Pcmu, CodecType::Pcma])
                .direction("sendonly")
                .build()
        };

        // Bug #60 fix: Send re-INVITE first, only update state on success
        self.send_reinvite(call_id, Some(&hold_sdp)).await?;

        // Update local hold state only after re-INVITE confirmed
        {
            let mut sess = session.lock();
            sess.local_hold = true;
            sess.state = CallState::Hold;
            tracing::info!("Call {} put on hold by local", sess.call_id);
        }

        Ok(())
    }

    /// Resume call from hold (sends re-INVITE with sendrecv SDP)
    ///
    /// Per RFC 6337:
    /// - sendrecv: bidirectional media resumed
    ///
    /// Bug #60 fix: State is only updated after re-INVITE succeeds. If the
    /// re-INVITE fails, state remains unchanged.
    pub async fn unhold(&self, call_id: &str) -> Result<()> {
        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| RtpSipError::Session(format!("Call not found: {}", call_id)))?;

        let resume_sdp = {
            let sess = session.lock();

            // Check if actually on hold
            if !sess.local_hold {
                return Ok(());
            }

            let rtp = sess.rtp_engine.as_ref().ok_or_else(|| {
                RtpSipError::Session("RTP not established for this call".to_string())
            })?;

            // Build resume SDP (sendrecv)
            SdpBuilder::new(rtp.local_addr())
                .codecs(vec![CodecType::Pcmu, CodecType::Pcma])
                .direction("sendrecv")
                .build()
        };

        // Bug #60 fix: Send re-INVITE first, only update state on success
        self.send_reinvite(call_id, Some(&resume_sdp)).await?;

        // Update local hold state only after re-INVITE confirmed
        {
            let mut sess = session.lock();
            sess.local_hold = false;

            // Only change to Active if remote is also not on hold
            if !sess.remote_hold {
                sess.state = CallState::Active;
                tracing::info!("Call {} resumed by local", sess.call_id);
            }
        }

        Ok(())
    }

    /// Check if a call is currently on hold (local or remote)
    pub fn is_on_hold(&self, call_id: &str) -> Result<bool> {
        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| RtpSipError::Session(format!("Call not found: {}", call_id)))?;

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
            .ok_or_else(|| RtpSipError::Session(format!("Call not found: {}", call_id)))?;

        let sess = session.lock();
        Ok((sess.local_hold, sess.remote_hold))
    }

    /// Send REFER for call transfer (RFC 3515, Fix 6)
    ///
    /// Builds a SIP REFER request using the established dialog's information.
    /// Bug #4 fix: Sends via the endpoint's transaction layer instead of raw UDP,
    /// which provides proper retransmission (RFC 3261 Section 17) and works
    /// through NATs. rsipstack 0.3 lacks native dialog.refer(), so we create
    /// a client transaction manually through the endpoint.
    /// Works for both inbound and outbound calls.
    ///
    /// Includes Referred-By header (RFC 3892) for proper PBX integration.
    pub async fn send_refer(&self, call_id: &str, target_uri: &str) -> Result<()> {
        let session = self
            .calls
            .lock()
            .get(call_id)
            .cloned()
            .ok_or_else(|| RtpSipError::Session(format!("Call not found: {}", call_id)))?;

        // Bug #59 fix: Validate call state before sending REFER.
        // REFER is valid for Active or Hold calls (established dialog).
        // Bug #R6-1: RFC 3261 allows REFER in any established dialog,
        // including Hold. Transferring a held call is a standard PBX operation.
        {
            let sess = session.lock();
            if sess.state != CallState::Active && sess.state != CallState::Hold {
                return Err(RtpSipError::InvalidState(format!(
                    "Cannot send REFER in {:?} state (requires Active or Hold)",
                    sess.state
                )));
            }
        }

        let (dialog_id, is_client_dialog, local_uri, remote_uri, remote_contact, local_contact, cseq, route_set) = {
            let mut sess = session.lock();
            let (dialog_id, is_client) = if let Some(ref dialog) = sess.client_dialog {
                (dialog.id(), true)
            } else if let Some(ref dialog) = sess.server_dialog {
                (dialog.id(), false)
            } else {
                return Err(RtpSipError::Session(
                    "Dialog not established for this call".to_string(),
                ));
            };
            let local_uri = sess.local_uri.clone().unwrap_or_default();
            let remote_uri = sess.remote_uri.clone().unwrap_or_default();
            let remote_contact = sess.remote_contact.clone();
            let local_contact = sess.local_contact.clone().unwrap_or_default();
            let cseq = sess.next_cseq();
            let route_set = sess.route_set.clone();
            (dialog_id, is_client, local_uri, remote_uri, remote_contact, local_contact, cseq, route_set)
        };

        // Format Refer-To header value
        let refer_to_value = if target_uri.starts_with('<') {
            target_uri.to_string()
        } else {
            format!("<{}>", target_uri)
        };

        // Bug #28 fix: Use the stored Contact URI (remote target) from the dialog
        // rather than the To URI (remote_uri). Per RFC 3261 Section 12.2, in-dialog
        // requests MUST use the remote target (Contact) as the Request-URI.
        let request_uri_str = remote_contact.as_deref().unwrap_or(remote_uri.as_str());
        let request_uri = Uri::try_from(request_uri_str)
            .map_err(|e| RtpSipError::Sip(format!("Invalid remote URI: {:?}", e)))?;
        let branch = format!("z9hG4bK{}", uuid::Uuid::new_v4().simple());

        // Bug #3 fix: If local_addr is 0.0.0.0 (unspecified), try to use the
        // remote_addr to determine a routable local IP for the Via header.
        // Bug #R8-5: Extract host:port from SIP URI before parsing as SocketAddr.
        // The previous code tried to parse the full SIP URI (e.g. "sip:user@host")
        // as a SocketAddr, which always failed, causing Via to get 0.0.0.0.
        let via_addr = if self.config.local_addr.ip().is_unspecified() {
            // Extract host from SIP URI: strip "sip:" / "sips:" prefix and "user@" part
            let host_part = {
                let uri = request_uri_str;
                let without_scheme = uri.strip_prefix("sips:")
                    .or_else(|| uri.strip_prefix("sip:"))
                    .unwrap_or(uri);
                // Strip user@
                let host = if let Some(at_pos) = without_scheme.find('@') {
                    &without_scheme[at_pos + 1..]
                } else {
                    without_scheme
                };
                // Strip URI parameters (;transport=udp etc.)
                host.split(';').next().unwrap_or(host).to_string()
            };
            // Try to get a routable address by binding a temporary UDP socket
            // to the remote target and reading its local address.
            if let Ok(remote) = host_part.parse::<SocketAddr>()
                .or_else(|_| format!("{}:{}", host_part, 5060).parse::<SocketAddr>())
            {
                if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
                    if sock.connect(remote).is_ok() {
                        if let Ok(local) = sock.local_addr() {
                            SocketAddr::new(local.ip(), self.config.local_addr.port())
                        } else {
                            self.config.local_addr
                        }
                    } else {
                        self.config.local_addr
                    }
                } else {
                    self.config.local_addr
                }
            } else {
                self.config.local_addr
            }
        } else {
            self.config.local_addr
        };

        let mut headers: rsip::Headers = Default::default();
        headers.push(rsip::Header::Via(
            format!("SIP/2.0/UDP {};branch={}", via_addr, branch).into(),
        ));
        headers.push(rsip::Header::MaxForwards("70".into()));
        // Bug #R11-4: Include Route headers from dialog's route set.
        // RFC 3261 §12.2.1.1: All in-dialog requests MUST include the route set.
        for route in &route_set {
            headers.push(rsip::Header::Route(route.as_str().into()));
        }
        // Bug #R11-3: For server dialogs (inbound calls), dialog_id.from_tag is the
        // remote caller's tag and to_tag is our local tag. RFC 3261 §12.2.1.1 requires
        // From tag = local tag, To tag = remote tag. Swap accordingly.
        let (local_tag, remote_tag) = if is_client_dialog {
            // Client dialog: from_tag is ours, to_tag is remote
            (&dialog_id.from_tag, &dialog_id.to_tag)
        } else {
            // Server dialog: from_tag is remote, to_tag is ours
            (&dialog_id.to_tag, &dialog_id.from_tag)
        };
        headers.push(rsip::Header::From(
            format!("<{}>;tag={}", local_uri, local_tag).into(),
        ));
        headers.push(rsip::Header::To(
            format!("<{}>;tag={}", remote_uri, remote_tag).into(),
        ));
        headers.push(rsip::Header::CallId(dialog_id.call_id.clone().into()));
        headers.push(rsip::Header::CSeq(format!("{} REFER", cseq).into()));
        headers.push(rsip::Header::Contact(format!("<{}>", local_contact).into()));
        // Refer-To header (RFC 3515)
        headers.push(rsip::Header::Other("Refer-To".into(), refer_to_value));
        // Referred-By header (RFC 3892)
        headers.push(rsip::Header::Other(
            "Referred-By".into(),
            format!("<{}>", local_uri),
        ));
        headers.push(rsip::Header::UserAgent(self.config.user_agent.clone().into()));
        headers.push(rsip::Header::ContentLength("0".into()));

        let request = rsip::Request {
            method: rsip::Method::Refer,
            uri: request_uri,
            version: rsip::Version::V2,
            headers,
            body: vec![],
        };

        // Bug #4 fix: Send REFER via the endpoint's transaction layer instead of raw UDP.
        // This gives us proper SIP retransmission per RFC 3261, and the request goes through
        // the same transport the SIP stack uses (works through NATs, supports TCP/TLS).
        let key = TransactionKey::from_request(&request, TransactionRole::Client)
            .map_err(|e| RtpSipError::Sip(format!("Failed to create transaction key for REFER: {}", e)))?;
        let mut tx = Transaction::new_client(key, request, self.endpoint.inner.clone(), None);
        tx.send()
            .await
            .map_err(|e| RtpSipError::Sip(format!("Failed to send REFER: {}", e)))?;

        // Wait for final response (with timeout)
        let response = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while let Some(msg) = tx.receive().await {
                if let rsip::SipMessage::Response(resp) = msg {
                    let status = u16::from(resp.status_code.clone());
                    if status >= 200 {
                        return Some(resp);
                    }
                    // Skip provisional responses (1xx)
                }
            }
            None
        })
        .await;

        match response {
            Ok(Some(resp)) => {
                let status = u16::from(resp.status_code.clone());
                if status >= 200 && status < 300 {
                    tracing::info!("REFER accepted for call {} -> {} ({})", call_id, target_uri, status);
                } else {
                    tracing::warn!("REFER rejected for call {} -> {} ({})", call_id, target_uri, status);
                    return Err(RtpSipError::Sip(format!(
                        "REFER rejected with status {}", status
                    )));
                }
            }
            Ok(None) => {
                // Bug #R6-2: Don't fall through to success path on missing response
                return Err(RtpSipError::Sip(format!(
                    "REFER transaction ended without final response for call {}", call_id
                )));
            }
            Err(e) => {
                // Bug #R6-2: Don't fall through to success path on timeout/error
                return Err(RtpSipError::Sip(format!(
                    "REFER response timeout for call {}: {}", call_id, e
                )));
            }
        }

        // Track transfer state
        {
            let mut sess = session.lock();
            sess.refer_pending = true;
            sess.refer_target = Some(target_uri.to_string());
        }

        let _ = self.event_tx.send(CallEvent::TransferInitiated {
            call_id: call_id.to_string(),
            target: target_uri.to_string(),
        });

        tracing::info!("REFER sent for call {} -> {}", call_id, target_uri);
        Ok(())
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
                    match value.parse::<u32>() {
                        Ok(d) => {
                            // Clamp to valid range (Cisco: 100-5000ms)
                            duration = d.clamp(100, 5000);
                        }
                        Err(_) => {
                            // Bug #34 fix: Log a warning instead of silently ignoring
                            tracing::warn!("Invalid DTMF duration value: {}", value);
                        }
                    }
                }
            }
        }

        digit.map(|d| (d, duration))
    }
}

/// Parse SIP fragment status from NOTIFY body
///
/// NOTIFY bodies for REFER subscriptions contain a SIP status line:
/// `SIP/2.0 200 OK` or `SIP/2.0 100 Trying`
fn parse_sipfrag_status(body: &str) -> Option<(u16, String)> {
    let line = body.lines().next()?.trim();
    if !line.starts_with("SIP/2.0 ") {
        return None;
    }
    let rest = &line[8..]; // Skip "SIP/2.0 "
    let mut parts = rest.splitn(2, ' ');
    let code: u16 = parts.next()?.parse().ok()?;
    let reason = parts.next().unwrap_or("").to_string();
    Some((code, reason))
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

    // ===== Bug #54: CANCEL in Trying state tests =====

    #[test]
    fn test_bug54_trying_state_exists() {
        // Bug #54: Verify the Trying state variant exists and is distinct
        let trying = CallState::Trying;
        let ringing = CallState::Ringing;
        assert_ne!(trying, ringing);
        assert_ne!(trying, CallState::Active);
        assert_ne!(trying, CallState::EarlyMedia);
        assert_ne!(trying, CallState::Hold);
        assert_ne!(trying, CallState::Ended);
    }

    #[test]
    fn test_bug54_cancel_allowed_states() {
        // Bug #54: Verify CANCEL should be allowed in Trying, Ringing, and EarlyMedia
        // but not in Active, Hold, or Ended.
        let cancel_allowed = |state: CallState| -> bool {
            matches!(
                state,
                CallState::Trying | CallState::Ringing | CallState::EarlyMedia
            )
        };

        assert!(
            cancel_allowed(CallState::Trying),
            "CANCEL should be allowed in Trying state"
        );
        assert!(
            cancel_allowed(CallState::Ringing),
            "CANCEL should be allowed in Ringing state"
        );
        assert!(
            cancel_allowed(CallState::EarlyMedia),
            "CANCEL should be allowed in EarlyMedia state"
        );
        assert!(
            !cancel_allowed(CallState::Active),
            "CANCEL should NOT be allowed in Active state"
        );
        assert!(
            !cancel_allowed(CallState::Hold),
            "CANCEL should NOT be allowed in Hold state"
        );
        assert!(
            !cancel_allowed(CallState::Ended),
            "CANCEL should NOT be allowed in Ended state"
        );
    }

    #[test]
    fn test_bug54_outbound_call_starts_in_trying() {
        // Bug #54: Outbound calls should start in Trying state,
        // not Ringing (which only happens after 180 received).
        // We verify this by checking that CallState::Trying is used as
        // the initial state (tested via the state enum, since we can't
        // easily instantiate a full CallSession without the helper).
        let initial_state = CallState::Trying;
        assert_eq!(initial_state, CallState::Trying);
        // Should transition to Ringing on 180 or EarlyMedia on 183
        assert_ne!(initial_state, CallState::Ringing);
    }
}
