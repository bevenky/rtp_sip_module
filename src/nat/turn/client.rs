//! Full TURN client lifecycle (RFC 5766)
//!
//! Manages the complete TURN relay lifecycle:
//!
//! ```text
//! Init -> Allocating -> Allocated -> ChannelBound -> Expired
//! ```
//!
//! Handles authentication (long-term credential mechanism per RFC 5389),
//! allocation creation/refresh, permission installation, and channel binding.
//!
//! Bug #33 fix: Permissions (expire 300s, RFC 5766 §8) and channel bindings
//! (expire 600s, §11) are tracked and automatically refreshed at 80% of their
//! lifetime by the background refresh loop alongside allocation refresh.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::net::UdpSocket;

use crate::error::{Result, RtpSipError};
use crate::nat::stun::message::{StunMessage, TransactionId, MAGIC_COOKIE};
use crate::nat::stun::StunAttribute;

use super::message::*;

/// Maximum retries for a TURN transaction (RFC 5389 §7.2.1)
const MAX_RETRIES: u32 = 7;

/// Initial retransmission timeout in milliseconds
const INITIAL_RTO_MS: u64 = 500;

/// Fraction of lifetime at which to refresh (80%)
const REFRESH_FRACTION: f64 = 0.8;

/// TURN client state machine states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnState {
    /// Initial state, no allocation
    Init,
    /// Allocate request in progress
    Allocating,
    /// Allocation is active
    Allocated,
    /// At least one channel is bound
    ChannelBound,
    /// Allocation has expired or been released
    Expired,
}

impl std::fmt::Display for TurnState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TurnState::Init => write!(f, "Init"),
            TurnState::Allocating => write!(f, "Allocating"),
            TurnState::Allocated => write!(f, "Allocated"),
            TurnState::ChannelBound => write!(f, "ChannelBound"),
            TurnState::Expired => write!(f, "Expired"),
        }
    }
}

/// Information about an active TURN allocation
#[derive(Debug, Clone)]
pub struct TurnAllocation {
    /// The relay address assigned by the TURN server
    pub relayed_addr: SocketAddr,
    /// Our reflexive address (server-reflexive)
    pub mapped_addr: SocketAddr,
    /// Allocation lifetime in seconds
    pub lifetime: u32,
}

/// Authentication credentials for TURN long-term mechanism
#[derive(Debug, Clone)]
struct TurnAuth {
    username: String,
    password: String,
    realm: String,
    /// Nonce obtained from 401 challenge
    nonce: Option<String>,
}

impl TurnAuth {
    /// Compute the long-term credential key: MD5(username:realm:password)
    fn compute_key(&self) -> Vec<u8> {
        use md5::{Digest, Md5};

        let input = format!("{}:{}:{}", self.username, self.realm, self.password);
        let mut hasher = Md5::new();
        hasher.update(input.as_bytes());
        hasher.finalize().to_vec()
    }
}

/// Tracked permission with creation time for automatic refresh
#[derive(Debug, Clone)]
struct TrackedPermission {
    peer_addr: SocketAddr,
    created: std::time::Instant,
}

/// Tracked channel binding with creation time for automatic refresh
#[derive(Debug, Clone)]
struct TrackedChannelBinding {
    peer_addr: SocketAddr,
    channel: u16,
    created: std::time::Instant,
}

/// Full TURN client managing the relay lifecycle
pub struct TurnClient {
    /// TURN server address
    server: SocketAddr,
    /// P1-NAT-6: Authentication credentials stored in Arc<Mutex<>> so the
    /// background refresh loop can update the nonce in-place when it
    /// receives a 438 Stale Nonce response, propagating the new nonce to
    /// subsequent permission and channel binding refreshes.
    auth: Arc<Mutex<TurnAuth>>,
    /// Current state
    state: Arc<Mutex<TurnState>>,
    /// Current allocation info (if allocated)
    allocation: Arc<Mutex<Option<TurnAllocation>>>,
    /// Handle to cancel the background refresh task
    refresh_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Bug #33 fix: Track installed permissions for automatic refresh (expire 300s)
    permissions: Arc<Mutex<Vec<TrackedPermission>>>,
    /// Bug #33 fix: Track channel bindings for automatic refresh (expire 600s)
    channel_bindings: Arc<Mutex<Vec<TrackedChannelBinding>>>,
}

impl TurnClient {
    /// Create a new TURN client with authentication credentials.
    ///
    /// # Arguments
    /// * `server` - TURN server address (typically port 3478)
    /// * `username` - Long-term credential username
    /// * `password` - Long-term credential password
    /// * `realm` - Authentication realm
    pub fn new(server: SocketAddr, username: &str, password: &str, realm: &str) -> Self {
        Self {
            server,
            auth: Arc::new(Mutex::new(TurnAuth {
                username: username.to_string(),
                password: password.to_string(),
                realm: realm.to_string(),
                nonce: None,
            })),
            state: Arc::new(Mutex::new(TurnState::Init)),
            allocation: Arc::new(Mutex::new(None)),
            refresh_handle: Mutex::new(None),
            permissions: Arc::new(Mutex::new(Vec::new())),
            channel_bindings: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get the current state of the TURN client
    pub fn state(&self) -> TurnState {
        *self.state.lock()
    }

    /// Get the current allocation info, if any
    pub fn allocation(&self) -> Option<TurnAllocation> {
        self.allocation.lock().clone()
    }

    /// Send an Allocate request to the TURN server.
    ///
    /// Handles the 401 authentication challenge automatically:
    /// 1. Send initial Allocate (unauthenticated)
    /// 2. Receive 401 with realm and nonce
    /// 3. Retry with MESSAGE-INTEGRITY using long-term credentials
    ///
    /// Returns the allocation info on success.
    pub async fn allocate(&mut self, socket: &UdpSocket) -> Result<TurnAllocation> {
        {
            let state = self.state.lock();
            match *state {
                TurnState::Allocated | TurnState::ChannelBound => {
                    return Err(RtpSipError::InvalidState(
                        "already allocated; refresh or deallocate first".to_string(),
                    ));
                }
                _ => {}
            }
        }

        *self.state.lock() = TurnState::Allocating;

        // Step 1: Send unauthenticated Allocate request
        let mut request = self.build_allocate_request();
        let response = match self
            .send_request(socket, &request)
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                *self.state.lock() = TurnState::Init;
                return Err(e);
            }
        };

        // Step 2: Handle 401 challenge
        if response.is_error() {
            if let Some(401) = response.error_code() {
                // Extract realm and nonce from the error response
                let (realm, nonce) = extract_auth_challenge(&response)?;
                {
                    let mut auth = self.auth.lock();
                    auth.realm = realm;
                    auth.nonce = Some(nonce);
                }

                // Step 3: Retry with authentication
                request = self.build_allocate_request();
                self.add_auth_attributes(&mut request);
                let auth_response = match self
                    .send_request(socket, &request)
                    .await
                {
                    Ok(resp) => resp,
                    Err(e) => {
                        *self.state.lock() = TurnState::Init;
                        return Err(e);
                    }
                };

                if auth_response.is_error() {
                    let code = auth_response.error_code().unwrap_or(0);

                    // Bug #23: Handle 438 Stale Nonce in allocate path,
                    // matching the pattern used in refresh().
                    if code == 438 {
                        if let Some(new_nonce) = extract_nonce(&auth_response) {
                            self.auth.lock().nonce = Some(new_nonce);
                            let mut retry_request = self.build_allocate_request();
                            self.add_auth_attributes(&mut retry_request);
                            let retry_response = match self
                                .send_request(socket, &retry_request)
                                .await
                            {
                                Ok(resp) => resp,
                                Err(e) => {
                                    *self.state.lock() = TurnState::Init;
                                    return Err(e);
                                }
                            };
                            if retry_response.is_error() {
                                *self.state.lock() = TurnState::Init;
                                let retry_code = retry_response.error_code().unwrap_or(0);
                                return Err(RtpSipError::Auth(format!(
                                    "TURN Allocate failed with error {} after stale nonce retry",
                                    retry_code
                                )));
                            }
                            let alloc = self.parse_allocate_success(&retry_response)?;
                            *self.allocation.lock() = Some(alloc.clone());
                            *self.state.lock() = TurnState::Allocated;
                            return Ok(alloc);
                        }
                        *self.state.lock() = TurnState::Init;
                        return Err(RtpSipError::Auth(
                            "TURN Allocate 438 Stale Nonce but no NONCE in response".to_string(),
                        ));
                    }

                    *self.state.lock() = TurnState::Init;
                    return Err(RtpSipError::Auth(format!(
                        "TURN Allocate failed with error {}: {}",
                        code,
                        turn_error_description(code)
                    )));
                }

                let alloc = self.parse_allocate_success(&auth_response)?;
                *self.allocation.lock() = Some(alloc.clone());
                *self.state.lock() = TurnState::Allocated;
                return Ok(alloc);
            } else {
                *self.state.lock() = TurnState::Init;
                let code = response.error_code().unwrap_or(0);
                return Err(RtpSipError::Sip(format!(
                    "TURN Allocate failed with error {}: {}",
                    code,
                    turn_error_description(code)
                )));
            }
        }

        // Unlikely: success without auth challenge (some servers allow it)
        let alloc = self.parse_allocate_success(&response)?;
        *self.allocation.lock() = Some(alloc.clone());
        *self.state.lock() = TurnState::Allocated;
        Ok(alloc)
    }

    /// Create a permission for a peer address.
    ///
    /// This must be done before the peer can send data through the relay.
    /// Permissions last for 300 seconds. Bug #33 fix: permissions are now
    /// tracked and automatically refreshed by the background refresh loop.
    pub async fn create_permission(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        self.ensure_allocated()?;

        let mut request = self.build_create_permission_request(peer_addr);
        self.add_auth_attributes(&mut request);

        let response = self.send_request(socket, &request).await?;

        if response.is_error() {
            let code = response.error_code().unwrap_or(0);
            return Err(RtpSipError::Sip(format!(
                "TURN CreatePermission failed with error {}: {}",
                code,
                turn_error_description(code)
            )));
        }

        // Bug #33 fix: Track permission for automatic refresh
        {
            let mut perms = self.permissions.lock();
            // Update existing or add new
            if let Some(existing) = perms.iter_mut().find(|p| p.peer_addr == peer_addr) {
                existing.created = std::time::Instant::now();
            } else {
                perms.push(TrackedPermission {
                    peer_addr,
                    created: std::time::Instant::now(),
                });
            }
        }

        Ok(())
    }

    /// Bind a channel number to a peer address.
    ///
    /// Channel numbers must be in the range 0x4000-0x7FFE.
    /// After binding, data can be sent using the more efficient ChannelData format.
    pub async fn channel_bind(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        channel: u16,
    ) -> Result<()> {
        self.ensure_allocated()?;

        if !is_valid_channel(channel) {
            return Err(RtpSipError::Config(format!(
                "invalid TURN channel number 0x{:04X} (must be 0x4000-0x7FFE)",
                channel
            )));
        }

        let mut request = self.build_channel_bind_request(peer_addr, channel);
        self.add_auth_attributes(&mut request);

        let response = self.send_request(socket, &request).await?;

        if response.is_error() {
            let code = response.error_code().unwrap_or(0);
            return Err(RtpSipError::Sip(format!(
                "TURN ChannelBind failed with error {}: {}",
                code,
                turn_error_description(code)
            )));
        }

        *self.state.lock() = TurnState::ChannelBound;

        // Bug #33 fix: Track channel binding for automatic refresh
        {
            let mut bindings = self.channel_bindings.lock();
            if let Some(existing) = bindings.iter_mut().find(|b| b.channel == channel) {
                existing.peer_addr = peer_addr;
                existing.created = std::time::Instant::now();
            } else {
                bindings.push(TrackedChannelBinding {
                    peer_addr,
                    channel,
                    created: std::time::Instant::now(),
                });
            }
        }

        Ok(())
    }

    /// Refresh the current allocation.
    ///
    /// Returns the new lifetime in seconds.
    /// Bug #47: Handles 438 Stale Nonce by extracting the new nonce and retrying.
    pub async fn refresh(&mut self, socket: &UdpSocket) -> Result<u32> {
        self.ensure_allocated()?;

        let lifetime = self
            .allocation
            .lock()
            .as_ref()
            .map(|a| a.lifetime)
            .unwrap_or(DEFAULT_LIFETIME);

        let mut request = self.build_refresh_request(lifetime);
        self.add_auth_attributes(&mut request);

        let response = self.send_request(socket, &request).await?;

        if response.is_error() {
            let code = response.error_code().unwrap_or(0);

            // Bug #47: Handle 438 Stale Nonce
            if code == 438 {
                if let Some(new_nonce) = extract_nonce(&response) {
                    self.auth.lock().nonce = Some(new_nonce);
                    let mut retry_request = self.build_refresh_request(lifetime);
                    self.add_auth_attributes(&mut retry_request);
                    let retry_response = self.send_request(socket, &retry_request).await?;
                    if retry_response.is_error() {
                        let retry_code = retry_response.error_code().unwrap_or(0);
                        return Err(RtpSipError::Sip(format!(
                            "TURN Refresh failed with error {} after stale nonce retry",
                            retry_code
                        )));
                    }
                    let new_lifetime =
                        parse_lifetime(&retry_response).unwrap_or(DEFAULT_LIFETIME);
                    if let Some(ref mut alloc) = *self.allocation.lock() {
                        alloc.lifetime = new_lifetime;
                    }
                    return Ok(new_lifetime);
                }
                return Err(RtpSipError::Sip(
                    "TURN Refresh 438 Stale Nonce but no NONCE in response".to_string(),
                ));
            }

            return Err(RtpSipError::Sip(format!(
                "TURN Refresh failed with error {}",
                code
            )));
        }

        let new_lifetime = parse_lifetime(&response).unwrap_or(DEFAULT_LIFETIME);

        // Update the allocation lifetime
        if let Some(ref mut alloc) = *self.allocation.lock() {
            alloc.lifetime = new_lifetime;
        }

        Ok(new_lifetime)
    }

    /// Deallocate the TURN relay by sending a Refresh with lifetime=0.
    pub async fn deallocate(&self, socket: &UdpSocket) -> Result<()> {
        self.ensure_allocated()?;

        // Stop the refresh loop first
        self.stop_refresh_loop();

        let mut request = self.build_refresh_request(0);
        self.add_auth_attributes(&mut request);

        let response = self.send_request(socket, &request).await?;

        if response.is_error() {
            let code = response.error_code().unwrap_or(0);
            return Err(RtpSipError::Sip(format!(
                "TURN Deallocate (Refresh lifetime=0) failed with error {}",
                code
            )));
        }

        *self.allocation.lock() = None;
        *self.state.lock() = TurnState::Expired;

        Ok(())
    }

    /// Start a background task that automatically refreshes the allocation
    /// at 80% of its lifetime.
    ///
    /// The task runs until the client is deallocated or the returned handle is dropped.
    pub fn start_refresh_loop(&self, socket: Arc<UdpSocket>) {
        let state = Arc::clone(&self.state);
        let allocation = Arc::clone(&self.allocation);
        let permissions = Arc::clone(&self.permissions);
        let channel_bindings = Arc::clone(&self.channel_bindings);
        let server = self.server;
        // P1-NAT-6: Clone the Arc so the refresh loop shares the same auth
        // state and can propagate nonce updates from 438 responses.
        let auth_arc = Arc::clone(&self.auth);

        let handle = tokio::spawn(async move {
            // Bug #33 fix: Track time for permission and channel binding refresh.
            // Use a shorter check interval (30s) to catch permission/binding expiry
            // while still respecting allocation refresh timing.
            let mut next_alloc_refresh = tokio::time::Instant::now();

            loop {
                // P1-NAT-6: Snapshot the auth state at the start of each loop
                // iteration so we use the latest nonce (which may have been
                // updated by a 438 retry in a previous iteration).
                let auth = auth_arc.lock().clone();
                let lifetime = {
                    let alloc = allocation.lock();
                    match alloc.as_ref() {
                        Some(a) => a.lifetime,
                        None => break,
                    }
                };

                // Sleep for minimum of: 80% allocation lifetime or 30s check interval
                let alloc_refresh_secs = (lifetime as f64 * REFRESH_FRACTION) as u64;
                let alloc_refresh_delay = Duration::from_secs(alloc_refresh_secs.max(1));

                if next_alloc_refresh <= tokio::time::Instant::now() {
                    next_alloc_refresh = tokio::time::Instant::now() + alloc_refresh_delay;
                }

                // Check every 30 seconds for permission/binding refresh needs
                let check_interval = Duration::from_secs(30);
                let sleep_duration = check_interval.min(
                    next_alloc_refresh.saturating_duration_since(tokio::time::Instant::now())
                );

                tokio::time::sleep(sleep_duration).await;

                // Check if we're still in an allocated state
                {
                    let s = state.lock();
                    match *s {
                        TurnState::Allocated | TurnState::ChannelBound => {}
                        _ => break,
                    }
                }

                // Refresh allocation if it's time
                let now = tokio::time::Instant::now();
                if now >= next_alloc_refresh {
                    let current_lifetime = {
                        let alloc = allocation.lock();
                        alloc.as_ref().map(|a| a.lifetime).unwrap_or(DEFAULT_LIFETIME)
                    };

                    let mut request = build_refresh_request_static(current_lifetime);
                    add_auth_attributes_static(&auth, &mut request);

                    let key = auth.compute_key();
                    match send_request_static(&socket, server, &request, Some(&key)).await {
                        Ok(response) => {
                            if response.is_success() {
                                let new_lifetime =
                                    parse_lifetime(&response).unwrap_or(DEFAULT_LIFETIME);
                                if let Some(ref mut alloc) = *allocation.lock() {
                                    alloc.lifetime = new_lifetime;
                                }
                                let refresh_secs = (new_lifetime as f64 * REFRESH_FRACTION) as u64;
                                next_alloc_refresh = tokio::time::Instant::now()
                                    + Duration::from_secs(refresh_secs.max(1));
                                tracing::debug!(
                                    lifetime = new_lifetime,
                                    "TURN allocation refreshed"
                                );
                            } else {
                                let code = response.error_code().unwrap_or(0);

                                // Bug #47: Handle 438 Stale Nonce per RFC 5389 §7.3.1.
                                if code == 438 {
                                    tracing::info!(
                                        "TURN refresh received 438 Stale Nonce, \
                                         extracting new nonce and retrying"
                                    );
                                    if let Some(new_nonce) = extract_nonce(&response) {
                                        // P1-NAT-6: Propagate updated nonce to shared auth
                                        auth_arc.lock().nonce = Some(new_nonce.clone());
                                        let mut retry_auth = auth.clone();
                                        retry_auth.nonce = Some(new_nonce);
                                        let mut retry_request =
                                            build_refresh_request_static(current_lifetime);
                                        add_auth_attributes_static(&retry_auth, &mut retry_request);
                                        let retry_key = retry_auth.compute_key();
                                        match send_request_static(
                                            &socket, server, &retry_request, Some(&retry_key),
                                        )
                                        .await
                                        {
                                            Ok(retry_resp) if retry_resp.is_success() => {
                                                let new_lifetime = parse_lifetime(&retry_resp)
                                                    .unwrap_or(DEFAULT_LIFETIME);
                                                if let Some(ref mut alloc) = *allocation.lock() {
                                                    alloc.lifetime = new_lifetime;
                                                }
                                                let refresh_secs = (new_lifetime as f64 * REFRESH_FRACTION) as u64;
                                                next_alloc_refresh = tokio::time::Instant::now()
                                                    + Duration::from_secs(refresh_secs.max(1));
                                                tracing::debug!(
                                                    lifetime = new_lifetime,
                                                    "TURN allocation refreshed after \
                                                     stale nonce retry"
                                                );
                                            }
                                            Ok(retry_resp) => {
                                                let retry_code =
                                                    retry_resp.error_code().unwrap_or(0);
                                                tracing::warn!(
                                                    error_code = retry_code,
                                                    "TURN refresh retry after 438 failed"
                                                );
                                                *state.lock() = TurnState::Expired;
                                                break;
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    error = %e,
                                                    "TURN refresh retry after 438 failed"
                                                );
                                                *state.lock() = TurnState::Expired;
                                                break;
                                            }
                                        }
                                    } else {
                                        tracing::warn!(
                                            "438 response missing NONCE attribute, \
                                             cannot retry"
                                        );
                                        *state.lock() = TurnState::Expired;
                                        break;
                                    }
                                } else {
                                    tracing::warn!(
                                        error_code = code,
                                        "TURN refresh failed"
                                    );
                                    *state.lock() = TurnState::Expired;
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "TURN refresh request failed");
                            *state.lock() = TurnState::Expired;
                            break;
                        }
                    }
                }

                // Bug #33 fix: Refresh permissions at 80% of 300s lifetime (240s)
                let perm_refresh_threshold = Duration::from_secs(
                    (PERMISSION_LIFETIME as f64 * REFRESH_FRACTION) as u64,
                );
                let perms_to_refresh: Vec<SocketAddr> = {
                    let perms = permissions.lock();
                    perms
                        .iter()
                        .filter(|p| p.created.elapsed() >= perm_refresh_threshold)
                        .map(|p| p.peer_addr)
                        .collect()
                };
                for peer_addr in perms_to_refresh {
                    let mut perm_request = build_create_permission_request_static(peer_addr);
                    add_auth_attributes_static(&auth, &mut perm_request);
                    let key = auth.compute_key();
                    match send_request_static(&socket, server, &perm_request, Some(&key)).await {
                        Ok(response) if response.is_success() => {
                            let mut perms = permissions.lock();
                            if let Some(p) = perms.iter_mut().find(|p| p.peer_addr == peer_addr) {
                                p.created = std::time::Instant::now();
                            }
                            tracing::debug!(
                                peer = %peer_addr,
                                "TURN permission refreshed"
                            );
                        }
                        Ok(response) => {
                            let code = response.error_code().unwrap_or(0);
                            // P1-NAT-12: Handle 438 Stale Nonce for permission refresh.
                            // Extract the new nonce and retry the request.
                            if code == 438 {
                                tracing::info!(
                                    peer = %peer_addr,
                                    "TURN permission refresh received 438 Stale Nonce, retrying"
                                );
                                if let Some(new_nonce) = extract_nonce(&response) {
                                    // P1-NAT-6: Propagate updated nonce to shared auth
                                    auth_arc.lock().nonce = Some(new_nonce.clone());
                                    let mut retry_auth = auth.clone();
                                    retry_auth.nonce = Some(new_nonce);
                                    let mut retry_req = build_create_permission_request_static(peer_addr);
                                    add_auth_attributes_static(&retry_auth, &mut retry_req);
                                    let retry_key = retry_auth.compute_key();
                                    match send_request_static(&socket, server, &retry_req, Some(&retry_key)).await {
                                        Ok(retry_resp) if retry_resp.is_success() => {
                                            let mut perms = permissions.lock();
                                            if let Some(p) = perms.iter_mut().find(|p| p.peer_addr == peer_addr) {
                                                p.created = std::time::Instant::now();
                                            }
                                            tracing::debug!(
                                                peer = %peer_addr,
                                                "TURN permission refreshed after stale nonce retry"
                                            );
                                        }
                                        Ok(retry_resp) => {
                                            let c = retry_resp.error_code().unwrap_or(0);
                                            tracing::warn!(
                                                peer = %peer_addr, error_code = c,
                                                "TURN permission refresh retry after 438 failed"
                                            );
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                peer = %peer_addr, error = %e,
                                                "TURN permission refresh retry after 438 failed"
                                            );
                                        }
                                    }
                                } else {
                                    tracing::warn!(
                                        peer = %peer_addr,
                                        "438 response missing NONCE for permission refresh"
                                    );
                                }
                            } else {
                                tracing::warn!(
                                    peer = %peer_addr, error_code = code,
                                    "TURN permission refresh failed"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                peer = %peer_addr, error = %e,
                                "TURN permission refresh request failed"
                            );
                        }
                    }
                }

                // Bug #33 fix: Refresh channel bindings at 80% of 600s lifetime (480s)
                let bind_refresh_threshold = Duration::from_secs(
                    (CHANNEL_BIND_LIFETIME as f64 * REFRESH_FRACTION) as u64,
                );
                let bindings_to_refresh: Vec<(SocketAddr, u16)> = {
                    let bindings = channel_bindings.lock();
                    bindings
                        .iter()
                        .filter(|b| b.created.elapsed() >= bind_refresh_threshold)
                        .map(|b| (b.peer_addr, b.channel))
                        .collect()
                };
                for (peer_addr, channel) in bindings_to_refresh {
                    let mut bind_request = build_channel_bind_request_static(peer_addr, channel);
                    add_auth_attributes_static(&auth, &mut bind_request);
                    let key = auth.compute_key();
                    match send_request_static(&socket, server, &bind_request, Some(&key)).await {
                        Ok(response) if response.is_success() => {
                            let mut bindings = channel_bindings.lock();
                            if let Some(b) = bindings.iter_mut().find(|b| b.channel == channel) {
                                b.created = std::time::Instant::now();
                            }
                            tracing::debug!(
                                peer = %peer_addr, channel = channel,
                                "TURN channel binding refreshed"
                            );
                        }
                        Ok(response) => {
                            let code = response.error_code().unwrap_or(0);
                            // P1-NAT-13: Handle 438 Stale Nonce for channel binding refresh.
                            // Extract the new nonce and retry the request.
                            if code == 438 {
                                tracing::info!(
                                    peer = %peer_addr, channel = channel,
                                    "TURN channel binding refresh received 438 Stale Nonce, retrying"
                                );
                                if let Some(new_nonce) = extract_nonce(&response) {
                                    // P1-NAT-6: Propagate updated nonce to shared auth
                                    auth_arc.lock().nonce = Some(new_nonce.clone());
                                    let mut retry_auth = auth.clone();
                                    retry_auth.nonce = Some(new_nonce);
                                    let mut retry_req = build_channel_bind_request_static(peer_addr, channel);
                                    add_auth_attributes_static(&retry_auth, &mut retry_req);
                                    let retry_key = retry_auth.compute_key();
                                    match send_request_static(&socket, server, &retry_req, Some(&retry_key)).await {
                                        Ok(retry_resp) if retry_resp.is_success() => {
                                            let mut bindings = channel_bindings.lock();
                                            if let Some(b) = bindings.iter_mut().find(|b| b.channel == channel) {
                                                b.created = std::time::Instant::now();
                                            }
                                            tracing::debug!(
                                                peer = %peer_addr, channel = channel,
                                                "TURN channel binding refreshed after stale nonce retry"
                                            );
                                        }
                                        Ok(retry_resp) => {
                                            let c = retry_resp.error_code().unwrap_or(0);
                                            tracing::warn!(
                                                peer = %peer_addr, channel = channel, error_code = c,
                                                "TURN channel binding refresh retry after 438 failed"
                                            );
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                peer = %peer_addr, channel = channel, error = %e,
                                                "TURN channel binding refresh retry after 438 failed"
                                            );
                                        }
                                    }
                                } else {
                                    tracing::warn!(
                                        peer = %peer_addr, channel = channel,
                                        "438 response missing NONCE for channel binding refresh"
                                    );
                                }
                            } else {
                                tracing::warn!(
                                    peer = %peer_addr, channel = channel, error_code = code,
                                    "TURN channel binding refresh failed"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                peer = %peer_addr, channel = channel, error = %e,
                                "TURN channel binding refresh request failed"
                            );
                        }
                    }
                }
            }
        });

        *self.refresh_handle.lock() = Some(handle);
    }

    /// Stop the background refresh loop
    pub fn stop_refresh_loop(&self) {
        if let Some(handle) = self.refresh_handle.lock().take() {
            handle.abort();
        }
    }

    // --- Private helpers ---

    /// Ensure the client is in an allocated state
    fn ensure_allocated(&self) -> Result<()> {
        let state = self.state.lock();
        match *state {
            TurnState::Allocated | TurnState::ChannelBound => Ok(()),
            other => Err(RtpSipError::InvalidState(format!(
                "TURN client is in state '{}', expected Allocated or ChannelBound",
                other
            ))),
        }
    }

    /// Build an Allocate request (REQUESTED-TRANSPORT = UDP/17)
    fn build_allocate_request(&self) -> StunMessage {
        let mut msg = new_turn_message(ALLOCATE_REQUEST);
        // REQUESTED-TRANSPORT: UDP (protocol number 17)
        msg.add_attribute(StunAttribute::Unknown(
            ATTR_REQUESTED_TRANSPORT,
            encode_requested_transport(17),
        ));
        msg
    }

    /// Build a CreatePermission request for a peer address
    fn build_create_permission_request(&self, peer_addr: SocketAddr) -> StunMessage {
        let mut msg = new_turn_message(CREATE_PERMISSION_REQUEST);
        msg.add_attribute(StunAttribute::Unknown(
            ATTR_XOR_PEER_ADDRESS,
            encode_xor_address(&peer_addr, &msg.transaction_id),
        ));
        msg
    }

    /// Build a ChannelBind request
    fn build_channel_bind_request(
        &self,
        peer_addr: SocketAddr,
        channel: u16,
    ) -> StunMessage {
        let mut msg = new_turn_message(CHANNEL_BIND_REQUEST);
        msg.add_attribute(StunAttribute::Unknown(
            ATTR_CHANNEL_NUMBER,
            encode_channel_number(channel),
        ));
        msg.add_attribute(StunAttribute::Unknown(
            ATTR_XOR_PEER_ADDRESS,
            encode_xor_address(&peer_addr, &msg.transaction_id),
        ));
        msg
    }

    /// Build a Refresh request with a given lifetime
    fn build_refresh_request(&self, lifetime: u32) -> StunMessage {
        build_refresh_request_static(lifetime)
    }

    /// Add authentication attributes (USERNAME, REALM, NONCE, MESSAGE-INTEGRITY)
    fn add_auth_attributes(&self, msg: &mut StunMessage) {
        let auth = self.auth.lock();
        add_auth_attributes_static(&auth, msg);
    }

    /// Parse a successful Allocate response to extract allocation info
    fn parse_allocate_success(&self, response: &StunMessage) -> Result<TurnAllocation> {
        let relayed_addr = find_xor_relayed_address(response)
            .ok_or_else(|| {
                RtpSipError::Sip(
                    "Allocate response missing XOR-RELAYED-ADDRESS".to_string(),
                )
            })?;

        let mapped_addr = response
            .xor_mapped_address()
            .or_else(|| response.mapped_address())
            .ok_or_else(|| {
                RtpSipError::Sip(
                    "Allocate response missing XOR-MAPPED-ADDRESS".to_string(),
                )
            })?;

        let lifetime = parse_lifetime(response).unwrap_or(DEFAULT_LIFETIME);

        Ok(TurnAllocation {
            relayed_addr,
            mapped_addr,
            lifetime,
        })
    }

    /// Send a STUN/TURN request with retransmission and exponential backoff
    async fn send_request(
        &self,
        socket: &UdpSocket,
        request: &StunMessage,
    ) -> Result<StunMessage> {
        let key = self.auth.lock().compute_key();
        send_request_static(socket, self.server, request, Some(&key)).await
    }
}

impl Drop for TurnClient {
    fn drop(&mut self) {
        self.stop_refresh_loop();
    }
}

// --- Static helper functions (usable from both methods and background tasks) ---

/// P2-NAT-7: Format a descriptive TURN error message for known error codes.
fn turn_error_description(code: u16) -> &'static str {
    match code {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden (credentials valid but operation not permitted)",
        420 => "Unknown Attribute",
        437 => "Allocation Mismatch (5-tuple already has an allocation)",
        438 => "Stale Nonce",
        441 => "Wrong Credentials",
        442 => "Unsupported Transport Protocol (server does not support requested transport)",
        486 => "Allocation Quota Reached (too many allocations for this user)",
        508 => "Insufficient Capacity (server is overloaded)",
        _ => "Unknown error",
    }
}

/// Build a Refresh request with a given lifetime (static version)
/// Bug #33: Build a CreatePermission request (static version for refresh loop)
fn build_create_permission_request_static(peer_addr: SocketAddr) -> StunMessage {
    let mut msg = new_turn_message(CREATE_PERMISSION_REQUEST);
    msg.add_attribute(StunAttribute::Unknown(
        ATTR_XOR_PEER_ADDRESS,
        encode_xor_address(&peer_addr, &msg.transaction_id),
    ));
    msg
}

/// Bug #33: Build a ChannelBind request (static version for refresh loop)
fn build_channel_bind_request_static(peer_addr: SocketAddr, channel: u16) -> StunMessage {
    let mut msg = new_turn_message(CHANNEL_BIND_REQUEST);
    msg.add_attribute(StunAttribute::Unknown(
        ATTR_CHANNEL_NUMBER,
        encode_channel_number(channel),
    ));
    msg.add_attribute(StunAttribute::Unknown(
        ATTR_XOR_PEER_ADDRESS,
        encode_xor_address(&peer_addr, &msg.transaction_id),
    ));
    msg
}

fn build_refresh_request_static(lifetime: u32) -> StunMessage {
    let mut msg = new_turn_message(REFRESH_REQUEST);
    msg.add_attribute(StunAttribute::Unknown(
        ATTR_LIFETIME,
        encode_lifetime(lifetime),
    ));
    msg
}

/// Add authentication attributes (static version)
fn add_auth_attributes_static(auth: &TurnAuth, msg: &mut StunMessage) {
    // USERNAME
    msg.add_attribute(StunAttribute::Unknown(
        ATTR_USERNAME,
        auth.username.as_bytes().to_vec(),
    ));

    // REALM
    msg.add_attribute(StunAttribute::Unknown(
        ATTR_REALM,
        auth.realm.as_bytes().to_vec(),
    ));

    // NONCE (if available)
    if let Some(ref nonce) = auth.nonce {
        msg.add_attribute(StunAttribute::Unknown(
            ATTR_NONCE,
            nonce.as_bytes().to_vec(),
        ));
    }

    // MESSAGE-INTEGRITY: HMAC-SHA1 over the message up to (but not including)
    // the MESSAGE-INTEGRITY attribute, with key = MD5(username:realm:password)
    let key = auth.compute_key();
    let integrity = compute_message_integrity(msg, &key);
    msg.add_attribute(StunAttribute::Unknown(ATTR_MESSAGE_INTEGRITY, integrity));
}

/// Send a STUN/TURN request with retransmission (static version).
///
/// `integrity_key` is the long-term credential key (MD5(username:realm:password))
/// used to verify MESSAGE-INTEGRITY on the response. Pass `None` for
/// unauthenticated requests (e.g. the initial Allocate before 401 challenge).
///
/// Bug #105: This function calls `socket.recv_from()` directly, which means
/// concurrent callers using the same socket will race for incoming datagrams.
/// A response intended for one caller may be consumed by another. Currently
/// this is mitigated by matching on transaction ID and retransmitting, but
/// under high concurrency it can cause spurious timeouts.
/// TODO: Implement a centralized recv loop (demultiplexer) that dispatches
/// incoming datagrams to the correct pending transaction by transaction ID,
/// rather than having each caller recv independently on the shared socket.
async fn send_request_static(
    socket: &UdpSocket,
    server: SocketAddr,
    request: &StunMessage,
    integrity_key: Option<&[u8]>,
) -> Result<StunMessage> {
    let data = request.marshal();
    let txn_id = request.transaction_id;
    let mut rto = Duration::from_millis(INITIAL_RTO_MS);
    let mut recv_buf = [0u8; 1500];

    for attempt in 0..=MAX_RETRIES {
        socket
            .send_to(&data, server)
            .await
            .map_err(RtpSipError::Io)?;

        // Wait for response with current timeout
        // RFC 5389 §7.2.1: cap retransmission timeout at Rm * RTO
        // where Rm = 16 for the last attempt
        let timeout = if attempt < MAX_RETRIES {
            rto
        } else {
            // Last attempt: cap at Rm * initial RTO (Rm = 16)
            std::cmp::min(rto, Duration::from_millis(INITIAL_RTO_MS * 16))
        };

        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            match tokio::time::timeout(remaining, socket.recv_from(&mut recv_buf)).await {
                Ok(Ok((len, from))) => {
                    // Bug #59: Validate that the response came from the expected
                    // TURN server. Responses from unexpected sources could be
                    // spoofed and must be discarded.
                    if from != server {
                        tracing::warn!(
                            expected = %server,
                            actual = %from,
                            "TURN response from unexpected address, discarding"
                        );
                        continue;
                    }
                    if let Ok(response) = StunMessage::unmarshal(&recv_buf[..len]) {
                        if response.transaction_id == txn_id {
                            // Bug #8: Verify MESSAGE-INTEGRITY on the response
                            // if present, to prevent tampering.
                            if let Err(e) = verify_response_integrity(
                                &recv_buf[..len],
                                &response,
                                integrity_key,
                            ) {
                                tracing::warn!(
                                    error = %e,
                                    "TURN response MESSAGE-INTEGRITY verification \
                                     failed, rejecting response"
                                );
                                // Reject this response and keep waiting for a
                                // valid one (or timeout).
                                continue;
                            }
                            return Ok(response);
                        }
                    }
                    // Not our response, keep waiting
                }
                Ok(Err(e)) => return Err(RtpSipError::Io(e)),
                Err(_) => break, // Timeout
            }
        }

        // Exponential backoff
        rto *= 2;
    }

    Err(RtpSipError::Timeout(
        "TURN transaction timed out after max retries".to_string(),
    ))
}

/// Verify MESSAGE-INTEGRITY on a STUN/TURN response.
///
/// Per RFC 5389 Section 15.4, MESSAGE-INTEGRITY contains an HMAC-SHA1 computed
/// over the STUN message up to (but not including) the MESSAGE-INTEGRITY
/// attribute, with the message header length field adjusted to include the
/// MESSAGE-INTEGRITY attribute (24 bytes: 4 TLV header + 20 HMAC value).
///
/// If MESSAGE-INTEGRITY is not present, this is a no-op (returns Ok).
/// If present and `key` is provided, performs full HMAC-SHA1 verification.
/// If present but `key` is `None`, logs a warning and accepts the response.
///
/// # Arguments
/// * `raw_bytes` - The raw received bytes (needed for HMAC computation)
/// * `response` - The parsed STUN message (to locate the attribute)
/// * `key` - Optional long-term credential key: MD5(username:realm:password)
fn verify_response_integrity(
    raw_bytes: &[u8],
    response: &StunMessage,
    key: Option<&[u8]>,
) -> std::result::Result<(), String> {
    use crate::nat::stun::message::HEADER_SIZE;
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    // Find MESSAGE-INTEGRITY attribute in the response
    let mut mi_value: Option<&[u8]> = None;
    for attr in &response.attributes {
        if let StunAttribute::Unknown(attr_type, data) = attr {
            if *attr_type == ATTR_MESSAGE_INTEGRITY {
                mi_value = Some(data);
                break;
            }
        }
    }

    let mi_data = match mi_value {
        Some(data) => data,
        None => return Ok(()), // No MESSAGE-INTEGRITY present, nothing to verify
    };

    if mi_data.len() != 20 {
        return Err(format!(
            "MESSAGE-INTEGRITY has invalid length {} (expected 20)",
            mi_data.len()
        ));
    }

    // Walk the raw bytes to find the offset of the MESSAGE-INTEGRITY attribute.
    let msg_len =
        u16::from_be_bytes([raw_bytes[2], raw_bytes[3]]) as usize;
    let end = HEADER_SIZE + msg_len;
    // Bug #R7-4: Validate declared msg_len doesn't exceed actual buffer
    if end > raw_bytes.len() {
        return Err(format!(
            "STUN message length {} exceeds buffer size {}",
            msg_len,
            raw_bytes.len()
        ));
    }
    let mut offset = HEADER_SIZE;
    let mut mi_offset: Option<usize> = None;

    while offset + 4 <= end {
        let attr_type =
            u16::from_be_bytes([raw_bytes[offset], raw_bytes[offset + 1]]);
        let attr_len =
            u16::from_be_bytes([raw_bytes[offset + 2], raw_bytes[offset + 3]]) as usize;

        if attr_type == ATTR_MESSAGE_INTEGRITY {
            mi_offset = Some(offset);
            break;
        }

        offset += 4 + ((attr_len + 3) & !3); // advance past padded value
    }

    let mi_off = match mi_offset {
        Some(off) => off,
        None => {
            return Err(
                "MESSAGE-INTEGRITY found in parsed attributes but not in raw bytes"
                    .to_string(),
            );
        }
    };

    // Build the input for HMAC-SHA1 verification:
    // - Bytes before the MESSAGE-INTEGRITY attribute
    // - With the STUN header message-length adjusted to include up to and
    //   including the MESSAGE-INTEGRITY attribute (24 bytes: 4 TLV header + 20 value)
    let adjusted_len = (mi_off - HEADER_SIZE + 24) as u16;
    let mut buf = Vec::with_capacity(mi_off);
    buf.extend_from_slice(&raw_bytes[..mi_off]);
    let len_bytes = adjusted_len.to_be_bytes();
    buf[2] = len_bytes[0];
    buf[3] = len_bytes[1];

    match key {
        Some(k) => {
            // Full HMAC-SHA1 verification
            let mut mac = Hmac::<Sha1>::new_from_slice(k)
                .expect("HMAC can take key of any size");
            mac.update(&buf);
            let expected = mac.finalize().into_bytes();

            if expected.as_slice() != mi_data {
                return Err(
                    "MESSAGE-INTEGRITY HMAC-SHA1 mismatch: response may be \
                     tampered or credentials differ"
                        .to_string(),
                );
            }

            tracing::trace!(
                mi_offset = mi_off,
                "TURN response MESSAGE-INTEGRITY verified successfully"
            );
        }
        None => {
            // No key available — MESSAGE-INTEGRITY is present but we have
            // no credentials to verify it. Accepting the response would
            // bypass authentication, so reject it.
            return Err(
                "MESSAGE-INTEGRITY present but no key for verification"
                    .to_string(),
            );
        }
    }

    Ok(())
}

/// Create a new STUN message with a TURN method type and random transaction ID
fn new_turn_message(msg_type: u16) -> StunMessage {
    let mut txn_id = [0u8; 12];
    for byte in txn_id.iter_mut() {
        *byte = rand::random();
    }
    StunMessage {
        msg_type,
        transaction_id: txn_id,
        attributes: Vec::new(),
    }
}

// --- TURN attribute encoding helpers ---

/// Encode REQUESTED-TRANSPORT attribute value.
/// 4 bytes: protocol number (1 byte) + 3 bytes RFFU (reserved)
fn encode_requested_transport(protocol: u8) -> Vec<u8> {
    vec![protocol, 0, 0, 0]
}

/// Encode LIFETIME attribute value (4 bytes, big-endian seconds)
fn encode_lifetime(lifetime: u32) -> Vec<u8> {
    lifetime.to_be_bytes().to_vec()
}

/// Encode CHANNEL-NUMBER attribute value.
/// 4 bytes: channel number (2 bytes) + 2 bytes RFFU (reserved)
fn encode_channel_number(channel: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4);
    buf.extend_from_slice(&channel.to_be_bytes());
    buf.extend_from_slice(&[0, 0]); // RFFU
    buf
}

/// Encode an address as XOR-PEER-ADDRESS or XOR-RELAYED-ADDRESS value
/// (same format as XOR-MAPPED-ADDRESS, without the TLV header).
fn encode_xor_address(addr: &SocketAddr, txn_id: &TransactionId) -> Vec<u8> {
    let cookie = MAGIC_COOKIE;
    match addr {
        SocketAddr::V4(v4) => {
            let mut buf = Vec::with_capacity(8);
            buf.push(0); // reserved
            buf.push(0x01); // IPv4
            let port = v4.port() ^ (cookie >> 16) as u16;
            buf.extend_from_slice(&port.to_be_bytes());
            let ip = v4.ip().octets();
            let cookie_bytes = cookie.to_be_bytes();
            buf.push(ip[0] ^ cookie_bytes[0]);
            buf.push(ip[1] ^ cookie_bytes[1]);
            buf.push(ip[2] ^ cookie_bytes[2]);
            buf.push(ip[3] ^ cookie_bytes[3]);
            buf
        }
        SocketAddr::V6(v6) => {
            let mut buf = Vec::with_capacity(20);
            buf.push(0); // reserved
            buf.push(0x02); // IPv6
            let port = v6.port() ^ (cookie >> 16) as u16;
            buf.extend_from_slice(&port.to_be_bytes());
            let ip = v6.ip().octets();
            let cookie_bytes = cookie.to_be_bytes();
            let mut xor_key = [0u8; 16];
            xor_key[0..4].copy_from_slice(&cookie_bytes);
            xor_key[4..16].copy_from_slice(txn_id);
            for i in 0..16 {
                buf.push(ip[i] ^ xor_key[i]);
            }
            buf
        }
    }
}

/// Decode an XOR address from attribute value bytes (same format as XOR-MAPPED-ADDRESS)
fn decode_xor_address(data: &[u8], txn_id: &TransactionId) -> Option<SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    if data.len() < 4 {
        return None;
    }
    let family = data[1];
    let raw_port = u16::from_be_bytes([data[2], data[3]]);
    let port = raw_port ^ (MAGIC_COOKIE >> 16) as u16;

    match family {
        0x01 => {
            // IPv4
            if data.len() < 8 {
                return None;
            }
            let cookie = MAGIC_COOKIE.to_be_bytes();
            let ip = Ipv4Addr::new(
                data[4] ^ cookie[0],
                data[5] ^ cookie[1],
                data[6] ^ cookie[2],
                data[7] ^ cookie[3],
            );
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            // IPv6
            if data.len() < 20 {
                return None;
            }
            let cookie = MAGIC_COOKIE.to_be_bytes();
            let mut octets = [0u8; 16];
            for i in 0..4 {
                octets[i] = data[4 + i] ^ cookie[i];
            }
            for i in 0..12 {
                octets[4 + i] = data[8 + i] ^ txn_id[i];
            }
            let ip = Ipv6Addr::from(octets);
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => None,
    }
}

/// Compute MESSAGE-INTEGRITY (HMAC-SHA1) for a STUN message.
///
/// Per RFC 5389 Section 15.4:
/// The HMAC is computed over the STUN message up to and including the attribute
/// preceding the MESSAGE-INTEGRITY attribute, with the message header length
/// adjusted to include the MESSAGE-INTEGRITY TLV (24 bytes: 4 header + 20 HMAC).
///
/// FINGERPRINT is NOT included in the HMAC input because it comes after
/// MESSAGE-INTEGRITY in the attribute ordering (RFC 5389 Section 15.5).
fn compute_message_integrity(msg: &StunMessage, key: &[u8]) -> Vec<u8> {
    use crate::nat::stun::message::HEADER_SIZE;
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    // Encode user attributes only (no FINGERPRINT, no MESSAGE-INTEGRITY)
    let mut attr_bytes = Vec::new();
    for attr in &msg.attributes {
        attr_bytes.extend_from_slice(&attr.encode(&msg.transaction_id));
    }

    // Build the HMAC input: header + user_attrs, with header length adjusted
    // to include the MESSAGE-INTEGRITY TLV (24 bytes) that will follow.
    let mi_adjusted_attr_len = attr_bytes.len() + 24;

    let mut hmac_input = Vec::with_capacity(HEADER_SIZE + attr_bytes.len());
    hmac_input.extend_from_slice(&msg.msg_type.to_be_bytes());
    hmac_input.extend_from_slice(&(mi_adjusted_attr_len as u16).to_be_bytes());
    hmac_input.extend_from_slice(&crate::nat::stun::message::MAGIC_COOKIE.to_be_bytes());
    hmac_input.extend_from_slice(&msg.transaction_id);
    hmac_input.extend_from_slice(&attr_bytes);

    // Compute HMAC-SHA1
    let mut mac =
        Hmac::<Sha1>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(&hmac_input);
    let result = mac.finalize();
    result.into_bytes().to_vec()
}

/// Extract realm and nonce from a 401 Unauthorized error response
fn extract_auth_challenge(response: &StunMessage) -> Result<(String, String)> {
    let mut realm = None;
    let mut nonce = None;

    for attr in &response.attributes {
        if let StunAttribute::Unknown(attr_type, data) = attr {
            match *attr_type {
                ATTR_REALM => {
                    realm = Some(String::from_utf8_lossy(data).to_string());
                }
                ATTR_NONCE => {
                    nonce = Some(String::from_utf8_lossy(data).to_string());
                }
                _ => {}
            }
        }
    }

    match (realm, nonce) {
        (Some(r), Some(n)) => Ok((r, n)),
        (None, _) => Err(RtpSipError::Auth(
            "401 response missing REALM attribute".to_string(),
        )),
        (_, None) => Err(RtpSipError::Auth(
            "401 response missing NONCE attribute".to_string(),
        )),
    }
}

/// Extract the NONCE attribute from a STUN/TURN response.
/// Used for handling 438 Stale Nonce responses (Bug #47).
fn extract_nonce(msg: &StunMessage) -> Option<String> {
    for attr in &msg.attributes {
        if let StunAttribute::Unknown(attr_type, data) = attr {
            if *attr_type == ATTR_NONCE {
                return Some(String::from_utf8_lossy(data).to_string());
            }
        }
    }
    None
}

/// Find XOR-RELAYED-ADDRESS in a STUN message
fn find_xor_relayed_address(msg: &StunMessage) -> Option<SocketAddr> {
    for attr in &msg.attributes {
        if let StunAttribute::Unknown(attr_type, data) = attr {
            if *attr_type == ATTR_XOR_RELAYED_ADDRESS {
                return decode_xor_address(data, &msg.transaction_id);
            }
        }
    }
    None
}

/// Parse the LIFETIME attribute from a response
fn parse_lifetime(msg: &StunMessage) -> Option<u32> {
    for attr in &msg.attributes {
        if let StunAttribute::Unknown(attr_type, data) = attr {
            if *attr_type == ATTR_LIFETIME && data.len() >= 4 {
                return Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    // --- Unit tests for encoding/decoding helpers ---

    #[test]
    fn test_encode_requested_transport_udp() {
        let encoded = encode_requested_transport(17);
        assert_eq!(encoded, vec![17, 0, 0, 0]);
    }

    #[test]
    fn test_encode_lifetime() {
        let encoded = encode_lifetime(600);
        assert_eq!(encoded, 600u32.to_be_bytes().to_vec());

        let encoded_zero = encode_lifetime(0);
        assert_eq!(encoded_zero, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_encode_channel_number() {
        let encoded = encode_channel_number(0x4000);
        assert_eq!(encoded, vec![0x40, 0x00, 0x00, 0x00]);

        let encoded = encode_channel_number(0x7FFE);
        assert_eq!(encoded, vec![0x7F, 0xFE, 0x00, 0x00]);
    }

    #[test]
    fn test_xor_address_roundtrip_v4() {
        let txn_id: TransactionId = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let addr: SocketAddr = "203.0.113.50:32853".parse().unwrap();

        let encoded = encode_xor_address(&addr, &txn_id);
        let decoded = decode_xor_address(&encoded, &txn_id).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_xor_address_roundtrip_v6() {
        let txn_id: TransactionId =
            [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let addr: SocketAddr = "[2001:db8::1]:8080".parse().unwrap();

        let encoded = encode_xor_address(&addr, &txn_id);
        let decoded = decode_xor_address(&encoded, &txn_id).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_xor_address_is_xored() {
        let txn_id: TransactionId = [0; 12];
        let addr: SocketAddr = "192.168.1.1:5060".parse().unwrap();

        let encoded = encode_xor_address(&addr, &txn_id);
        // The encoded bytes should NOT match the plain address bytes
        // Port 5060 = 0x13C4, XOR with 0x2112 = 0x32D6
        let expected_port = 5060u16 ^ (MAGIC_COOKIE >> 16) as u16;
        let actual_port = u16::from_be_bytes([encoded[2], encoded[3]]);
        assert_eq!(actual_port, expected_port);
    }

    #[test]
    fn test_decode_xor_address_too_short() {
        let txn_id: TransactionId = [0; 12];
        assert!(decode_xor_address(&[0, 1], &txn_id).is_none());
        assert!(decode_xor_address(&[], &txn_id).is_none());
    }

    #[test]
    fn test_decode_xor_address_invalid_family() {
        let txn_id: TransactionId = [0; 12];
        let data = vec![0, 0x03, 0, 0, 0, 0, 0, 0]; // family 0x03 is invalid
        assert!(decode_xor_address(&data, &txn_id).is_none());
    }

    // --- Unit tests for authentication ---

    #[test]
    fn test_auth_key_computation() {
        // RFC 5389 long-term credential: key = MD5(username:realm:password)
        let auth = TurnAuth {
            username: "user".to_string(),
            password: "pass".to_string(),
            realm: "example.com".to_string(),
            nonce: None,
        };

        let key = auth.compute_key();
        assert_eq!(key.len(), 16); // MD5 produces 16 bytes

        // Verify deterministic
        let key2 = auth.compute_key();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_auth_key_changes_with_credentials() {
        let auth1 = TurnAuth {
            username: "user1".to_string(),
            password: "pass1".to_string(),
            realm: "example.com".to_string(),
            nonce: None,
        };
        let auth2 = TurnAuth {
            username: "user2".to_string(),
            password: "pass2".to_string(),
            realm: "example.com".to_string(),
            nonce: None,
        };

        assert_ne!(auth1.compute_key(), auth2.compute_key());
    }

    // --- Unit tests for MESSAGE-INTEGRITY ---

    #[test]
    fn test_message_integrity_is_20_bytes() {
        let msg = new_turn_message(ALLOCATE_REQUEST);
        let key = vec![0u8; 16];
        let integrity = compute_message_integrity(&msg, &key);
        assert_eq!(integrity.len(), 20); // HMAC-SHA1 output
    }

    #[test]
    fn test_message_integrity_deterministic() {
        let msg = new_turn_message(ALLOCATE_REQUEST);
        let key = b"test-key-1234567".to_vec();
        let h1 = compute_message_integrity(&msg, &key);
        let h2 = compute_message_integrity(&msg, &key);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_message_integrity_changes_with_key() {
        let msg = new_turn_message(ALLOCATE_REQUEST);
        let key1 = b"key-1-0000000000".to_vec();
        let key2 = b"key-2-0000000000".to_vec();
        let h1 = compute_message_integrity(&msg, &key1);
        let h2 = compute_message_integrity(&msg, &key2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_message_integrity_changes_with_content() {
        let key = b"same-key-0000000".to_vec();
        let msg1 = new_turn_message(ALLOCATE_REQUEST);
        let msg2 = new_turn_message(REFRESH_REQUEST);
        let h1 = compute_message_integrity(&msg1, &key);
        let h2 = compute_message_integrity(&msg2, &key);
        assert_ne!(h1, h2);
    }

    // --- Unit tests for message construction ---

    #[test]
    fn test_build_allocate_request() {
        let client = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "user",
            "pass",
            "realm",
        );
        let msg = client.build_allocate_request();
        assert_eq!(msg.msg_type, ALLOCATE_REQUEST);
        assert_eq!(msg.attributes.len(), 1); // REQUESTED-TRANSPORT

        // Verify REQUESTED-TRANSPORT attribute
        if let StunAttribute::Unknown(attr_type, data) = &msg.attributes[0] {
            assert_eq!(*attr_type, ATTR_REQUESTED_TRANSPORT);
            assert_eq!(data, &[17, 0, 0, 0]); // UDP
        } else {
            panic!("Expected Unknown attribute for REQUESTED-TRANSPORT");
        }
    }

    #[test]
    fn test_build_refresh_request() {
        let msg = build_refresh_request_static(600);
        assert_eq!(msg.msg_type, REFRESH_REQUEST);
        assert_eq!(msg.attributes.len(), 1); // LIFETIME

        if let StunAttribute::Unknown(attr_type, data) = &msg.attributes[0] {
            assert_eq!(*attr_type, ATTR_LIFETIME);
            assert_eq!(u32::from_be_bytes([data[0], data[1], data[2], data[3]]), 600);
        } else {
            panic!("Expected Unknown attribute for LIFETIME");
        }
    }

    #[test]
    fn test_build_refresh_request_zero_lifetime() {
        let msg = build_refresh_request_static(0);
        assert_eq!(msg.msg_type, REFRESH_REQUEST);

        if let StunAttribute::Unknown(attr_type, data) = &msg.attributes[0] {
            assert_eq!(*attr_type, ATTR_LIFETIME);
            assert_eq!(u32::from_be_bytes([data[0], data[1], data[2], data[3]]), 0);
        } else {
            panic!("Expected Unknown attribute for LIFETIME");
        }
    }

    #[test]
    fn test_build_create_permission_request() {
        let client = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "user",
            "pass",
            "realm",
        );
        let peer: SocketAddr = "10.0.0.1:5060".parse().unwrap();
        let msg = client.build_create_permission_request(peer);
        assert_eq!(msg.msg_type, CREATE_PERMISSION_REQUEST);
        assert_eq!(msg.attributes.len(), 1); // XOR-PEER-ADDRESS

        if let StunAttribute::Unknown(attr_type, data) = &msg.attributes[0] {
            assert_eq!(*attr_type, ATTR_XOR_PEER_ADDRESS);
            let decoded = decode_xor_address(data, &msg.transaction_id).unwrap();
            assert_eq!(decoded, peer);
        } else {
            panic!("Expected Unknown attribute for XOR-PEER-ADDRESS");
        }
    }

    #[test]
    fn test_build_channel_bind_request() {
        let client = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "user",
            "pass",
            "realm",
        );
        let peer: SocketAddr = "10.0.0.1:5060".parse().unwrap();
        let channel = 0x4000u16;
        let msg = client.build_channel_bind_request(peer, channel);
        assert_eq!(msg.msg_type, CHANNEL_BIND_REQUEST);
        assert_eq!(msg.attributes.len(), 2); // CHANNEL-NUMBER + XOR-PEER-ADDRESS

        // Check CHANNEL-NUMBER
        if let StunAttribute::Unknown(attr_type, data) = &msg.attributes[0] {
            assert_eq!(*attr_type, ATTR_CHANNEL_NUMBER);
            assert_eq!(u16::from_be_bytes([data[0], data[1]]), channel);
        } else {
            panic!("Expected Unknown attribute for CHANNEL-NUMBER");
        }

        // Check XOR-PEER-ADDRESS
        if let StunAttribute::Unknown(attr_type, data) = &msg.attributes[1] {
            assert_eq!(*attr_type, ATTR_XOR_PEER_ADDRESS);
            let decoded = decode_xor_address(data, &msg.transaction_id).unwrap();
            assert_eq!(decoded, peer);
        } else {
            panic!("Expected Unknown attribute for XOR-PEER-ADDRESS");
        }
    }

    // --- Unit tests for auth attribute addition ---

    #[test]
    fn test_add_auth_attributes_without_nonce() {
        let auth = TurnAuth {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            realm: "example.com".to_string(),
            nonce: None,
        };
        let mut msg = new_turn_message(ALLOCATE_REQUEST);
        add_auth_attributes_static(&auth, &mut msg);

        // Should have USERNAME, REALM, MESSAGE-INTEGRITY (no NONCE)
        assert_eq!(msg.attributes.len(), 3);

        let attr_types: Vec<u16> = msg
            .attributes
            .iter()
            .filter_map(|a| {
                if let StunAttribute::Unknown(t, _) = a {
                    Some(*t)
                } else {
                    None
                }
            })
            .collect();
        assert!(attr_types.contains(&ATTR_USERNAME));
        assert!(attr_types.contains(&ATTR_REALM));
        assert!(attr_types.contains(&ATTR_MESSAGE_INTEGRITY));
    }

    #[test]
    fn test_add_auth_attributes_with_nonce() {
        let auth = TurnAuth {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            realm: "example.com".to_string(),
            nonce: Some("abc123nonce".to_string()),
        };
        let mut msg = new_turn_message(ALLOCATE_REQUEST);
        add_auth_attributes_static(&auth, &mut msg);

        // Should have USERNAME, REALM, NONCE, MESSAGE-INTEGRITY
        assert_eq!(msg.attributes.len(), 4);

        let attr_types: Vec<u16> = msg
            .attributes
            .iter()
            .filter_map(|a| {
                if let StunAttribute::Unknown(t, _) = a {
                    Some(*t)
                } else {
                    None
                }
            })
            .collect();
        assert!(attr_types.contains(&ATTR_USERNAME));
        assert!(attr_types.contains(&ATTR_REALM));
        assert!(attr_types.contains(&ATTR_NONCE));
        assert!(attr_types.contains(&ATTR_MESSAGE_INTEGRITY));
    }

    // --- Unit tests for response parsing ---

    #[test]
    fn test_parse_lifetime_from_response() {
        let txn_id: TransactionId = [0; 12];
        let msg = StunMessage {
            msg_type: ALLOCATE_SUCCESS,
            transaction_id: txn_id,
            attributes: vec![StunAttribute::Unknown(
                ATTR_LIFETIME,
                600u32.to_be_bytes().to_vec(),
            )],
        };
        assert_eq!(parse_lifetime(&msg), Some(600));
    }

    #[test]
    fn test_parse_lifetime_missing() {
        let txn_id: TransactionId = [0; 12];
        let msg = StunMessage {
            msg_type: ALLOCATE_SUCCESS,
            transaction_id: txn_id,
            attributes: vec![],
        };
        assert_eq!(parse_lifetime(&msg), None);
    }

    #[test]
    fn test_find_xor_relayed_address() {
        let txn_id: TransactionId = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let relay_addr: SocketAddr = "198.51.100.1:49152".parse().unwrap();
        let encoded = encode_xor_address(&relay_addr, &txn_id);

        let msg = StunMessage {
            msg_type: ALLOCATE_SUCCESS,
            transaction_id: txn_id,
            attributes: vec![StunAttribute::Unknown(ATTR_XOR_RELAYED_ADDRESS, encoded)],
        };

        let found = find_xor_relayed_address(&msg).unwrap();
        assert_eq!(found, relay_addr);
    }

    #[test]
    fn test_find_xor_relayed_address_missing() {
        let txn_id: TransactionId = [0; 12];
        let msg = StunMessage {
            msg_type: ALLOCATE_SUCCESS,
            transaction_id: txn_id,
            attributes: vec![],
        };
        assert!(find_xor_relayed_address(&msg).is_none());
    }

    // --- Unit tests for auth challenge extraction ---

    #[test]
    fn test_extract_auth_challenge() {
        let txn_id: TransactionId = [0; 12];
        let msg = StunMessage {
            msg_type: ALLOCATE_ERROR,
            transaction_id: txn_id,
            attributes: vec![
                StunAttribute::ErrorCode {
                    code: 401,
                    reason: "Unauthorized".to_string(),
                },
                StunAttribute::Unknown(ATTR_REALM, b"example.com".to_vec()),
                StunAttribute::Unknown(ATTR_NONCE, b"nonce123".to_vec()),
            ],
        };

        let (realm, nonce) = extract_auth_challenge(&msg).unwrap();
        assert_eq!(realm, "example.com");
        assert_eq!(nonce, "nonce123");
    }

    #[test]
    fn test_extract_auth_challenge_missing_realm() {
        let txn_id: TransactionId = [0; 12];
        let msg = StunMessage {
            msg_type: ALLOCATE_ERROR,
            transaction_id: txn_id,
            attributes: vec![
                StunAttribute::ErrorCode {
                    code: 401,
                    reason: "Unauthorized".to_string(),
                },
                StunAttribute::Unknown(ATTR_NONCE, b"nonce123".to_vec()),
            ],
        };

        assert!(extract_auth_challenge(&msg).is_err());
    }

    #[test]
    fn test_extract_auth_challenge_missing_nonce() {
        let txn_id: TransactionId = [0; 12];
        let msg = StunMessage {
            msg_type: ALLOCATE_ERROR,
            transaction_id: txn_id,
            attributes: vec![
                StunAttribute::ErrorCode {
                    code: 401,
                    reason: "Unauthorized".to_string(),
                },
                StunAttribute::Unknown(ATTR_REALM, b"example.com".to_vec()),
            ],
        };

        assert!(extract_auth_challenge(&msg).is_err());
    }

    // --- State machine tests ---

    #[test]
    fn test_initial_state() {
        let client = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "user",
            "pass",
            "realm",
        );
        assert_eq!(client.state(), TurnState::Init);
        assert!(client.allocation().is_none());
    }

    #[test]
    fn test_turn_state_display() {
        assert_eq!(TurnState::Init.to_string(), "Init");
        assert_eq!(TurnState::Allocating.to_string(), "Allocating");
        assert_eq!(TurnState::Allocated.to_string(), "Allocated");
        assert_eq!(TurnState::ChannelBound.to_string(), "ChannelBound");
        assert_eq!(TurnState::Expired.to_string(), "Expired");
    }

    #[test]
    fn test_ensure_allocated_in_init_state() {
        let client = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "user",
            "pass",
            "realm",
        );
        assert!(client.ensure_allocated().is_err());
    }

    // --- Allocate response parsing test ---

    #[test]
    fn test_parse_allocate_success() {
        let client = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "user",
            "pass",
            "realm",
        );
        let txn_id: TransactionId = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let relay_addr: SocketAddr = "198.51.100.1:49152".parse().unwrap();
        let mapped_addr: SocketAddr = "203.0.113.50:32853".parse().unwrap();

        let relay_encoded = encode_xor_address(&relay_addr, &txn_id);

        let response = StunMessage {
            msg_type: ALLOCATE_SUCCESS,
            transaction_id: txn_id,
            attributes: vec![
                StunAttribute::Unknown(ATTR_XOR_RELAYED_ADDRESS, relay_encoded),
                StunAttribute::XorMappedAddress(mapped_addr),
                StunAttribute::Unknown(ATTR_LIFETIME, 600u32.to_be_bytes().to_vec()),
            ],
        };

        let alloc = client.parse_allocate_success(&response).unwrap();
        assert_eq!(alloc.relayed_addr, relay_addr);
        assert_eq!(alloc.mapped_addr, mapped_addr);
        assert_eq!(alloc.lifetime, 600);
    }

    #[test]
    fn test_parse_allocate_success_missing_relay() {
        let client = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "user",
            "pass",
            "realm",
        );
        let txn_id: TransactionId = [0; 12];
        let mapped_addr: SocketAddr = "203.0.113.50:32853".parse().unwrap();

        let response = StunMessage {
            msg_type: ALLOCATE_SUCCESS,
            transaction_id: txn_id,
            attributes: vec![
                StunAttribute::XorMappedAddress(mapped_addr),
                StunAttribute::Unknown(ATTR_LIFETIME, 600u32.to_be_bytes().to_vec()),
            ],
        };

        assert!(client.parse_allocate_success(&response).is_err());
    }

    #[test]
    fn test_parse_allocate_success_missing_mapped() {
        let client = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "user",
            "pass",
            "realm",
        );
        let txn_id: TransactionId = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let relay_addr: SocketAddr = "198.51.100.1:49152".parse().unwrap();
        let relay_encoded = encode_xor_address(&relay_addr, &txn_id);

        let response = StunMessage {
            msg_type: ALLOCATE_SUCCESS,
            transaction_id: txn_id,
            attributes: vec![
                StunAttribute::Unknown(ATTR_XOR_RELAYED_ADDRESS, relay_encoded),
                StunAttribute::Unknown(ATTR_LIFETIME, 600u32.to_be_bytes().to_vec()),
            ],
        };

        assert!(client.parse_allocate_success(&response).is_err());
    }

    #[test]
    fn test_parse_allocate_success_default_lifetime() {
        let client = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "user",
            "pass",
            "realm",
        );
        let txn_id: TransactionId = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let relay_addr: SocketAddr = "198.51.100.1:49152".parse().unwrap();
        let mapped_addr: SocketAddr = "203.0.113.50:32853".parse().unwrap();
        let relay_encoded = encode_xor_address(&relay_addr, &txn_id);

        // No LIFETIME attribute — should use default
        let response = StunMessage {
            msg_type: ALLOCATE_SUCCESS,
            transaction_id: txn_id,
            attributes: vec![
                StunAttribute::Unknown(ATTR_XOR_RELAYED_ADDRESS, relay_encoded),
                StunAttribute::XorMappedAddress(mapped_addr),
            ],
        };

        let alloc = client.parse_allocate_success(&response).unwrap();
        assert_eq!(alloc.lifetime, DEFAULT_LIFETIME);
    }

    // --- Integration-style tests with mock sockets ---

    #[tokio::test]
    async fn test_allocate_rejects_when_already_allocated() {
        let mut client = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "user",
            "pass",
            "realm",
        );

        // Manually set state to Allocated
        *client.state.lock() = TurnState::Allocated;
        *client.allocation.lock() = Some(TurnAllocation {
            relayed_addr: "198.51.100.1:49152".parse().unwrap(),
            mapped_addr: "203.0.113.50:32853".parse().unwrap(),
            lifetime: 600,
        });

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let result = client.allocate(&socket).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("already allocated"));
    }

    #[tokio::test]
    async fn test_channel_bind_rejects_invalid_channel() {
        let client = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "user",
            "pass",
            "realm",
        );

        // Set state to Allocated so channel_bind doesn't fail on state check
        *client.state.lock() = TurnState::Allocated;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Invalid channel numbers
        let result = client
            .channel_bind(&socket, "10.0.0.1:5060".parse().unwrap(), 0x3FFF)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid TURN channel"));

        let result = client
            .channel_bind(&socket, "10.0.0.1:5060".parse().unwrap(), 0x7FFF)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_refresh_rejects_when_not_allocated() {
        let mut client = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "user",
            "pass",
            "realm",
        );

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let result = client.refresh(&socket).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Init"));
    }

    #[tokio::test]
    async fn test_deallocate_rejects_when_not_allocated() {
        let client = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "user",
            "pass",
            "realm",
        );

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let result = client.deallocate(&socket).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_permission_rejects_when_not_allocated() {
        let client = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "user",
            "pass",
            "realm",
        );

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let result = client
            .create_permission(&socket, "10.0.0.1:5060".parse().unwrap())
            .await;
        assert!(result.is_err());
    }

    /// Simulated TURN server that responds to Allocate with 401, then success
    #[tokio::test]
    async fn test_allocate_with_mock_server() {
        // Bind a mock server
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let relay_addr: SocketAddr =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 49152));
        let mapped_addr: SocketAddr =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 50), 32853));

        // Spawn mock server task
        let server_handle = tokio::spawn(async move {
            let mut buf = [0u8; 1500];

            // 1) Receive initial Allocate (unauthenticated) -> reply 401
            let (len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
            let request = StunMessage::unmarshal(&buf[..len]).unwrap();
            assert_eq!(request.msg_type, ALLOCATE_REQUEST);

            let error_resp = StunMessage {
                msg_type: ALLOCATE_ERROR,
                transaction_id: request.transaction_id,
                attributes: vec![
                    StunAttribute::ErrorCode {
                        code: 401,
                        reason: "Unauthorized".to_string(),
                    },
                    StunAttribute::Unknown(ATTR_REALM, b"test.example.com".to_vec()),
                    StunAttribute::Unknown(ATTR_NONCE, b"test-nonce-abc".to_vec()),
                ],
            };
            let resp_data = error_resp.marshal();
            server_socket.send_to(&resp_data, client_addr).await.unwrap();

            // 2) Receive authenticated Allocate -> reply success
            let (len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
            let request = StunMessage::unmarshal(&buf[..len]).unwrap();
            assert_eq!(request.msg_type, ALLOCATE_REQUEST);

            // Verify it has auth attributes
            let has_username = request.attributes.iter().any(|a| {
                matches!(a, StunAttribute::Unknown(t, _) if *t == ATTR_USERNAME)
            });
            let has_integrity = request.attributes.iter().any(|a| {
                matches!(a, StunAttribute::Unknown(t, _) if *t == ATTR_MESSAGE_INTEGRITY)
            });
            assert!(has_username, "authenticated request should have USERNAME");
            assert!(
                has_integrity,
                "authenticated request should have MESSAGE-INTEGRITY"
            );

            let relay_encoded = encode_xor_address(&relay_addr, &request.transaction_id);
            let success_resp = StunMessage {
                msg_type: ALLOCATE_SUCCESS,
                transaction_id: request.transaction_id,
                attributes: vec![
                    StunAttribute::Unknown(ATTR_XOR_RELAYED_ADDRESS, relay_encoded),
                    StunAttribute::XorMappedAddress(mapped_addr),
                    StunAttribute::Unknown(ATTR_LIFETIME, 600u32.to_be_bytes().to_vec()),
                ],
            };
            let resp_data = success_resp.marshal();
            server_socket.send_to(&resp_data, client_addr).await.unwrap();
        });

        // Client side
        let mut client = TurnClient::new(server_addr, "testuser", "testpass", "initial-realm");

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let alloc = client.allocate(&socket).await.unwrap();

        assert_eq!(alloc.relayed_addr, relay_addr);
        assert_eq!(alloc.mapped_addr, mapped_addr);
        assert_eq!(alloc.lifetime, 600);
        assert_eq!(client.state(), TurnState::Allocated);

        server_handle.await.unwrap();
    }

    /// Test Refresh with mock server
    #[tokio::test]
    async fn test_refresh_with_mock_server() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            let (len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
            let request = StunMessage::unmarshal(&buf[..len]).unwrap();
            assert_eq!(request.msg_type, REFRESH_REQUEST);

            let success_resp = StunMessage {
                msg_type: REFRESH_SUCCESS,
                transaction_id: request.transaction_id,
                attributes: vec![StunAttribute::Unknown(
                    ATTR_LIFETIME,
                    300u32.to_be_bytes().to_vec(),
                )],
            };
            let resp_data = success_resp.marshal();
            server_socket.send_to(&resp_data, client_addr).await.unwrap();
        });

        // Bug #R11-8: refresh() requires &mut self
        let mut client = TurnClient::new(server_addr, "user", "pass", "realm");
        *client.state.lock() = TurnState::Allocated;
        *client.allocation.lock() = Some(TurnAllocation {
            relayed_addr: "198.51.100.1:49152".parse().unwrap(),
            mapped_addr: "203.0.113.50:32853".parse().unwrap(),
            lifetime: 600,
        });

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let new_lifetime = client.refresh(&socket).await.unwrap();
        assert_eq!(new_lifetime, 300);

        // Verify the allocation was updated
        let alloc = client.allocation().unwrap();
        assert_eq!(alloc.lifetime, 300);

        server_handle.await.unwrap();
    }

    /// Test CreatePermission with mock server
    #[tokio::test]
    async fn test_create_permission_with_mock_server() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            let (len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
            let request = StunMessage::unmarshal(&buf[..len]).unwrap();
            assert_eq!(request.msg_type, CREATE_PERMISSION_REQUEST);

            let success_resp = StunMessage {
                msg_type: CREATE_PERMISSION_SUCCESS,
                transaction_id: request.transaction_id,
                attributes: vec![],
            };
            let resp_data = success_resp.marshal();
            server_socket.send_to(&resp_data, client_addr).await.unwrap();
        });

        let client = TurnClient::new(server_addr, "user", "pass", "realm");
        *client.state.lock() = TurnState::Allocated;
        *client.allocation.lock() = Some(TurnAllocation {
            relayed_addr: "198.51.100.1:49152".parse().unwrap(),
            mapped_addr: "203.0.113.50:32853".parse().unwrap(),
            lifetime: 600,
        });

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let result = client
            .create_permission(&socket, "10.0.0.1:5060".parse().unwrap())
            .await;
        assert!(result.is_ok());

        server_handle.await.unwrap();
    }

    /// Test ChannelBind with mock server
    #[tokio::test]
    async fn test_channel_bind_with_mock_server() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            let (len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
            let request = StunMessage::unmarshal(&buf[..len]).unwrap();
            assert_eq!(request.msg_type, CHANNEL_BIND_REQUEST);

            let success_resp = StunMessage {
                msg_type: CHANNEL_BIND_SUCCESS,
                transaction_id: request.transaction_id,
                attributes: vec![],
            };
            let resp_data = success_resp.marshal();
            server_socket.send_to(&resp_data, client_addr).await.unwrap();
        });

        let client = TurnClient::new(server_addr, "user", "pass", "realm");
        *client.state.lock() = TurnState::Allocated;
        *client.allocation.lock() = Some(TurnAllocation {
            relayed_addr: "198.51.100.1:49152".parse().unwrap(),
            mapped_addr: "203.0.113.50:32853".parse().unwrap(),
            lifetime: 600,
        });

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let result = client
            .channel_bind(&socket, "10.0.0.1:5060".parse().unwrap(), 0x4001)
            .await;
        assert!(result.is_ok());
        assert_eq!(client.state(), TurnState::ChannelBound);

        server_handle.await.unwrap();
    }

    /// Test Deallocate with mock server
    #[tokio::test]
    async fn test_deallocate_with_mock_server() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            let (len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
            let request = StunMessage::unmarshal(&buf[..len]).unwrap();
            assert_eq!(request.msg_type, REFRESH_REQUEST);

            // Verify lifetime=0
            let lifetime_attr = request.attributes.iter().find(|a| {
                matches!(a, StunAttribute::Unknown(t, _) if *t == ATTR_LIFETIME)
            });
            if let Some(StunAttribute::Unknown(_, data)) = lifetime_attr {
                let lt = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                assert_eq!(lt, 0, "Deallocate should send lifetime=0");
            } else {
                panic!("Deallocate request should have LIFETIME attribute");
            }

            let success_resp = StunMessage {
                msg_type: REFRESH_SUCCESS,
                transaction_id: request.transaction_id,
                attributes: vec![StunAttribute::Unknown(
                    ATTR_LIFETIME,
                    0u32.to_be_bytes().to_vec(),
                )],
            };
            let resp_data = success_resp.marshal();
            server_socket.send_to(&resp_data, client_addr).await.unwrap();
        });

        let client = TurnClient::new(server_addr, "user", "pass", "realm");
        *client.state.lock() = TurnState::Allocated;
        *client.allocation.lock() = Some(TurnAllocation {
            relayed_addr: "198.51.100.1:49152".parse().unwrap(),
            mapped_addr: "203.0.113.50:32853".parse().unwrap(),
            lifetime: 600,
        });

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let result = client.deallocate(&socket).await;
        assert!(result.is_ok());
        assert_eq!(client.state(), TurnState::Expired);
        assert!(client.allocation().is_none());

        server_handle.await.unwrap();
    }

    /// Test the full lifecycle: Allocate -> CreatePermission -> ChannelBind -> Deallocate
    #[tokio::test]
    async fn test_full_lifecycle_with_mock_server() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let relay_addr: SocketAddr = "198.51.100.1:49152".parse().unwrap();
        let mapped_addr: SocketAddr = "203.0.113.50:32853".parse().unwrap();

        let server_handle = tokio::spawn(async move {
            let mut buf = [0u8; 1500];

            // 1) Allocate (unauthenticated) -> 401
            let (len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
            let req = StunMessage::unmarshal(&buf[..len]).unwrap();
            assert_eq!(req.msg_type, ALLOCATE_REQUEST);
            let err = StunMessage {
                msg_type: ALLOCATE_ERROR,
                transaction_id: req.transaction_id,
                attributes: vec![
                    StunAttribute::ErrorCode {
                        code: 401,
                        reason: "Unauthorized".to_string(),
                    },
                    StunAttribute::Unknown(ATTR_REALM, b"lifecycle.test".to_vec()),
                    StunAttribute::Unknown(ATTR_NONCE, b"nonce-42".to_vec()),
                ],
            };
            server_socket
                .send_to(&err.marshal(), client_addr)
                .await
                .unwrap();

            // 2) Allocate (authenticated) -> success
            let (len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
            let req = StunMessage::unmarshal(&buf[..len]).unwrap();
            assert_eq!(req.msg_type, ALLOCATE_REQUEST);
            let relay_enc = encode_xor_address(&relay_addr, &req.transaction_id);
            let ok = StunMessage {
                msg_type: ALLOCATE_SUCCESS,
                transaction_id: req.transaction_id,
                attributes: vec![
                    StunAttribute::Unknown(ATTR_XOR_RELAYED_ADDRESS, relay_enc),
                    StunAttribute::XorMappedAddress(mapped_addr),
                    StunAttribute::Unknown(ATTR_LIFETIME, 600u32.to_be_bytes().to_vec()),
                ],
            };
            server_socket
                .send_to(&ok.marshal(), client_addr)
                .await
                .unwrap();

            // 3) CreatePermission -> success
            let (len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
            let req = StunMessage::unmarshal(&buf[..len]).unwrap();
            assert_eq!(req.msg_type, CREATE_PERMISSION_REQUEST);
            let ok = StunMessage {
                msg_type: CREATE_PERMISSION_SUCCESS,
                transaction_id: req.transaction_id,
                attributes: vec![],
            };
            server_socket
                .send_to(&ok.marshal(), client_addr)
                .await
                .unwrap();

            // 4) ChannelBind -> success
            let (len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
            let req = StunMessage::unmarshal(&buf[..len]).unwrap();
            assert_eq!(req.msg_type, CHANNEL_BIND_REQUEST);
            let ok = StunMessage {
                msg_type: CHANNEL_BIND_SUCCESS,
                transaction_id: req.transaction_id,
                attributes: vec![],
            };
            server_socket
                .send_to(&ok.marshal(), client_addr)
                .await
                .unwrap();

            // 5) Deallocate (Refresh lifetime=0) -> success
            let (len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
            let req = StunMessage::unmarshal(&buf[..len]).unwrap();
            assert_eq!(req.msg_type, REFRESH_REQUEST);
            let ok = StunMessage {
                msg_type: REFRESH_SUCCESS,
                transaction_id: req.transaction_id,
                attributes: vec![StunAttribute::Unknown(
                    ATTR_LIFETIME,
                    0u32.to_be_bytes().to_vec(),
                )],
            };
            server_socket
                .send_to(&ok.marshal(), client_addr)
                .await
                .unwrap();
        });

        // Client side: full lifecycle
        let mut client = TurnClient::new(server_addr, "user", "pass", "initial");
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Allocate
        let alloc = client.allocate(&socket).await.unwrap();
        assert_eq!(alloc.relayed_addr, relay_addr);
        assert_eq!(alloc.mapped_addr, mapped_addr);
        assert_eq!(alloc.lifetime, 600);
        assert_eq!(client.state(), TurnState::Allocated);

        // CreatePermission
        client
            .create_permission(&socket, "10.0.0.1:5060".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(client.state(), TurnState::Allocated);

        // ChannelBind
        client
            .channel_bind(&socket, "10.0.0.1:5060".parse().unwrap(), 0x4000)
            .await
            .unwrap();
        assert_eq!(client.state(), TurnState::ChannelBound);

        // Deallocate
        client.deallocate(&socket).await.unwrap();
        assert_eq!(client.state(), TurnState::Expired);
        assert!(client.allocation().is_none());

        server_handle.await.unwrap();
    }

    /// Test transaction timeout
    #[tokio::test]
    async fn test_allocate_timeout() {
        // Bind a server that never responds
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let mut client = TurnClient::new(server_addr, "user", "pass", "realm");
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // This should timeout after retries (with MAX_RETRIES=7 and
        // exponential backoff, total time can be ~72 seconds)
        let result = tokio::time::timeout(
            Duration::from_secs(120),
            client.allocate(&socket),
        )
        .await;

        match result {
            Ok(Err(RtpSipError::Timeout(_))) => {} // expected
            Ok(Err(e)) => panic!("Expected Timeout error, got: {}", e),
            Ok(Ok(_)) => panic!("Expected timeout, got success"),
            Err(_) => panic!("Test itself timed out"),
        }

        // State should be back to Init after timeout
        assert_eq!(client.state(), TurnState::Init);
    }

    /// Test that messages are properly serializable and roundtrip through marshal/unmarshal
    #[test]
    fn test_turn_message_roundtrip() {
        let msg = new_turn_message(ALLOCATE_REQUEST);
        let data = msg.marshal();
        let parsed = StunMessage::unmarshal(&data).unwrap();
        assert_eq!(parsed.msg_type, ALLOCATE_REQUEST);
        assert_eq!(parsed.transaction_id, msg.transaction_id);
    }

    #[test]
    fn test_turn_message_with_attributes_roundtrip() {
        let mut msg = new_turn_message(ALLOCATE_REQUEST);
        msg.add_attribute(StunAttribute::Unknown(
            ATTR_REQUESTED_TRANSPORT,
            encode_requested_transport(17),
        ));
        msg.add_attribute(StunAttribute::Unknown(
            ATTR_LIFETIME,
            encode_lifetime(600),
        ));

        let data = msg.marshal();
        let parsed = StunMessage::unmarshal(&data).unwrap();
        assert_eq!(parsed.msg_type, ALLOCATE_REQUEST);
        assert_eq!(parsed.attributes.len(), 2);

        // Verify attributes survived roundtrip
        if let StunAttribute::Unknown(t, d) = &parsed.attributes[0] {
            assert_eq!(*t, ATTR_REQUESTED_TRANSPORT);
            assert_eq!(d, &[17, 0, 0, 0]);
        } else {
            panic!("Expected Unknown attribute");
        }

        if let StunAttribute::Unknown(t, d) = &parsed.attributes[1] {
            assert_eq!(*t, ATTR_LIFETIME);
            assert_eq!(
                u32::from_be_bytes([d[0], d[1], d[2], d[3]]),
                600
            );
        } else {
            panic!("Expected Unknown attribute");
        }
    }
}
