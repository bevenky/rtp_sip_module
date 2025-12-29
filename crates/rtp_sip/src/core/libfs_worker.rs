//! libfs Worker Thread
//!
//! All libfs operations run on a single dedicated thread to maintain
//! thread affinity. This allows async Python code to create sessions
//! concurrently without blocking.
//!
//! Architecture:
//! ```text
//! Python async code
//!       |
//!       v
//! Tokio runtime (multi-threaded)
//!       |
//!       v (via channel)
//! libfs Worker (single thread)
//!       |
//!       v
//! libfs FFI calls
//! ```
//!
//! ## Graceful Shutdown
//!
//! Call `LibFsWorker::shutdown()` to gracefully stop the worker:
//! 1. Stops accepting new commands
//! 2. Destroys all active RTP sessions
//! 3. Shuts down libfs core
//! 4. Waits for worker thread to exit

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use libfs_sys::{
    switch_core_destroy_memory_pool, switch_core_new_memory_pool,
    switch_memory_pool_t, switch_rtp_destroy, switch_rtp_new,
    switch_rtp_set_remote_address, switch_rtp_t,
    switch_rtp_get_rtp_socket, switch_socket_fd_get,
    switch_call_cause_t, switch_core_session_t, switch_event_create, switch_event_destroy,
    switch_event_t, switch_ivr_originate, SWITCH_CAUSE_NONE, SWITCH_EVENT_CLONE,
    SOF_NONE,
    RTP_PAYLOAD_PCMA, RTP_PAYLOAD_PCMU, SWITCH_FALSE, SWITCH_STATUS_SUCCESS,
    SWITCH_RTP_FLAG_AUTOADJ, SWITCH_RTP_FLAG_IO,
};

use crate::core::audio::Codec;
use crate::core::error::{Error, Result};
use crate::core::runtime::Runtime;

/// Global libfs worker instance
static LIBFS_WORKER: OnceCell<LibFsWorker> = OnceCell::new();

/// Commands sent to the libfs worker thread
pub(crate) enum FsCommand {
    /// Create a new RTP session
    CreateRtpSession {
        id: SessionId,
        local_ip: String,
        local_port: u16,
        remote_ip: String,
        remote_port: u16,
        codec: Codec,
        reply: oneshot::Sender<Result<RtpHandle>>,
    },
    /// Read a frame from an RTP session
    ReadFrame {
        handle: RtpHandle,
        reply: oneshot::Sender<Result<Option<Vec<u8>>>>,
    },
    /// Write a frame to an RTP session
    WriteFrame {
        handle: RtpHandle,
        data: Vec<u8>,
        timestamp: u32,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Destroy an RTP session
    DestroyRtpSession {
        handle: RtpHandle,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Originate a SIP call (switch_ivr_originate)
    SipOriginate {
        dial_string: String,
        timeout_sec: u32,
        caller_id_name: String,
        caller_id_number: String,
        reply: oneshot::Sender<Result<SipSessionHandle>>,
    },
    /// Shutdown the worker gracefully
    Shutdown {
        reply: oneshot::Sender<Result<()>>,
    },
}

/// Handle to a SIP session returned from originate
#[derive(Debug, Clone, Copy)]
pub struct SipSessionHandle {
    pub session: *mut switch_core_session_t,
}

// Safety: SipSessionHandle is only used via the worker thread
unsafe impl Send for SipSessionHandle {}
unsafe impl Sync for SipSessionHandle {}

/// Unique session ID for tracking active sessions
type SessionId = u64;

/// Handle to an RTP session (opaque pointer wrapper)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RtpHandle {
    id: SessionId,
    rtp: *mut switch_rtp_t,
    pool: *mut switch_memory_pool_t,
    payload_type: u8,
    ssrc: u32,
    /// Remote address for direct socket sends
    remote_addr: std::net::SocketAddr,
}

/// Sequence number counter (global for all sessions for simplicity)
static SEQ_COUNTER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

// Safety: RtpHandle is only used via the worker thread
unsafe impl Send for RtpHandle {}
unsafe impl Sync for RtpHandle {}

/// libfs worker that runs all FS operations on a dedicated thread
pub struct LibFsWorker {
    pub(crate) sender: mpsc::Sender<FsCommand>,
    running: Arc<AtomicBool>,
    handle: Mutex<Option<JoinHandle<()>>>,
    /// Counter for generating unique session IDs
    next_session_id: AtomicU64,
}

impl LibFsWorker {
    /// Get or create the global libfs worker
    pub fn get() -> Result<&'static LibFsWorker> {
        LIBFS_WORKER.get_or_try_init(|| Self::new())
    }

    /// Get the worker if it's already initialized (doesn't create new one)
    pub fn get_if_initialized() -> Option<&'static LibFsWorker> {
        LIBFS_WORKER.get()
    }

    /// Check if the worker is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get the number of active sessions (approximate)
    pub fn active_session_count(&self) -> u64 {
        // This is the total sessions created, not necessarily active
        // For accurate count, we'd need to query the worker thread
        self.next_session_id.load(Ordering::Relaxed)
    }

    /// Create a new libfs worker
    fn new() -> Result<Self> {
        let (sender, receiver) = mpsc::channel::<FsCommand>(256);
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        // Spawn dedicated thread for libfs operations
        let handle = thread::Builder::new()
            .name("freeswitch-worker".to_string())
            .spawn(move || {
                Self::worker_loop(receiver, running_clone);
            })
            .map_err(|e| Error::Runtime(format!("Failed to spawn FS worker: {}", e)))?;

        Ok(Self {
            sender,
            running,
            handle: Mutex::new(Some(handle)),
            next_session_id: AtomicU64::new(0),
        })
    }

    /// Generate a unique session ID
    fn next_id(&self) -> SessionId {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Worker thread main loop
    fn worker_loop(mut receiver: mpsc::Receiver<FsCommand>, running: Arc<AtomicBool>) {
        info!("libfs worker thread started");

        // Check if libfs is already initialized
        // The mode should have been set by the caller (SipTransport or RtpSession)
        let mode = Runtime::get_mode();

        if Runtime::is_freeswitch_ready() {
            info!("libfs already initialized in {} mode, worker ready", mode);
        } else {
            // Not yet initialized - the caller should have set the mode first
            // This path is taken when LibFsWorker::get() is called before
            // SipTransport::start() or RtpSession::start()
            match mode {
                crate::core::runtime::FsMode::SIP => {
                    info!("Worker initializing libfs in SIP mode");
                    if let Err(e) = Runtime::ensure_sip_mode() {
                        error!("Failed to initialize libfs in SIP mode: {:?}", e);
                        return;
                    }
                }
                crate::core::runtime::FsMode::RtpOnly => {
                    info!("Worker initializing libfs in RTP-only mode");
                    if let Err(e) = Runtime::ensure_rtp_mode() {
                        error!("Failed to initialize libfs in RTP-only mode: {:?}", e);
                        return;
                    }
                }
                crate::core::runtime::FsMode::Uninitialized => {
                    // Default to RTP-only mode if no mode was specified
                    info!("No mode specified, defaulting to RTP-only mode");
                    if let Err(e) = Runtime::ensure_rtp_mode() {
                        error!("Failed to initialize libfs in RTP-only mode: {:?}", e);
                        return;
                    }
                }
            }
        }

        info!("libfs worker ready");

        // Track active sessions for graceful shutdown
        let mut active_sessions: HashMap<SessionId, RtpHandle> = HashMap::new();

        // Process commands
        while running.load(Ordering::SeqCst) {
            match receiver.blocking_recv() {
                Some(cmd) => {
                    let should_exit = Self::handle_command(cmd, &mut active_sessions);
                    if should_exit {
                        break;
                    }
                }
                None => {
                    info!("libfs worker channel closed");
                    break;
                }
            }
        }

        // Graceful cleanup: destroy any remaining active sessions
        if !active_sessions.is_empty() {
            warn!(
                "Cleaning up {} orphaned RTP sessions during shutdown",
                active_sessions.len()
            );
            for (id, handle) in active_sessions.drain() {
                debug!("Destroying orphaned session {}", id);
                if let Err(e) = Self::destroy_rtp_session_impl(handle) {
                    error!("Failed to destroy session {}: {:?}", id, e);
                }
            }
        }

        // Shutdown libfs core
        if let Err(e) = Runtime::shutdown() {
            error!("Error during libfs shutdown: {:?}", e);
        }

        info!("libfs worker thread exiting");
    }

    /// Handle a command on the worker thread
    /// Returns true if the worker should exit
    fn handle_command(
        cmd: FsCommand,
        active_sessions: &mut HashMap<SessionId, RtpHandle>,
    ) -> bool {
        match cmd {
            FsCommand::CreateRtpSession {
                id,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                codec,
                reply,
            } => {
                let result = Self::create_rtp_session_impl(
                    id, &local_ip, local_port, &remote_ip, remote_port, codec,
                );
                if let Ok(ref handle) = result {
                    active_sessions.insert(handle.id, *handle);
                    debug!("Session {} created, active count: {}", handle.id, active_sessions.len());
                }
                let _ = reply.send(result);
                false
            }

            FsCommand::ReadFrame { handle, reply } => {
                let result = Self::read_frame_impl(handle);
                let _ = reply.send(result);
                false
            }

            FsCommand::WriteFrame { handle, data, timestamp, reply } => {
                let result = Self::write_frame_impl(handle, &data, timestamp);
                let _ = reply.send(result);
                false
            }

            FsCommand::DestroyRtpSession { handle, reply } => {
                active_sessions.remove(&handle.id);
                let result = Self::destroy_rtp_session_impl(handle);
                debug!("Session {} destroyed, active count: {}", handle.id, active_sessions.len());
                let _ = reply.send(result);
                false
            }

            FsCommand::SipOriginate {
                dial_string,
                timeout_sec,
                caller_id_name,
                caller_id_number,
                reply,
            } => {
                let result = Self::sip_originate_impl(
                    &dial_string,
                    timeout_sec,
                    &caller_id_name,
                    &caller_id_number,
                );
                let _ = reply.send(result);
                false
            }

            FsCommand::Shutdown { reply } => {
                info!(
                    "libfs worker received shutdown command, {} active sessions",
                    active_sessions.len()
                );
                let _ = reply.send(Ok(()));
                true // Signal to exit the loop
            }
        }
    }

    /// Create RTP session implementation (runs on worker thread)
    fn create_rtp_session_impl(
        id: SessionId,
        local_ip: &str,
        local_port: u16,
        remote_ip: &str,
        remote_port: u16,
        codec: Codec,
    ) -> Result<RtpHandle> {
        debug!(
            "Creating RTP session {}: local={}:{}, remote={}:{}",
            id, local_ip, local_port, remote_ip, remote_port
        );

        // Create memory pool
        let pool = unsafe {
            let mut pool: *mut switch_memory_pool_t = ptr::null_mut();
            let status = switch_core_new_memory_pool(
                &mut pool,
                b"pyswitch_rtp\0".as_ptr() as *const libc::c_char,
                b"LibFsWorker::create\0".as_ptr() as *const libc::c_char,
                0,
            );
            if status != SWITCH_STATUS_SUCCESS || pool.is_null() {
                return Err(Error::Rtp("Failed to create memory pool".to_string()));
            }
            pool
        };

        // Prepare parameters
        let rx_host = CString::new(local_ip)
            .map_err(|_| Error::Rtp("Invalid local IP".to_string()))?;
        let tx_host = CString::new(remote_ip)
            .map_err(|_| Error::Rtp("Invalid remote IP".to_string()))?;

        let payload = match codec {
            Codec::Pcmu => RTP_PAYLOAD_PCMU,
            Codec::Pcma => RTP_PAYLOAD_PCMA,
            Codec::L16 => {
                return Err(Error::Rtp("L16 not supported, use PCMU or PCMA".to_string()));
            }
        };

        // Create RTP session
        // NOTE: SWITCH_RTP_FLAG_NOBLOCK = 0, so it acts as NULL terminator in flags array
        // We must NOT include NOBLOCK in the flags array! Only non-zero flags should be passed.
        let rtp = unsafe {
            let mut err: *const libc::c_char = ptr::null();
            // Flags array: only non-zero flags, then NULL terminator
            // NOBLOCK (=0) cannot be in array as it terminates the loop
            let flags: [libfs_sys::switch_rtp_flag_t; 3] = [
                SWITCH_RTP_FLAG_IO,      // = 2: Enable I/O operations
                SWITCH_RTP_FLAG_AUTOADJ, // = 7: Auto-adjust destination based on incoming packets
                0,                       // NULL terminator
            ];
            let samples_per_interval = 8000 / 50; // 160 samples for 20ms @ 8kHz
            let ms_per_packet = 20;

            let rtp = switch_rtp_new(
                rx_host.as_ptr(),
                local_port,
                tx_host.as_ptr(),
                remote_port,
                payload,
                samples_per_interval,
                ms_per_packet,
                flags.as_ptr(),
                ptr::null(), // No timer
                &mut err,
                pool,
                0,
                0,
            );

            if rtp.is_null() {
                let err_msg = if !err.is_null() {
                    CStr::from_ptr(err).to_string_lossy().to_string()
                } else {
                    "Unknown error".to_string()
                };

                // Clean up pool
                let mut pool_ptr = pool;
                switch_core_destroy_memory_pool(
                    &mut pool_ptr,
                    b"pyswitch_rtp\0".as_ptr() as *const libc::c_char,
                    b"LibFsWorker::create\0".as_ptr() as *const libc::c_char,
                    0,
                );

                return Err(Error::Rtp(format!("switch_rtp_new failed: {}", err_msg)));
            }

            rtp
        };

        // Explicitly set flags using switch_rtp_set_flag to ensure they're set
        unsafe {
            libfs_sys::switch_rtp_set_flag(rtp, SWITCH_RTP_FLAG_IO);
            libfs_sys::switch_rtp_set_flag(rtp, SWITCH_RTP_FLAG_AUTOADJ);
        }

        // Check IO flag is set
        let io_set = unsafe { libfs_sys::switch_rtp_test_flag(rtp, SWITCH_RTP_FLAG_IO) };
        info!("SWITCH_RTP_FLAG_IO set: {}", io_set);

        // Set remote address - this should create sock_output when IO flag is set
        let remote_status = unsafe {
            let mut err: *const libc::c_char = ptr::null();
            let status = switch_rtp_set_remote_address(
                rtp,
                tx_host.as_ptr(),
                remote_port,
                0,
                SWITCH_FALSE,
                &mut err,
            );
            if status != SWITCH_STATUS_SUCCESS {
                let err_msg = if !err.is_null() {
                    std::ffi::CStr::from_ptr(err).to_string_lossy().to_string()
                } else {
                    format!("status={}", status)
                };
                warn!("switch_rtp_set_remote_address failed: {}", err_msg);
            }
            status
        };
        info!("switch_rtp_set_remote_address returned: {}", remote_status);

        // Check if session is ready
        let ready = unsafe { libfs_sys::switch_rtp_ready(rtp) };
        info!("switch_rtp_ready returned: {}", ready);

        // Generate random SSRC for this session
        let ssrc = rand::random::<u32>();

        // Parse remote address for direct socket sends
        let remote_addr: std::net::SocketAddr = format!("{}:{}", remote_ip, remote_port)
            .parse()
            .map_err(|e| Error::Rtp(format!("Invalid remote address: {}", e)))?;

        info!("RTP session {} created with flags: IO, AUTOADJ, ssrc={}, remote={}", id, ssrc, remote_addr);
        Ok(RtpHandle { id, rtp, pool, payload_type: payload, ssrc, remote_addr })
    }

    /// Read frame implementation (runs on worker thread)
    /// Uses raw socket read since switch_rtp_read doesn't work in embedded mode
    fn read_frame_impl(handle: RtpHandle) -> Result<Option<Vec<u8>>> {
        // Get the socket file descriptor from FreeSWITCH RTP session
        let fd = unsafe {
            let socket = switch_rtp_get_rtp_socket(handle.rtp);
            if socket.is_null() {
                return Err(Error::Rtp("RTP socket is null".to_string()));
            }
            switch_socket_fd_get(socket)
        };

        if fd < 0 {
            return Err(Error::Rtp("Invalid socket fd".to_string()));
        }

        info!("read_frame: fd={}", fd);

        // Set socket to non-blocking for this read
        let mut recv_buf = vec![0u8; 2048]; // Max RTP packet size

        let bytes_read = unsafe {
            libc::recv(
                fd,
                recv_buf.as_mut_ptr() as *mut libc::c_void,
                recv_buf.len(),
                libc::MSG_DONTWAIT, // Non-blocking
            )
        };

        info!("recv returned: {}", bytes_read);

        if bytes_read <= 0 {
            // EAGAIN/EWOULDBLOCK means no data available (normal for non-blocking)
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            info!("recv errno: {} (EAGAIN={})", errno, libc::EAGAIN);
            if bytes_read == 0 || errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                return Ok(None);
            }
            // Actual error
            info!("recv error: {}", std::io::Error::last_os_error());
            return Ok(None);
        }

        let bytes_read = bytes_read as usize;

        // RTP header is 12 bytes minimum
        if bytes_read < 12 {
            debug!("RTP packet too small: {} bytes", bytes_read);
            return Ok(None);
        }

        // Parse RTP header to extract payload
        // Byte 0: V(2) P(1) X(1) CC(4)
        // Byte 1: M(1) PT(7)
        let version = (recv_buf[0] >> 6) & 0x03;
        if version != 2 {
            debug!("Invalid RTP version: {}", version);
            return Ok(None);
        }

        let has_padding = (recv_buf[0] >> 5) & 0x01 == 1;
        let has_extension = (recv_buf[0] >> 4) & 0x01 == 1;
        let csrc_count = (recv_buf[0] & 0x0F) as usize;
        let payload_type = recv_buf[1] & 0x7F;

        // Calculate header size
        let mut header_size = 12 + (csrc_count * 4);

        // Handle extension header if present
        if has_extension && bytes_read > header_size + 4 {
            let ext_length = u16::from_be_bytes([recv_buf[header_size + 2], recv_buf[header_size + 3]]) as usize;
            header_size += 4 + (ext_length * 4);
        }

        if bytes_read <= header_size {
            debug!("No RTP payload: header={}, total={}", header_size, bytes_read);
            return Ok(None);
        }

        let mut payload_end = bytes_read;

        // Handle padding if present
        if has_padding && bytes_read > header_size {
            let padding_len = recv_buf[bytes_read - 1] as usize;
            if padding_len < payload_end - header_size {
                payload_end -= padding_len;
            }
        }

        // Extract payload
        let payload = recv_buf[header_size..payload_end].to_vec();

        debug!(
            "RTP recv: {} bytes total, pt={}, payload={} bytes",
            bytes_read, payload_type, payload.len()
        );

        Ok(Some(payload))
    }

    /// Write frame implementation (runs on worker thread)
    /// Uses direct socket sendto() since FreeSWITCH's sock_output may not be initialized in standalone mode
    fn write_frame_impl(handle: RtpHandle, data: &[u8], timestamp: u32) -> Result<()> {
        // Build RTP packet manually
        // RTP Header (12 bytes):
        // Byte 0: V=2, P=0, X=0, CC=0 => 0x80
        // Byte 1: M=0, PT=payload_type
        // Bytes 2-3: Sequence number (big-endian)
        // Bytes 4-7: Timestamp (big-endian)
        // Bytes 8-11: SSRC (big-endian)
        let seq = SEQ_COUNTER.fetch_add(1, Ordering::SeqCst);

        let mut packet = Vec::with_capacity(12 + data.len());
        packet.push(0x80); // V=2, P=0, X=0, CC=0
        packet.push(handle.payload_type); // M=0, PT
        packet.extend_from_slice(&seq.to_be_bytes()); // Sequence number
        packet.extend_from_slice(&timestamp.to_be_bytes()); // Timestamp
        packet.extend_from_slice(&handle.ssrc.to_be_bytes()); // SSRC
        packet.extend_from_slice(data); // Payload

        // Get the socket fd from FreeSWITCH session
        let fd = unsafe {
            let socket = switch_rtp_get_rtp_socket(handle.rtp);
            if socket.is_null() {
                return Err(Error::Rtp("RTP socket is null".to_string()));
            }
            switch_socket_fd_get(socket)
        };

        if fd < 0 {
            return Err(Error::Rtp("Invalid socket fd".to_string()));
        }

        // Use direct sendto() to send the packet to the remote address
        // This bypasses FreeSWITCH's sock_output which may not be initialized
        let bytes_sent = match handle.remote_addr {
            std::net::SocketAddr::V4(addr) => {
                let sockaddr = libc::sockaddr_in {
                    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
                    sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: addr.port().to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(addr.ip().octets()),
                    },
                    sin_zero: [0; 8],
                };
                unsafe {
                    libc::sendto(
                        fd,
                        packet.as_ptr() as *const libc::c_void,
                        packet.len(),
                        0,
                        &sockaddr as *const libc::sockaddr_in as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                }
            }
            std::net::SocketAddr::V6(addr) => {
                let sockaddr = libc::sockaddr_in6 {
                    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
                    sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: addr.port().to_be(),
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr {
                        s6_addr: addr.ip().octets(),
                    },
                    sin6_scope_id: 0,
                };
                unsafe {
                    libc::sendto(
                        fd,
                        packet.as_ptr() as *const libc::c_void,
                        packet.len(),
                        0,
                        &sockaddr as *const libc::sockaddr_in6 as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    )
                }
            }
        };

        if bytes_sent < 0 {
            let errno = std::io::Error::last_os_error();
            warn!(
                "write_frame sendto FAILED: fd={}, errno={}, ts={}, seq={}",
                fd, errno, timestamp, seq
            );
            return Err(Error::Rtp(format!("sendto failed: {}", errno)));
        }

        debug!(
            "write_frame OK: fd={}, bytes_sent={}, ts={}, seq={}",
            fd, bytes_sent, timestamp, seq
        );

        Ok(())
    }

    /// Destroy RTP session implementation (runs on worker thread)
    fn destroy_rtp_session_impl(handle: RtpHandle) -> Result<()> {
        debug!("Destroying RTP session: rtp={:?}", handle.rtp);

        unsafe {
            let mut rtp_ptr = handle.rtp;
            switch_rtp_destroy(&mut rtp_ptr);

            let mut pool_ptr = handle.pool;
            switch_core_destroy_memory_pool(
                &mut pool_ptr,
                b"pyswitch_rtp\0".as_ptr() as *const libc::c_char,
                b"LibFsWorker::destroy\0".as_ptr() as *const libc::c_char,
                0,
            );
        }

        Ok(())
    }

    /// SIP originate implementation (runs on worker thread)
    ///
    /// This is the key fix: switch_ivr_originate() is now called on the
    /// same thread that initialized FreeSWITCH, ensuring proper thread affinity.
    fn sip_originate_impl(
        dial_string: &str,
        timeout_sec: u32,
        caller_id_name: &str,
        caller_id_number: &str,
    ) -> Result<SipSessionHandle> {
        use std::ffi::CString;

        info!(
            "SIP originate on worker thread: dial_string={}, timeout={}s",
            dial_string, timeout_sec
        );

        // Check if FreeSWITCH is ready
        if !Runtime::is_freeswitch_ready() {
            error!("FreeSWITCH core not ready for SIP originate");
            return Err(Error::Sip(
                "FreeSWITCH core not ready - mod_sofia may not be loaded".to_string(),
            ));
        }

        let dial_string_c = CString::new(dial_string)
            .map_err(|_| Error::Sip("Invalid dial string".to_string()))?;
        let cid_name_c = CString::new(caller_id_name)
            .map_err(|_| Error::Sip("Invalid caller ID name".to_string()))?;
        let cid_number_c = CString::new(caller_id_number)
            .map_err(|_| Error::Sip("Invalid caller ID number".to_string()))?;

        let mut new_session: *mut switch_core_session_t = std::ptr::null_mut();
        let mut cause: switch_call_cause_t = SWITCH_CAUSE_NONE;

        // Create variables event for the call
        let mut ovars: *mut switch_event_t = std::ptr::null_mut();
        unsafe {
            if switch_event_create(&mut ovars, SWITCH_EVENT_CLONE) == SWITCH_STATUS_SUCCESS {
                // Variables event created
            }
        }

        // Originate the call via libfs - ON THE WORKER THREAD
        let status = unsafe {
            switch_ivr_originate(
                std::ptr::null_mut(), // No existing session
                &mut new_session,
                &mut cause,
                dial_string_c.as_ptr(),
                timeout_sec,
                std::ptr::null(),      // No state handlers
                cid_name_c.as_ptr(),
                cid_number_c.as_ptr(),
                std::ptr::null_mut(),  // No caller profile override
                ovars,
                SOF_NONE,
                std::ptr::null_mut(),  // No cancel cause
            )
        };

        // Clean up event
        unsafe {
            if !ovars.is_null() {
                switch_event_destroy(&mut ovars);
            }
        }

        if status != SWITCH_STATUS_SUCCESS || new_session.is_null() {
            let cause_str = match cause {
                libfs_sys::SWITCH_CAUSE_USER_BUSY => "User busy",
                libfs_sys::SWITCH_CAUSE_NO_ANSWER => "No answer",
                libfs_sys::SWITCH_CAUSE_CALL_REJECTED => "Call rejected",
                libfs_sys::SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER => "Destination out of order",
                libfs_sys::SWITCH_CAUSE_NORMAL_TEMPORARY_FAILURE => "Temporary failure",
                _ => "Unknown error",
            };
            error!(
                "SIP originate failed: {} (cause: {}, status: {})",
                cause_str, cause, status
            );
            return Err(Error::Call(format!("Dial failed: {}", cause_str)));
        }

        info!("SIP originate successful, session={:?}", new_session);
        Ok(SipSessionHandle { session: new_session })
    }

    // ========================================================================
    // Public async API
    // ========================================================================

    /// Create a new RTP session asynchronously
    pub async fn create_rtp_session(
        &self,
        local_ip: String,
        local_port: u16,
        remote_ip: String,
        remote_port: u16,
        codec: Codec,
    ) -> Result<RtpHandle> {
        if !self.is_running() {
            return Err(Error::Runtime("FS worker is not running".to_string()));
        }

        let id = self.next_id();
        let (reply_tx, reply_rx) = oneshot::channel();

        self.sender
            .send(FsCommand::CreateRtpSession {
                id,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                codec,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Error::Runtime("FS worker channel closed".to_string()))?;

        reply_rx
            .await
            .map_err(|_| Error::Runtime("FS worker reply channel closed".to_string()))?
    }

    /// Read a frame from an RTP session asynchronously
    pub async fn read_frame(&self, handle: RtpHandle) -> Result<Option<Vec<u8>>> {
        let (reply_tx, reply_rx) = oneshot::channel();

        self.sender
            .send(FsCommand::ReadFrame {
                handle,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Error::Runtime("FS worker channel closed".to_string()))?;

        reply_rx
            .await
            .map_err(|_| Error::Runtime("FS worker reply channel closed".to_string()))?
    }

    /// Write a frame to an RTP session asynchronously
    pub async fn write_frame(&self, handle: RtpHandle, data: Vec<u8>, timestamp: u32) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();

        self.sender
            .send(FsCommand::WriteFrame {
                handle,
                data,
                timestamp,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Error::Runtime("FS worker channel closed".to_string()))?;

        reply_rx
            .await
            .map_err(|_| Error::Runtime("FS worker reply channel closed".to_string()))?
    }

    /// Destroy an RTP session asynchronously
    pub async fn destroy_rtp_session(&self, handle: RtpHandle) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();

        self.sender
            .send(FsCommand::DestroyRtpSession {
                handle,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Error::Runtime("FS worker channel closed".to_string()))?;

        reply_rx
            .await
            .map_err(|_| Error::Runtime("FS worker reply channel closed".to_string()))?
    }

    /// Originate a SIP call asynchronously
    ///
    /// This sends the originate command to the worker thread, which ensures
    /// the FFI call happens on the thread that initialized FreeSWITCH.
    pub async fn sip_originate(
        &self,
        dial_string: String,
        timeout_sec: u32,
        caller_id_name: String,
        caller_id_number: String,
    ) -> Result<SipSessionHandle> {
        if !self.is_running() {
            return Err(Error::Runtime("FS worker is not running".to_string()));
        }

        let (reply_tx, reply_rx) = oneshot::channel();

        self.sender
            .send(FsCommand::SipOriginate {
                dial_string,
                timeout_sec,
                caller_id_name,
                caller_id_number,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Error::Runtime("FS worker channel closed".to_string()))?;

        reply_rx
            .await
            .map_err(|_| Error::Runtime("FS worker reply channel closed".to_string()))?
    }

    /// Gracefully shutdown the libfs worker
    ///
    /// This will:
    /// 1. Stop accepting new commands
    /// 2. Destroy all active RTP sessions
    /// 3. Shutdown libfs core
    /// 4. Wait for the worker thread to exit
    ///
    /// Returns Ok(()) on success, or an error if shutdown fails.
    pub async fn shutdown(&self) -> Result<()> {
        if !self.running.swap(false, Ordering::SeqCst) {
            // Already shut down
            return Ok(());
        }

        info!("Initiating graceful shutdown of libfs worker");

        let (reply_tx, reply_rx) = oneshot::channel();

        // Send shutdown command
        self.sender
            .send(FsCommand::Shutdown { reply: reply_tx })
            .await
            .map_err(|_| Error::Runtime("Failed to send shutdown command".to_string()))?;

        // Wait for acknowledgment
        reply_rx
            .await
            .map_err(|_| Error::Runtime("Shutdown reply channel closed".to_string()))??;

        info!("libfs worker shutdown complete");
        Ok(())
    }

    /// Shutdown synchronously (for use in drop or signal handlers)
    ///
    /// This is a blocking version of shutdown() for use when async is not available.
    /// Note: During Python atexit, we avoid blocking on thread join to prevent
    /// GIL-related crashes when Python is finalizing.
    pub fn shutdown_sync(&self) -> Result<()> {
        if !self.running.swap(false, Ordering::SeqCst) {
            return Ok(());
        }

        info!("Initiating synchronous shutdown of libfs worker");

        let (reply_tx, mut reply_rx) = oneshot::channel();

        // Send shutdown command (blocking) with short timeout
        match self.sender.blocking_send(FsCommand::Shutdown { reply: reply_tx }) {
            Ok(_) => {
                // Wait for acknowledgment with timeout using a simple loop
                // Don't block forever during atexit as Python may be finalizing
                let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
                loop {
                    match reply_rx.try_recv() {
                        Ok(result) => {
                            if let Err(e) = result {
                                warn!("Worker shutdown returned error: {}", e);
                            }
                            break;
                        }
                        Err(oneshot::error::TryRecvError::Empty) => {
                            if std::time::Instant::now() >= deadline {
                                debug!("Shutdown timed out, worker may be blocked");
                                break;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                        Err(oneshot::error::TryRecvError::Closed) => {
                            debug!("Shutdown reply channel closed");
                            break;
                        }
                    }
                }
            }
            Err(_) => {
                debug!("Channel closed, worker may have already exited");
            }
        }

        // Take the thread handle but don't join it during atexit
        // Joining can cause GIL issues when Python is finalizing
        // The OS will clean up the thread when the process exits
        if let Some(_handle) = self.handle.lock().take() {
            debug!("Worker thread handle released (not joining during shutdown)");
        }

        info!("libfs worker synchronous shutdown complete");
        Ok(())
    }
}

impl Drop for LibFsWorker {
    fn drop(&mut self) {
        // Best-effort shutdown on drop
        if self.running.load(Ordering::SeqCst) {
            warn!("LibFsWorker dropped without explicit shutdown, attempting cleanup");
            let _ = self.shutdown_sync();
        }
    }
}
