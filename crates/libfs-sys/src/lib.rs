//! Low-level FFI bindings for libfs RTP and audio APIs
//!
//! This crate provides manual FFI bindings to libfs's C API.
//! Focused on RTP, resampling, and core audio functions needed for pyswitch.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(clippy::all)]

use libc::{c_char, c_int, c_void};

pub use libc;

// ============================================================================
// Basic Types
// ============================================================================

pub type switch_status_t = c_int;
pub type switch_bool_t = c_int;
pub type switch_payload_t = u8;
pub type switch_rtp_flag_t = u32;
pub type switch_frame_flag_t = u32;
pub type switch_io_flag_t = u32;
pub type switch_size_t = libc::size_t;

// ============================================================================
// Status Codes
// ============================================================================

pub const SWITCH_STATUS_SUCCESS: switch_status_t = 0;
pub const SWITCH_STATUS_FALSE: switch_status_t = 1;
pub const SWITCH_STATUS_TIMEOUT: switch_status_t = 2;
pub const SWITCH_STATUS_RESTART: switch_status_t = 3;
pub const SWITCH_STATUS_TERM: switch_status_t = 6;

pub const SWITCH_TRUE: switch_bool_t = 1;
pub const SWITCH_FALSE: switch_bool_t = 0;

// ============================================================================
// Core Flags (for switch_core_init)
// ============================================================================

pub type switch_core_flag_t = u32;

/// Minimal core initialization (no console, no modules)
pub const SCF_NONE: switch_core_flag_t = 0;
/// Use SQL for call state
pub const SCF_USE_SQL: switch_core_flag_t = 1 << 0;
/// Enable auto NAT detection
pub const SCF_AUTO_NAT: switch_core_flag_t = 1 << 1;
/// Disable NAT detection
pub const SCF_NO_NAT: switch_core_flag_t = 1 << 2;
/// Disable auto schemas
pub const SCF_NO_AUTO_SCHEMAS: switch_core_flag_t = 1 << 3;
/// Use heavy timing
pub const SCF_USE_HEAVY_TIMING: switch_core_flag_t = 1 << 4;
/// Use clock RT
pub const SCF_USE_CLOCK_RT: switch_core_flag_t = 1 << 5;
/// Verbose events
pub const SCF_VERBOSE_EVENTS: switch_core_flag_t = 1 << 6;
/// Use NANOSLEEP for timing
pub const SCF_USE_NANOSLEEP: switch_core_flag_t = 1 << 7;
/// Minimal initialization
pub const SCF_MINIMAL: switch_core_flag_t = 1 << 8;
/// Calibrate clock
pub const SCF_CALIBRATE_CLOCK: switch_core_flag_t = 1 << 9;
/// Use COND timerfd
pub const SCF_USE_COND_TIMING: switch_core_flag_t = 1 << 10;
/// API expansion
pub const SCF_API_EXPANSION: switch_core_flag_t = 1 << 11;

// ============================================================================
// Session Control
// ============================================================================

pub type switch_session_ctl_t = c_int;

/// Shutdown gracefully
pub const SCSC_SHUTDOWN_ELEGANT: switch_session_ctl_t = 5;
/// Shutdown now
pub const SCSC_SHUTDOWN_NOW: switch_session_ctl_t = 6;
/// Shutdown as soon as possible
pub const SCSC_SHUTDOWN_ASAP: switch_session_ctl_t = 7;
/// Cancel shutdown
pub const SCSC_CANCEL_SHUTDOWN: switch_session_ctl_t = 8;

// ============================================================================
// Opaque Types
// ============================================================================

/// Memory pool handle (opaque)
#[repr(C)]
pub struct switch_memory_pool_t {
    _opaque: [u8; 0],
}

/// RTP session handle (opaque)
#[repr(C)]
pub struct switch_rtp_t {
    _opaque: [u8; 0],
}

/// Socket handle (opaque)
#[repr(C)]
pub struct switch_socket_t {
    _opaque: [u8; 0],
}

/// Codec structure (opaque for our purposes)
#[repr(C)]
pub struct switch_codec_t {
    _opaque: [u8; 0],
}

/// Speex resampler state (opaque)
#[repr(C)]
pub struct SpeexResamplerState {
    _opaque: [u8; 0],
}

// ============================================================================
// Frame Structure
// ============================================================================

/// RTP/Audio frame structure
#[repr(C)]
#[derive(Debug)]
pub struct switch_frame_t {
    pub codec: *mut switch_codec_t,
    pub source: *const c_char,
    pub packet: *mut c_void,
    pub packetlen: u32,
    pub extra_data: *mut c_void,
    pub data: *mut c_void,
    pub datalen: u32,
    pub buflen: u32,
    pub samples: u32,
    pub rate: u32,
    pub channels: u32,
    pub payload: u8,
    pub timestamp: u32,
    pub seq: u16,
    pub ssrc: u32,
    pub m: c_int,
    pub flags: u32,
    pub user_data: *mut c_void,
    pub pmap: *mut c_void,
    pub img: *mut c_void,
}

impl Default for switch_frame_t {
    fn default() -> Self {
        Self {
            codec: std::ptr::null_mut(),
            source: std::ptr::null(),
            packet: std::ptr::null_mut(),
            packetlen: 0,
            extra_data: std::ptr::null_mut(),
            data: std::ptr::null_mut(),
            datalen: 0,
            buflen: 0,
            samples: 0,
            rate: 0,
            channels: 0,
            payload: 0,
            timestamp: 0,
            seq: 0,
            ssrc: 0,
            m: 0,
            flags: 0,
            user_data: std::ptr::null_mut(),
            pmap: std::ptr::null_mut(),
            img: std::ptr::null_mut(),
        }
    }
}

// ============================================================================
// Speex Types
// ============================================================================

pub type spx_int16_t = i16;
pub type spx_uint32_t = u32;

// ============================================================================
// RTP Payload Types
// ============================================================================

/// G.711 u-law (PCMU)
pub const RTP_PAYLOAD_PCMU: switch_payload_t = 0;
/// G.711 A-law (PCMA)
pub const RTP_PAYLOAD_PCMA: switch_payload_t = 8;

// ============================================================================
// RTP Flags
// ============================================================================

pub const SWITCH_RTP_FLAG_NOBLOCK: switch_rtp_flag_t = 0;
pub const SWITCH_RTP_FLAG_DTMF_ON: switch_rtp_flag_t = 1;
pub const SWITCH_RTP_FLAG_IO: switch_rtp_flag_t = 2;
pub const SWITCH_RTP_FLAG_USE_TIMER: switch_rtp_flag_t = 3;
pub const SWITCH_RTP_FLAG_RTCP_PASSTHRU: switch_rtp_flag_t = 4;
pub const SWITCH_RTP_FLAG_SECURE_SEND: switch_rtp_flag_t = 5;
pub const SWITCH_RTP_FLAG_SECURE_RECV: switch_rtp_flag_t = 6;
pub const SWITCH_RTP_FLAG_AUTOADJ: switch_rtp_flag_t = 7;
pub const SWITCH_RTP_FLAG_RAW_WRITE: switch_rtp_flag_t = 9;
pub const SWITCH_RTP_FLAG_DATAWAIT: switch_rtp_flag_t = 14;
pub const SWITCH_RTP_FLAG_DEBUG_RTP_READ: switch_rtp_flag_t = 26;
pub const SWITCH_RTP_FLAG_DEBUG_RTP_WRITE: switch_rtp_flag_t = 27;
pub const SWITCH_RTP_FLAG_PROXY_MEDIA: switch_rtp_flag_t = 31;

// ============================================================================
// FFI Functions
// ============================================================================

extern "C" {
    // ========================================================================
    // APR (Apache Portable Runtime) Initialization
    // ========================================================================

    /// Initialize the Apache Portable Runtime
    /// MUST be called before switch_core_init/switch_core_init_and_modload
    pub fn fspr_initialize() -> switch_status_t;

    /// Terminate the Apache Portable Runtime
    pub fn fspr_terminate();

    // ========================================================================
    // RTP Functions
    // ========================================================================

    /// Create a new RTP session
    ///
    /// # Arguments
    /// * `rx_host` - Local host to bind for receiving (e.g., "0.0.0.0")
    /// * `rx_port` - Local port to bind
    /// * `tx_host` - Remote host to send to
    /// * `tx_port` - Remote port to send to
    /// * `payload` - RTP payload type (0=PCMU, 8=PCMA)
    /// * `samples_per_interval` - Samples per packet (160 for 20ms @ 8kHz)
    /// * `ms_per_packet` - Milliseconds per packet (20)
    /// * `flags` - RTP flags (NULL for defaults)
    /// * `timer_name` - Timer name (NULL for no timer)
    /// * `err` - Output: error message if failed
    /// * `pool` - Memory pool
    /// * `bundle_internal_ports` - Bundle internal ports (0)
    /// * `bundle_external_port` - Bundle external port (0)
    ///
    /// # Returns
    /// RTP session pointer, or NULL on failure
    pub fn switch_rtp_new(
        rx_host: *const c_char,
        rx_port: u16,
        tx_host: *const c_char,
        tx_port: u16,
        payload: switch_payload_t,
        samples_per_interval: u32,
        ms_per_packet: u32,
        flags: *const switch_rtp_flag_t,
        timer_name: *const c_char,
        err: *mut *const c_char,
        pool: *mut switch_memory_pool_t,
        bundle_internal_ports: u16,
        bundle_external_port: u16,
    ) -> *mut switch_rtp_t;

    /// Set remote RTP address
    pub fn switch_rtp_set_remote_address(
        rtp_session: *mut switch_rtp_t,
        host: *const c_char,
        port: u16,
        remote_rtcp_port: u16,
        change_adv_addr: switch_bool_t,
        err: *mut *const c_char,
    ) -> switch_status_t;

    /// Check if RTP session is ready for I/O
    ///
    /// # Returns
    /// 1 if ready, 0 if not ready
    pub fn switch_rtp_ready(rtp_session: *mut switch_rtp_t) -> u8;

    /// Activate RTCP for an RTP session
    /// This may also initialize the output socket infrastructure
    pub fn switch_rtp_activate_rtcp(
        rtp_session: *mut switch_rtp_t,
        send_rate: c_int,
        remote_port: u16,
        mux: switch_bool_t,
    ) -> switch_status_t;

    /// Set a flag on an RTP session
    pub fn switch_rtp_set_flag(rtp_session: *mut switch_rtp_t, flag: switch_rtp_flag_t);

    /// Clear a flag on an RTP session
    pub fn switch_rtp_clear_flag(rtp_session: *mut switch_rtp_t, flag: switch_rtp_flag_t);

    /// Test if a flag is set on an RTP session
    pub fn switch_rtp_test_flag(rtp_session: *mut switch_rtp_t, flag: switch_rtp_flag_t) -> u32;

    /// Write a frame as an RTP packet
    ///
    /// libfs builds the RTP header automatically.
    ///
    /// # Returns
    /// Number of bytes written, or negative on error
    pub fn switch_rtp_write_frame(
        rtp_session: *mut switch_rtp_t,
        frame: *mut switch_frame_t,
    ) -> c_int;

    /// Write data manually as an RTP packet
    ///
    /// More direct control over RTP packet generation.
    ///
    /// # Arguments
    /// * `rtp_session` - RTP session
    /// * `data` - Payload data to send
    /// * `datalen` - Length of payload data
    /// * `m` - Marker bit (1 or 0)
    /// * `payload` - Payload type (0=PCMU, 8=PCMA)
    /// * `ts` - Timestamp
    /// * `flags` - Frame flags (can be NULL)
    ///
    /// # Returns
    /// Number of bytes written, or negative on error
    pub fn switch_rtp_write_manual(
        rtp_session: *mut switch_rtp_t,
        data: *mut c_void,
        datalen: u32,
        m: u8,
        payload: switch_payload_t,
        ts: u32,
        flags: *mut switch_frame_flag_t,
    ) -> c_int;

    /// Write raw data directly to RTP socket
    ///
    /// Most direct control - sends data as-is to the socket.
    ///
    /// # Arguments
    /// * `rtp_session` - RTP session
    /// * `data` - Raw data to send (should include RTP header if needed)
    /// * `bytes` - Pointer to length (input: data length, output: bytes sent)
    /// * `process_encryption` - Whether to apply encryption
    ///
    /// # Returns
    /// SWITCH_STATUS_SUCCESS on success
    pub fn switch_rtp_write_raw(
        rtp_session: *mut switch_rtp_t,
        data: *mut c_void,
        bytes: *mut switch_size_t,
        process_encryption: switch_bool_t,
    ) -> switch_status_t;

    /// Get the SSRC from an RTP session
    pub fn switch_rtp_get_ssrc(rtp_session: *mut switch_rtp_t) -> u32;

    /// Get the sequence number from an RTP session
    pub fn switch_rtp_get_seq(rtp_session: *mut switch_rtp_t) -> u16;

    /// Read an RTP packet
    ///
    /// libfs handles jitter buffer and packet ordering.
    pub fn switch_rtp_read(
        rtp_session: *mut switch_rtp_t,
        data: *mut c_void,
        datalen: *mut u32,
        payload_type: *mut switch_payload_t,
        flags: *mut switch_frame_flag_t,
        io_flags: switch_io_flag_t,
    ) -> switch_status_t;

    /// Destroy an RTP session
    pub fn switch_rtp_destroy(rtp_session: *mut *mut switch_rtp_t);

    /// Get the RTP socket from a session
    pub fn switch_rtp_get_rtp_socket(rtp_session: *mut switch_rtp_t) -> *mut switch_socket_t;

    /// Get the file descriptor from a socket
    pub fn switch_socket_fd_get(sock: *mut switch_socket_t) -> c_int;

    // ========================================================================
    // Speex Resampler Functions
    // ========================================================================

    /// Initialize a Speex resampler
    ///
    /// # Arguments
    /// * `nb_channels` - Number of channels
    /// * `in_rate` - Input sample rate
    /// * `out_rate` - Output sample rate
    /// * `quality` - Quality level (0-10, 5 is reasonable)
    /// * `err` - Output: error code
    pub fn speex_resampler_init(
        nb_channels: spx_uint32_t,
        in_rate: spx_uint32_t,
        out_rate: spx_uint32_t,
        quality: c_int,
        err: *mut c_int,
    ) -> *mut SpeexResamplerState;

    /// Destroy a Speex resampler
    pub fn speex_resampler_destroy(st: *mut SpeexResamplerState);

    /// Resample audio (single channel)
    pub fn speex_resampler_process_int(
        st: *mut SpeexResamplerState,
        channel_index: spx_uint32_t,
        in_: *const spx_int16_t,
        in_len: *mut spx_uint32_t,
        out: *mut spx_int16_t,
        out_len: *mut spx_uint32_t,
    ) -> c_int;

    /// Resample interleaved audio (multi-channel)
    pub fn speex_resampler_process_interleaved_int(
        st: *mut SpeexResamplerState,
        in_: *const spx_int16_t,
        in_len: *mut spx_uint32_t,
        out: *mut spx_int16_t,
        out_len: *mut spx_uint32_t,
    ) -> c_int;

    /// Get error string
    pub fn speex_resampler_strerror(err: c_int) -> *const c_char;

    // ========================================================================
    // Memory Pool (for standalone RTP without full libfs)
    // ========================================================================

    /// Create a memory pool (internal perform version)
    ///
    /// Note: libfs exports this as `switch_core_perform_new_memory_pool`
    /// The non-perform version is a macro in the header.
    #[link_name = "switch_core_perform_new_memory_pool"]
    pub fn switch_core_new_memory_pool(
        pool: *mut *mut switch_memory_pool_t,
        file: *const libc::c_char,
        func: *const libc::c_char,
        line: libc::c_int,
    ) -> switch_status_t;

    /// Destroy a memory pool (internal perform version)
    #[link_name = "switch_core_perform_destroy_memory_pool"]
    pub fn switch_core_destroy_memory_pool(
        pool: *mut *mut switch_memory_pool_t,
        file: *const libc::c_char,
        func: *const libc::c_char,
        line: libc::c_int,
    ) -> switch_status_t;

    // ========================================================================
    // Core Initialization
    // ========================================================================

    /// Set global directories before initialization
    ///
    /// # Arguments
    /// * `base` - Base directory (usually installation prefix)
    /// * `run` - Runtime directory for PIDs etc
    /// * `log` - Log directory
    /// * `db` - Database directory
    /// * `conf` - Config directory
    /// * `htdocs` - HTTP documents directory
    /// * `scripts` - Scripts directory
    /// * `temp` - Temp directory
    /// * `grammar` - Grammar directory
    /// * `certs` - Certificates directory
    /// * `sounds` - Sounds directory
    /// * `recordings` - Recordings directory
    /// * `storage` - Storage directory
    /// * `cache` - Cache directory
    /// * `fonts` - Fonts directory
    /// * `images` - Images directory
    /// * `data` - Data directory
    /// * `localstate` - Local state directory
    pub fn switch_core_set_globals();

    /// Initialize libfs core
    ///
    /// # Arguments
    /// * `flags` - Core initialization flags (SCF_*)
    /// * `console` - Enable console (SWITCH_FALSE for embedded)
    /// * `err` - Error message output
    ///
    /// # Returns
    /// SWITCH_STATUS_SUCCESS on success
    pub fn switch_core_init(
        flags: switch_core_flag_t,
        console: switch_bool_t,
        err: *mut *const c_char,
    ) -> switch_status_t;

    /// Initialize libfs core and load modules
    ///
    /// # Arguments
    /// * `flags` - Core initialization flags (SCF_*)
    /// * `console` - Enable console (SWITCH_FALSE for embedded)
    /// * `err` - Error message output
    ///
    /// # Returns
    /// SWITCH_STATUS_SUCCESS on success
    pub fn switch_core_init_and_modload(
        flags: switch_core_flag_t,
        console: switch_bool_t,
        err: *mut *const c_char,
    ) -> switch_status_t;

    /// Destroy libfs core
    pub fn switch_core_destroy() -> switch_status_t;

    /// Session control (shutdown, etc.)
    pub fn switch_core_session_ctl(cmd: switch_session_ctl_t, val: *mut c_int) -> switch_status_t;

    /// Check if core is ready
    pub fn switch_core_ready() -> switch_bool_t;

    /// Check if core is ready for inbound
    pub fn switch_core_ready_inbound() -> switch_bool_t;

    /// Check if core is ready for outbound
    pub fn switch_core_ready_outbound() -> switch_bool_t;

    /// Get current number of sessions
    pub fn switch_core_session_count() -> u32;

    // ========================================================================
    // Module Loading
    // ========================================================================

    /// Initialize the loadable module subsystem
    /// Must be called after switch_core_init but before loading modules
    pub fn switch_loadable_module_init(autoload: switch_bool_t) -> switch_status_t;

    /// Load a specific module
    ///
    /// # Arguments
    /// * `dir` - Directory containing the module (can be NULL for default)
    /// * `fname` - Module filename (e.g., "mod_sofia")
    /// * `runtime` - Start module runtime (usually SWITCH_TRUE)
    /// * `err` - Error message output
    ///
    /// # Returns
    /// SWITCH_STATUS_SUCCESS on success
    pub fn switch_loadable_module_load_module(
        dir: *const c_char,
        fname: *const c_char,
        runtime: switch_bool_t,
        err: *mut *const c_char,
    ) -> switch_status_t;

    /// Shutdown the loadable module subsystem
    pub fn switch_loadable_module_shutdown();
}

// ============================================================================
// Session and Channel Types
// ============================================================================

/// libfs core session handle (opaque)
#[repr(C)]
pub struct switch_core_session_t {
    _opaque: [u8; 0],
}

/// Channel handle (opaque)
#[repr(C)]
pub struct switch_channel_t {
    _opaque: [u8; 0],
}

/// Event handle (opaque)
#[repr(C)]
pub struct switch_event_t {
    _opaque: [u8; 0],
}

/// Caller profile
#[repr(C)]
pub struct switch_caller_profile_t {
    _opaque: [u8; 0],
}

/// Dial handle (opaque)
#[repr(C)]
pub struct switch_dial_handle_t {
    _opaque: [u8; 0],
}

// ============================================================================
// Channel States and Flags
// ============================================================================

/// Channel state
pub type switch_channel_state_t = c_int;

pub const CS_NEW: switch_channel_state_t = 0;
pub const CS_INIT: switch_channel_state_t = 1;
pub const CS_ROUTING: switch_channel_state_t = 2;
pub const CS_SOFT_EXECUTE: switch_channel_state_t = 3;
pub const CS_EXECUTE: switch_channel_state_t = 4;
pub const CS_EXCHANGE_MEDIA: switch_channel_state_t = 5;
pub const CS_PARK: switch_channel_state_t = 6;
pub const CS_CONSUME_MEDIA: switch_channel_state_t = 7;
pub const CS_HIBERNATE: switch_channel_state_t = 8;
pub const CS_RESET: switch_channel_state_t = 9;
pub const CS_HANGUP: switch_channel_state_t = 10;
pub const CS_REPORTING: switch_channel_state_t = 11;
pub const CS_DESTROY: switch_channel_state_t = 12;

/// Channel flags
pub type switch_channel_flag_t = u32;

/// Call direction
pub type switch_call_direction_t = c_int;

pub const SWITCH_CALL_DIRECTION_INBOUND: switch_call_direction_t = 0;
pub const SWITCH_CALL_DIRECTION_OUTBOUND: switch_call_direction_t = 1;

/// Hangup cause codes (subset of common ones)
pub type switch_call_cause_t = c_int;

pub const SWITCH_CAUSE_NONE: switch_call_cause_t = 0;
pub const SWITCH_CAUSE_NORMAL_CLEARING: switch_call_cause_t = 16;
pub const SWITCH_CAUSE_USER_BUSY: switch_call_cause_t = 17;
pub const SWITCH_CAUSE_NO_ANSWER: switch_call_cause_t = 18;
pub const SWITCH_CAUSE_CALL_REJECTED: switch_call_cause_t = 21;
pub const SWITCH_CAUSE_INVALID_NUMBER_FORMAT: switch_call_cause_t = 28;
pub const SWITCH_CAUSE_ORIGINATOR_CANCEL: switch_call_cause_t = 487;
pub const SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER: switch_call_cause_t = 27;
pub const SWITCH_CAUSE_NORMAL_TEMPORARY_FAILURE: switch_call_cause_t = 41;

// ============================================================================
// Originate Flags
// ============================================================================

pub type switch_originate_flag_t = u32;

pub const SOF_NONE: switch_originate_flag_t = 0;
pub const SOF_NO_LIMITS: switch_originate_flag_t = 1 << 0;
pub const SOF_FORKED_DIAL: switch_originate_flag_t = 1 << 1;
pub const SOF_NO_EFFECTIVE_ANI: switch_originate_flag_t = 1 << 2;
pub const SOF_NO_EFFECTIVE_ANIII: switch_originate_flag_t = 1 << 3;
pub const SOF_NO_EFFECTIVE_DNIS: switch_originate_flag_t = 1 << 4;

// ============================================================================
// Session/Channel FFI Functions
// ============================================================================

extern "C" {
    // ========================================================================
    // Session Management
    // ========================================================================

    /// Locate a session by UUID (actual function - switch_core_session_locate is a macro)
    pub fn switch_core_session_perform_locate(
        uuid: *const c_char,
        file: *const c_char,
        func: *const c_char,
        line: c_int,
    ) -> *mut switch_core_session_t;

    /// Force locate a session (ignores mutex)
    pub fn switch_core_session_perform_force_locate(
        uuid: *const c_char,
        file: *const c_char,
        func: *const c_char,
        line: c_int,
    ) -> *mut switch_core_session_t;

    /// Release a session (decrement reference count)
    pub fn switch_core_session_rwunlock(session: *mut switch_core_session_t);

    /// Get session's UUID
    pub fn switch_core_session_get_uuid(session: *mut switch_core_session_t) -> *const c_char;

    /// Get channel from session
    pub fn switch_core_session_get_channel(
        session: *mut switch_core_session_t,
    ) -> *mut switch_channel_t;

    /// Get session's memory pool
    pub fn switch_core_session_get_pool(
        session: *mut switch_core_session_t,
    ) -> *mut switch_memory_pool_t;

    /// Force-destroy a session
    pub fn switch_core_session_destroy(session: *mut *mut switch_core_session_t) -> switch_status_t;

    // ========================================================================
    // Channel Management
    // ========================================================================

    /// Answer the call (actual function - switch_channel_answer is a macro)
    pub fn switch_channel_perform_answer(
        channel: *mut switch_channel_t,
        file: *const c_char,
        func: *const c_char,
        line: c_int,
    ) -> switch_status_t;

    /// Pre-answer (early media) (actual function - switch_channel_pre_answer is a macro)
    pub fn switch_channel_perform_pre_answer(
        channel: *mut switch_channel_t,
        file: *const c_char,
        func: *const c_char,
        line: c_int,
    ) -> switch_status_t;

    /// Hangup the channel (actual function - switch_channel_hangup is a macro)
    pub fn switch_channel_perform_hangup(
        channel: *mut switch_channel_t,
        file: *const c_char,
        func: *const c_char,
        line: c_int,
        hangup_cause: switch_call_cause_t,
    ) -> switch_status_t;

    /// Get channel state
    pub fn switch_channel_get_state(channel: *mut switch_channel_t) -> switch_channel_state_t;

    /// Check if channel is ready (flags, not a macro)
    pub fn switch_channel_test_ready(
        channel: *mut switch_channel_t,
        check_media: switch_bool_t,
        check_hangup: switch_bool_t,
    ) -> switch_bool_t;

    /// Check if media is ready
    pub fn switch_core_media_ready(
        session: *mut switch_core_session_t,
        type_: c_int, // SWITCH_MEDIA_TYPE_AUDIO = 0
    ) -> switch_bool_t;

    /// Get channel variable (actual function - switch_channel_get_variable is a macro)
    pub fn switch_channel_get_variable_dup(
        channel: *mut switch_channel_t,
        varname: *const c_char,
        dup: switch_bool_t,
        idx: c_int,
    ) -> *const c_char;

    /// Set channel variable (actual function - switch_channel_set_variable is a macro)
    pub fn switch_channel_set_variable_var_check(
        channel: *mut switch_channel_t,
        varname: *const c_char,
        value: *const c_char,
        var_check: switch_bool_t,
    ) -> switch_status_t;

    /// Get channel name
    pub fn switch_channel_get_name(channel: *mut switch_channel_t) -> *const c_char;

    /// Get caller ID number
    pub fn switch_channel_get_caller_profile(
        channel: *mut switch_channel_t,
    ) -> *mut switch_caller_profile_t;

    /// Get call direction
    pub fn switch_channel_direction(channel: *mut switch_channel_t) -> switch_call_direction_t;

    // ========================================================================
    // Call Origination (Outbound Calls)
    // ========================================================================

    /// Originate a call
    ///
    /// # Arguments
    /// * `session` - Existing session to use as origin (can be NULL)
    /// * `cause` - Output: hangup cause if failed
    /// * `bridgeto` - Dial string (e.g., "sofia/gateway/mytrunk/18005551234")
    /// * `timelimit_sec` - Call timeout in seconds
    /// * `state_handler_table` - State handlers (NULL for none)
    /// * `cid_name_override` - Override caller ID name (NULL for default)
    /// * `cid_num_override` - Override caller ID number (NULL for default)
    /// * `caller_profile_override` - Override caller profile (NULL for default)
    /// * `ovars` - Variables to set on new session (NULL for none)
    /// * `flags` - Originate flags
    /// * `cancel_cause` - Pointer to cancel cause (NULL if not needed)
    /// * `new_session` - Output: pointer to new session
    pub fn switch_ivr_originate(
        session: *mut switch_core_session_t,
        new_session: *mut *mut switch_core_session_t,
        cause: *mut switch_call_cause_t,
        bridgeto: *const c_char,
        timelimit_sec: u32,
        state_handler_table: *const c_void, // switch_state_handler_table_t
        cid_name_override: *const c_char,
        cid_num_override: *const c_char,
        caller_profile_override: *mut switch_caller_profile_t,
        ovars: *mut switch_event_t,
        flags: switch_originate_flag_t,
        cancel_cause: *mut switch_call_cause_t,
    ) -> switch_status_t;

    // ========================================================================
    // Event System
    // ========================================================================

    /// Create a new event (actual function - switch_event_create is a macro)
    pub fn switch_event_create_subclass_detailed(
        file: *const c_char,
        func: *const c_char,
        line: c_int,
        event: *mut *mut switch_event_t,
        event_id: c_int,
        subclass_name: *const c_char,
    ) -> switch_status_t;

    /// Destroy an event (actual function)
    pub fn switch_event_destroy(event: *mut *mut switch_event_t);

    /// Add header to event (actual function - switch_event_add_header_string is a macro)
    pub fn switch_event_add_header_string(
        event: *mut switch_event_t,
        stack: c_int,
        header_name: *const c_char,
        data: *const c_char,
    ) -> switch_status_t;

    // ========================================================================
    // Media Functions
    // ========================================================================

    /// Read a frame from the session
    pub fn switch_core_session_read_frame(
        session: *mut switch_core_session_t,
        frame: *mut *mut switch_frame_t,
        flags: switch_io_flag_t,
        stream_id: c_int,
    ) -> switch_status_t;

    /// Write a frame to the session
    pub fn switch_core_session_write_frame(
        session: *mut switch_core_session_t,
        frame: *mut switch_frame_t,
        flags: switch_io_flag_t,
        stream_id: c_int,
    ) -> switch_status_t;

    // ========================================================================
    // Codec Functions
    // ========================================================================

    /// Get the read codec from session
    pub fn switch_core_session_get_read_codec(
        session: *mut switch_core_session_t,
    ) -> *mut switch_codec_t;

    /// Get the write codec from session
    pub fn switch_core_session_get_write_codec(
        session: *mut switch_core_session_t,
    ) -> *mut switch_codec_t;

    // ========================================================================
    // DTMF Functions
    // ========================================================================

    /// Queue DTMF digits
    pub fn switch_channel_queue_dtmf_string(
        channel: *mut switch_channel_t,
        dtmf_string: *const c_char,
    ) -> switch_status_t;

    // ========================================================================
    // Caller Profile Functions
    // ========================================================================

    /// Get caller ID number from profile
    pub fn switch_caller_get_field_by_name(
        caller_profile: *mut switch_caller_profile_t,
        name: *const c_char,
    ) -> *const c_char;
}

// ============================================================================
// Event IDs (subset)
// ============================================================================

pub const SWITCH_EVENT_CHANNEL_CREATE: c_int = 1;
pub const SWITCH_EVENT_CHANNEL_DESTROY: c_int = 2;
pub const SWITCH_EVENT_CHANNEL_STATE: c_int = 3;
pub const SWITCH_EVENT_CHANNEL_ANSWER: c_int = 4;
pub const SWITCH_EVENT_CHANNEL_HANGUP: c_int = 5;
pub const SWITCH_EVENT_CHANNEL_HANGUP_COMPLETE: c_int = 6;
pub const SWITCH_EVENT_CHANNEL_PROGRESS: c_int = 14;
pub const SWITCH_EVENT_CHANNEL_PROGRESS_MEDIA: c_int = 15;
pub const SWITCH_EVENT_CUSTOM: c_int = 50;
pub const SWITCH_EVENT_CLONE: c_int = 51;

// ============================================================================
// Event Stack Flags
// ============================================================================

pub const SWITCH_STACK_BOTTOM: c_int = 0;
pub const SWITCH_STACK_TOP: c_int = 1;

// ============================================================================
// Helper Functions
// ============================================================================

/// Safe wrapper to get string from C pointer
#[inline]
pub unsafe fn cstr_to_string(s: *const c_char) -> Option<String> {
    if s.is_null() {
        None
    } else {
        std::ffi::CStr::from_ptr(s)
            .to_str()
            .ok()
            .map(|s| s.to_string())
    }
}

// ============================================================================
// Convenience Wrappers for Macro Functions
// ============================================================================

/// Answer a channel (wrapper for switch_channel_perform_answer macro)
#[inline]
pub unsafe fn switch_channel_answer(channel: *mut switch_channel_t) -> switch_status_t {
    switch_channel_perform_answer(
        channel,
        b"pyswitch\0".as_ptr() as *const c_char,
        b"switch_channel_answer\0".as_ptr() as *const c_char,
        0,
    )
}

/// Pre-answer a channel (wrapper for switch_channel_perform_pre_answer macro)
#[inline]
pub unsafe fn switch_channel_pre_answer(channel: *mut switch_channel_t) -> switch_status_t {
    switch_channel_perform_pre_answer(
        channel,
        b"pyswitch\0".as_ptr() as *const c_char,
        b"switch_channel_pre_answer\0".as_ptr() as *const c_char,
        0,
    )
}

/// Hangup a channel (wrapper for switch_channel_perform_hangup macro)
#[inline]
pub unsafe fn switch_channel_hangup(
    channel: *mut switch_channel_t,
    cause: switch_call_cause_t,
) -> switch_status_t {
    switch_channel_perform_hangup(
        channel,
        b"pyswitch\0".as_ptr() as *const c_char,
        b"switch_channel_hangup\0".as_ptr() as *const c_char,
        0,
        cause,
    )
}

/// Check if channel is ready (wrapper for switch_channel_test_ready)
#[inline]
pub unsafe fn switch_channel_ready(channel: *mut switch_channel_t) -> switch_bool_t {
    switch_channel_test_ready(channel, SWITCH_TRUE, SWITCH_TRUE)
}

/// Check if media is ready on a channel (wrapper for switch_channel_test_ready)
/// In libfs: switch_channel_media_ready(c) => switch_channel_test_ready(c, SWITCH_TRUE, SWITCH_FALSE)
#[inline]
pub unsafe fn switch_channel_media_ready(channel: *mut switch_channel_t) -> switch_bool_t {
    switch_channel_test_ready(channel, SWITCH_TRUE, SWITCH_FALSE)
}

/// Get channel variable (wrapper for switch_channel_get_variable_dup)
#[inline]
pub unsafe fn switch_channel_get_variable(
    channel: *mut switch_channel_t,
    varname: *const c_char,
) -> *const c_char {
    switch_channel_get_variable_dup(channel, varname, SWITCH_FALSE, -1)
}

/// Set channel variable (wrapper for switch_channel_set_variable_var_check)
#[inline]
pub unsafe fn switch_channel_set_variable(
    channel: *mut switch_channel_t,
    varname: *const c_char,
    value: *const c_char,
) -> switch_status_t {
    switch_channel_set_variable_var_check(channel, varname, value, SWITCH_TRUE)
}

/// Locate a session by UUID (wrapper for switch_core_session_perform_locate macro)
#[inline]
pub unsafe fn switch_core_session_locate(uuid: *const c_char) -> *mut switch_core_session_t {
    switch_core_session_perform_locate(
        uuid,
        b"pyswitch\0".as_ptr() as *const c_char,
        b"switch_core_session_locate\0".as_ptr() as *const c_char,
        0,
    )
}

/// Create an event (wrapper for switch_event_create_subclass_detailed macro)
#[inline]
pub unsafe fn switch_event_create(
    event: *mut *mut switch_event_t,
    event_id: c_int,
) -> switch_status_t {
    switch_event_create_subclass_detailed(
        b"pyswitch\0".as_ptr() as *const c_char,
        b"switch_event_create\0".as_ptr() as *const c_char,
        0,
        event,
        event_id,
        std::ptr::null(),
    )
}

/// Get event header (wrapper for switch_event_get_header_idx macro)
/// #define switch_event_get_header(_e, _h) switch_event_get_header_idx(_e, _h, -1)
#[inline]
pub unsafe fn switch_event_get_header(
    event: *mut switch_event_t,
    header_name: *const c_char,
) -> *const c_char {
    switch_event_get_header_idx(event, header_name, -1)
}

// ============================================================================
// Media Bug Types and Constants
// ============================================================================

/// Media bug handle (opaque)
#[repr(C)]
pub struct switch_media_bug_t {
    _opaque: [u8; 0],
}

/// Media bug callback type
pub type switch_media_bug_callback_t = Option<
    unsafe extern "C" fn(
        bug: *mut switch_media_bug_t,
        user_data: *mut c_void,
        type_: switch_abc_type_t,
    ) -> switch_bool_t,
>;

/// Media bug callback event types
pub type switch_abc_type_t = c_int;

pub const SWITCH_ABC_TYPE_INIT: switch_abc_type_t = 0;
pub const SWITCH_ABC_TYPE_READ: switch_abc_type_t = 1;
pub const SWITCH_ABC_TYPE_WRITE: switch_abc_type_t = 2;
pub const SWITCH_ABC_TYPE_WRITE_REPLACE: switch_abc_type_t = 3;
pub const SWITCH_ABC_TYPE_READ_REPLACE: switch_abc_type_t = 4;
pub const SWITCH_ABC_TYPE_READ_PING: switch_abc_type_t = 5;
pub const SWITCH_ABC_TYPE_TAP_NATIVE_READ: switch_abc_type_t = 6;
pub const SWITCH_ABC_TYPE_TAP_NATIVE_WRITE: switch_abc_type_t = 7;
pub const SWITCH_ABC_TYPE_CLOSE: switch_abc_type_t = 8;
pub const SWITCH_ABC_TYPE_READ_VIDEO_PING: switch_abc_type_t = 9;
pub const SWITCH_ABC_TYPE_WRITE_VIDEO_PING: switch_abc_type_t = 10;
pub const SWITCH_ABC_TYPE_STREAM_VIDEO_PING: switch_abc_type_t = 11;
pub const SWITCH_ABC_TYPE_VIDEO_PATCH: switch_abc_type_t = 12;

/// Media bug flags
pub type switch_media_bug_flag_t = u32;

pub const SMBF_BOTH: switch_media_bug_flag_t = 0;
pub const SMBF_READ_STREAM: switch_media_bug_flag_t = 1 << 0;
pub const SMBF_WRITE_STREAM: switch_media_bug_flag_t = 1 << 1;
pub const SMBF_WRITE_REPLACE: switch_media_bug_flag_t = 1 << 2;
pub const SMBF_READ_REPLACE: switch_media_bug_flag_t = 1 << 3;
pub const SMBF_READ_PING: switch_media_bug_flag_t = 1 << 4;
pub const SMBF_STEREO: switch_media_bug_flag_t = 1 << 5;
pub const SMBF_ANSWER_REQ: switch_media_bug_flag_t = 1 << 6;
pub const SMBF_BRIDGE_REQ: switch_media_bug_flag_t = 1 << 7;
pub const SMBF_THREAD_LOCK: switch_media_bug_flag_t = 1 << 8;
pub const SMBF_PRUNE: switch_media_bug_flag_t = 1 << 9;
pub const SMBF_NO_PAUSE: switch_media_bug_flag_t = 1 << 10;
pub const SMBF_STEREO_SWAP: switch_media_bug_flag_t = 1 << 11;
pub const SMBF_LOCK: switch_media_bug_flag_t = 1 << 12;
pub const SMBF_TAP_NATIVE_READ: switch_media_bug_flag_t = 1 << 13;
pub const SMBF_TAP_NATIVE_WRITE: switch_media_bug_flag_t = 1 << 14;
pub const SMBF_ONE_ONLY: switch_media_bug_flag_t = 1 << 15;
pub const SMBF_MASK: switch_media_bug_flag_t = 1 << 16;
pub const SMBF_READ_VIDEO_PING: switch_media_bug_flag_t = 1 << 17;
pub const SMBF_WRITE_VIDEO_PING: switch_media_bug_flag_t = 1 << 18;
pub const SMBF_READ_VIDEO_STREAM: switch_media_bug_flag_t = 1 << 19;
pub const SMBF_WRITE_VIDEO_STREAM: switch_media_bug_flag_t = 1 << 20;
pub const SMBF_VIDEO_PATCH: switch_media_bug_flag_t = 1 << 21;
pub const SMBF_SPY_VIDEO_STREAM: switch_media_bug_flag_t = 1 << 22;
pub const SMBF_SPY_VIDEO_STREAM_BLEG: switch_media_bug_flag_t = 1 << 23;
pub const SMBF_RECORD_ANSWER_REQ: switch_media_bug_flag_t = 1 << 24;
pub const SMBF_MEDIA_LOCKED: switch_media_bug_flag_t = 1 << 25;

/// Event callback function type
pub type switch_event_callback_t =
    Option<unsafe extern "C" fn(event: *mut switch_event_t)>;

/// Event node handle (opaque)
#[repr(C)]
pub struct switch_event_node_t {
    _opaque: [u8; 0],
}

// ============================================================================
// Media Bug and Event FFI Functions
// ============================================================================

extern "C" {
    /// Add a media bug to a session
    ///
    /// # Arguments
    /// * `session` - Session to attach bug to
    /// * `function` - Name of the function (for logging)
    /// * `target` - Target description (can be NULL)
    /// * `callback` - Callback function for audio events
    /// * `user_data` - User data passed to callback
    /// * `stop_time` - Time to stop (0 for never)
    /// * `flags` - Media bug flags (SMBF_*)
    /// * `new_bug` - Output: pointer to new bug
    pub fn switch_core_media_bug_add(
        session: *mut switch_core_session_t,
        function: *const c_char,
        target: *const c_char,
        callback: switch_media_bug_callback_t,
        user_data: *mut c_void,
        stop_time: i64,
        flags: switch_media_bug_flag_t,
        new_bug: *mut *mut switch_media_bug_t,
    ) -> switch_status_t;

    /// Read audio from a media bug
    ///
    /// # Arguments
    /// * `bug` - Media bug handle
    /// * `frame` - Frame to fill with audio data
    /// * `fill` - Whether to fill with silence if no data
    pub fn switch_core_media_bug_read(
        bug: *mut switch_media_bug_t,
        frame: *mut switch_frame_t,
        fill: switch_bool_t,
    ) -> switch_status_t;

    /// Remove a media bug from a session
    pub fn switch_core_media_bug_remove(
        session: *mut switch_core_session_t,
        bug: *mut *mut switch_media_bug_t,
    ) -> switch_status_t;

    /// Get the session from a media bug
    pub fn switch_core_media_bug_get_session(
        bug: *mut switch_media_bug_t,
    ) -> *mut switch_core_session_t;

    /// Get user data from a media bug
    pub fn switch_core_media_bug_get_user_data(
        bug: *mut switch_media_bug_t,
    ) -> *mut c_void;

    /// Get the write replace frame from a media bug
    pub fn switch_core_media_bug_get_write_replace_frame(
        bug: *mut switch_media_bug_t,
    ) -> *mut switch_frame_t;

    /// Set the write replace frame on a media bug
    pub fn switch_core_media_bug_set_write_replace_frame(
        bug: *mut switch_media_bug_t,
        frame: *mut switch_frame_t,
    );

    /// Bind to an event type
    ///
    /// # Arguments
    /// * `id` - Unique identifier for this binding (for removal)
    /// * `event` - Event type to bind to (SWITCH_EVENT_*)
    /// * `subclass_name` - Subclass name (NULL for all)
    /// * `callback` - Callback function
    /// * `user_data` - User data (passed via global, not per-event)
    pub fn switch_event_bind(
        id: *const c_char,
        event: c_int,
        subclass_name: *const c_char,
        callback: switch_event_callback_t,
        user_data: *mut c_void,
    ) -> switch_status_t;

    /// Bind to an event type with removable handle
    pub fn switch_event_bind_removable(
        id: *const c_char,
        event: c_int,
        subclass_name: *const c_char,
        callback: switch_event_callback_t,
        user_data: *mut c_void,
        node: *mut *mut switch_event_node_t,
    ) -> switch_status_t;

    /// Unbind from events
    pub fn switch_event_unbind(node: *mut *mut switch_event_node_t) -> switch_status_t;

    /// Get a header value from an event by index
    /// This is the actual function - switch_event_get_header is a macro
    pub fn switch_event_get_header_idx(
        event: *mut switch_event_t,
        header_name: *const c_char,
        idx: c_int,
    ) -> *const c_char;

    /// Get the body from an event
    pub fn switch_event_get_body(event: *mut switch_event_t) -> *const c_char;
}

// ============================================================================
// Recommended Buffer Size
// ============================================================================

/// Recommended buffer size for audio frames (from switch_types.h)
pub const SWITCH_RECOMMENDED_BUFFER_SIZE: usize = 8192;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(SWITCH_STATUS_SUCCESS, 0);
        assert_eq!(SWITCH_TRUE, 1);
        assert_eq!(SWITCH_FALSE, 0);
        assert_eq!(RTP_PAYLOAD_PCMU, 0);
        assert_eq!(RTP_PAYLOAD_PCMA, 8);
    }

    #[test]
    fn test_frame_default() {
        let frame = switch_frame_t::default();
        assert!(frame.data.is_null());
        assert_eq!(frame.datalen, 0);
        assert_eq!(frame.samples, 0);
    }
}
