//! Media bug callback and audio channel bridge
//!
//! This module provides the infrastructure for capturing audio from FreeSWITCH
//! sessions using the media bug API. Media bugs run on the FS session thread
//! (which is thread-safe) and use channels to transfer audio to the async runtime.
//!
//! Key insight: Media bug callbacks are called on FreeSWITCH's session thread,
//! making it safe to access session data. We copy audio data immediately and
//! send it via channels to avoid holding FS pointers across thread boundaries.

use std::collections::HashMap;
use std::ffi::CStr;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{info, trace};

use std::ffi::c_void;

use libfs_sys::{
    switch_abc_type_t, switch_bool_t, switch_core_media_bug_add,
    switch_core_media_bug_get_write_replace_frame,
    switch_core_media_bug_read, switch_core_media_bug_remove,
    switch_core_media_bug_set_write_replace_frame, switch_media_bug_t,
    switch_core_session_get_uuid, switch_core_session_locate, switch_core_session_rwunlock,
    switch_core_session_t, switch_frame_t, switch_media_bug_flag_t,
    SMBF_READ_STREAM, SMBF_WRITE_REPLACE, SWITCH_ABC_TYPE_CLOSE, SWITCH_ABC_TYPE_READ,
    SWITCH_ABC_TYPE_WRITE_REPLACE, SWITCH_FALSE, SWITCH_RECOMMENDED_BUFFER_SIZE,
    SWITCH_STATUS_SUCCESS, SWITCH_TRUE,
};

/// Audio frame from media bug
#[derive(Debug, Clone)]
pub struct MediaBugFrame {
    /// L16 PCM audio data (16-bit signed, little-endian)
    pub data: Vec<i16>,
    /// Sample rate (typically 8000 Hz)
    pub sample_rate: u32,
    /// Number of channels (typically 1 for mono)
    pub channels: u32,
}

/// Sender/receiver pair for a session's audio
pub struct SessionAudioChannels {
    /// Inbound audio (from remote party to us)
    pub rx_sender: mpsc::Sender<MediaBugFrame>,
    /// Wrapped in Mutex for shared access from Arc
    pub rx_receiver: tokio::sync::Mutex<mpsc::Receiver<MediaBugFrame>>,
    /// Outbound audio (from us to remote party)
    pub tx_sender: mpsc::Sender<MediaBugFrame>,
    /// Not used in the state (callback has its own receiver)
    pub tx_receiver: tokio::sync::Mutex<mpsc::Receiver<MediaBugFrame>>,
}

impl SessionAudioChannels {
    pub fn new(buffer_size: usize) -> Self {
        let (rx_sender, rx_receiver) = mpsc::channel(buffer_size);
        let (tx_sender, tx_receiver) = mpsc::channel(buffer_size);
        Self {
            rx_sender,
            rx_receiver: tokio::sync::Mutex::new(rx_receiver),
            tx_sender,
            tx_receiver: tokio::sync::Mutex::new(tx_receiver),
        }
    }
}

/// User data passed to media bug callback
struct MediaBugUserData {
    /// UUID of the session
    uuid: String,
    /// Sender for inbound audio (READ events)
    rx_sender: mpsc::Sender<MediaBugFrame>,
    /// Receiver for outbound audio (WRITE_REPLACE events)
    /// Note: We use try_recv in the callback so this needs to be accessible
    tx_receiver: std::sync::Mutex<mpsc::Receiver<MediaBugFrame>>,
    /// Whether the bug is still active
    active: AtomicBool,
}

/// Global registry of active media bugs by session UUID
static MEDIA_BUG_REGISTRY: once_cell::sync::Lazy<RwLock<HashMap<String, Arc<MediaBugState>>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(HashMap::new()));

/// State for a media bug attached to a session
pub struct MediaBugState {
    pub uuid: String,
    pub bug: *mut switch_media_bug_t,
    /// Audio channels for this session
    pub channels: SessionAudioChannels,
    /// Whether the bug is active
    active: AtomicBool,
}

// MediaBugState contains raw pointers but is only accessed from FS threads
// or through the registry with proper synchronization
unsafe impl Send for MediaBugState {}
unsafe impl Sync for MediaBugState {}

impl MediaBugState {
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    pub fn deactivate(&self) {
        self.active.store(false, Ordering::SeqCst);
    }
}

/// Media bug callback function
///
/// # Safety
/// This is called from FreeSWITCH's session thread. We must:
/// - Not panic
/// - Not hold locks across the callback
/// - Copy data immediately and send via channels
/// - Return quickly to not block audio processing
unsafe extern "C" fn media_bug_callback(
    bug: *mut switch_media_bug_t,
    user_data: *mut c_void,
    type_: switch_abc_type_t,
) -> switch_bool_t {
    if bug.is_null() || user_data.is_null() {
        return SWITCH_FALSE;
    }

    let user_data = &*(user_data as *const MediaBugUserData);

    if !user_data.active.load(Ordering::SeqCst) {
        return SWITCH_FALSE;
    }

    match type_ {
        t if t == SWITCH_ABC_TYPE_READ => {
            // Read audio from the session (inbound audio from remote)
            let mut frame = switch_frame_t::default();
            let mut buffer = [0u8; SWITCH_RECOMMENDED_BUFFER_SIZE];
            frame.data = buffer.as_mut_ptr() as *mut c_void;
            frame.buflen = buffer.len() as u32;

            let status = switch_core_media_bug_read(bug, &mut frame, SWITCH_TRUE);
            if status == SWITCH_STATUS_SUCCESS && frame.datalen > 0 {
                // Convert to i16 samples
                let data_len = frame.datalen as usize;
                let samples: Vec<i16> = buffer[..data_len]
                    .chunks_exact(2)
                    .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect();

                let audio_frame = MediaBugFrame {
                    data: samples,
                    sample_rate: frame.rate,
                    channels: frame.channels.max(1),
                };

                // Non-blocking send to avoid blocking the session thread
                if let Err(e) = user_data.rx_sender.try_send(audio_frame) {
                    trace!("Media bug rx channel full or closed: {}", e);
                }
            }
        }
        t if t == SWITCH_ABC_TYPE_WRITE_REPLACE => {
            // Write replacement audio (outbound audio to remote)
            let write_frame = switch_core_media_bug_get_write_replace_frame(bug);
            if write_frame.is_null() {
                return SWITCH_TRUE;
            }

            // Try to get outbound audio from the channel
            if let Ok(mut receiver) = user_data.tx_receiver.try_lock() {
                if let Ok(audio_frame) = receiver.try_recv() {
                    let frame = &mut *write_frame;

                    // Convert i16 samples to bytes
                    let bytes: Vec<u8> = audio_frame
                        .data
                        .iter()
                        .flat_map(|s| s.to_le_bytes())
                        .collect();

                    // Copy to frame buffer (don't exceed buffer size)
                    let copy_len = bytes.len().min(frame.buflen as usize);
                    if !frame.data.is_null() && copy_len > 0 {
                        std::ptr::copy_nonoverlapping(
                            bytes.as_ptr(),
                            frame.data as *mut u8,
                            copy_len,
                        );
                        frame.datalen = copy_len as u32;
                        frame.samples = (copy_len / 2) as u32;
                    }

                    switch_core_media_bug_set_write_replace_frame(bug, write_frame);
                }
            }
        }
        t if t == SWITCH_ABC_TYPE_CLOSE => {
            // Media bug is being closed
            info!("Media bug closed for session {}", user_data.uuid);
            user_data.active.store(false, Ordering::SeqCst);

            // Remove from registry
            let mut registry = MEDIA_BUG_REGISTRY.write();
            registry.remove(&user_data.uuid);

            // Don't drop user_data here - it will be cleaned up by the registry
        }
        _ => {}
    }

    SWITCH_TRUE
}

/// Attach a media bug to a session
///
/// # Safety
/// The session pointer must be valid.
pub unsafe fn attach_media_bug(
    session: *mut switch_core_session_t,
) -> Result<Arc<MediaBugState>, String> {
    if session.is_null() {
        return Err("Null session pointer".to_string());
    }

    // Get session UUID
    let uuid_ptr = switch_core_session_get_uuid(session);
    if uuid_ptr.is_null() {
        return Err("Failed to get session UUID".to_string());
    }
    let uuid = CStr::from_ptr(uuid_ptr)
        .to_str()
        .map_err(|_| "Invalid UUID")?
        .to_string();

    // Check if already attached
    {
        let registry = MEDIA_BUG_REGISTRY.read();
        if registry.contains_key(&uuid) {
            return Err(format!("Media bug already attached to session {}", uuid));
        }
    }

    // Create audio channels (100 frames buffer = ~2 seconds at 50fps)
    let channels = SessionAudioChannels::new(100);

    // Create user data for callback
    // We need to keep the receiver in a form that can be accessed from the callback
    let (tx_sender, tx_receiver) = mpsc::channel(100);

    let user_data = Box::new(MediaBugUserData {
        uuid: uuid.clone(),
        rx_sender: channels.rx_sender.clone(),
        tx_receiver: std::sync::Mutex::new(tx_receiver),
        active: AtomicBool::new(true),
    });
    let user_data_ptr = Box::into_raw(user_data) as *mut c_void;

    // Attach media bug
    let mut bug: *mut switch_media_bug_t = ptr::null_mut();
    let flags: switch_media_bug_flag_t = SMBF_READ_STREAM | SMBF_WRITE_REPLACE;

    let status = switch_core_media_bug_add(
        session,
        b"rtp_sip_media_bug\0".as_ptr() as *const libc::c_char,
        ptr::null(), // target
        Some(media_bug_callback),
        user_data_ptr,
        0, // stop_time (0 = never)
        flags,
        &mut bug,
    );

    if status != SWITCH_STATUS_SUCCESS {
        // Clean up user_data on failure
        let _ = Box::from_raw(user_data_ptr as *mut MediaBugUserData);
        return Err(format!("Failed to attach media bug: status {}", status));
    }

    info!("Media bug attached to session {}", uuid);

    // Create and register the state
    // Note: We create new channels here since we gave rx_sender to user_data
    // The tx_sender we give to the caller, tx_receiver goes to the callback
    let state = Arc::new(MediaBugState {
        uuid: uuid.clone(),
        bug,
        channels: SessionAudioChannels {
            rx_sender: channels.rx_sender,
            rx_receiver: channels.rx_receiver,
            tx_sender,
            tx_receiver: channels.tx_receiver, // This won't be used since callback has its own
        },
        active: AtomicBool::new(true),
    });

    {
        let mut registry = MEDIA_BUG_REGISTRY.write();
        registry.insert(uuid.clone(), state.clone());
    }

    Ok(state)
}

/// Attach media bug to a session by UUID
///
/// Locates the session and attaches a media bug.
pub fn attach_media_bug_by_uuid(uuid: &str) -> Result<Arc<MediaBugState>, String> {
    unsafe {
        let uuid_cstr = std::ffi::CString::new(uuid).map_err(|_| "Invalid UUID")?;
        let session = switch_core_session_locate(uuid_cstr.as_ptr());
        if session.is_null() {
            return Err(format!("Session not found: {}", uuid));
        }

        let result = attach_media_bug(session);

        // Release session reference
        switch_core_session_rwunlock(session);

        result
    }
}

/// Get media bug state for a session
pub fn get_media_bug_state(uuid: &str) -> Option<Arc<MediaBugState>> {
    let registry = MEDIA_BUG_REGISTRY.read();
    registry.get(uuid).cloned()
}

/// Remove media bug from a session
pub fn remove_media_bug(uuid: &str) -> Result<(), String> {
    let state = {
        let registry = MEDIA_BUG_REGISTRY.read();
        registry.get(uuid).cloned()
    };

    if let Some(state) = state {
        state.deactivate();

        unsafe {
            let uuid_cstr = std::ffi::CString::new(uuid).map_err(|_| "Invalid UUID")?;
            let session = switch_core_session_locate(uuid_cstr.as_ptr());
            if !session.is_null() {
                let mut bug = state.bug;
                switch_core_media_bug_remove(session, &mut bug);
                switch_core_session_rwunlock(session);
            }
        }

        // Remove from registry
        let mut registry = MEDIA_BUG_REGISTRY.write();
        registry.remove(uuid);

        info!("Media bug removed from session {}", uuid);
        Ok(())
    } else {
        Err(format!("No media bug found for session {}", uuid))
    }
}

/// Get list of all active media bug sessions
pub fn list_active_sessions() -> Vec<String> {
    let registry = MEDIA_BUG_REGISTRY.read();
    registry.keys().cloned().collect()
}
