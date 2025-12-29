//! Call session - wrapper around libfs session
//!
//! Thin wrapper that delegates to libfs for:
//! - Call control (answer, hangup)
//! - Audio read/write via session frames
//! - DTMF
//!
//! # Thread Safety
//!
//! libfs session access is protected by a mutex to ensure thread safety.
//! The audio loop holds a strong reference to prevent use-after-free.

use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use parking_lot::Mutex as SyncMutex;
use tokio::sync::Mutex;
use tracing::{debug, info, trace, warn};

use crate::core::audio::{AudioFrame, Resampler};
use crate::core::error::{Error, Result};

use libfs_sys::{
    cstr_to_string, switch_channel_answer, switch_channel_direction, switch_channel_get_variable,
    switch_channel_hangup, switch_channel_media_ready, switch_channel_queue_dtmf_string,
    switch_channel_ready, switch_core_session_get_channel, switch_core_session_get_uuid,
    switch_core_session_read_frame, switch_core_session_rwunlock, switch_core_session_t,
    switch_core_session_write_frame, switch_channel_t, switch_frame_t, SWITCH_CALL_DIRECTION_INBOUND,
    SWITCH_CAUSE_NORMAL_CLEARING, SWITCH_STATUS_SUCCESS, SWITCH_TRUE,
};

/// Channel capacity for audio frames
const AUDIO_CHANNEL_CAPACITY: usize = 100;

/// Frame duration for audio processing (20ms is standard for telephony)
const FRAME_DURATION_MS: u64 = 20;

/// Call direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallDirection {
    Inbound,
    Outbound,
}

/// Call state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    /// Call is ringing (not yet answered)
    Ringing,
    /// Call is answered and media is flowing
    Active,
    /// Call is being hung up
    Hangingup,
    /// Call has ended
    Ended,
}

/// Wrapper for libfs session pointer with thread-safe access
///
/// All access to the session pointer goes through this wrapper,
/// which ensures proper synchronization.
struct SessionHandle {
    /// The raw session pointer - only accessed while holding the lock
    ptr: *mut switch_core_session_t,
    /// Whether the session is still valid
    valid: AtomicBool,
}

impl SessionHandle {
    fn new(ptr: *mut switch_core_session_t) -> Self {
        Self {
            ptr,
            valid: AtomicBool::new(true),
        }
    }

    /// Check if session is still valid
    fn is_valid(&self) -> bool {
        self.valid.load(Ordering::SeqCst)
    }

    /// Invalidate the session (called on hangup/drop)
    fn invalidate(&self) {
        self.valid.store(false, Ordering::SeqCst);
    }

    /// Get the raw pointer (only valid while lock is held)
    ///
    /// # Safety
    /// Caller must ensure the session is valid and lock is held.
    unsafe fn get(&self) -> *mut switch_core_session_t {
        self.ptr
    }

    /// Get channel from session with null check
    ///
    /// # Safety
    /// Session must be valid.
    unsafe fn get_channel(&self) -> Option<*mut switch_channel_t> {
        if !self.is_valid() || self.ptr.is_null() {
            return None;
        }
        let channel = switch_core_session_get_channel(self.ptr);
        if channel.is_null() {
            None
        } else {
            Some(channel)
        }
    }
}

// SessionHandle is Send+Sync because all access is synchronized via the outer mutex
unsafe impl Send for SessionHandle {}
unsafe impl Sync for SessionHandle {}

/// Internal call state shared via Arc
struct CallInner {
    /// Thread-safe session handle with mutex protection
    session: SyncMutex<SessionHandle>,
    /// Call UUID
    uuid: String,
    /// Direction
    direction: CallDirection,
    /// Running flag - used for quick checks without locking
    running: AtomicBool,
    /// Sender for outbound audio (Python -> RTP)
    tx_sender: Sender<AudioFrame>,
    /// Receiver for outbound audio (used by audio loop)
    tx_receiver: Receiver<AudioFrame>,
    /// Sender for inbound audio (used by audio loop)
    rx_sender: Sender<AudioFrame>,
    /// Receiver for inbound audio (Python <- RTP)
    rx_receiver: Receiver<AudioFrame>,
    /// Resampler for 16kHz -> 8kHz (outbound)
    downsampler: Mutex<Option<Resampler>>,
    /// Resampler for 8kHz -> 16kHz (inbound)
    upsampler: Mutex<Option<Resampler>>,
    /// Audio loop handle
    audio_loop_running: AtomicBool,
}

/// Call session - represents an active call
///
/// Thin wrapper around libfs session. libfs handles:
/// - SIP signaling
/// - RTP transport
/// - Codec encoding/decoding
/// - Jitter buffer
///
/// This struct is Clone-able and uses Arc internally for safe sharing.
/// All session access is synchronized to prevent data races.
#[derive(Clone)]
pub struct Call {
    inner: Arc<CallInner>,
}

impl Call {
    /// Create a new Call from a libfs session
    ///
    /// # Safety
    /// The session pointer must be valid and the caller must ensure
    /// proper session lifecycle management. The session's reference
    /// count should already be incremented by the caller.
    pub unsafe fn from_session(session: *mut switch_core_session_t) -> Result<Self> {
        if session.is_null() {
            return Err(Error::Session("Null session pointer".to_string()));
        }

        let uuid = {
            let uuid_ptr = switch_core_session_get_uuid(session);
            cstr_to_string(uuid_ptr)
                .ok_or_else(|| Error::Session("Failed to get UUID".to_string()))?
        };

        let channel = switch_core_session_get_channel(session);
        if channel.is_null() {
            return Err(Error::Session("Failed to get channel".to_string()));
        }

        let direction = if switch_channel_direction(channel) == SWITCH_CALL_DIRECTION_INBOUND {
            CallDirection::Inbound
        } else {
            CallDirection::Outbound
        };

        // Create connected channels for audio
        let (tx_sender, tx_receiver) = bounded(AUDIO_CHANNEL_CAPACITY);
        let (rx_sender, rx_receiver) = bounded(AUDIO_CHANNEL_CAPACITY);

        let inner = Arc::new(CallInner {
            session: SyncMutex::new(SessionHandle::new(session)),
            uuid,
            direction,
            running: AtomicBool::new(true),
            tx_sender,
            tx_receiver,
            rx_sender,
            rx_receiver,
            downsampler: Mutex::new(None),
            upsampler: Mutex::new(None),
            audio_loop_running: AtomicBool::new(false),
        });

        Ok(Self { inner })
    }

    /// Get call UUID
    pub fn uuid(&self) -> &str {
        &self.inner.uuid
    }

    /// Get call direction
    pub fn direction(&self) -> CallDirection {
        self.inner.direction
    }

    /// Get caller ID (for inbound calls)
    pub fn caller_id(&self) -> Option<String> {
        if !self.inner.running.load(Ordering::SeqCst) {
            return None;
        }

        let session_guard = self.inner.session.lock();
        unsafe {
            let channel = session_guard.get_channel()?;
            let varname = CString::new("caller_id_number").ok()?;
            let value = switch_channel_get_variable(channel, varname.as_ptr());
            cstr_to_string(value)
        }
    }

    /// Get called number (destination)
    pub fn destination(&self) -> Option<String> {
        if !self.inner.running.load(Ordering::SeqCst) {
            return None;
        }

        let session_guard = self.inner.session.lock();
        unsafe {
            let channel = session_guard.get_channel()?;
            let varname = CString::new("destination_number").ok()?;
            let value = switch_channel_get_variable(channel, varname.as_ptr());
            cstr_to_string(value)
        }
    }

    /// Check if call is still active
    pub fn is_active(&self) -> bool {
        if !self.inner.running.load(Ordering::SeqCst) {
            return false;
        }

        let session_guard = self.inner.session.lock();
        if !session_guard.is_valid() {
            return false;
        }

        unsafe {
            if let Some(channel) = session_guard.get_channel() {
                switch_channel_ready(channel) == SWITCH_TRUE
            } else {
                false
            }
        }
    }

    /// Check if media is ready (call answered)
    pub fn is_media_ready(&self) -> bool {
        if !self.inner.running.load(Ordering::SeqCst) {
            return false;
        }

        let session_guard = self.inner.session.lock();
        unsafe {
            if let Some(channel) = session_guard.get_channel() {
                switch_channel_media_ready(channel) == SWITCH_TRUE
            } else {
                false
            }
        }
    }

    /// Answer the call (for inbound calls)
    pub async fn answer(&self) -> Result<()> {
        if self.inner.direction != CallDirection::Inbound {
            return Err(Error::Call("Cannot answer outbound call".to_string()));
        }

        {
            let session_guard = self.inner.session.lock();
            if !session_guard.is_valid() {
                return Err(Error::SessionClosed);
            }

            unsafe {
                let channel = session_guard.get_channel()
                    .ok_or_else(|| Error::Call("Channel not available".to_string()))?;
                let status = switch_channel_answer(channel);
                if status != SWITCH_STATUS_SUCCESS {
                    return Err(Error::Call("Failed to answer call".to_string()));
                }
            }
        }

        // Initialize resamplers
        {
            let mut ds = self.inner.downsampler.lock().await;
            *ds = Some(Resampler::downsample_16k_to_8k()?);
        }
        {
            let mut us = self.inner.upsampler.lock().await;
            *us = Some(Resampler::upsample_8k_to_16k()?);
        }

        // Start audio loop
        self.start_audio_loop();

        info!("Call {} answered", self.inner.uuid);
        Ok(())
    }

    /// Start the audio processing loop
    fn start_audio_loop(&self) {
        if self
            .inner
            .audio_loop_running
            .swap(true, Ordering::SeqCst)
        {
            return; // Already running
        }

        // Clone the Arc to keep CallInner alive during the audio loop
        // This prevents use-after-free when the Call is dropped elsewhere
        let inner = self.inner.clone();
        tokio::spawn(async move {
            Self::audio_loop(inner).await;
        });
    }

    /// Audio loop that reads/writes frames from libfs
    ///
    /// This loop holds a strong reference to CallInner, preventing
    /// the session from being freed while audio processing is active.
    async fn audio_loop(inner: Arc<CallInner>) {
        debug!("Audio loop started for call {}", inner.uuid);

        // Use 20ms frame timing for telephony
        let frame_interval = Duration::from_millis(FRAME_DURATION_MS);
        let mut last_frame_time = std::time::Instant::now();

        while inner.running.load(Ordering::SeqCst) {
            // Check if session is still valid before any FFI calls
            {
                let session_guard = inner.session.lock();
                if !session_guard.is_valid() {
                    debug!("Session invalidated, stopping audio loop");
                    break;
                }
            }

            // Read from libfs
            // We clone the Arc again to ensure the inner stays alive during spawn_blocking
            let inner_clone = inner.clone();
            let read_result = tokio::task::spawn_blocking(move || {
                let session_guard = inner_clone.session.lock();
                if !session_guard.is_valid() {
                    return None;
                }

                unsafe {
                    let session = session_guard.get();
                    let mut frame_ptr: *mut switch_frame_t = std::ptr::null_mut();
                    let status = switch_core_session_read_frame(
                        session,
                        &mut frame_ptr,
                        0, // flags
                        0, // stream_id
                    );
                    if status == SWITCH_STATUS_SUCCESS && !frame_ptr.is_null() {
                        let frame = &*frame_ptr;
                        if !frame.data.is_null() && frame.datalen > 0 {
                            let data = std::slice::from_raw_parts(
                                frame.data as *const u8,
                                frame.datalen as usize,
                            );
                            return Some(data.to_vec());
                        }
                    }
                    None
                }
            })
            .await;

            // Handle read result
            if let Ok(Some(data)) = read_result {
                // Upsample 8kHz -> 16kHz if needed
                let upsampled = {
                    let us = inner.upsampler.lock().await;
                    if let Some(ref resampler) = *us {
                        match resampler.process_bytes(&data) {
                            Ok(d) => d,
                            Err(e) => {
                                warn!("Upsample error: {}", e);
                                data
                            }
                        }
                    } else {
                        data
                    }
                };

                // Send to Python
                let frame = AudioFrame::new(upsampled, 16000);
                if let Err(TrySendError::Full(_)) = inner.rx_sender.try_send(frame) {
                    trace!("Audio rx channel full, dropping frame");
                }
            }

            // Check for outbound audio from Python
            if let Ok(frame) = inner.tx_receiver.try_recv() {
                // Downsample 16kHz -> 8kHz if needed
                let downsampled = {
                    let ds = inner.downsampler.lock().await;
                    if let Some(ref resampler) = *ds {
                        match resampler.process_bytes(&frame.samples) {
                            Ok(d) => d,
                            Err(e) => {
                                warn!("Downsample error: {}", e);
                                frame.samples
                            }
                        }
                    } else {
                        frame.samples
                    }
                };

                // Write to libfs
                let write_data = downsampled;
                let inner_clone = inner.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let session_guard = inner_clone.session.lock();
                    if !session_guard.is_valid() {
                        return;
                    }

                    unsafe {
                        let session = session_guard.get();
                        let mut frame = switch_frame_t::default();
                        frame.data = write_data.as_ptr() as *mut std::ffi::c_void;
                        frame.datalen = write_data.len() as u32;
                        frame.samples = (write_data.len() / 2) as u32; // 16-bit samples
                        frame.rate = 8000;
                        frame.channels = 1;

                        switch_core_session_write_frame(
                            session,
                            &mut frame,
                            0, // flags
                            0, // stream_id
                        );
                    }
                })
                .await;
            }

            // Sleep until next frame time (20ms intervals)
            let elapsed = last_frame_time.elapsed();
            if elapsed < frame_interval {
                tokio::time::sleep(frame_interval - elapsed).await;
            }
            last_frame_time = std::time::Instant::now();
        }

        inner.audio_loop_running.store(false, Ordering::SeqCst);
        debug!("Audio loop stopped for call {}", inner.uuid);
    }

    /// Hangup the call
    pub async fn hangup(&self, cause: Option<&str>) -> Result<()> {
        if !self.inner.running.swap(false, Ordering::SeqCst) {
            return Ok(()); // Already hung up
        }

        let cause_code = match cause {
            Some("user_busy") => libfs_sys::SWITCH_CAUSE_USER_BUSY,
            Some("no_answer") => libfs_sys::SWITCH_CAUSE_NO_ANSWER,
            Some("call_rejected") => libfs_sys::SWITCH_CAUSE_CALL_REJECTED,
            _ => SWITCH_CAUSE_NORMAL_CLEARING,
        };

        {
            let session_guard = self.inner.session.lock();
            session_guard.invalidate();

            unsafe {
                if let Some(channel) = session_guard.get_channel() {
                    switch_channel_hangup(channel, cause_code);
                }
            }
        }

        info!("Call {} hung up", self.inner.uuid);
        Ok(())
    }

    /// Receive audio frame from remote
    ///
    /// Returns L16 PCM at 16kHz mono (resampled from 8kHz).
    /// libfs handles codec decoding internally.
    pub async fn recv_audio(&self, timeout_ms: u64) -> Result<Option<AudioFrame>> {
        if !self.is_active() {
            return Err(Error::SessionClosed);
        }

        let timeout = Duration::from_millis(timeout_ms);

        match self.inner.rx_receiver.recv_timeout(timeout) {
            Ok(frame) => Ok(Some(frame)),
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => Ok(None),
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => Err(Error::SessionClosed),
        }
    }

    /// Send audio frame to remote
    ///
    /// Frame should be L16 PCM at 16kHz mono.
    /// libfs handles codec encoding internally.
    pub async fn send_audio(&self, frame: AudioFrame) -> Result<()> {
        if !self.is_active() {
            return Err(Error::SessionClosed);
        }

        // Queue for the audio loop to process
        match self.inner.tx_sender.try_send(frame) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                warn!("Audio tx channel full, frame dropped");
                Ok(())
            }
            Err(TrySendError::Disconnected(_)) => Err(Error::SessionClosed),
        }
    }

    /// Send DTMF digits
    pub async fn send_dtmf(&self, digits: &str) -> Result<()> {
        if !self.is_active() {
            return Err(Error::SessionClosed);
        }

        let digits_cstr =
            CString::new(digits).map_err(|_| Error::Call("Invalid DTMF digits".to_string()))?;

        {
            let session_guard = self.inner.session.lock();
            if !session_guard.is_valid() {
                return Err(Error::SessionClosed);
            }

            unsafe {
                let channel = session_guard.get_channel()
                    .ok_or_else(|| Error::Call("Channel not available".to_string()))?;
                let status = switch_channel_queue_dtmf_string(channel, digits_cstr.as_ptr());
                if status != SWITCH_STATUS_SUCCESS {
                    return Err(Error::Call("Failed to queue DTMF".to_string()));
                }
            }
        }

        debug!("Sent DTMF: {}", digits);
        Ok(())
    }

    /// Get a channel variable
    pub fn get_variable(&self, name: &str) -> Option<String> {
        if !self.inner.running.load(Ordering::SeqCst) {
            return None;
        }

        let varname = CString::new(name).ok()?;
        let session_guard = self.inner.session.lock();

        unsafe {
            let channel = session_guard.get_channel()?;
            let value = switch_channel_get_variable(channel, varname.as_ptr());
            cstr_to_string(value)
        }
    }
}

impl Drop for CallInner {
    fn drop(&mut self) {
        // Ensure running is false to stop any audio loops
        self.running.store(false, Ordering::SeqCst);

        // Invalidate and release the session
        let session_guard = self.session.lock();
        if session_guard.is_valid() {
            session_guard.invalidate();
            unsafe {
                switch_core_session_rwunlock(session_guard.ptr);
            }
            debug!("Call {} dropped and session released", self.uuid);
        }
    }
}
