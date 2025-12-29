//! SipSession - wraps a FreeSWITCH session with media bug for audio
//!
//! Provides async API for:
//! - Receiving audio from remote party
//! - Sending audio to remote party
//! - Call control (answer, hangup, DTMF)

use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::core::audio::{AudioFrame, Resampler};
use crate::core::error::{Error, Result};
use crate::core::sip::media_bug::{attach_media_bug_by_uuid, remove_media_bug, MediaBugFrame, MediaBugState};

use libfs_sys::{
    cstr_to_string, switch_channel_answer, switch_channel_direction, switch_channel_get_variable,
    switch_channel_hangup, switch_channel_queue_dtmf_string, switch_channel_ready,
    switch_core_session_get_channel, switch_core_session_get_uuid, switch_core_session_locate,
    switch_core_session_rwunlock, switch_core_session_t,
    SWITCH_CALL_DIRECTION_INBOUND, SWITCH_CAUSE_NORMAL_CLEARING, SWITCH_STATUS_SUCCESS, SWITCH_TRUE,
};

/// Call direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SipCallDirection {
    Inbound,
    Outbound,
}

/// SIP session with media bug for audio capture/injection
///
/// This session uses media bugs instead of direct frame reads, which:
/// - Works correctly with mod_sofia's internal RTP management
/// - Runs callbacks on the FS session thread (thread-safe)
/// - Uses channels for async audio transfer
pub struct SipSession {
    /// Session UUID
    uuid: String,
    /// Call direction
    direction: SipCallDirection,
    /// Media bug state (owns the audio channels)
    media_bug: Option<Arc<MediaBugState>>,
    /// Whether the session is active
    active: AtomicBool,
    /// Resampler for 16kHz -> 8kHz (outbound)
    downsampler: Mutex<Option<Resampler>>,
    /// Resampler for 8kHz -> 16kHz (inbound)
    upsampler: Mutex<Option<Resampler>>,
}

impl SipSession {
    /// Create a new SipSession from a session UUID
    ///
    /// This will locate the session and attach a media bug to it.
    pub fn from_uuid(uuid: &str) -> Result<Self> {
        // Get session info
        let direction = unsafe {
            let uuid_cstr = CString::new(uuid)
                .map_err(|_| Error::Session("Invalid UUID".to_string()))?;
            let session = switch_core_session_locate(uuid_cstr.as_ptr());
            if session.is_null() {
                return Err(Error::Session(format!("Session not found: {}", uuid)));
            }

            let channel = switch_core_session_get_channel(session);
            let dir = if !channel.is_null() && switch_channel_direction(channel) == SWITCH_CALL_DIRECTION_INBOUND {
                SipCallDirection::Inbound
            } else {
                SipCallDirection::Outbound
            };

            switch_core_session_rwunlock(session);
            dir
        };

        Ok(Self {
            uuid: uuid.to_string(),
            direction,
            media_bug: None,
            active: AtomicBool::new(true),
            downsampler: Mutex::new(None),
            upsampler: Mutex::new(None),
        })
    }

    /// Create from raw session pointer
    ///
    /// # Safety
    /// The session pointer must be valid.
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
        let direction = if !channel.is_null() && switch_channel_direction(channel) == SWITCH_CALL_DIRECTION_INBOUND {
            SipCallDirection::Inbound
        } else {
            SipCallDirection::Outbound
        };

        Ok(Self {
            uuid,
            direction,
            media_bug: None,
            active: AtomicBool::new(true),
            downsampler: Mutex::new(None),
            upsampler: Mutex::new(None),
        })
    }

    /// Get session UUID
    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    /// Get call direction
    pub fn direction(&self) -> SipCallDirection {
        self.direction
    }

    /// Check if session is active
    pub fn is_active(&self) -> bool {
        if !self.active.load(Ordering::SeqCst) {
            return false;
        }

        // Check if channel is still ready
        unsafe {
            let uuid_cstr = match CString::new(self.uuid.as_str()) {
                Ok(c) => c,
                Err(_) => return false,
            };
            let session = switch_core_session_locate(uuid_cstr.as_ptr());
            if session.is_null() {
                return false;
            }

            let channel = switch_core_session_get_channel(session);
            let ready = !channel.is_null() && switch_channel_ready(channel) == SWITCH_TRUE;
            switch_core_session_rwunlock(session);
            ready
        }
    }

    /// Answer the call (for inbound calls)
    pub async fn answer(&mut self) -> Result<()> {
        if self.direction != SipCallDirection::Inbound {
            return Err(Error::Call("Cannot answer outbound call".to_string()));
        }

        unsafe {
            let uuid_cstr = CString::new(self.uuid.as_str())
                .map_err(|_| Error::Session("Invalid UUID".to_string()))?;
            let session = switch_core_session_locate(uuid_cstr.as_ptr());
            if session.is_null() {
                return Err(Error::SessionClosed);
            }

            let channel = switch_core_session_get_channel(session);
            if channel.is_null() {
                switch_core_session_rwunlock(session);
                return Err(Error::Call("Channel not available".to_string()));
            }

            let status = switch_channel_answer(channel);
            switch_core_session_rwunlock(session);

            if status != SWITCH_STATUS_SUCCESS {
                return Err(Error::Call("Failed to answer call".to_string()));
            }
        }

        // Attach media bug for audio capture
        self.attach_media_bug()?;

        // Initialize resamplers
        {
            let mut ds = self.downsampler.lock().await;
            *ds = Some(Resampler::downsample_16k_to_8k()?);
        }
        {
            let mut us = self.upsampler.lock().await;
            *us = Some(Resampler::upsample_8k_to_16k()?);
        }

        info!("SipSession {} answered", self.uuid);
        Ok(())
    }

    /// Attach media bug to capture/inject audio
    fn attach_media_bug(&mut self) -> Result<()> {
        if self.media_bug.is_some() {
            return Ok(()); // Already attached
        }

        match attach_media_bug_by_uuid(&self.uuid) {
            Ok(state) => {
                self.media_bug = Some(state);
                debug!("Media bug attached to session {}", self.uuid);
                Ok(())
            }
            Err(e) => {
                warn!("Failed to attach media bug: {}", e);
                Err(Error::Call(format!("Failed to attach media bug: {}", e)))
            }
        }
    }

    /// Start audio processing (for outbound calls that are already connected)
    pub async fn start_audio(&mut self) -> Result<()> {
        // Attach media bug
        self.attach_media_bug()?;

        // Initialize resamplers
        {
            let mut ds = self.downsampler.lock().await;
            *ds = Some(Resampler::downsample_16k_to_8k()?);
        }
        {
            let mut us = self.upsampler.lock().await;
            *us = Some(Resampler::upsample_8k_to_16k()?);
        }

        debug!("Audio started for session {}", self.uuid);
        Ok(())
    }

    /// Receive audio from remote party
    ///
    /// Returns L16 PCM at 16kHz mono (upsampled from 8kHz).
    /// Returns None if timeout expires without receiving a frame.
    pub async fn recv_audio(&mut self, timeout_ms: u64) -> Result<Option<AudioFrame>> {
        if !self.is_active() {
            return Err(Error::SessionClosed);
        }

        let media_bug = self.media_bug.as_ref()
            .ok_or_else(|| Error::Call("Media bug not attached".to_string()))?;

        let timeout = Duration::from_millis(timeout_ms);

        // Lock the receiver and try to receive with timeout
        let mut receiver = media_bug.channels.rx_receiver.lock().await;

        match tokio::time::timeout(timeout, receiver.recv()).await {
            Ok(Some(frame)) => {
                // Upsample 8kHz -> 16kHz if needed
                let upsampled = {
                    let us = self.upsampler.lock().await;
                    if let Some(ref resampler) = *us {
                        // Convert i16 samples to bytes
                        let bytes: Vec<u8> = frame.data
                            .iter()
                            .flat_map(|s| s.to_le_bytes())
                            .collect();

                        match resampler.process_bytes(&bytes) {
                            Ok(d) => d,
                            Err(e) => {
                                warn!("Upsample error: {}", e);
                                bytes
                            }
                        }
                    } else {
                        // No resampler, just convert to bytes
                        frame.data
                            .iter()
                            .flat_map(|s| s.to_le_bytes())
                            .collect()
                    }
                };

                Ok(Some(AudioFrame::new(upsampled, 16000)))
            }
            Ok(None) => {
                // Channel closed
                Err(Error::SessionClosed)
            }
            Err(_) => {
                // Timeout
                Ok(None)
            }
        }
    }

    /// Send audio to remote party
    ///
    /// Frame should be L16 PCM at 16kHz mono.
    pub async fn send_audio(&self, frame: AudioFrame) -> Result<()> {
        if !self.is_active() {
            return Err(Error::SessionClosed);
        }

        let media_bug = self.media_bug.as_ref()
            .ok_or_else(|| Error::Call("Media bug not attached".to_string()))?;

        // Downsample 16kHz -> 8kHz if needed
        let downsampled = {
            let ds = self.downsampler.lock().await;
            if let Some(ref resampler) = *ds {
                match resampler.process_bytes(&frame.samples) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!("Downsample error: {}", e);
                        frame.samples.clone()
                    }
                }
            } else {
                frame.samples.clone()
            }
        };

        // Convert bytes to i16 samples
        let samples: Vec<i16> = downsampled
            .chunks_exact(2)
            .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        let bug_frame = MediaBugFrame {
            data: samples,
            sample_rate: 8000,
            channels: 1,
        };

        // Send to the media bug's tx_sender
        media_bug.channels.tx_sender
            .try_send(bug_frame)
            .map_err(|_| Error::Call("Failed to send audio - channel full or closed".to_string()))?;

        Ok(())
    }

    /// Hangup the call
    pub async fn hangup(&mut self, cause: Option<&str>) -> Result<()> {
        if !self.active.swap(false, Ordering::SeqCst) {
            return Ok(()); // Already hung up
        }

        // Remove media bug first
        if self.media_bug.is_some() {
            let _ = remove_media_bug(&self.uuid);
            self.media_bug = None;
        }

        let cause_code = match cause {
            Some("user_busy") => libfs_sys::SWITCH_CAUSE_USER_BUSY,
            Some("no_answer") => libfs_sys::SWITCH_CAUSE_NO_ANSWER,
            Some("call_rejected") => libfs_sys::SWITCH_CAUSE_CALL_REJECTED,
            _ => SWITCH_CAUSE_NORMAL_CLEARING,
        };

        unsafe {
            let uuid_cstr = CString::new(self.uuid.as_str())
                .map_err(|_| Error::Session("Invalid UUID".to_string()))?;
            let session = switch_core_session_locate(uuid_cstr.as_ptr());
            if !session.is_null() {
                let channel = switch_core_session_get_channel(session);
                if !channel.is_null() {
                    switch_channel_hangup(channel, cause_code);
                }
                switch_core_session_rwunlock(session);
            }
        }

        info!("SipSession {} hung up", self.uuid);
        Ok(())
    }

    /// Send DTMF digits
    pub async fn send_dtmf(&self, digits: &str) -> Result<()> {
        if !self.is_active() {
            return Err(Error::SessionClosed);
        }

        let digits_cstr =
            CString::new(digits).map_err(|_| Error::Call("Invalid DTMF digits".to_string()))?;

        unsafe {
            let uuid_cstr = CString::new(self.uuid.as_str())
                .map_err(|_| Error::Session("Invalid UUID".to_string()))?;
            let session = switch_core_session_locate(uuid_cstr.as_ptr());
            if session.is_null() {
                return Err(Error::SessionClosed);
            }

            let channel = switch_core_session_get_channel(session);
            if channel.is_null() {
                switch_core_session_rwunlock(session);
                return Err(Error::Call("Channel not available".to_string()));
            }

            let status = switch_channel_queue_dtmf_string(channel, digits_cstr.as_ptr());
            switch_core_session_rwunlock(session);

            if status != SWITCH_STATUS_SUCCESS {
                return Err(Error::Call("Failed to queue DTMF".to_string()));
            }
        }

        debug!("Sent DTMF: {}", digits);
        Ok(())
    }

    /// Get caller ID (for inbound calls)
    pub fn caller_id(&self) -> Option<String> {
        self.get_variable("caller_id_number")
    }

    /// Get destination number
    pub fn destination(&self) -> Option<String> {
        self.get_variable("destination_number")
    }

    /// Get a channel variable
    pub fn get_variable(&self, name: &str) -> Option<String> {
        if !self.active.load(Ordering::SeqCst) {
            return None;
        }

        unsafe {
            let uuid_cstr = CString::new(self.uuid.as_str()).ok()?;
            let session = switch_core_session_locate(uuid_cstr.as_ptr());
            if session.is_null() {
                return None;
            }

            let channel = switch_core_session_get_channel(session);
            if channel.is_null() {
                switch_core_session_rwunlock(session);
                return None;
            }

            let varname = CString::new(name).ok()?;
            let value = switch_channel_get_variable(channel, varname.as_ptr());
            let result = cstr_to_string(value);

            switch_core_session_rwunlock(session);
            result
        }
    }
}

impl Drop for SipSession {
    fn drop(&mut self) {
        if self.active.swap(false, Ordering::SeqCst) {
            // Clean up media bug
            if self.media_bug.is_some() {
                let _ = remove_media_bug(&self.uuid);
            }
            debug!("SipSession {} dropped", self.uuid);
        }
    }
}
