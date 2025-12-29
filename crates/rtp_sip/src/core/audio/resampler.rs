//! Audio resampling using libfs's bundled Speex library
//!
//! This is a thin wrapper around libfs's Speex resampler.
//! The Speex library is bundled with libfs (libspeexdsp).

use libfs_sys::{
    speex_resampler_destroy, speex_resampler_init, speex_resampler_process_int,
    speex_resampler_strerror, SpeexResamplerState,
};
use std::ptr;

use crate::core::error::{Error, Result};

/// Resampler quality (0-10, higher = better quality, more CPU)
const RESAMPLER_QUALITY: i32 = 5;

/// Audio resampler - thin wrapper around libfs's Speex
pub struct Resampler {
    state: *mut SpeexResamplerState,
    in_rate: u32,
    out_rate: u32,
}

// Speex resampler is thread-safe for processing operations
unsafe impl Send for Resampler {}

impl Resampler {
    /// Create a new resampler
    pub fn new(in_rate: u32, out_rate: u32) -> Result<Self> {
        if in_rate == out_rate {
            // No resampling needed, but create anyway for API consistency
        }

        let mut err: i32 = 0;
        let state = unsafe {
            speex_resampler_init(
                1, // mono
                in_rate,
                out_rate,
                RESAMPLER_QUALITY,
                &mut err,
            )
        };

        if state.is_null() || err != 0 {
            let err_msg = if err != 0 {
                unsafe {
                    let ptr = speex_resampler_strerror(err);
                    if ptr.is_null() {
                        "Unknown error".to_string()
                    } else {
                        std::ffi::CStr::from_ptr(ptr)
                            .to_string_lossy()
                            .to_string()
                    }
                }
            } else {
                "Failed to create resampler".to_string()
            };
            return Err(Error::Resampler(err_msg));
        }

        Ok(Self {
            state,
            in_rate,
            out_rate,
        })
    }

    /// Create resampler for 8kHz -> 16kHz (telephony to STT)
    pub fn upsample_8k_to_16k() -> Result<Self> {
        Self::new(8000, 16000)
    }

    /// Create resampler for 16kHz -> 8kHz (STT output to telephony)
    pub fn downsample_16k_to_8k() -> Result<Self> {
        Self::new(16000, 8000)
    }

    /// Process audio samples
    pub fn process(&self, input: &[i16]) -> Result<Vec<i16>> {
        if self.in_rate == self.out_rate {
            return Ok(input.to_vec());
        }

        if input.is_empty() {
            return Ok(Vec::new());
        }

        // Calculate output size
        let out_samples =
            (input.len() as u64 * self.out_rate as u64 / self.in_rate as u64) as usize + 16;
        let mut output = vec![0i16; out_samples];

        let mut in_len = input.len() as u32;
        let mut out_len = output.len() as u32;

        let err = unsafe {
            speex_resampler_process_int(
                self.state,
                0, // channel 0
                input.as_ptr(),
                &mut in_len,
                output.as_mut_ptr(),
                &mut out_len,
            )
        };

        if err != 0 {
            let err_msg = unsafe {
                let ptr = speex_resampler_strerror(err);
                if ptr.is_null() {
                    "Unknown error".to_string()
                } else {
                    std::ffi::CStr::from_ptr(ptr)
                        .to_string_lossy()
                        .to_string()
                }
            };
            return Err(Error::Resampler(err_msg));
        }

        output.truncate(out_len as usize);
        Ok(output)
    }

    /// Process audio bytes (L16 PCM little-endian)
    pub fn process_bytes(&self, input: &[u8]) -> Result<Vec<u8>> {
        let samples: Vec<i16> = input
            .chunks_exact(2)
            .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        let resampled = self.process(&samples)?;

        Ok(resampled.iter().flat_map(|&s| s.to_le_bytes()).collect())
    }
}

impl Drop for Resampler {
    fn drop(&mut self) {
        if !self.state.is_null() {
            unsafe {
                speex_resampler_destroy(self.state);
            }
            self.state = ptr::null_mut();
        }
    }
}
