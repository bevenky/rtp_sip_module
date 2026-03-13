//! Voice Activity Detection (VAD) / Silence Detection
//!
//! Energy-based VAD for detecting voice/silence in audio streams.
//! Used to trigger comfort noise generation (CNG) and optimize
//! bandwidth by suppressing silence packets.
//!
//! # Algorithm
//!
//! 1. Compute mean absolute energy of each frame: `sum(|sample|) / n`
//!    (pure mean absolute value, sample-rate-invariant)
//! 2. Compare against configurable threshold (default 100)
//! 3. Voice onset: require sustained energy above threshold for `voice_onset_ms`
//!    (default 200ms) before emitting `StartTalking`
//! 4. Silence holdoff: require sustained silence for `silence_holdoff_ms`
//!    (default 500ms) before emitting `StopTalking`
//! 5. `StartTalking` and `StopTalking` are one-shot transition events that
//!    automatically advance to `Talking` and `None` on the next call
//!
//! # Multi-channel Support
//!
//! For interleaved multi-channel audio, set `channels > 1`. The VAD
//! processes only channel 0 using stride-based access (`j += channels`),
//! and the `samples` parameter to `process()` is the per-channel count.
//!
//! # VAD Modes
//!
//! - `VadMode::Energy` (default): Pure energy-based detection
//! - `VadMode::Quality` through `VadMode::VeryAggressive`: WebRTC-style
//!   detection modes. When enabled, the binary voice/non-voice result
//!   is mapped to the energy score for the same state machine:
//!   voice → `threshold + 100`, non-voice → `0`.
//!
//! # State Machine
//!
//! ```text
//!  ┌──────┐  energy > thresh   ┌──────────────┐  onset confirmed  ┌────────────────┐
//!  │ None │ ──── count ────→  │ (onset count) │ ────────────────→ │  StartTalking  │
//!  └──────┘  for onset_ms     └──────────────┘                   └───────┬────────┘
//!     ↑                                                                  │ auto
//!     │                                                                  ▼
//!     │                                                           ┌─────────┐
//!     │  silence_holdoff_ms                                       │ Talking │
//!     │  ◀──────────────────── silence count ◀────────────────── └────┬────┘
//!     │                                                               │
//!     │                        ┌──────────────┐                       │
//!     └──── auto ◀──────────── │ StopTalking  │ ◀──── holdoff done ──┘
//!                              └──────────────┘
//! ```
//!
//! # Example
//!
//! ```
//! use rtpsip::rtp::vad::{VoiceActivityDetector, VadState};
//!
//! let mut vad = VoiceActivityDetector::new(8000);
//!
//! // Process a 20ms frame of silence (160 samples at 8kHz)
//! let silence = vec![0i16; 160];
//! let state = vad.process(&silence);
//! assert_eq!(state, VadState::None);
//! ```

/// Voice Activity Detection states
///
/// The state machine has four states. `StartTalking` and `StopTalking` are
/// one-shot transition events — they are emitted exactly once and then
/// automatically advance to `Talking` or `None` on the next `process()` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VadState {
    /// Silence / no voice detected (initial state)
    None,
    /// One-shot: voice onset just confirmed (will become `Talking` next frame)
    StartTalking,
    /// Sustained voice activity
    Talking,
    /// One-shot: silence onset just confirmed (will become `None` next frame)
    StopTalking,
}

impl std::fmt::Display for VadState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VadState::None => write!(f, "None"),
            VadState::StartTalking => write!(f, "StartTalking"),
            VadState::Talking => write!(f, "Talking"),
            VadState::StopTalking => write!(f, "StopTalking"),
        }
    }
}

impl VadState {
    /// Returns true if this state represents active voice (StartTalking or Talking)
    pub fn is_talking(&self) -> bool {
        matches!(self, VadState::StartTalking | VadState::Talking)
    }

    /// Returns true if this state represents silence (None or StopTalking)
    pub fn is_silent(&self) -> bool {
        matches!(self, VadState::None | VadState::StopTalking)
    }
}

/// VAD detection mode
///
/// Controls how voice activity is detected. `Energy` uses mean absolute
/// energy (default). The WebRTC-style modes (Quality through VeryAggressive)
/// use a more sophisticated detection algorithm that maps binary
/// voice/non-voice results to the energy score for the same state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VadMode {
    /// Pure energy-based detection (default)
    Energy,
    /// WebRTC-style mode 0: highest quality, least aggressive
    Quality,
    /// WebRTC-style mode 1: low bitrate
    LowBitrate,
    /// WebRTC-style mode 2: aggressive
    Aggressive,
    /// WebRTC-style mode 3: most aggressive, may clip speech edges
    VeryAggressive,
}

impl VadMode {
    /// Returns the numeric mode index for WebRTC-style modes, or -1 for Energy.
    #[cfg(test)]
    fn mode_index(&self) -> i32 {
        match self {
            VadMode::Energy => -1,
            VadMode::Quality => 0,
            VadMode::LowBitrate => 1,
            VadMode::Aggressive => 2,
            VadMode::VeryAggressive => 3,
        }
    }

    /// Whether this mode uses WebRTC-style detection
    pub fn is_webrtc_style(&self) -> bool {
        *self != VadMode::Energy
    }
}

/// Energy-based Voice Activity Detector
///
/// Uses mean absolute energy with sample-rate normalization, voice onset
/// confirmation, and silence holdoff.
///
/// Supports multi-channel interleaved audio (processes channel 0 only)
/// and optional WebRTC-style detection modes.
pub struct VoiceActivityDetector {
    /// Energy threshold (mean absolute, normalized)
    threshold: u32,
    /// Sample rate (Hz)
    sample_rate: u32,
    /// Divisor for sample-rate normalization: sample_rate / 8000
    divisor: u32,
    /// Number of interleaved audio channels (1 = mono)
    channels: u32,

    /// Voice onset confirmation: samples of sustained voice needed
    voice_onset_samples: u32,
    /// Silence holdoff: samples of sustained silence before StopTalking
    silence_holdoff_samples: u32,

    /// Accumulated voice samples during onset confirmation
    voice_sample_count: u32,
    /// Accumulated silence samples during holdoff
    silence_sample_count: u32,

    /// Current VAD state
    state: VadState,
    /// Energy of the last processed frame (mean absolute, normalized)
    last_energy: u32,

    /// Detection mode
    mode: VadMode,

    /// Bug #92: DC offset estimate (exponential moving average, scaled by 256).
    /// Used to remove DC bias from samples before energy computation.
    dc_estimate: i64,
}

impl VoiceActivityDetector {
    /// Create a new Voice Activity Detector with production defaults
    ///
    /// Defaults:
    /// - Threshold: 100 (mean absolute energy, normalized)
    /// - Voice onset: 200ms of sustained voice before StartTalking
    /// - Silence holdoff: 500ms of sustained silence before StopTalking
    /// - Channels: 1 (mono)
    /// - Mode: Energy
    ///
    /// # Arguments
    /// - `sample_rate` - Audio sample rate in Hz (8000, 16000, etc.)
    pub fn new(sample_rate: u32) -> Self {
        let sample_rate = sample_rate.max(8000);
        // Round instead of truncating to handle non-standard rates
        let divisor = ((sample_rate + 4000) / 8000).max(1);
        Self {
            threshold: 100,
            sample_rate,
            divisor,
            channels: 1,
            // Bug #57: Use same formula as with_config() for consistency
            voice_onset_samples: sample_rate * 200 / 1000,
            silence_holdoff_samples: sample_rate * 500 / 1000,
            voice_sample_count: 0,
            silence_sample_count: 0,
            state: VadState::None,
            last_energy: 0,
            mode: VadMode::Energy,
            dc_estimate: 0,
        }
    }

    /// Create a VAD with custom configuration
    ///
    /// # Arguments
    /// - `sample_rate` - Audio sample rate in Hz
    /// - `threshold` - Mean absolute energy threshold (default 100)
    /// - `voice_onset_ms` - Milliseconds of sustained voice before StartTalking (default 200)
    /// - `silence_holdoff_ms` - Milliseconds of sustained silence before StopTalking (default 500)
    pub fn with_config(
        sample_rate: u32,
        threshold: u32,
        voice_onset_ms: u32,
        silence_holdoff_ms: u32,
    ) -> Self {
        let sample_rate = sample_rate.max(8000);
        // Round instead of truncating to handle non-standard rates
        let divisor = ((sample_rate + 4000) / 8000).max(1);
        Self {
            threshold,
            sample_rate,
            divisor,
            channels: 1,
            voice_onset_samples: sample_rate * voice_onset_ms / 1000,
            silence_holdoff_samples: sample_rate * silence_holdoff_ms / 1000,
            voice_sample_count: 0,
            silence_sample_count: 0,
            state: VadState::None,
            last_energy: 0,
            mode: VadMode::Energy,
            dc_estimate: 0,
        }
    }

    /// Set the number of interleaved audio channels.
    ///
    /// When `channels > 1`, the VAD processes only channel 0 by
    /// striding through the interleaved buffer. The `samples` slice
    /// passed to `process()` contains all channels interleaved,
    /// and `per_channel_count = samples.len() / channels`.
    pub fn set_channels(&mut self, channels: u32) {
        self.channels = channels.max(1);
    }

    /// Get the number of configured channels
    pub fn channels(&self) -> u32 {
        self.channels
    }

    /// Set the VAD detection mode.
    ///
    /// - `VadMode::Energy`: pure energy-based (default)
    /// - `VadMode::Quality` through `VadMode::VeryAggressive`: WebRTC-style
    pub fn set_mode(&mut self, mode: VadMode) {
        self.mode = mode;
    }

    /// Get the current VAD mode
    pub fn mode(&self) -> VadMode {
        self.mode
    }

    /// Set the energy threshold (default 100)
    ///
    /// This is the mean absolute energy threshold, normalized by sample rate.
    /// Higher values = less sensitive. Lower values = more sensitive.
    pub fn set_threshold(&mut self, threshold: u32) {
        self.threshold = threshold;
    }

    /// Get the current energy threshold
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Set voice onset confirmation duration in milliseconds (default 200)
    ///
    /// Voice must persist this long before `StartTalking` is emitted.
    /// Prevents false triggers from transient noises.
    pub fn set_voice_onset_ms(&mut self, ms: u32) {
        self.voice_onset_samples = self.sample_rate * ms / 1000;
    }

    /// Set silence holdoff duration in milliseconds (default 500)
    ///
    /// Silence must persist this long before `StopTalking` is emitted.
    /// Prevents premature silence detection during natural speech pauses.
    pub fn set_silence_holdoff_ms(&mut self, ms: u32) {
        self.silence_holdoff_samples = self.sample_rate * ms / 1000;
    }

    /// Get the configured sample rate
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Process one audio frame and return the resulting VAD state
    ///
    /// The state machine:
    /// - `None` → accumulates voice samples → `StartTalking` when onset confirmed
    /// - `StartTalking` → automatically becomes `Talking`
    /// - `Talking` → accumulates silence samples → `StopTalking` when holdoff expires
    /// - `StopTalking` → automatically becomes `None`
    ///
    /// For multi-channel interleaved audio, `samples` contains all channels
    /// interleaved. The per-channel sample count is `samples.len() / channels`.
    ///
    /// An empty slice is treated as silence (energy = 0).
    pub fn process(&mut self, samples: &[i16]) -> VadState {
        // Advance one-shot states before processing
        match self.state {
            VadState::StartTalking => self.state = VadState::Talking,
            VadState::StopTalking => self.state = VadState::None,
            _ => {}
        }

        if samples.is_empty() {
            self.last_energy = 0;
            return self.process_silence(0);
        }

        // Bug #23 / #92: Update DC offset estimate (exponential moving average).
        // Per-frame update using the frame's average on channel 0, with a slow
        // time constant (255/256) to avoid stripping voice energy. The old code
        // ran the EMA per-sample with time constant 15/16 which was far too fast.
        {
            let channels = self.channels.max(1) as usize;
            let per_ch = samples.len() / channels;
            if per_ch > 0 {
                let frame_avg = (0..per_ch)
                    .filter_map(|i| {
                        let idx = i * channels;
                        if idx < samples.len() {
                            Some(samples[idx] as i64)
                        } else {
                            None
                        }
                    })
                    .sum::<i64>()
                    / per_ch as i64;
                // Bug #25: Use f64 intermediate for division to avoid precision loss
                self.dc_estimate = ((self.dc_estimate as f64 * 255.0) / 256.0) as i64 + frame_avg;
            }
        }

        // Per-channel sample count
        let per_channel = samples.len() as u32 / self.channels;

        // Compute energy based on mode
        // Bug #92 / #23: Subtract DC offset from each sample before computing energy
        let dc_offset = (self.dc_estimate / 256) as i32;
        let energy = if self.mode.is_webrtc_style() {
            // Bug #43: Apply DC correction before computing WebRTC score,
            // same as the energy-based mode does.
            self.compute_webrtc_score(samples, per_channel, dc_offset)
        } else {
            compute_mean_abs_multichannel_dc(samples, self.divisor, self.channels, dc_offset)
        };
        self.last_energy = energy;

        if energy > self.threshold {
            self.process_voice(per_channel)
        } else {
            self.process_silence(per_channel)
        }
    }

    /// WebRTC-style VAD scoring.
    ///
    /// Uses energy plus zero-crossing rate (ZCR) analysis, inspired by the
    /// WebRTC VAD. Voiced speech has high energy and low ZCR, while noise
    /// tends to have high ZCR relative to energy. Higher mode numbers are
    /// more aggressive (more likely to classify as silence).
    ///
    /// Returns: if voice detected → `threshold + 100`, else → `0`.
    /// This maps the binary result into the energy-based state machine.
    fn compute_webrtc_score(&self, samples: &[i16], per_channel: u32, dc_offset: i32) -> u32 {
        if per_channel < 2 {
            return 0;
        }

        let channels = self.channels as usize;
        let n = per_channel as usize;

        // Bug #43: Apply DC correction before computing RMS energy and
        // zero-crossing rate on channel 0, same as the energy-based mode does.
        let mut sum_sq: u64 = 0;
        let mut zero_crossings: u32 = 0;
        let first_corrected = samples[0] as i32 - dc_offset;
        let mut prev_sign = first_corrected >= 0;

        for i in 0..n {
            let idx = i * channels;
            if idx >= samples.len() {
                break;
            }
            let s = samples[idx] as i64 - dc_offset as i64;
            sum_sq += (s * s) as u64;

            let cur_sign = s >= 0;
            if cur_sign != prev_sign {
                zero_crossings += 1;
            }
            prev_sign = cur_sign;
        }

        // Bug #R12-1: Cast to f64 before division to avoid integer truncation
        let rms = (sum_sq as f64 / n as f64).sqrt() as u64;

        // Mode-dependent minimum RMS threshold (higher = more aggressive)
        let min_rms: u64 = match self.mode {
            VadMode::Quality => 8,
            VadMode::LowBitrate => 15,
            VadMode::Aggressive => 30,
            VadMode::VeryAggressive => 60,
            VadMode::Energy => 8,
        };

        // Must exceed minimum energy
        if rms < min_rms {
            return 0;
        }

        // Zero-crossing rate: fraction of sample transitions that cross zero.
        // Voiced speech (100-400Hz) at 8kHz has ~25-100 crossings per 160 samples.
        // White noise has ~80 crossings per 160 samples.
        // Very high ZCR relative to frame length suggests noise, not voice.
        let zcr_ratio = zero_crossings as f64 / (n - 1).max(1) as f64;

        // Mode-dependent ZCR threshold (lower = more strict about ZCR)
        let max_zcr: f64 = match self.mode {
            VadMode::Quality => 0.8,      // very permissive
            VadMode::LowBitrate => 0.6,   // moderate
            VadMode::Aggressive => 0.45,  // stricter
            VadMode::VeryAggressive => 0.35, // strictest
            VadMode::Energy => 1.0,
        };

        if zcr_ratio > max_zcr {
            return 0; // too many zero crossings → likely noise
        }

        // Bug #91: Use saturating_add to prevent overflow
        self.threshold.saturating_add(100) // voice detected
    }

    /// Handle a voice frame (energy above threshold)
    ///
    /// Uses strictly `>` for the threshold comparison, meaning onset
    /// fires on the frame AFTER the sample count exceeds the threshold.
    fn process_voice(&mut self, num_samples: u32) -> VadState {
        self.silence_sample_count = 0;
        self.voice_sample_count = self.voice_sample_count.saturating_add(num_samples);

        // Strictly greater than (>) not >=
        if self.state == VadState::None && self.voice_sample_count > self.voice_onset_samples {
            self.state = VadState::StartTalking;
        }

        self.state
    }

    /// Handle a silence frame (energy at or below threshold)
    fn process_silence(&mut self, num_samples: u32) -> VadState {
        self.silence_sample_count = self.silence_sample_count.saturating_add(num_samples);
        self.voice_sample_count = 0;

        // Strictly greater than (>) not >=
        if self.state == VadState::Talking && self.silence_sample_count > self.silence_holdoff_samples {
            self.state = VadState::StopTalking;
        }

        self.state
    }

    /// Get the current VAD state
    pub fn state(&self) -> VadState {
        self.state
    }

    /// Check if currently in a silent state (None or StopTalking)
    pub fn is_silent(&self) -> bool {
        self.state.is_silent()
    }

    /// Check if currently in a talking state (StartTalking or Talking)
    pub fn is_talking(&self) -> bool {
        self.state.is_talking()
    }

    /// Get the mean absolute energy of the last processed frame (normalized)
    ///
    /// Returns 0 if no frame has been processed yet.
    pub fn last_energy(&self) -> u32 {
        self.last_energy
    }

    /// Reset the VAD to its initial state
    ///
    /// Useful after hold/resume or transfer where audio context changes.
    pub fn reset(&mut self) {
        self.voice_sample_count = 0;
        self.silence_sample_count = 0;
        self.state = VadState::None;
        self.last_energy = 0;
        self.dc_estimate = 0;
    }
}

impl Default for VoiceActivityDetector {
    fn default() -> Self {
        Self::new(8000)
    }
}

/// Compute mean absolute energy with multi-channel support.
///
/// For multi-channel interleaved audio, processes only channel 0 using
/// stride-based access (`j += channels`). The per-channel sample count
/// is `total_samples / channels`.
///
/// Formula: `sum(|sample[j]|) / per_channel_count`
///
/// This is a pure mean absolute value, making it sample-rate-invariant
/// so the threshold works consistently across all rates.
///
/// The `_divisor` parameter is retained for API compatibility but is
/// no longer used in the computation.
///
/// Returns 0 for empty input.
fn compute_mean_abs_multichannel(samples: &[i16], _divisor: u32, channels: u32) -> u32 {
    let channels = channels.max(1) as usize;
    let per_channel = samples.len() / channels;
    let n = per_channel as u32;

    if n == 0 {
        return 0;
    }

    // Sum absolute values of channel 0 only, striding by channels
    let mut sum: u64 = 0;
    let mut j = 0usize;
    for _ in 0..per_channel {
        if j < samples.len() {
            sum += samples[j].unsigned_abs() as u64;
        }
        j += channels;
    }

    // Pure mean absolute value: sample-rate-invariant so threshold
    // works consistently across all rates.
    (sum / n as u64) as u32
}

/// Bug #92: DC-offset-corrected version of `compute_mean_abs_multichannel`.
/// Subtracts `dc_offset` from each sample before taking the absolute value.
fn compute_mean_abs_multichannel_dc(
    samples: &[i16],
    _divisor: u32,
    channels: u32,
    dc_offset: i32,
) -> u32 {
    let channels = channels.max(1) as usize;
    let per_channel = samples.len() / channels;
    let n = per_channel as u32;

    if n == 0 {
        return 0;
    }

    let mut sum: u64 = 0;
    let mut j = 0usize;
    for _ in 0..per_channel {
        if j < samples.len() {
            let corrected = (samples[j] as i32) - dc_offset;
            sum += corrected.unsigned_abs() as u64;
        }
        j += channels;
    }

    (sum / n as u64) as u32
}

/// Backward-compatible mono wrapper
#[cfg(test)]
fn compute_mean_abs(samples: &[i16], divisor: u32) -> u32 {
    compute_mean_abs_multichannel(samples, divisor, 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== compute_mean_abs tests ==========

    #[test]
    fn test_mean_abs_pure_silence() {
        let silence = vec![0i16; 160];
        assert_eq!(compute_mean_abs(&silence, 1), 0);
    }

    #[test]
    fn test_mean_abs_empty_slice() {
        assert_eq!(compute_mean_abs(&[], 1), 0);
    }

    #[test]
    fn test_mean_abs_constant_positive() {
        let samples = vec![1000i16; 160];
        assert_eq!(compute_mean_abs(&samples, 1), 1000);
    }

    #[test]
    fn test_mean_abs_constant_negative() {
        let samples = vec![-1000i16; 160];
        assert_eq!(compute_mean_abs(&samples, 1), 1000);
    }

    #[test]
    fn test_mean_abs_alternating() {
        let samples: Vec<i16> = (0..160).map(|i| if i % 2 == 0 { 500 } else { -500 }).collect();
        assert_eq!(compute_mean_abs(&samples, 1), 500);
    }

    #[test]
    fn test_mean_abs_sample_rate_invariant() {
        // With pure mean (sum/n), energy is sample-rate-invariant:
        // 8kHz: 160*1000 / 160 = 1000
        // 16kHz: 320*1000 / 320 = 1000
        let samples_8k = vec![1000i16; 160];
        let samples_16k = vec![1000i16; 320];
        assert_eq!(compute_mean_abs(&samples_8k, 1), 1000);
        assert_eq!(compute_mean_abs(&samples_16k, 2), 1000);
    }

    #[test]
    fn test_mean_abs_48khz_invariant() {
        // 48kHz: 960*1000 / 960 = 1000
        let samples = vec![1000i16; 960];
        assert_eq!(compute_mean_abs(&samples, 6), 1000);
    }

    #[test]
    fn test_mean_abs_short_frame() {
        // With pure mean, even single samples compute correctly
        assert_eq!(compute_mean_abs(&[10000], 2), 10000);
        assert_eq!(compute_mean_abs(&[10000; 5], 6), 10000);
        assert_eq!(compute_mean_abs(&[1000, 1000], 2), 1000); // sum=2000, n=2, 2000/2=1000
    }

    #[test]
    fn test_mean_abs_max_amplitude() {
        let samples = vec![i16::MAX; 160];
        assert_eq!(compute_mean_abs(&samples, 1), 32767);
    }

    #[test]
    fn test_mean_abs_i16_min() {
        // i16::MIN = -32768, unsigned_abs() = 32768
        let samples = vec![i16::MIN; 160];
        assert_eq!(compute_mean_abs(&samples, 1), 32768);
    }

    #[test]
    fn test_mean_abs_no_overflow_large_frame() {
        // 8000 samples at max amplitude — u64 accumulation prevents overflow
        let samples = vec![i16::MAX; 8000];
        assert_eq!(compute_mean_abs(&samples, 1), 32767);
    }

    #[test]
    fn test_mean_abs_divisor_ignored() {
        // Divisor is no longer used in computation; pure mean is returned
        assert_eq!(compute_mean_abs(&[1000; 160], 0), 1000);
    }

    // ========== Multi-channel compute_mean_abs tests ==========

    #[test]
    fn test_multichannel_stereo_processes_channel_0() {
        // Stereo interleaved: [ch0, ch1, ch0, ch1, ...]
        // Channel 0 = 1000, Channel 1 = 0
        // Per-channel count = 4, divisor = 1
        // Energy should be based only on channel 0
        let samples: Vec<i16> = vec![1000, 0, 1000, 0, 1000, 0, 1000, 0];
        assert_eq!(compute_mean_abs_multichannel(&samples, 1, 2), 1000);
    }

    #[test]
    fn test_multichannel_stereo_ignores_channel_1() {
        // Channel 0 = 0 (silence), Channel 1 = 10000 (loud)
        // VAD should see silence from channel 0
        let samples: Vec<i16> = vec![0, 10000, 0, 10000, 0, 10000, 0, 10000];
        assert_eq!(compute_mean_abs_multichannel(&samples, 1, 2), 0);
    }

    #[test]
    fn test_multichannel_mono_same_as_regular() {
        let samples = vec![1000i16; 160];
        assert_eq!(
            compute_mean_abs_multichannel(&samples, 1, 1),
            compute_mean_abs(&samples, 1)
        );
    }

    #[test]
    fn test_multichannel_stereo_with_divisor() {
        // 16kHz stereo: 320 interleaved samples = 160 per channel
        // Channel 0 = 500
        let mut samples = vec![0i16; 320];
        for i in 0..160 {
            samples[i * 2] = 500; // ch0
            samples[i * 2 + 1] = 0; // ch1
        }
        // per_channel=160, sum=160*500=80000, mean = 80000/160 = 500
        assert_eq!(compute_mean_abs_multichannel(&samples, 2, 2), 500);
    }

    #[test]
    fn test_multichannel_short_frame() {
        // 16kHz stereo: 2 total samples = 1 per channel
        // With pure mean, single sample computes normally: 10000
        assert_eq!(compute_mean_abs_multichannel(&[10000, 5000], 2, 2), 10000);
    }

    #[test]
    fn test_multichannel_6_channels() {
        // 6-channel (5.1 surround), 6 total samples = 1 per channel
        let samples: Vec<i16> = vec![5000, 1000, 2000, 3000, 4000, 500];
        // per_channel = 1, divisor = 1, channel 0 = 5000
        assert_eq!(compute_mean_abs_multichannel(&samples, 1, 6), 5000);
    }

    // ========== VadState tests ==========

    #[test]
    fn test_vad_state_display() {
        assert_eq!(VadState::None.to_string(), "None");
        assert_eq!(VadState::StartTalking.to_string(), "StartTalking");
        assert_eq!(VadState::Talking.to_string(), "Talking");
        assert_eq!(VadState::StopTalking.to_string(), "StopTalking");
    }

    #[test]
    fn test_vad_state_is_talking() {
        assert!(!VadState::None.is_talking());
        assert!(VadState::StartTalking.is_talking());
        assert!(VadState::Talking.is_talking());
        assert!(!VadState::StopTalking.is_talking());
    }

    #[test]
    fn test_vad_state_is_silent() {
        assert!(VadState::None.is_silent());
        assert!(!VadState::StartTalking.is_silent());
        assert!(!VadState::Talking.is_silent());
        assert!(VadState::StopTalking.is_silent());
    }

    // ========== Construction — verify defaults ==========

    #[test]
    fn test_vad_defaults() {
        // Defaults:
        //   thresh = 100
        //   voice_samples_thresh = 200 * (sample_rate / 1000) = 1600 at 8kHz
        //   silence_samples_thresh = 500 * (sample_rate / 1000) = 4000 at 8kHz
        //   divisor = sample_rate / 8000 = 1
        //   channels = 1
        //   mode = Energy
        let vad = VoiceActivityDetector::new(8000);
        assert_eq!(vad.threshold(), 100);
        assert_eq!(vad.divisor, 1);
        assert_eq!(vad.voice_onset_samples, 1600);
        assert_eq!(vad.silence_holdoff_samples, 4000);
        assert_eq!(vad.state(), VadState::None);
        assert_eq!(vad.channels(), 1);
        assert_eq!(vad.mode(), VadMode::Energy);
    }

    #[test]
    fn test_vad_defaults_16khz() {
        // At 16kHz:
        //   thresh = 100
        //   voice_samples_thresh = 200 * 16 = 3200
        //   silence_samples_thresh = 500 * 16 = 8000
        //   divisor = 16000/8000 = 2
        let vad = VoiceActivityDetector::new(16000);
        assert_eq!(vad.threshold(), 100);
        assert_eq!(vad.divisor, 2);
        assert_eq!(vad.voice_onset_samples, 3200);
        assert_eq!(vad.silence_holdoff_samples, 8000);
    }

    #[test]
    fn test_vad_default_trait() {
        let vad = VoiceActivityDetector::default();
        assert_eq!(vad.sample_rate(), 8000);
        assert_eq!(vad.threshold(), 100);
    }

    #[test]
    fn test_vad_with_config() {
        let vad = VoiceActivityDetector::with_config(8000, 500, 100, 300);
        assert_eq!(vad.threshold(), 500);
        assert_eq!(vad.voice_onset_samples, 800);   // 100ms * 8
        assert_eq!(vad.silence_holdoff_samples, 2400); // 300ms * 8
    }

    #[test]
    fn test_vad_set_threshold() {
        let mut vad = VoiceActivityDetector::new(8000);
        vad.set_threshold(500);
        assert_eq!(vad.threshold(), 500);
    }

    #[test]
    fn test_vad_set_onset_ms() {
        let mut vad = VoiceActivityDetector::new(8000);
        vad.set_voice_onset_ms(100);
        assert_eq!(vad.voice_onset_samples, 800);
    }

    #[test]
    fn test_vad_set_holdoff_ms() {
        let mut vad = VoiceActivityDetector::new(8000);
        vad.set_silence_holdoff_ms(300);
        assert_eq!(vad.silence_holdoff_samples, 2400);
    }

    #[test]
    fn test_vad_set_channels() {
        let mut vad = VoiceActivityDetector::new(8000);
        assert_eq!(vad.channels(), 1);
        vad.set_channels(2);
        assert_eq!(vad.channels(), 2);
        // channels=0 is clamped to 1
        vad.set_channels(0);
        assert_eq!(vad.channels(), 1);
    }

    #[test]
    fn test_vad_set_mode() {
        let mut vad = VoiceActivityDetector::new(8000);
        assert_eq!(vad.mode(), VadMode::Energy);
        vad.set_mode(VadMode::Aggressive);
        assert_eq!(vad.mode(), VadMode::Aggressive);
    }

    // ========== Voice onset — strictly greater than (>) ==========
    // At default 8kHz: voice_onset_samples=1600, so we need >1600 samples.
    // 10 frames = 1600 samples: NOT > 1600, stays None.
    // 11th frame = 1760 samples: > 1600, fires StartTalking.

    #[test]
    fn test_vad_onset_strictly_greater_than() {
        let mut vad = VoiceActivityDetector::new(8000);
        let voice = vec![1000i16; 160]; // well above threshold 100

        // Frames 1-10: accumulate 1600 samples. 1600 is NOT > 1600 → None
        for i in 0..10 {
            let state = vad.process(&voice);
            assert_eq!(state, VadState::None, "Frame {} should still be None", i + 1);
        }

        // Frame 11: 1760 samples > 1600 → StartTalking
        let state = vad.process(&voice);
        assert_eq!(state, VadState::StartTalking);
    }

    #[test]
    fn test_vad_start_talking_becomes_talking() {
        // Use custom config: onset=20ms=160 samples. Need >160, so 2 frames (320 > 160).
        let mut vad = VoiceActivityDetector::with_config(8000, 100, 20, 500);
        let voice = vec![1000i16; 160];

        // Frame 1: voice_samples=160. 160 NOT > 160 → None
        assert_eq!(vad.process(&voice), VadState::None);

        // Frame 2: voice_samples=320. 320 > 160 → StartTalking
        assert_eq!(vad.process(&voice), VadState::StartTalking);

        // Frame 3: auto-advance → Talking
        assert_eq!(vad.process(&voice), VadState::Talking);
    }

    #[test]
    fn test_vad_voice_onset_reset_by_silence() {
        let mut vad = VoiceActivityDetector::new(8000);
        let voice = vec![1000i16; 160];
        let silence = vec![0i16; 160];

        // 5 voice frames (800 samples, partial onset)
        for _ in 0..5 {
            vad.process(&voice);
        }
        assert_eq!(vad.state(), VadState::None);

        // Silence interrupts — resets voice_sample_count to 0
        vad.process(&silence);

        // Need full 11 frames of voice again (>1600 samples)
        for i in 0..10 {
            assert_eq!(vad.process(&voice), VadState::None, "Frame {} after reset", i + 1);
        }
        assert_eq!(vad.process(&voice), VadState::StartTalking);
    }

    // ========== Silence holdoff — strictly greater than (>) ==========
    // At 500ms holdoff: silence_samples_thresh=4000, need >4000 samples.
    // 25 frames = 4000 samples: NOT > 4000, stays Talking.
    // 26th frame = 4160 samples: > 4000, fires StopTalking.

    #[test]
    fn test_vad_holdoff_strictly_greater_than() {
        // onset=20ms so we can get to Talking quickly
        let mut vad = VoiceActivityDetector::with_config(8000, 100, 20, 500);
        let voice = vec![1000i16; 160];
        let silence = vec![0i16; 160];

        // Get to Talking: need >160 voice_samples → 2 voice frames
        vad.process(&voice); // voice_samples=160, None
        vad.process(&voice); // voice_samples=320 > 160, StartTalking
        vad.process(&voice); // Talking

        // 25 silent frames = 4000 samples. 4000 NOT > 4000 → stays Talking
        for i in 0..25 {
            let state = vad.process(&silence);
            assert_eq!(state, VadState::Talking, "Holdoff frame {} should be Talking", i + 1);
        }

        // 26th frame = 4160 > 4000 → StopTalking
        assert_eq!(vad.process(&silence), VadState::StopTalking);
    }

    #[test]
    fn test_vad_stop_talking_becomes_none() {
        // holdoff=20ms=160 samples. Need >160 → 2 silent frames.
        let mut vad = VoiceActivityDetector::with_config(8000, 100, 20, 20);
        let voice = vec![1000i16; 160];
        let silence = vec![0i16; 160];

        // Get to Talking
        vad.process(&voice); // None (160 not > 160)
        vad.process(&voice); // StartTalking (320 > 160)
        vad.process(&voice); // Talking

        // Silent frame 1: 160 not > 160 → Talking
        assert_eq!(vad.process(&silence), VadState::Talking);
        // Silent frame 2: 320 > 160 → StopTalking
        assert_eq!(vad.process(&silence), VadState::StopTalking);
        // Auto-advance → None
        assert_eq!(vad.process(&silence), VadState::None);
    }

    #[test]
    fn test_vad_silence_holdoff_reset_by_voice() {
        let mut vad = VoiceActivityDetector::with_config(8000, 100, 20, 500);
        let voice = vec![1000i16; 160];
        let silence = vec![0i16; 160];

        // Get to Talking
        vad.process(&voice);
        vad.process(&voice); // StartTalking
        vad.process(&voice); // Talking

        // 15 silent frames (partial holdoff)
        for _ in 0..15 {
            vad.process(&silence);
        }
        assert_eq!(vad.state(), VadState::Talking);

        // Voice returns — resets silence_sample_count
        vad.process(&voice);
        assert_eq!(vad.state(), VadState::Talking);

        // Need full 26 frames of silence again (>4000 samples)
        for i in 0..25 {
            assert_eq!(vad.process(&silence), VadState::Talking, "Frame {}", i + 1);
        }
        assert_eq!(vad.process(&silence), VadState::StopTalking);
    }

    // ========== Full lifecycle ==========

    #[test]
    fn test_vad_full_lifecycle() {
        // onset=20ms (>160 samples → 2 frames), holdoff=40ms (>320 samples → 3 frames)
        let mut vad = VoiceActivityDetector::with_config(8000, 100, 20, 40);
        let voice = vec![1000i16; 160];
        let silence = vec![0i16; 160];

        assert_eq!(vad.state(), VadState::None);

        // Voice onset: frame 1 (160 not > 160) → None, frame 2 (320 > 160) → StartTalking
        assert_eq!(vad.process(&voice), VadState::None);
        assert_eq!(vad.process(&voice), VadState::StartTalking);

        // Auto-advance → Talking
        assert_eq!(vad.process(&voice), VadState::Talking);

        // Silence holdoff: frames 1-2 (160, 320 not > 320) → Talking, frame 3 (480 > 320) → StopTalking
        assert_eq!(vad.process(&silence), VadState::Talking);
        assert_eq!(vad.process(&silence), VadState::Talking);
        assert_eq!(vad.process(&silence), VadState::StopTalking);

        // Auto-advance → None
        assert_eq!(vad.process(&silence), VadState::None);
    }

    #[test]
    fn test_vad_sustained_silence_stays_none() {
        let mut vad = VoiceActivityDetector::new(8000);
        let silence = vec![0i16; 160];
        for _ in 0..100 {
            assert_eq!(vad.process(&silence), VadState::None);
        }
    }

    #[test]
    fn test_vad_sustained_voice_stays_talking() {
        let mut vad = VoiceActivityDetector::with_config(8000, 100, 20, 500);
        let voice = vec![1000i16; 160];

        // Get to Talking
        vad.process(&voice);
        vad.process(&voice); // StartTalking
        vad.process(&voice); // Talking

        for _ in 0..100 {
            assert_eq!(vad.process(&voice), VadState::Talking);
        }
    }

    // ========== Speech with natural pauses ==========

    #[test]
    fn test_vad_speech_with_short_pauses() {
        // 500ms holdoff: short pauses (200ms) should NOT trigger StopTalking
        let mut vad = VoiceActivityDetector::with_config(8000, 100, 20, 500);
        let voice = vec![1000i16; 160];
        let silence = vec![0i16; 160];

        // Get to Talking
        vad.process(&voice);
        vad.process(&voice); // StartTalking
        vad.process(&voice); // Talking

        // 12 silent frames = 1920 samples, well under 4000
        for _ in 0..12 {
            assert_eq!(vad.process(&silence), VadState::Talking);
        }

        // Speech resumes — holdoff was reset
        assert_eq!(vad.process(&voice), VadState::Talking);
    }

    // ========== Edge cases ==========

    #[test]
    fn test_vad_empty_frame() {
        let mut vad = VoiceActivityDetector::new(8000);
        assert_eq!(vad.process(&[]), VadState::None);
        assert_eq!(vad.last_energy(), 0);
    }

    #[test]
    fn test_vad_single_sample_at_8khz() {
        // Pure mean: sum=10000, n=1, energy=10000.
        // But onset requires >1600 samples, so state stays None.
        let mut vad = VoiceActivityDetector::new(8000);
        let state = vad.process(&[10000]);
        assert_eq!(state, VadState::None);
        assert_eq!(vad.last_energy(), 10000);
    }

    #[test]
    fn test_vad_single_sample_at_16khz() {
        // Pure mean: sum=10000, n=1, energy=10000 (same as 8kHz).
        // State stays None because onset needs >3200 samples.
        let mut vad = VoiceActivityDetector::new(16000);
        let state = vad.process(&[10000]);
        assert_eq!(state, VadState::None);
        assert_eq!(vad.last_energy(), 10000);
    }

    #[test]
    fn test_vad_threshold_zero() {
        // Threshold 0: any non-zero audio is voice (energy > 0)
        // onset=20ms → need >160 samples = 2 frames
        let mut vad = VoiceActivityDetector::with_config(8000, 0, 20, 20);
        let tiny = vec![1i16; 160];
        let silence = vec![0i16; 160];

        // Frame 1: energy=1 > 0 → voice, but voice_samples=160, not > 160 → None
        assert_eq!(vad.process(&tiny), VadState::None);
        // Frame 2: voice_samples=320 > 160 → StartTalking
        assert_eq!(vad.process(&tiny), VadState::StartTalking);

        // Now silence: 2 frames needed (>160)
        // Frame 1: Talking (one-shot advance from StartTalking)
        //          silence_samples=160, not > 160 → Talking
        assert_eq!(vad.process(&silence), VadState::Talking);
        // Frame 2: silence_samples=320 > 160 → StopTalking
        assert_eq!(vad.process(&silence), VadState::StopTalking);
    }

    #[test]
    fn test_vad_reset() {
        let mut vad = VoiceActivityDetector::with_config(8000, 100, 20, 500);
        let voice = vec![5000i16; 160];

        // Get to Talking
        vad.process(&voice);
        vad.process(&voice); // StartTalking
        vad.process(&voice); // Talking
        assert_eq!(vad.state(), VadState::Talking);

        vad.reset();
        assert_eq!(vad.state(), VadState::None);
        assert!(vad.is_silent());
        assert_eq!(vad.last_energy(), 0);
    }

    #[test]
    fn test_vad_counter_saturation() {
        let mut vad = VoiceActivityDetector::with_config(8000, 100, 20, 500);
        let silence = vec![0i16; 160];

        // Process many silence frames
        for _ in 0..100_000 {
            vad.process(&silence);
        }
        assert_eq!(vad.state(), VadState::None);

        // onset=20ms=160 samples, need >160 → 2 voice frames
        let voice = vec![1000i16; 160];
        assert_eq!(vad.process(&voice), VadState::None);
        assert_eq!(vad.process(&voice), VadState::StartTalking);
        assert_eq!(vad.process(&voice), VadState::Talking);
    }

    #[test]
    fn test_vad_one_shot_events_fire_once() {
        // onset=20ms (>160 → 2 frames), holdoff=20ms (>160 → 2 frames)
        let mut vad = VoiceActivityDetector::with_config(8000, 100, 20, 20);
        let voice = vec![1000i16; 160];
        let silence = vec![0i16; 160];

        let mut start_count = 0;
        let mut stop_count = 0;

        for _ in 0..30 {
            let state = vad.process(&voice);
            if state == VadState::StartTalking {
                start_count += 1;
            }
        }
        for _ in 0..30 {
            let state = vad.process(&silence);
            if state == VadState::StopTalking {
                stop_count += 1;
            }
        }

        assert_eq!(start_count, 1, "StartTalking should fire exactly once");
        assert_eq!(stop_count, 1, "StopTalking should fire exactly once");
    }

    #[test]
    fn test_vad_multiple_talk_cycles() {
        // onset=20ms (2 frames), holdoff=20ms (2 frames)
        let mut vad = VoiceActivityDetector::with_config(8000, 100, 20, 20);
        let voice = vec![1000i16; 160];
        let silence = vec![0i16; 160];

        for _cycle in 0..3 {
            // Onset: frame 1 → None, frame 2 → StartTalking
            assert_eq!(vad.process(&voice), VadState::None);
            assert_eq!(vad.process(&voice), VadState::StartTalking);

            // Sustained voice
            for _ in 0..5 {
                assert_eq!(vad.process(&voice), VadState::Talking);
            }

            // Holdoff: frame 1 → Talking, frame 2 → StopTalking
            assert_eq!(vad.process(&silence), VadState::Talking);
            assert_eq!(vad.process(&silence), VadState::StopTalking);

            // Auto-advance to None
            assert_eq!(vad.process(&silence), VadState::None);
        }
    }

    #[test]
    fn test_vad_energy_tracks_correctly() {
        let mut vad = VoiceActivityDetector::new(8000);

        let loud = vec![5000i16; 160];
        vad.process(&loud);
        assert_eq!(vad.last_energy(), 5000);

        let quiet = vec![50i16; 160];
        vad.process(&quiet);
        assert_eq!(vad.last_energy(), 50);
    }

    #[test]
    fn test_vad_pure_tone_440hz() {
        let mut vad = VoiceActivityDetector::new(8000);

        // Generate 20ms of 440Hz sine wave at 8kHz, amplitude 5000
        let samples: Vec<i16> = (0..160)
            .map(|i| {
                let t = i as f64 / 8000.0;
                (5000.0 * (2.0 * std::f64::consts::PI * 440.0 * t).sin()) as i16
            })
            .collect();

        vad.process(&samples);

        // Mean absolute value of sine with amplitude A = 2A/π ≈ 3183
        let expected = (5000.0 * 2.0 / std::f64::consts::PI) as u32;
        let actual = vad.last_energy();
        assert!(
            (actual as i64 - expected as i64).unsigned_abs() < 100,
            "Expected energy ~{}, got {}",
            expected,
            actual
        );
    }

    // ========== Full state machine step-by-step verification ==========

    #[test]
    fn test_vad_state_machine_step_by_step() {
        // sample_rate=8000, thresh=100, voice_thresh=1600, silence_thresh=4000
        let mut vad = VoiceActivityDetector::new(8000);
        let voice = vec![500i16; 160]; // energy=500, > 100
        let silence = vec![0i16; 160]; // energy=0, not > 100

        // --- Onset phase ---
        // voice_samples accumulates, need > 1600
        // Frame 1-10: voice_samples = 160..1600. 1600 NOT > 1600 → None
        for _ in 0..10 {
            assert_eq!(vad.process(&voice), VadState::None);
        }
        // Frame 11: voice_samples = 1760 > 1600 → START_TALKING
        assert_eq!(vad.process(&voice), VadState::StartTalking);

        // --- Talking phase ---
        // Frame 12: one-shot advance to TALKING
        assert_eq!(vad.process(&voice), VadState::Talking);
        // Frame 13-20: sustained voice
        for _ in 0..8 {
            assert_eq!(vad.process(&voice), VadState::Talking);
        }

        // --- Holdoff phase ---
        // silence_samples accumulates, need > 4000
        // Frames 1-25: silence_samples = 160..4000. 4000 NOT > 4000 → Talking
        for _ in 0..25 {
            assert_eq!(vad.process(&silence), VadState::Talking);
        }
        // Frame 26: silence_samples = 4160 > 4000 → STOP_TALKING
        assert_eq!(vad.process(&silence), VadState::StopTalking);

        // --- Back to silence ---
        // One-shot advance to NONE
        assert_eq!(vad.process(&silence), VadState::None);
    }

    // ========== Multi-channel VAD integration tests ==========

    #[test]
    fn test_vad_stereo_detects_voice_on_channel_0() {
        let mut vad = VoiceActivityDetector::with_config(8000, 100, 20, 20);
        vad.set_channels(2);

        // 160 per-channel samples → 320 interleaved total
        // Channel 0 = 1000 (voice), Channel 1 = 0
        let mut voice_stereo = vec![0i16; 320];
        for i in 0..160 {
            voice_stereo[i * 2] = 1000;
        }

        // Need >160 per-channel → 2 frames for onset
        assert_eq!(vad.process(&voice_stereo), VadState::None);
        assert_eq!(vad.process(&voice_stereo), VadState::StartTalking);
    }

    #[test]
    fn test_vad_stereo_silence_on_channel_0() {
        let mut vad = VoiceActivityDetector::with_config(8000, 100, 20, 20);
        vad.set_channels(2);

        // Channel 0 = 0 (silence), Channel 1 = 10000 (loud)
        // VAD should treat as silence
        let mut loud_ch1 = vec![0i16; 320];
        for i in 0..160 {
            loud_ch1[i * 2 + 1] = 10000;
        }

        for _ in 0..20 {
            assert_eq!(vad.process(&loud_ch1), VadState::None);
        }
    }

    #[test]
    fn test_vad_stereo_full_lifecycle() {
        let mut vad = VoiceActivityDetector::with_config(8000, 100, 20, 40);
        vad.set_channels(2);

        // Voice on channel 0
        let mut voice = vec![0i16; 320];
        for i in 0..160 {
            voice[i * 2] = 1000;
        }
        let silence = vec![0i16; 320];

        // Onset: frame 1 → None, frame 2 → StartTalking
        assert_eq!(vad.process(&voice), VadState::None);
        assert_eq!(vad.process(&voice), VadState::StartTalking);
        assert_eq!(vad.process(&voice), VadState::Talking);

        // Holdoff: 3 frames of silence (>320 per-channel)
        assert_eq!(vad.process(&silence), VadState::Talking);
        assert_eq!(vad.process(&silence), VadState::Talking);
        assert_eq!(vad.process(&silence), VadState::StopTalking);
        assert_eq!(vad.process(&silence), VadState::None);
    }

    // ========== VadMode tests ==========

    #[test]
    fn test_vad_mode_energy_default() {
        let vad = VoiceActivityDetector::new(8000);
        assert_eq!(vad.mode(), VadMode::Energy);
        assert!(!vad.mode().is_webrtc_style());
    }

    #[test]
    fn test_vad_mode_webrtc_style_flag() {
        assert!(!VadMode::Energy.is_webrtc_style());
        assert!(VadMode::Quality.is_webrtc_style());
        assert!(VadMode::LowBitrate.is_webrtc_style());
        assert!(VadMode::Aggressive.is_webrtc_style());
        assert!(VadMode::VeryAggressive.is_webrtc_style());
    }

    #[test]
    fn test_vad_mode_quality_detects_voice() {
        let mut vad = VoiceActivityDetector::with_config(8000, 100, 20, 20);
        vad.set_mode(VadMode::Quality);

        let voice = vec![5000i16; 160]; // loud voice
        // Onset: 2 frames needed (>160 per-channel)
        assert_eq!(vad.process(&voice), VadState::None);
        assert_eq!(vad.process(&voice), VadState::StartTalking);
        assert_eq!(vad.process(&voice), VadState::Talking);
    }

    #[test]
    fn test_vad_mode_quality_detects_silence() {
        let mut vad = VoiceActivityDetector::with_config(8000, 100, 20, 20);
        vad.set_mode(VadMode::Quality);

        let silence = vec![0i16; 160];
        for _ in 0..20 {
            assert_eq!(vad.process(&silence), VadState::None);
        }
    }

    #[test]
    fn test_vad_mode_aggressive_rejects_noise() {
        let mut vad = VoiceActivityDetector::with_config(8000, 100, 20, 20);
        vad.set_mode(VadMode::VeryAggressive);

        // Low-level flat noise (equal energy in all frequencies)
        // VeryAggressive mode requires strong spectral tilt → should reject
        let noise: Vec<i16> = (0..160).map(|i| ((i * 137 + 42) % 100) as i16 - 50).collect();
        for _ in 0..20 {
            assert_eq!(vad.process(&noise), VadState::None,
                "VeryAggressive should reject low-level flat noise");
        }
    }

    #[test]
    fn test_vad_mode_aggressive_detects_loud_voice() {
        let mut vad = VoiceActivityDetector::with_config(8000, 100, 20, 20);
        vad.set_mode(VadMode::VeryAggressive);

        // Loud voice (high energy, concentrated in low frequencies)
        let voice: Vec<i16> = (0..160)
            .map(|i| {
                let t = i as f64 / 8000.0;
                (10000.0 * (2.0 * std::f64::consts::PI * 200.0 * t).sin()) as i16
            })
            .collect();

        assert_eq!(vad.process(&voice), VadState::None); // onset accumulation
        assert_eq!(vad.process(&voice), VadState::StartTalking);
    }

    #[test]
    fn test_vad_mode_index() {
        assert_eq!(VadMode::Energy.mode_index(), -1);
        assert_eq!(VadMode::Quality.mode_index(), 0);
        assert_eq!(VadMode::LowBitrate.mode_index(), 1);
        assert_eq!(VadMode::Aggressive.mode_index(), 2);
        assert_eq!(VadMode::VeryAggressive.mode_index(), 3);
    }

    #[test]
    fn test_vad_webrtc_mode_with_stereo() {
        // Combine multi-channel + WebRTC mode
        let mut vad = VoiceActivityDetector::with_config(8000, 100, 20, 20);
        vad.set_channels(2);
        vad.set_mode(VadMode::Quality);

        // 320 interleaved samples, voice on ch0
        let mut voice = vec![0i16; 320];
        for i in 0..160 {
            voice[i * 2] = 5000;
        }

        assert_eq!(vad.process(&voice), VadState::None);
        assert_eq!(vad.process(&voice), VadState::StartTalking);
    }
}
