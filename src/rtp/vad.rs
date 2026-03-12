//! Voice Activity Detection (VAD) / Silence Detection
//!
//! Energy-based VAD for detecting silence in audio streams. Used to trigger
//! comfort noise generation (CNG) and optimize bandwidth by suppressing
//! silence packets.
//!
//! Modeled after FreeSWITCH's `switch_vad` which uses RMS energy thresholds
//! with hangover to prevent choppy voice/silence transitions.
//!
//! # Algorithm
//!
//! 1. Compute RMS energy of each audio frame: `sqrt(sum(sample^2) / n)`
//! 2. Compare against configurable threshold (~250 RMS = -30 dBFS for 16-bit PCM)
//! 3. Transition to silence only after `hangover_frames` consecutive silent frames
//! 4. Transition back to voice immediately on detection
//!
//! # Example
//!
//! ```
//! use rtpsip::rtp::vad::{VoiceActivityDetector, VadState};
//!
//! let mut vad = VoiceActivityDetector::new();
//!
//! // Process a 20ms frame of silence (160 samples at 8kHz)
//! let silence = vec![0i16; 160];
//! let has_voice = vad.process(&silence);
//! assert!(!has_voice);
//! assert_eq!(vad.state(), VadState::Silence);
//! ```

/// Voice activity state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VadState {
    /// Voice (or non-silence) detected
    Voice,
    /// Silence detected (after hangover period)
    Silence,
}

impl std::fmt::Display for VadState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VadState::Voice => write!(f, "Voice"),
            VadState::Silence => write!(f, "Silence"),
        }
    }
}

/// Energy-based Voice Activity Detector
///
/// Uses RMS energy thresholds with a hangover mechanism to provide
/// stable voice/silence classification. The hangover prevents rapid
/// toggling during natural speech pauses.
pub struct VoiceActivityDetector {
    /// Energy threshold (RMS) below which audio is considered silence
    threshold: f64,
    /// Number of consecutive silent frames before declaring silence
    hangover_frames: u32,
    /// Current silent frame counter
    silent_count: u32,
    /// Current VAD state
    state: VadState,
    /// RMS energy of the last processed frame
    last_energy: f64,
}

impl VoiceActivityDetector {
    /// Create a new Voice Activity Detector with default settings
    ///
    /// Defaults:
    /// - Threshold: 250.0 RMS (~-30 dBFS for 16-bit PCM)
    /// - Hangover: 10 frames (200ms at 20ms frame size)
    pub fn new() -> Self {
        Self {
            threshold: 250.0,
            hangover_frames: 10,
            silent_count: 0,
            state: VadState::Silence,
            last_energy: 0.0,
        }
    }

    /// Create a VAD with custom threshold and hangover
    ///
    /// # Arguments
    /// - `threshold` - RMS energy threshold (clamped to >= 0.0)
    /// - `hangover_frames` - Number of consecutive silent frames before
    ///   transitioning to silence state
    pub fn with_config(threshold: f64, hangover_frames: u32) -> Self {
        Self {
            threshold: threshold.max(0.0),
            hangover_frames,
            silent_count: 0,
            state: VadState::Silence,
            last_energy: 0.0,
        }
    }

    /// Set the energy threshold (default 250 RMS)
    ///
    /// Higher values make the detector less sensitive (more audio classified
    /// as silence). Lower values make it more sensitive.
    ///
    /// Reference points for 16-bit PCM:
    /// - ~50 RMS: very quiet background noise
    /// - ~250 RMS: typical silence threshold (~-30 dBFS)
    /// - ~1000 RMS: moderate speech
    /// - ~10000 RMS: loud speech
    pub fn set_threshold(&mut self, threshold: f64) {
        self.threshold = threshold.max(0.0);
    }

    /// Get the current energy threshold
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Set hangover duration in frames (default 10 = 200ms at 20ms frames)
    ///
    /// The hangover prevents choppy detection during natural speech pauses.
    /// A value of 0 disables hangover (immediate silence transition).
    pub fn set_hangover(&mut self, frames: u32) {
        self.hangover_frames = frames;
    }

    /// Get the current hangover frame count
    pub fn hangover(&self) -> u32 {
        self.hangover_frames
    }

    /// Process one audio frame (typically 160 samples at 8kHz = 20ms)
    ///
    /// Returns `true` if the frame contains voice activity, `false` if silence.
    ///
    /// The state machine works as follows:
    /// - Voice -> Silence: only after `hangover_frames` consecutive below-threshold frames
    /// - Silence -> Voice: immediately on first above-threshold frame
    ///
    /// An empty slice is treated as silence (energy = 0.0).
    pub fn process(&mut self, samples: &[i16]) -> bool {
        let energy = compute_rms(samples);
        self.last_energy = energy;

        if energy >= self.threshold {
            // Voice detected — reset counter and transition immediately
            self.silent_count = 0;
            self.state = VadState::Voice;
            true
        } else {
            // Below threshold — increment silent frame counter
            self.silent_count = self.silent_count.saturating_add(1);

            if self.silent_count > self.hangover_frames {
                // Enough consecutive silent frames — declare silence
                self.state = VadState::Silence;
                false
            } else {
                // Still in hangover period — report as voice to avoid choppiness
                self.state = VadState::Voice;
                true
            }
        }
    }

    /// Get the current VAD state
    pub fn state(&self) -> VadState {
        self.state
    }

    /// Check if currently in silence state
    pub fn is_silent(&self) -> bool {
        self.state == VadState::Silence
    }

    /// Get the RMS energy of the last processed frame
    ///
    /// Returns 0.0 if no frame has been processed yet.
    pub fn last_energy(&self) -> f64 {
        self.last_energy
    }

    /// Reset the VAD to its initial state
    ///
    /// Useful after hold/resume or transfer where audio context changes.
    pub fn reset(&mut self) {
        self.silent_count = 0;
        self.state = VadState::Silence;
        self.last_energy = 0.0;
    }
}

impl Default for VoiceActivityDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute RMS (Root Mean Square) energy of PCM samples
///
/// Returns 0.0 for empty input. Uses `i64` accumulation to avoid
/// overflow with 16-bit samples (max sum of squares for 160 samples:
/// 160 * 32767^2 = ~1.7e11, well within i64 range).
fn compute_rms(samples: &[i16]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }

    let sum_sq: i64 = samples.iter().map(|&s| (s as i64) * (s as i64)).sum();
    let mean_sq = sum_sq as f64 / samples.len() as f64;
    mean_sq.sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== compute_rms tests ==========

    #[test]
    fn test_rms_pure_silence() {
        let silence = vec![0i16; 160];
        assert_eq!(compute_rms(&silence), 0.0);
    }

    #[test]
    fn test_rms_empty_slice() {
        assert_eq!(compute_rms(&[]), 0.0);
    }

    #[test]
    fn test_rms_single_sample() {
        // RMS of a single sample = |sample|
        assert!((compute_rms(&[1000]) - 1000.0).abs() < 0.01);
        assert!((compute_rms(&[-1000]) - 1000.0).abs() < 0.01);
    }

    #[test]
    fn test_rms_known_value() {
        // All samples at 100 → RMS = 100
        let samples = vec![100i16; 160];
        let rms = compute_rms(&samples);
        assert!((rms - 100.0).abs() < 0.01, "RMS of constant 100 = {}", rms);
    }

    #[test]
    fn test_rms_symmetric_signal() {
        // Alternating +1000 / -1000 → RMS = 1000
        let samples: Vec<i16> = (0..160).map(|i| if i % 2 == 0 { 1000 } else { -1000 }).collect();
        let rms = compute_rms(&samples);
        assert!((rms - 1000.0).abs() < 0.01, "RMS = {}", rms);
    }

    #[test]
    fn test_rms_max_amplitude() {
        // Full-scale 16-bit: all samples at i16::MAX
        let samples = vec![i16::MAX; 160];
        let rms = compute_rms(&samples);
        assert!(
            (rms - 32767.0).abs() < 1.0,
            "RMS of max amplitude = {}",
            rms
        );
    }

    #[test]
    fn test_rms_no_overflow() {
        // Worst case: 8000 samples (1 second at 8kHz) all at max amplitude
        let samples = vec![i16::MAX; 8000];
        let rms = compute_rms(&samples);
        assert!(rms.is_finite());
        assert!(rms > 32000.0);
    }

    // ========== VadState tests ==========

    #[test]
    fn test_vad_state_display() {
        assert_eq!(VadState::Voice.to_string(), "Voice");
        assert_eq!(VadState::Silence.to_string(), "Silence");
    }

    #[test]
    fn test_vad_state_equality() {
        assert_eq!(VadState::Voice, VadState::Voice);
        assert_eq!(VadState::Silence, VadState::Silence);
        assert_ne!(VadState::Voice, VadState::Silence);
    }

    // ========== VoiceActivityDetector basic tests ==========

    #[test]
    fn test_vad_default_creation() {
        let vad = VoiceActivityDetector::new();
        assert_eq!(vad.threshold(), 250.0);
        assert_eq!(vad.hangover(), 10);
        assert!(vad.is_silent());
        assert_eq!(vad.state(), VadState::Silence);
        assert_eq!(vad.last_energy(), 0.0);
    }

    #[test]
    fn test_vad_default_trait() {
        let vad = VoiceActivityDetector::default();
        assert_eq!(vad.threshold(), 250.0);
    }

    #[test]
    fn test_vad_with_config() {
        let vad = VoiceActivityDetector::with_config(500.0, 20);
        assert_eq!(vad.threshold(), 500.0);
        assert_eq!(vad.hangover(), 20);
    }

    #[test]
    fn test_vad_negative_threshold_clamped() {
        let vad = VoiceActivityDetector::with_config(-100.0, 5);
        assert_eq!(vad.threshold(), 0.0);

        let mut vad2 = VoiceActivityDetector::new();
        vad2.set_threshold(-50.0);
        assert_eq!(vad2.threshold(), 0.0);
    }

    #[test]
    fn test_vad_set_threshold() {
        let mut vad = VoiceActivityDetector::new();
        vad.set_threshold(500.0);
        assert_eq!(vad.threshold(), 500.0);
    }

    #[test]
    fn test_vad_set_hangover() {
        let mut vad = VoiceActivityDetector::new();
        vad.set_hangover(20);
        assert_eq!(vad.hangover(), 20);
    }

    // ========== Voice detection tests ==========

    #[test]
    fn test_vad_detects_voice() {
        let mut vad = VoiceActivityDetector::new();

        // Generate a frame with RMS well above threshold (250)
        // Samples at amplitude 1000 → RMS = 1000
        let voice_frame = vec![1000i16; 160];
        let result = vad.process(&voice_frame);

        assert!(result, "Should detect voice");
        assert_eq!(vad.state(), VadState::Voice);
        assert!(!vad.is_silent());
        assert!((vad.last_energy() - 1000.0).abs() < 1.0);
    }

    #[test]
    fn test_vad_detects_loud_voice() {
        let mut vad = VoiceActivityDetector::new();

        // Near full-scale audio
        let loud_frame = vec![20000i16; 160];
        assert!(vad.process(&loud_frame));
        assert_eq!(vad.state(), VadState::Voice);
    }

    #[test]
    fn test_vad_detects_threshold_boundary() {
        let mut vad = VoiceActivityDetector::with_config(100.0, 0);

        // Exactly at threshold — should be detected as voice (>= threshold)
        let at_threshold = vec![100i16; 160];
        assert!(vad.process(&at_threshold));

        // Just below threshold
        let below = vec![99i16; 160];
        assert!(!vad.process(&below));
    }

    // ========== Silence detection tests ==========

    #[test]
    fn test_vad_detects_pure_silence() {
        let mut vad = VoiceActivityDetector::with_config(250.0, 0); // No hangover
        let silence = vec![0i16; 160];

        let result = vad.process(&silence);
        assert!(!result, "Should detect silence");
        assert_eq!(vad.state(), VadState::Silence);
        assert!(vad.is_silent());
        assert_eq!(vad.last_energy(), 0.0);
    }

    #[test]
    fn test_vad_detects_low_noise_as_silence() {
        let mut vad = VoiceActivityDetector::with_config(250.0, 0);

        // Very low amplitude noise (RMS ~10)
        let low_noise = vec![10i16; 160];
        assert!(!vad.process(&low_noise));
        assert!(vad.is_silent());
    }

    #[test]
    fn test_vad_empty_frame_is_silence() {
        let mut vad = VoiceActivityDetector::with_config(250.0, 0);
        assert!(!vad.process(&[]));
        assert!(vad.is_silent());
        assert_eq!(vad.last_energy(), 0.0);
    }

    // ========== Hangover behavior tests ==========

    #[test]
    fn test_vad_hangover_prevents_immediate_silence() {
        let mut vad = VoiceActivityDetector::with_config(250.0, 5);

        // First, establish voice state
        let voice = vec![1000i16; 160];
        vad.process(&voice);
        assert_eq!(vad.state(), VadState::Voice);

        // Send silent frames — should stay in voice during hangover
        let silence = vec![0i16; 160];
        for i in 0..5 {
            let result = vad.process(&silence);
            assert!(
                result,
                "Frame {} during hangover should report voice",
                i + 1
            );
            assert_eq!(vad.state(), VadState::Voice);
        }

        // One more silent frame pushes past hangover → silence
        let result = vad.process(&silence);
        assert!(!result, "Should transition to silence after hangover");
        assert_eq!(vad.state(), VadState::Silence);
    }

    #[test]
    fn test_vad_hangover_reset_on_voice() {
        let mut vad = VoiceActivityDetector::with_config(250.0, 5);

        // Establish voice
        let voice = vec![1000i16; 160];
        vad.process(&voice);

        // Send 3 silent frames (less than hangover of 5)
        let silence = vec![0i16; 160];
        for _ in 0..3 {
            let result = vad.process(&silence);
            assert!(result, "Still in hangover");
        }

        // Voice comes back — hangover counter should reset
        assert!(vad.process(&voice));
        assert_eq!(vad.state(), VadState::Voice);

        // Now need full 5 silent frames again before silence
        for i in 0..5 {
            let result = vad.process(&silence);
            assert!(result, "Hangover frame {} should be voice", i + 1);
        }

        // 6th silent frame → silence
        assert!(!vad.process(&silence));
        assert_eq!(vad.state(), VadState::Silence);
    }

    #[test]
    fn test_vad_zero_hangover() {
        let mut vad = VoiceActivityDetector::with_config(250.0, 0);

        // Voice
        let voice = vec![1000i16; 160];
        vad.process(&voice);
        assert_eq!(vad.state(), VadState::Voice);

        // Immediate silence transition with zero hangover
        let silence = vec![0i16; 160];
        assert!(!vad.process(&silence));
        assert_eq!(vad.state(), VadState::Silence);
    }

    #[test]
    fn test_vad_immediate_voice_from_silence() {
        let mut vad = VoiceActivityDetector::with_config(250.0, 10);

        // Start in silence
        let silence = vec![0i16; 160];
        for _ in 0..20 {
            vad.process(&silence);
        }
        assert!(vad.is_silent());

        // Single voice frame → immediate transition to voice
        let voice = vec![1000i16; 160];
        assert!(vad.process(&voice));
        assert_eq!(vad.state(), VadState::Voice);
        assert!(!vad.is_silent());
    }

    // ========== Realistic scenario tests ==========

    #[test]
    fn test_vad_speech_burst() {
        let mut vad = VoiceActivityDetector::new(); // threshold=250, hangover=10

        let silence = vec![0i16; 160];
        let speech = vec![2000i16; 160];

        // Initial silence
        for _ in 0..20 {
            vad.process(&silence);
        }
        assert!(vad.is_silent());

        // Speech burst (10 frames = 200ms)
        for _ in 0..10 {
            assert!(vad.process(&speech));
        }
        assert_eq!(vad.state(), VadState::Voice);

        // Post-speech silence — voice for hangover (10 frames), then silence
        for i in 0..10 {
            let result = vad.process(&silence);
            assert!(result, "Hangover frame {}", i + 1);
        }

        // Frame 11 → silence
        assert!(!vad.process(&silence));
        assert!(vad.is_silent());
    }

    #[test]
    fn test_vad_alternating_voice_silence() {
        let mut vad = VoiceActivityDetector::with_config(250.0, 3);

        let silence = vec![0i16; 160];
        let voice = vec![1000i16; 160];

        // Pattern: voice, silence, silence, voice (gap shorter than hangover)
        assert!(vad.process(&voice));
        assert!(vad.process(&silence)); // hangover 1
        assert!(vad.process(&silence)); // hangover 2
        assert!(vad.process(&voice)); // resets counter

        // Should still be voice — gap was shorter than hangover
        assert_eq!(vad.state(), VadState::Voice);
    }

    #[test]
    fn test_vad_pure_tone_440hz() {
        let mut vad = VoiceActivityDetector::new();

        // Generate 20ms of 440Hz sine wave at 8kHz, amplitude 5000
        let samples: Vec<i16> = (0..160)
            .map(|i| {
                let t = i as f64 / 8000.0;
                (5000.0 * (2.0 * std::f64::consts::PI * 440.0 * t).sin()) as i16
            })
            .collect();

        assert!(vad.process(&samples));
        assert_eq!(vad.state(), VadState::Voice);

        // RMS of sine wave with amplitude A = A / sqrt(2) ≈ 3535
        let expected_rms = 5000.0 / std::f64::consts::SQRT_2;
        assert!(
            (vad.last_energy() - expected_rms).abs() < 50.0,
            "Expected RMS ~{:.0}, got {:.0}",
            expected_rms,
            vad.last_energy()
        );
    }

    // ========== Reset test ==========

    #[test]
    fn test_vad_reset() {
        let mut vad = VoiceActivityDetector::new();

        // Process some voice
        let voice = vec![5000i16; 160];
        vad.process(&voice);
        assert_eq!(vad.state(), VadState::Voice);
        assert!(vad.last_energy() > 0.0);

        // Reset
        vad.reset();
        assert_eq!(vad.state(), VadState::Silence);
        assert!(vad.is_silent());
        assert_eq!(vad.last_energy(), 0.0);
    }

    // ========== Edge case tests ==========

    #[test]
    fn test_vad_single_sample_frame() {
        let mut vad = VoiceActivityDetector::with_config(250.0, 0);

        // Single loud sample
        assert!(vad.process(&[10000]));
        assert!((vad.last_energy() - 10000.0).abs() < 1.0);

        // Single quiet sample
        assert!(!vad.process(&[10]));
    }

    #[test]
    fn test_vad_very_large_hangover() {
        let mut vad = VoiceActivityDetector::with_config(250.0, 1000);

        let voice = vec![1000i16; 160];
        vad.process(&voice);

        // Even after many silent frames, still in hangover
        let silence = vec![0i16; 160];
        for _ in 0..999 {
            assert!(vad.process(&silence));
        }
        // Still not silent
        assert!(vad.process(&silence));

        // Frame 1001 → silence
        assert!(!vad.process(&silence));
    }

    #[test]
    fn test_vad_silent_count_saturates() {
        let mut vad = VoiceActivityDetector::with_config(250.0, 5);

        // Process a huge number of silent frames — silent_count should not overflow
        let silence = vec![0i16; 160];
        for _ in 0..100_000 {
            vad.process(&silence);
        }
        assert!(vad.is_silent());

        // Voice should still work after saturation
        let voice = vec![1000i16; 160];
        assert!(vad.process(&voice));
        assert_eq!(vad.state(), VadState::Voice);
    }

    #[test]
    fn test_vad_threshold_zero() {
        // Threshold of 0 means only true silence (all-zero) is classified as silence
        let mut vad = VoiceActivityDetector::with_config(0.0, 0);

        // Pure silence → RMS 0.0 which is not >= 0.0... wait, 0.0 >= 0.0 is true
        // So with threshold 0, even silence is "voice"
        let silence = vec![0i16; 160];
        // energy=0.0, threshold=0.0 → 0.0 >= 0.0 is true → voice
        assert!(vad.process(&silence));
    }

    #[test]
    fn test_vad_last_energy_updates_each_frame() {
        let mut vad = VoiceActivityDetector::new();

        let loud = vec![5000i16; 160];
        vad.process(&loud);
        let e1 = vad.last_energy();
        assert!((e1 - 5000.0).abs() < 1.0);

        let quiet = vec![50i16; 160];
        vad.process(&quiet);
        let e2 = vad.last_energy();
        assert!((e2 - 50.0).abs() < 1.0);

        // Energy reflects the most recent frame
        assert!(e1 > e2);
    }
}
