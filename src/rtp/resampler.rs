//! Audio resampler for sample rate conversion
//!
//! Supports conversion between standard telephony and WebRTC sample rates:
//! 8000, 16000, 32000, and 48000 Hz.
//!
//! Two quality modes:
//! - Linear interpolation: fast, suitable for voice
//! - Sinc interpolation: higher quality, suitable for music/tones

use std::f64::consts::PI;

/// Supported sample rates
pub const SUPPORTED_RATES: &[u32] = &[8000, 16000, 32000, 48000];

/// Number of taps for sinc interpolation (8 on each side)
const SINC_TAPS: usize = 16;

/// Resampler quality mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResampleQuality {
    /// Linear interpolation — fast, low CPU
    Linear,
    /// Windowed sinc interpolation — higher quality
    Sinc,
}

/// Audio resampler for converting between sample rates.
pub struct AudioResampler {
    from_rate: u32,
    to_rate: u32,
    quality: ResampleQuality,
    /// State for sinc filter (history buffer for continuity across calls)
    history: Vec<f64>,
}

impl AudioResampler {
    /// Create a new resampler.
    /// Returns `None` if either rate is not in `SUPPORTED_RATES`.
    pub fn new(from_rate: u32, to_rate: u32, quality: ResampleQuality) -> Option<Self> {
        if !is_supported_rate(from_rate) || !is_supported_rate(to_rate) {
            return None;
        }

        let history_len = if quality == ResampleQuality::Sinc {
            SINC_TAPS
        } else {
            0
        };

        Some(Self {
            from_rate,
            to_rate,
            quality,
            history: vec![0.0; history_len],
        })
    }

    /// Check if resampling is needed (rates differ).
    pub fn is_passthrough(&self) -> bool {
        self.from_rate == self.to_rate
    }

    /// Resample audio samples.
    /// Input: PCM i16 samples at `from_rate`.
    /// Output: PCM i16 samples at `to_rate`.
    pub fn resample(&mut self, input: &[i16]) -> Vec<i16> {
        if input.is_empty() {
            return Vec::new();
        }

        if self.is_passthrough() {
            return input.to_vec();
        }

        match self.quality {
            ResampleQuality::Linear => resample_linear(input, self.from_rate, self.to_rate),
            ResampleQuality::Sinc => {
                // Bug #80: Prepend history buffer to the input for continuity
                // across calls, then run the sinc filter on the extended input.
                let hist_len = self.history.len();
                let mut extended: Vec<i16> = self
                    .history
                    .iter()
                    .map(|&s| s.round().clamp(i16::MIN as f64, i16::MAX as f64) as i16)
                    .collect();
                extended.extend_from_slice(input);

                let full_result = resample_sinc(&extended, self.from_rate, self.to_rate);

                // The first `hist_len` input samples correspond to history; skip
                // the corresponding output samples.
                // Bug #27: The rounding here can cause off-by-one sample
                // discrepancies across consecutive calls. A proper fix would
                // track cumulative fractional samples across calls.  For now,
                // document the limitation and keep the rounding approach.
                let skip_output =
                    (hist_len as f64 * self.to_rate as f64 / self.from_rate as f64).round()
                        as usize;
                let result = full_result[skip_output.min(full_result.len())..].to_vec();

                // Update history with the tail of the input for continuity across calls
                let input_f64: Vec<f64> = input.iter().map(|&s| s as f64).collect();
                if input_f64.len() >= hist_len {
                    self.history
                        .copy_from_slice(&input_f64[input_f64.len() - hist_len..]);
                } else {
                    let keep = hist_len - input_f64.len();
                    let old_tail: Vec<f64> = self.history[hist_len - keep..].to_vec();
                    self.history[..keep].copy_from_slice(&old_tail);
                    self.history[keep..].copy_from_slice(&input_f64);
                }
                result
            }
        }
    }

    /// Reset internal state (call on stream discontinuity).
    pub fn reset(&mut self) {
        self.history.fill(0.0);
    }

    /// Get the expected output length for a given input length.
    ///
    /// Uses ceiling division to match the `.ceil()` used in the actual
    /// resample functions (`resample_linear` / `resample_sinc`).
    pub fn output_length(&self, input_len: usize) -> usize {
        if self.from_rate == self.to_rate {
            return input_len;
        }
        // Ceiling division: (a * b + c - 1) / c
        let num = input_len as u64 * self.to_rate as u64;
        let den = self.from_rate as u64;
        ((num + den - 1) / den) as usize
    }

    /// Get source sample rate.
    pub fn from_rate(&self) -> u32 {
        self.from_rate
    }

    /// Get destination sample rate.
    pub fn to_rate(&self) -> u32 {
        self.to_rate
    }
}

/// Linear interpolation resampler — fast, suitable for voice.
fn resample_linear(input: &[i16], from_rate: u32, to_rate: u32) -> Vec<i16> {
    let ratio = from_rate as f64 / to_rate as f64;
    let out_len = (input.len() as f64 / ratio).ceil() as usize;
    let mut output = Vec::with_capacity(out_len);

    for i in 0..out_len {
        let src_pos = i as f64 * ratio;
        let src_idx = src_pos as usize;
        let frac = src_pos - src_idx as f64;

        let s0 = input[src_idx.min(input.len() - 1)] as f64;
        let s1 = if src_idx + 1 >= input.len() {
            0.0
        } else {
            input[src_idx + 1] as f64
        };

        let sample = s0 + (s1 - s0) * frac;
        output.push(sample.round().clamp(i16::MIN as f64, i16::MAX as f64) as i16);
    }
    output
}

/// Blackman window function for sidelobe suppression.
fn blackman_window(i: usize, n: usize) -> f64 {
    if n <= 1 {
        return 1.0;
    }
    let x = i as f64 / (n - 1) as f64;
    0.42 - 0.5 * (2.0 * PI * x).cos() + 0.08 * (4.0 * PI * x).cos()
}

/// Normalized sinc function: sinc(x) = sin(pi*x) / (pi*x).
fn sinc(x: f64) -> f64 {
    if x.abs() < 1e-10 {
        1.0
    } else {
        (PI * x).sin() / (PI * x)
    }
}

/// Windowed sinc interpolation resampler — higher quality, suitable for music/tones.
fn resample_sinc(input: &[i16], from_rate: u32, to_rate: u32) -> Vec<i16> {
    let ratio = from_rate as f64 / to_rate as f64;
    let out_len = (input.len() as f64 / ratio).ceil() as usize;
    let mut output = Vec::with_capacity(out_len);

    let cutoff = if to_rate < from_rate {
        to_rate as f64 / from_rate as f64
    } else {
        1.0
    };
    let half_taps = SINC_TAPS / 2;

    for i in 0..out_len {
        let src_pos = i as f64 * ratio;
        // Bug #58: Round instead of truncate for symmetric filter placement
        let src_center = src_pos.round() as isize;
        let mut sum = 0.0;
        let mut weight_sum = 0.0;

        for j in 0..SINC_TAPS {
            let tap_offset = j as isize - half_taps as isize;
            let src_idx = src_center + tap_offset;

            if src_idx >= 0 && (src_idx as usize) < input.len() {
                let x = (src_pos - src_idx as f64) * cutoff;
                let w = sinc(x) * blackman_window(j, SINC_TAPS) * cutoff;
                sum += input[src_idx as usize] as f64 * w;
                weight_sum += w;
            }
        }

        let sample = if weight_sum.abs() > 1e-10 {
            sum / weight_sum
        } else {
            0.0
        };
        output.push(sample.round().clamp(i16::MIN as f64, i16::MAX as f64) as i16);
    }
    output
}

/// Resample a buffer with default quality (Linear).
///
/// Returns `None` if either rate is not in `SUPPORTED_RATES`.
pub fn resample_simple(input: &[i16], from_rate: u32, to_rate: u32) -> Option<Vec<i16>> {
    let mut r = AudioResampler::new(from_rate, to_rate, ResampleQuality::Linear)?;
    Some(r.resample(input))
}

/// Check if a sample rate is supported.
pub fn is_supported_rate(rate: u32) -> bool {
    SUPPORTED_RATES.contains(&rate)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a sine tone at the given frequency, sample rate, and amplitude.
    fn sine_tone(freq_hz: f64, sample_rate: f64, num_samples: usize, amplitude: f64) -> Vec<i16> {
        (0..num_samples)
            .map(|i| {
                let t = i as f64 / sample_rate;
                (amplitude * (2.0 * PI * freq_hz * t).sin()) as i16
            })
            .collect()
    }

    /// Compute the Pearson correlation coefficient between two signals.
    fn correlation(a: &[i16], b: &[i16]) -> f64 {
        let n = a.len().min(b.len());
        if n == 0 {
            return 0.0;
        }
        let mean_a: f64 = a[..n].iter().map(|&x| x as f64).sum::<f64>() / n as f64;
        let mean_b: f64 = b[..n].iter().map(|&x| x as f64).sum::<f64>() / n as f64;

        let mut cov = 0.0;
        let mut var_a = 0.0;
        let mut var_b = 0.0;
        for i in 0..n {
            let da = a[i] as f64 - mean_a;
            let db = b[i] as f64 - mean_b;
            cov += da * db;
            var_a += da * da;
            var_b += db * db;
        }

        if var_a < 1e-10 || var_b < 1e-10 {
            return 0.0;
        }
        cov / (var_a.sqrt() * var_b.sqrt())
    }

    /// Compute the signal-to-noise ratio in dB between original and reconstructed signals.
    #[allow(dead_code)]
    fn snr_db(original: &[i16], reconstructed: &[i16]) -> f64 {
        let n = original.len().min(reconstructed.len());
        let mut signal_power = 0.0;
        let mut noise_power = 0.0;
        for i in 0..n {
            let s = original[i] as f64;
            let e = (original[i] as f64) - (reconstructed[i] as f64);
            signal_power += s * s;
            noise_power += e * e;
        }
        if noise_power < 1e-10 {
            return 100.0; // Effectively perfect
        }
        10.0 * (signal_power / noise_power).log10()
    }

    // Test 1: Passthrough (same rate) returns identical samples
    #[test]
    fn test_passthrough_returns_identical() {
        let input: Vec<i16> = (0..160).map(|i| (i * 100) as i16).collect();
        let mut r = AudioResampler::new(8000, 8000, ResampleQuality::Linear).unwrap();
        let output = r.resample(&input);
        assert_eq!(input, output);
    }

    // Test 2: 8kHz -> 16kHz doubles the output length
    #[test]
    fn test_8k_to_16k_doubles_length() {
        let input = sine_tone(200.0, 8000.0, 160, 10000.0);
        let mut r = AudioResampler::new(8000, 16000, ResampleQuality::Linear).unwrap();
        let output = r.resample(&input);
        assert_eq!(output.len(), 320);
    }

    // Test 3: 16kHz -> 8kHz halves the output length
    #[test]
    fn test_16k_to_8k_halves_length() {
        let input = sine_tone(200.0, 16000.0, 320, 10000.0);
        let mut r = AudioResampler::new(16000, 8000, ResampleQuality::Linear).unwrap();
        let output = r.resample(&input);
        assert_eq!(output.len(), 160);
    }

    // Test 4: 8kHz -> 48kHz (6x upsample) correct length
    #[test]
    fn test_8k_to_48k_6x_upsample_length() {
        let input = sine_tone(200.0, 8000.0, 160, 10000.0);
        let mut r = AudioResampler::new(8000, 48000, ResampleQuality::Linear).unwrap();
        let output = r.resample(&input);
        assert_eq!(output.len(), 960);
    }

    // Test 5: 48kHz -> 8kHz (6x downsample) correct length
    #[test]
    fn test_48k_to_8k_6x_downsample_length() {
        let input = sine_tone(200.0, 48000.0, 960, 10000.0);
        let mut r = AudioResampler::new(48000, 8000, ResampleQuality::Linear).unwrap();
        let output = r.resample(&input);
        assert_eq!(output.len(), 160);
    }

    // Test 6: Roundtrip 8k -> 16k -> 8k preserves signal (within tolerance)
    #[test]
    fn test_roundtrip_8k_16k_8k() {
        let original = sine_tone(200.0, 8000.0, 800, 10000.0);
        let mut up = AudioResampler::new(8000, 16000, ResampleQuality::Sinc).unwrap();
        let mut down = AudioResampler::new(16000, 8000, ResampleQuality::Sinc).unwrap();
        let upsampled = up.resample(&original);
        let reconstructed = down.resample(&upsampled);

        // Skip the first and last few samples to avoid edge effects
        let skip = 20;
        let len = original.len().min(reconstructed.len());
        assert!(len > 2 * skip);
        let orig_slice = &original[skip..len - skip];
        let recon_slice = &reconstructed[skip..len - skip];

        let corr = correlation(orig_slice, recon_slice);
        assert!(
            corr > 0.9,
            "8k->16k->8k roundtrip correlation too low: {:.4}",
            corr
        );
    }

    // Test 7: Roundtrip 8k -> 48k -> 8k preserves signal (within tolerance)
    #[test]
    fn test_roundtrip_8k_48k_8k() {
        let original = sine_tone(200.0, 8000.0, 800, 10000.0);
        let mut up = AudioResampler::new(8000, 48000, ResampleQuality::Sinc).unwrap();
        let mut down = AudioResampler::new(48000, 8000, ResampleQuality::Sinc).unwrap();
        let upsampled = up.resample(&original);
        let reconstructed = down.resample(&upsampled);

        let skip = 20;
        let len = original.len().min(reconstructed.len());
        assert!(len > 2 * skip);
        let orig_slice = &original[skip..len - skip];
        let recon_slice = &reconstructed[skip..len - skip];

        let corr = correlation(orig_slice, recon_slice);
        assert!(
            corr > 0.9,
            "8k->48k->8k roundtrip correlation too low: {:.4}",
            corr
        );
    }

    // Test 8: Sine wave preservation — resample a 200Hz tone, verify frequency is preserved
    #[test]
    fn test_sine_wave_frequency_preserved() {
        let freq = 200.0;
        let original = sine_tone(freq, 8000.0, 800, 10000.0);
        let mut up = AudioResampler::new(8000, 48000, ResampleQuality::Sinc).unwrap();
        let upsampled = up.resample(&original);

        // Generate reference tone at 48kHz with same frequency
        let reference = sine_tone(freq, 48000.0, upsampled.len(), 10000.0);

        // Skip edges
        let skip = 100;
        let len = upsampled.len().min(reference.len());
        assert!(len > 2 * skip);

        let corr = correlation(&upsampled[skip..len - skip], &reference[skip..len - skip]);
        assert!(
            corr > 0.9,
            "Sine wave frequency not preserved after upsample, correlation: {:.4}",
            corr
        );
    }

    // Test 9: Sinc quality better than linear (lower error on sine roundtrip)
    //
    // Downsample a 48kHz signal containing energy above the 8kHz Nyquist limit.
    // Sinc interpolation applies a low-pass filter (via the cutoff parameter)
    // which attenuates aliasing, while linear interpolation does not. We compare
    // the 200 Hz component preservation: sinc should produce a cleaner result.
    #[test]
    fn test_sinc_quality_better_than_linear() {
        let num_samples = 4800; // 100ms at 48kHz
        let rate = 48000.0;
        // Composite: 200 Hz (below 4kHz Nyquist) + 6000 Hz (above — will alias with linear)
        let signal_48k: Vec<i16> = (0..num_samples)
            .map(|i| {
                let t = i as f64 / rate;
                let s = 8000.0 * (2.0 * PI * 200.0 * t).sin()
                    + 8000.0 * (2.0 * PI * 6000.0 * t).sin();
                s.round().clamp(i16::MIN as f64, i16::MAX as f64) as i16
            })
            .collect();

        // Reference: pure 200 Hz at 8kHz (what a perfect downsample should produce)
        let reference_8k = sine_tone(200.0, 8000.0, 800, 8000.0);

        // Linear downsample 48kHz -> 8kHz
        let mut down_lin = AudioResampler::new(48000, 8000, ResampleQuality::Linear).unwrap();
        let recon_lin = down_lin.resample(&signal_48k);

        // Sinc downsample 48kHz -> 8kHz
        let mut down_sinc = AudioResampler::new(48000, 8000, ResampleQuality::Sinc).unwrap();
        let recon_sinc = down_sinc.resample(&signal_48k);

        let skip = 30;
        let len_lin = reference_8k.len().min(recon_lin.len());
        let len_sinc = reference_8k.len().min(recon_sinc.len());
        assert!(len_lin > 2 * skip);
        assert!(len_sinc > 2 * skip);

        // Measure how well each result matches the pure 200 Hz reference
        let corr_lin = correlation(
            &reference_8k[skip..len_lin - skip],
            &recon_lin[skip..len_lin - skip],
        );
        let corr_sinc = correlation(
            &reference_8k[skip..len_sinc - skip],
            &recon_sinc[skip..len_sinc - skip],
        );

        // Sinc should correlate better with the clean reference
        assert!(
            corr_sinc > corr_lin,
            "Sinc correlation ({:.4}) should be higher than Linear ({:.4})",
            corr_sinc,
            corr_lin
        );
        // Sinc should have decent quality
        assert!(
            corr_sinc > 0.9,
            "Sinc correlation with reference should be > 0.9, got {:.4}",
            corr_sinc
        );
    }

    // Test 10: Unsupported rate returns None
    #[test]
    fn test_unsupported_rate_returns_none() {
        assert!(AudioResampler::new(44100, 8000, ResampleQuality::Linear).is_none());
        assert!(AudioResampler::new(8000, 22050, ResampleQuality::Linear).is_none());
        assert!(AudioResampler::new(11025, 44100, ResampleQuality::Sinc).is_none());
    }

    // Test 11: Empty input returns empty output
    #[test]
    fn test_empty_input_returns_empty() {
        let mut r = AudioResampler::new(8000, 16000, ResampleQuality::Linear).unwrap();
        let output = r.resample(&[]);
        assert!(output.is_empty());
    }

    // Test 12: output_length() is correct for all rate pairs
    #[test]
    fn test_output_length_all_pairs() {
        let rates = SUPPORTED_RATES;
        let input_len: usize = 960; // LCM-friendly length

        for &from in rates {
            for &to in rates {
                let r = AudioResampler::new(from, to, ResampleQuality::Linear).unwrap();
                let expected = (input_len as u64 * to as u64 / from as u64) as usize;
                assert_eq!(
                    r.output_length(input_len),
                    expected,
                    "output_length wrong for {} -> {}",
                    from,
                    to
                );
            }
        }
    }

    // Test 13: is_passthrough() returns true when rates match
    #[test]
    fn test_is_passthrough() {
        let r = AudioResampler::new(16000, 16000, ResampleQuality::Linear).unwrap();
        assert!(r.is_passthrough());

        let r = AudioResampler::new(8000, 48000, ResampleQuality::Linear).unwrap();
        assert!(!r.is_passthrough());
    }

    // Test 14: reset() clears state
    #[test]
    fn test_reset_clears_state() {
        let mut r = AudioResampler::new(8000, 16000, ResampleQuality::Sinc).unwrap();
        let input = sine_tone(200.0, 8000.0, 160, 10000.0);

        // Process some data to populate history
        let _ = r.resample(&input);
        assert!(r.history.iter().any(|&v| v != 0.0));

        // Reset should zero the history
        r.reset();
        assert!(r.history.iter().all(|&v| v == 0.0));
    }

    // Test 15: 16kHz -> 32kHz (2x upsample)
    #[test]
    fn test_16k_to_32k_2x_upsample() {
        let input = sine_tone(200.0, 16000.0, 320, 10000.0);
        let mut r = AudioResampler::new(16000, 32000, ResampleQuality::Linear).unwrap();
        let output = r.resample(&input);
        assert_eq!(output.len(), 640);
    }

    // Test 16: 32kHz -> 16kHz (2x downsample)
    #[test]
    fn test_32k_to_16k_2x_downsample() {
        let input = sine_tone(200.0, 32000.0, 640, 10000.0);
        let mut r = AudioResampler::new(32000, 16000, ResampleQuality::Linear).unwrap();
        let output = r.resample(&input);
        assert_eq!(output.len(), 320);
    }

    // Additional: resample_simple convenience function works
    #[test]
    fn test_resample_simple() {
        let input = sine_tone(200.0, 8000.0, 160, 10000.0);
        let output = resample_simple(&input, 8000, 16000).unwrap();
        assert_eq!(output.len(), 320);

        // Unsupported rate returns None
        assert!(resample_simple(&input, 44100, 8000).is_none());
    }

    // Additional: is_supported_rate function
    #[test]
    fn test_is_supported_rate() {
        assert!(is_supported_rate(8000));
        assert!(is_supported_rate(16000));
        assert!(is_supported_rate(32000));
        assert!(is_supported_rate(48000));
        assert!(!is_supported_rate(44100));
        assert!(!is_supported_rate(22050));
        assert!(!is_supported_rate(0));
    }

    // Additional: from_rate() and to_rate() accessors
    #[test]
    fn test_rate_accessors() {
        let r = AudioResampler::new(8000, 48000, ResampleQuality::Linear).unwrap();
        assert_eq!(r.from_rate(), 8000);
        assert_eq!(r.to_rate(), 48000);
    }

    // Bug #1: Verify output_length() matches actual resample output for all rate pairs
    #[test]
    fn test_output_length_matches_actual_linear() {
        let input_lengths: &[usize] = &[1, 80, 160, 320, 480, 960, 999];
        for &from in SUPPORTED_RATES {
            for &to in SUPPORTED_RATES {
                let mut r = AudioResampler::new(from, to, ResampleQuality::Linear).unwrap();
                for &input_len in input_lengths {
                    let input: Vec<i16> = (0..input_len).map(|i| (i % 256) as i16).collect();
                    let output = r.resample(&input);
                    let predicted = r.output_length(input_len);
                    assert_eq!(
                        output.len(),
                        predicted,
                        "output_length mismatch for {} -> {} with input_len={}",
                        from,
                        to,
                        input_len
                    );
                }
            }
        }
    }

    // Bug #1: Same verification for sinc quality
    #[test]
    fn test_output_length_matches_actual_sinc() {
        let input_lengths: &[usize] = &[1, 80, 160, 320, 480, 960, 999];
        for &from in SUPPORTED_RATES {
            for &to in SUPPORTED_RATES {
                let mut r = AudioResampler::new(from, to, ResampleQuality::Sinc).unwrap();
                for &input_len in input_lengths {
                    let input: Vec<i16> = (0..input_len).map(|i| (i % 256) as i16).collect();
                    let output = r.resample(&input);
                    let predicted = r.output_length(input_len);
                    assert_eq!(
                        output.len(),
                        predicted,
                        "output_length mismatch (sinc) for {} -> {} with input_len={}",
                        from,
                        to,
                        input_len
                    );
                }
            }
        }
    }

    // Bug #67: Blackman window with n=0 should not panic (division by zero guard)
    #[test]
    fn test_blackman_window_n_zero() {
        let val = blackman_window(0, 0);
        assert_eq!(val, 1.0);
    }

    // Bug #67: Blackman window with n=1 should not panic
    #[test]
    fn test_blackman_window_n_one() {
        let val = blackman_window(0, 1);
        assert_eq!(val, 1.0);
    }

    // Bug #67: Blackman window with n=2 should work normally
    #[test]
    fn test_blackman_window_n_two() {
        let val0 = blackman_window(0, 2);
        let val1 = blackman_window(1, 2);
        // At i=0: x=0.0 -> 0.42 - 0.5*cos(0) + 0.08*cos(0) = 0.42 - 0.5 + 0.08 = 0.0
        assert!((val0 - 0.0).abs() < 1e-10);
        // At i=1: x=1.0 -> 0.42 - 0.5*cos(2pi) + 0.08*cos(4pi) = 0.42 - 0.5 + 0.08 = 0.0
        assert!((val1 - 0.0).abs() < 1e-10);
    }
}
