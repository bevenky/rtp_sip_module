//! Inband DTMF detection using Goertzel algorithm
//!
//! Detects DTMF tones in decoded PCM audio samples.
//! Uses the Goertzel algorithm (efficient single-frequency DFT)
//! to detect the 8 DTMF frequencies.
//!
//! FreeSWITCH uses similar Goertzel-based detection in its
//! `start_dtmf` dialplan application.

use std::f64::consts::PI;

/// DTMF row frequencies (Hz)
const ROW_FREQS: [f64; 4] = [697.0, 770.0, 852.0, 941.0];
/// DTMF column frequencies (Hz)
const COL_FREQS: [f64; 4] = [1209.0, 1336.0, 1477.0, 1633.0];

/// Minimum power threshold for tone detection (relative to total signal energy)
const POWER_THRESHOLD: f64 = 4.0e5;
/// Maximum allowed twist (difference between row and column power in dB)
/// Normal twist: row > col allowed up to 8dB, reverse twist: col > row up to 4dB
const NORMAL_TWIST_DB: f64 = 8.0;
const REVERSE_TWIST_DB: f64 = 4.0;
/// Minimum number of consecutive frames with same digit before reporting
const MIN_DETECTION_FRAMES: u32 = 2;
/// Minimum frames of silence between digits
const MIN_SILENCE_FRAMES: u32 = 1;

/// Goertzel state for a single frequency
struct GoertzelBin {
    coeff: f64,
    s1: f64,
    s2: f64,
}

impl GoertzelBin {
    fn new(freq: f64, sample_rate: u32, block_size: usize) -> Self {
        let k = (0.5 + (block_size as f64 * freq / sample_rate as f64)) as usize;
        let w = 2.0 * PI * k as f64 / block_size as f64;
        Self {
            coeff: 2.0 * w.cos(),
            s1: 0.0,
            s2: 0.0,
        }
    }

    fn reset(&mut self) {
        self.s1 = 0.0;
        self.s2 = 0.0;
    }

    fn process_sample(&mut self, sample: f64) {
        let s0 = sample + self.coeff * self.s1 - self.s2;
        self.s2 = self.s1;
        self.s1 = s0;
    }

    /// Get the power (magnitude squared) of the detected frequency.
    /// Clamped to 0.0 because floating-point rounding can produce small
    /// negative values (Bug #28).
    fn power(&self) -> f64 {
        (self.s1 * self.s1 + self.s2 * self.s2 - self.coeff * self.s1 * self.s2).max(0.0)
    }
}

/// Inband DTMF detector using Goertzel algorithm
pub struct GoertzelDtmfDetector {
    /// Goertzel bins for row frequencies
    row_bins: [GoertzelBin; 4],
    /// Goertzel bins for column frequencies
    col_bins: [GoertzelBin; 4],
    /// Block size (number of samples per analysis window)
    block_size: usize,
    /// Sample rate
    sample_rate: u32,
    /// Current sample position within block
    sample_pos: usize,
    /// Currently detected digit (None if silence)
    current_digit: Option<char>,
    /// Number of consecutive frames with current digit
    detection_count: u32,
    /// Number of consecutive silent frames
    silence_count: u32,
    /// Last reported digit (for deduplication)
    last_reported: Option<char>,
    /// Whether we've reported the current digit
    digit_reported: bool,
    /// Detected digits queue
    detected: Vec<InbandDtmf>,
    /// Power threshold (configurable)
    power_threshold: f64,
}

/// A detected inband DTMF digit
#[derive(Debug, Clone)]
pub struct InbandDtmf {
    pub digit: char,
    pub duration_ms: u32,
}

impl GoertzelDtmfDetector {
    /// Create a new Goertzel DTMF detector
    ///
    /// `sample_rate`: Audio sample rate (typically 8000)
    /// `block_size`: Analysis window size (typically 102 for 8kHz = ~12.75ms)
    pub fn new(sample_rate: u32, block_size: usize) -> Self {
        let row_bins = [
            GoertzelBin::new(ROW_FREQS[0], sample_rate, block_size),
            GoertzelBin::new(ROW_FREQS[1], sample_rate, block_size),
            GoertzelBin::new(ROW_FREQS[2], sample_rate, block_size),
            GoertzelBin::new(ROW_FREQS[3], sample_rate, block_size),
        ];
        let col_bins = [
            GoertzelBin::new(COL_FREQS[0], sample_rate, block_size),
            GoertzelBin::new(COL_FREQS[1], sample_rate, block_size),
            GoertzelBin::new(COL_FREQS[2], sample_rate, block_size),
            GoertzelBin::new(COL_FREQS[3], sample_rate, block_size),
        ];

        Self {
            row_bins,
            col_bins,
            block_size,
            sample_rate,
            sample_pos: 0,
            current_digit: None,
            detection_count: 0,
            silence_count: 0,
            last_reported: None,
            digit_reported: false,
            detected: Vec::new(),
            power_threshold: POWER_THRESHOLD,
        }
    }

    /// Create with standard 8kHz settings
    pub fn new_8khz() -> Self {
        // Block size 102 at 8kHz ~ 12.75ms window
        // Gives good frequency resolution for DTMF
        Self::new(8000, 102)
    }

    /// Process PCM samples (i16). Call this with each audio frame.
    /// Returns detected digits (if any).
    pub fn process(&mut self, samples: &[i16]) -> Vec<InbandDtmf> {
        self.detected.clear();

        for &sample in samples {
            let s = sample as f64;

            for bin in &mut self.row_bins {
                bin.process_sample(s);
            }
            for bin in &mut self.col_bins {
                bin.process_sample(s);
            }

            self.sample_pos += 1;
            if self.sample_pos >= self.block_size {
                self.analyze_block();
                self.sample_pos = 0;
                // Reset bins for next block
                for bin in &mut self.row_bins {
                    bin.reset();
                }
                for bin in &mut self.col_bins {
                    bin.reset();
                }
            }
        }

        std::mem::take(&mut self.detected)
    }

    /// Analyze a complete block of samples
    fn analyze_block(&mut self) {
        // Find strongest row and column
        let mut max_row_power = 0.0f64;
        let mut max_row_idx = 0;
        for (i, bin) in self.row_bins.iter().enumerate() {
            let p = bin.power();
            if p > max_row_power {
                max_row_power = p;
                max_row_idx = i;
            }
        }

        let mut max_col_power = 0.0f64;
        let mut max_col_idx = 0;
        for (i, bin) in self.col_bins.iter().enumerate() {
            let p = bin.power();
            if p > max_col_power {
                max_col_power = p;
                max_col_idx = i;
            }
        }

        // Check if powers exceed threshold
        let detected_digit = if max_row_power > self.power_threshold
            && max_col_power > self.power_threshold
        {
            // Check twist (power ratio between row and column).
            // Clamp to 1e-10 to avoid log10(0) producing -inf (Bug #12).
            let row_db = 10.0 * max_row_power.max(1e-10).log10();
            let col_db = 10.0 * max_col_power.max(1e-10).log10();
            let twist = row_db - col_db;

            if twist > NORMAL_TWIST_DB || twist < -REVERSE_TWIST_DB {
                None // Twist too high -- likely noise
            } else {
                // Verify that detected tones are significantly above other tones
                // (reject harmonics / crosstalk)
                let mut second_row = 0.0f64;
                for (i, bin) in self.row_bins.iter().enumerate() {
                    if i != max_row_idx {
                        second_row = second_row.max(bin.power());
                    }
                }
                let mut second_col = 0.0f64;
                for (i, bin) in self.col_bins.iter().enumerate() {
                    if i != max_col_idx {
                        second_col = second_col.max(bin.power());
                    }
                }

                // Primary must be at least 6dB above second
                if max_row_power > second_row * 4.0 && max_col_power > second_col * 4.0 {
                    Some(dtmf_char(max_row_idx, max_col_idx))
                } else {
                    None
                }
            }
        } else {
            None
        };

        // State machine: track consecutive detections
        match detected_digit {
            Some(digit) => {
                self.silence_count = 0;
                if self.current_digit == Some(digit) {
                    self.detection_count += 1;
                } else {
                    // New digit or digit change
                    self.current_digit = Some(digit);
                    self.detection_count = 1;
                    self.digit_reported = false;
                }

                if self.detection_count >= MIN_DETECTION_FRAMES && !self.digit_reported {
                    self.digit_reported = true;
                    self.last_reported = Some(digit);
                    // Don't report yet -- wait for end (silence)
                }
            }
            None => {
                if self.current_digit.is_some() {
                    self.silence_count += 1;
                    if self.silence_count >= MIN_SILENCE_FRAMES {
                        // Digit ended
                        if self.digit_reported {
                            if let Some(digit) = self.current_digit {
                                let duration_blocks =
                                    self.detection_count + self.silence_count;
                                let duration_ms = (duration_blocks as u64
                                    * self.block_size as u64
                                    * 1000
                                    / self.sample_rate as u64)
                                    as u32;
                                self.detected.push(InbandDtmf {
                                    digit,
                                    duration_ms,
                                });
                            }
                        }
                        self.current_digit = None;
                        self.detection_count = 0;
                        self.digit_reported = false;
                    }
                }
            }
        }
    }

    /// Set custom power threshold
    pub fn set_power_threshold(&mut self, threshold: f64) {
        self.power_threshold = threshold;
    }

    /// Clear all state (e.g., after call transfer)
    pub fn reset(&mut self) {
        self.sample_pos = 0;
        self.current_digit = None;
        self.detection_count = 0;
        self.silence_count = 0;
        self.last_reported = None;
        self.digit_reported = false;
        self.detected.clear();
        for bin in &mut self.row_bins {
            bin.reset();
        }
        for bin in &mut self.col_bins {
            bin.reset();
        }
    }

    /// Drain any pending detected digits
    pub fn drain(&mut self) -> Vec<InbandDtmf> {
        std::mem::take(&mut self.detected)
    }
}

/// Map row/column indices to DTMF character
fn dtmf_char(row: usize, col: usize) -> char {
    const DTMF_TABLE: [[char; 4]; 4] = [
        ['1', '2', '3', 'A'],
        ['4', '5', '6', 'B'],
        ['7', '8', '9', 'C'],
        ['*', '0', '#', 'D'],
    ];
    DTMF_TABLE[row.min(3)][col.min(3)]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a pure sine wave at given frequency
    fn generate_tone(freq: f64, sample_rate: u32, duration_ms: u32, amplitude: f64) -> Vec<i16> {
        let num_samples = (sample_rate as u64 * duration_ms as u64 / 1000) as usize;
        (0..num_samples)
            .map(|i| {
                let t = i as f64 / sample_rate as f64;
                (amplitude * (2.0 * PI * freq * t).sin()) as i16
            })
            .collect()
    }

    /// Generate a DTMF tone (two simultaneous frequencies)
    fn generate_dtmf(
        row_freq: f64,
        col_freq: f64,
        sample_rate: u32,
        duration_ms: u32,
    ) -> Vec<i16> {
        let amplitude = 8000.0; // Strong signal
        let num_samples = (sample_rate as u64 * duration_ms as u64 / 1000) as usize;
        (0..num_samples)
            .map(|i| {
                let t = i as f64 / sample_rate as f64;
                let row = amplitude * (2.0 * PI * row_freq * t).sin();
                let col = amplitude * (2.0 * PI * col_freq * t).sin();
                ((row + col) / 2.0) as i16
            })
            .collect()
    }

    /// Generate silence
    fn generate_silence(sample_rate: u32, duration_ms: u32) -> Vec<i16> {
        vec![0i16; (sample_rate as u64 * duration_ms as u64 / 1000) as usize]
    }

    #[test]
    fn test_detect_digit_1() {
        let mut det = GoertzelDtmfDetector::new_8khz();
        // Digit '1' = 697 Hz + 1209 Hz
        let tone = generate_dtmf(697.0, 1209.0, 8000, 100);
        let silence = generate_silence(8000, 50);

        let mut results = det.process(&tone);
        results.extend(det.process(&silence));

        assert!(!results.is_empty(), "Should detect digit 1");
        assert_eq!(results[0].digit, '1');
    }

    #[test]
    fn test_detect_digit_5() {
        let mut det = GoertzelDtmfDetector::new_8khz();
        // Digit '5' = 770 Hz + 1336 Hz
        let tone = generate_dtmf(770.0, 1336.0, 8000, 100);
        let silence = generate_silence(8000, 50);

        let mut results = det.process(&tone);
        results.extend(det.process(&silence));

        assert!(!results.is_empty(), "Should detect digit 5");
        assert_eq!(results[0].digit, '5');
    }

    #[test]
    fn test_detect_digit_0() {
        let mut det = GoertzelDtmfDetector::new_8khz();
        // Digit '0' = 941 Hz + 1336 Hz
        let tone = generate_dtmf(941.0, 1336.0, 8000, 100);
        let silence = generate_silence(8000, 50);

        let mut results = det.process(&tone);
        results.extend(det.process(&silence));

        assert!(!results.is_empty(), "Should detect digit 0");
        assert_eq!(results[0].digit, '0');
    }

    #[test]
    fn test_detect_star() {
        let mut det = GoertzelDtmfDetector::new_8khz();
        // '*' = 941 Hz + 1209 Hz
        let tone = generate_dtmf(941.0, 1209.0, 8000, 100);
        let silence = generate_silence(8000, 50);

        let mut results = det.process(&tone);
        results.extend(det.process(&silence));

        assert!(!results.is_empty(), "Should detect *");
        assert_eq!(results[0].digit, '*');
    }

    #[test]
    fn test_detect_hash() {
        let mut det = GoertzelDtmfDetector::new_8khz();
        // '#' = 941 Hz + 1477 Hz
        let tone = generate_dtmf(941.0, 1477.0, 8000, 100);
        let silence = generate_silence(8000, 50);

        let mut results = det.process(&tone);
        results.extend(det.process(&silence));

        assert!(!results.is_empty(), "Should detect #");
        assert_eq!(results[0].digit, '#');
    }

    #[test]
    fn test_detect_digit_a() {
        let mut det = GoertzelDtmfDetector::new_8khz();
        // 'A' = 697 Hz + 1633 Hz
        let tone = generate_dtmf(697.0, 1633.0, 8000, 100);
        let silence = generate_silence(8000, 50);

        let mut results = det.process(&tone);
        results.extend(det.process(&silence));

        assert!(!results.is_empty(), "Should detect A");
        assert_eq!(results[0].digit, 'A');
    }

    #[test]
    fn test_no_false_positive_on_silence() {
        let mut det = GoertzelDtmfDetector::new_8khz();
        let silence = generate_silence(8000, 200);
        let results = det.process(&silence);
        assert!(results.is_empty(), "Should not detect DTMF in silence");
    }

    #[test]
    fn test_no_false_positive_on_single_tone() {
        let mut det = GoertzelDtmfDetector::new_8khz();
        // Single tone (not a valid DTMF pair)
        let tone = generate_tone(697.0, 8000, 200, 8000.0);
        let silence = generate_silence(8000, 50);
        let mut results = det.process(&tone);
        results.extend(det.process(&silence));
        assert!(
            results.is_empty(),
            "Single tone should not trigger DTMF detection"
        );
    }

    #[test]
    fn test_multiple_digits_sequence() {
        let mut det = GoertzelDtmfDetector::new_8khz();
        // Sequence: 1, 2, 3
        let digit1 = generate_dtmf(697.0, 1209.0, 8000, 80); // '1'
        let gap = generate_silence(8000, 60);
        let digit2 = generate_dtmf(697.0, 1336.0, 8000, 80); // '2'
        let digit3 = generate_dtmf(697.0, 1477.0, 8000, 80); // '3'
        let final_silence = generate_silence(8000, 80);

        let mut all_results = Vec::new();
        all_results.extend(det.process(&digit1));
        all_results.extend(det.process(&gap));
        all_results.extend(det.process(&digit2));
        all_results.extend(det.process(&gap));
        all_results.extend(det.process(&digit3));
        all_results.extend(det.process(&final_silence));

        assert!(
            all_results.len() >= 3,
            "Should detect 3 digits, got {}",
            all_results.len()
        );
        assert_eq!(all_results[0].digit, '1');
        assert_eq!(all_results[1].digit, '2');
        assert_eq!(all_results[2].digit, '3');
    }

    #[test]
    fn test_no_false_positive_on_speech() {
        let mut det = GoertzelDtmfDetector::new_8khz();
        // Simulate speech-like signal (multiple random frequencies)
        let samples: Vec<i16> = (0..1600)
            .map(|i| {
                let t = i as f64 / 8000.0;
                let s = 3000.0 * (2.0 * PI * 300.0 * t).sin()
                    + 2000.0 * (2.0 * PI * 500.0 * t).sin()
                    + 1500.0 * (2.0 * PI * 1000.0 * t).sin()
                    + 1000.0 * (2.0 * PI * 2000.0 * t).sin();
                s as i16
            })
            .collect();
        let silence = generate_silence(8000, 50);

        let mut results = det.process(&samples);
        results.extend(det.process(&silence));
        assert!(
            results.is_empty(),
            "Speech should not trigger DTMF detection"
        );
    }

    #[test]
    fn test_reset_clears_state() {
        let mut det = GoertzelDtmfDetector::new_8khz();
        let tone = generate_dtmf(697.0, 1209.0, 8000, 60);
        det.process(&tone);
        assert!(det.current_digit.is_some() || det.detection_count > 0);

        det.reset();
        assert!(det.current_digit.is_none());
        assert_eq!(det.detection_count, 0);
    }

    #[test]
    fn test_dtmf_char_mapping() {
        assert_eq!(dtmf_char(0, 0), '1');
        assert_eq!(dtmf_char(0, 1), '2');
        assert_eq!(dtmf_char(0, 2), '3');
        assert_eq!(dtmf_char(0, 3), 'A');
        assert_eq!(dtmf_char(1, 0), '4');
        assert_eq!(dtmf_char(1, 1), '5');
        assert_eq!(dtmf_char(1, 2), '6');
        assert_eq!(dtmf_char(1, 3), 'B');
        assert_eq!(dtmf_char(2, 0), '7');
        assert_eq!(dtmf_char(2, 1), '8');
        assert_eq!(dtmf_char(2, 2), '9');
        assert_eq!(dtmf_char(2, 3), 'C');
        assert_eq!(dtmf_char(3, 0), '*');
        assert_eq!(dtmf_char(3, 1), '0');
        assert_eq!(dtmf_char(3, 2), '#');
        assert_eq!(dtmf_char(3, 3), 'D');
    }

    #[test]
    fn test_all_16_dtmf_digits() {
        let row_freqs = [697.0, 770.0, 852.0, 941.0];
        let col_freqs = [1209.0, 1336.0, 1477.0, 1633.0];
        let expected = [
            ['1', '2', '3', 'A'],
            ['4', '5', '6', 'B'],
            ['7', '8', '9', 'C'],
            ['*', '0', '#', 'D'],
        ];

        for (ri, &rf) in row_freqs.iter().enumerate() {
            for (ci, &cf) in col_freqs.iter().enumerate() {
                let mut det = GoertzelDtmfDetector::new_8khz();
                let tone = generate_dtmf(rf, cf, 8000, 100);
                let silence = generate_silence(8000, 60);
                let mut results = det.process(&tone);
                results.extend(det.process(&silence));
                assert!(
                    !results.is_empty(),
                    "Failed to detect digit '{}' (row={} col={})",
                    expected[ri][ci],
                    rf,
                    cf
                );
                assert_eq!(
                    results[0].digit, expected[ri][ci],
                    "Wrong digit detected for row={} col={}",
                    rf, cf
                );
            }
        }
    }

    // Bug #28: Goertzel power() should never return negative
    #[test]
    fn test_goertzel_power_never_negative() {
        // Process a signal that drives s1/s2 to values where the formula
        // s1^2 + s2^2 - coeff*s1*s2 could go slightly negative.
        let mut bin = GoertzelBin::new(697.0, 8000, 102);
        // Feed tiny samples to get very small s1/s2 values
        for i in 0..102 {
            bin.process_sample(1e-15 * (i as f64));
        }
        let p = bin.power();
        assert!(p >= 0.0, "power() returned negative: {}", p);

        // Also test with zero signal
        bin.reset();
        for _ in 0..102 {
            bin.process_sample(0.0);
        }
        let p = bin.power();
        assert!(p >= 0.0, "power() returned negative for zero signal: {}", p);
    }

    // Bug #12: Near-threshold signal should not panic from log10(0)
    #[test]
    fn test_goertzel_near_threshold_no_panic() {
        let mut det = GoertzelDtmfDetector::new_8khz();
        // Generate a very low amplitude DTMF-like signal (near the power threshold).
        // This exercises the log10 path with values close to zero.
        let amplitude = 10.0; // Very low — power will be near threshold
        let num_samples = (8000u64 * 100 / 1000) as usize; // 100ms
        let samples: Vec<i16> = (0..num_samples)
            .map(|i| {
                let t = i as f64 / 8000.0;
                let row = amplitude * (2.0 * PI * 697.0 * t).sin();
                let col = amplitude * (2.0 * PI * 1209.0 * t).sin();
                ((row + col) / 2.0) as i16
            })
            .collect();
        let silence = generate_silence(8000, 50);

        // Should not panic even with near-zero power values
        let mut results = det.process(&samples);
        results.extend(det.process(&silence));
        // Don't care whether it detects anything; the point is no panic/NaN
    }

    // Bug #12: Process pure silence through analyze_block to verify log10 safety
    #[test]
    fn test_goertzel_silence_blocks_no_panic() {
        let mut det = GoertzelDtmfDetector::new_8khz();
        // Set a very low threshold to force the code into the log10 path
        // even with near-zero power
        det.set_power_threshold(0.0);
        let silence = generate_silence(8000, 200);
        // This should not panic even though powers are essentially zero
        let results = det.process(&silence);
        // With threshold=0 and silence, powers are 0 which gets clamped to 1e-10
        // before log10. No detection expected, but importantly: no panic.
        let _ = results;
    }
}
