//! G.711 Appendix I Packet Loss Concealment (PLC)
//!
//! Implements pitch-based concealment following ITU-T G.711 Appendix I:
//!
//! 1. Maintains a history buffer of the last ~48.75ms of decoded audio
//!    (390 samples at 8kHz).
//! 2. On packet loss, uses autocorrelation to detect the pitch period
//!    (search range 20-160 samples, covering 50Hz-400Hz at 8kHz).
//! 3. Repeats the last pitch period with overlap-add crossfade
//!    (16-sample Hann window).
//! 4. Applies exponential gain decay over successive concealed frames
//!    (starting at 1.0, decay factor ~0.96 per frame).
//! 5. After ~60ms of continuous concealment (~8 frames at 8kHz/160),
//!    fades to silence.
//! 6. On recovery, applies overlap-add blend between concealed and
//!    real audio for a smooth transition.
//!
//! Reference: ITU-T G.711 Appendix I.

/// History buffer length: ~48.75ms at 8kHz = 390 samples.
const HISTORY_LEN: usize = 390;

/// Minimum pitch period in samples (8000 / 400 = 20 => 400Hz).
const PITCH_MIN: usize = 20;

/// Maximum pitch period in samples (8000 / 50 = 160 => 50Hz).
const PITCH_MAX: usize = 160;

/// Overlap-add crossfade window length in samples.
const OLA_WINDOW: usize = 16;

/// Per-frame gain decay factor during concealment (~0.96).
const DECAY_PER_FRAME: f32 = 0.96;

/// Maximum concealment duration before fading to silence, in milliseconds.
/// G.711 Appendix I specifies ~60ms.
const MAX_CONCEAL_MS: f32 = 60.0;

/// Sample rate assumed for duration calculations.
const SAMPLE_RATE: f32 = 8000.0;

/// G.711 Appendix I pitch-based Packet Loss Concealer.
///
/// Drop-in replacement for the simple decay-based `PacketLossConcealer`.
/// Maintains the same public API: `new`, `update`, `conceal`.
pub struct PacketLossConcealer {
    /// Circular history buffer of recent decoded audio.
    history: Vec<i16>,
    /// Current write position in the history buffer.
    history_pos: usize,
    /// Number of valid samples written into history so far
    /// (may be less than HISTORY_LEN until the buffer fills).
    history_valid: usize,
    /// Detected pitch period (in samples), cached from last detection.
    pitch_period: usize,
    /// Overlap buffer used for crossfading at frame boundaries.
    overlap_buf: Vec<i16>,
    /// Number of consecutive concealed frames (reset on `update`).
    conceal_count: usize,
    /// Current gain level (starts at 1.0, decays each concealed frame).
    gain: f32,
    /// Samples per packet (frame size), set at construction.
    samples_per_packet: usize,
    /// Maximum number of concealment frames before silence.
    max_conceal_frames: usize,
    /// Sample rate in Hz (P2-JB-8: no longer hardcoded to 8kHz).
    sample_rate: f32,
}

impl PacketLossConcealer {
    /// Create a new PLC instance for the given frame size.
    ///
    /// `samples_per_packet` is the number of PCM samples in one RTP frame
    /// (e.g. 160 for 20ms at 8kHz).
    ///
    /// Uses the default sample rate of 8000 Hz. For other sample rates,
    /// use [`with_sample_rate`](Self::with_sample_rate).
    pub fn new(samples_per_packet: usize) -> Self {
        Self::with_sample_rate(samples_per_packet, SAMPLE_RATE as u32)
    }

    /// Create a new PLC instance with an explicit sample rate.
    ///
    /// P2-JB-8: Allows the PLC to work correctly at sample rates other
    /// than 8kHz (e.g. 16kHz for wideband codecs).
    pub fn with_sample_rate(samples_per_packet: usize, sample_rate: u32) -> Self {
        let sr = if sample_rate > 0 { sample_rate as f32 } else { SAMPLE_RATE };
        let max_conceal_frames = if samples_per_packet > 0 {
            let frame_duration_ms = (samples_per_packet as f32 / sr) * 1000.0;
            ((MAX_CONCEAL_MS / frame_duration_ms).ceil() as usize).max(1)
        } else {
            3
        };

        Self {
            history: vec![0i16; HISTORY_LEN],
            history_pos: 0,
            history_valid: 0,
            pitch_period: samples_per_packet.min(PITCH_MAX).max(PITCH_MIN),
            overlap_buf: Vec::new(),
            conceal_count: 0,
            gain: 1.0,
            samples_per_packet,
            max_conceal_frames,
            sample_rate: sr,
        }
    }

    /// Feed good (successfully decoded) audio into the PLC history.
    ///
    /// This resets the concealment state and saves an overlap tail
    /// for crossfading if we were previously concealing.
    pub fn update(&mut self, samples: &[i16]) {
        if samples.is_empty() {
            return;
        }

        // P2-JB-7: If we were concealing, apply overlap-add crossfade between
        // the concealed signal and the incoming recovered samples for a smooth
        // transition. Generate what the next concealed frame would have been,
        // then crossfade it with the start of the real frame.
        let crossfaded_samples;
        let samples_to_write = if self.conceal_count > 0 && !self.overlap_buf.is_empty() {
            let ola_len = self.overlap_buf.len().min(samples.len()).min(OLA_WINDOW);
            let mut blended = samples.to_vec();
            apply_crossfade(&self.overlap_buf, &mut blended, ola_len);
            crossfaded_samples = blended;
            &crossfaded_samples[..]
        } else {
            samples
        };

        // If we were concealing, prepare overlap for potential next loss
        if self.conceal_count > 0 {
            let tail = self.generate_pitch_repeat(OLA_WINDOW, self.gain);
            self.overlap_buf = tail;
        }

        // Write (potentially crossfaded) samples into the circular history buffer.
        self.append_history(samples_to_write);

        // Always save the tail of the input frame for crossfading with
        // the first concealment frame if a loss occurs next. This ensures
        // overlap_buf has valid data even when no concealment preceded.
        if self.conceal_count == 0 {
            let tail_len = OLA_WINDOW.min(samples_to_write.len());
            self.overlap_buf = samples_to_write[samples_to_write.len() - tail_len..].to_vec();
        }

        // Reset concealment state.
        self.conceal_count = 0;
        self.gain = 1.0;

        // Re-detect pitch from the updated history so it is fresh
        // for the next potential loss event.
        self.pitch_period = self.detect_pitch();
    }

    /// Reset concealer state (for codec switch or hold/resume).
    ///
    /// Clears the history buffer, resets gain to 1.0, and zeroes
    /// concealment counters. Equivalent to constructing a fresh
    /// instance with the same `samples_per_packet`.
    pub fn reset(&mut self) {
        self.history.fill(0);
        self.history_pos = 0;
        self.history_valid = 0;
        self.pitch_period = self.samples_per_packet.min(PITCH_MAX).max(PITCH_MIN);
        self.overlap_buf.clear();
        self.conceal_count = 0;
        self.gain = 1.0;
    }

    /// Generate a concealment frame to replace a lost packet.
    ///
    /// Returns a `Vec<i16>` of length `samples_per_packet`.
    pub fn conceal(&mut self) -> Vec<i16> {
        self.conceal_n(self.samples_per_packet)
    }

    /// Generate a concealment frame of exactly `n` samples.
    pub fn conceal_n(&mut self, n: usize) -> Vec<i16> {
        if n == 0 {
            return Vec::new();
        }

        self.conceal_count += 1;

        // After max concealment duration, output silence.
        if self.conceal_count > self.max_conceal_frames {
            self.gain = 0.0;
            return vec![0i16; n];
        }

        // Bug #54: Apply decay from first concealment frame per G.711 Appendix I.
        // Bug #55: Skip redundant detect_pitch — already called in update().
        self.gain *= DECAY_PER_FRAME;

        // Generate pitch-repeated signal with overlap-add.
        let mut frame = self.generate_pitch_repeat(n, self.gain);

        // On the first concealment frame, crossfade with the overlap
        // tail from the last good frame to avoid a discontinuity.
        if self.conceal_count == 1 && !self.overlap_buf.is_empty() {
            let ola_len = self.overlap_buf.len().min(n).min(OLA_WINDOW);
            apply_crossfade(&self.overlap_buf, &mut frame, ola_len);
            self.overlap_buf.clear();
        }

        // Write the concealed frame into history so that successive
        // concealments can chain smoothly.
        self.append_history(&frame);

        frame
    }

    // ------------------------------------------------------------------
    //  Internal helpers
    // ------------------------------------------------------------------

    /// Append samples to the circular history buffer.
    fn append_history(&mut self, samples: &[i16]) {
        for &s in samples {
            self.history[self.history_pos] = s;
            self.history_pos = (self.history_pos + 1) % HISTORY_LEN;
            if self.history_valid < HISTORY_LEN {
                self.history_valid += 1;
            }
        }
    }

    /// Read `count` samples from history ending at the current write
    /// position (i.e. the most recent `count` samples), returned in
    /// chronological order.
    fn read_history_tail(&self, count: usize) -> Vec<i16> {
        let count = count.min(self.history_valid);
        let mut out = Vec::with_capacity(count);
        // Start position: history_pos - count, wrapped.
        let start = if self.history_pos >= count {
            self.history_pos - count
        } else {
            HISTORY_LEN - (count - self.history_pos)
        };
        for i in 0..count {
            out.push(self.history[(start + i) % HISTORY_LEN]);
        }
        out
    }

    /// Normalized autocorrelation pitch detection.
    ///
    /// Searches for the pitch period that maximizes the normalized
    /// autocorrelation of the tail of the history buffer, in the range
    /// `[PITCH_MIN, PITCH_MAX]`.
    fn detect_pitch(&self) -> usize {
        // We need at least PITCH_MAX + PITCH_MAX samples of history
        // to do a meaningful autocorrelation.
        let analysis_len = PITCH_MAX * 2;
        if self.history_valid < analysis_len {
            // Not enough history; return a default.
            return self.samples_per_packet.min(PITCH_MAX).max(PITCH_MIN);
        }

        let buf = self.read_history_tail(analysis_len);
        // Analysis window: the last PITCH_MAX samples of `buf`.
        let window_start = buf.len() - PITCH_MAX;

        // Energy of the analysis window (denominator term).
        let energy_window: f64 = buf[window_start..]
            .iter()
            .map(|&s| (s as f64) * (s as f64))
            .sum();

        if energy_window < 1.0 {
            // Silence or near-silence; pitch detection is meaningless.
            return self.samples_per_packet.min(PITCH_MAX).max(PITCH_MIN);
        }

        let mut best_period = PITCH_MIN;
        let mut best_corr: f64 = -1.0;
        // Track whether we've found any strong correlation. Once found,
        // we only update if a strictly better (by a margin) correlation
        // appears. This ensures we detect the fundamental period rather
        // than a harmonic (longer multiples of the period).
        let mut found_strong = false;

        for lag in PITCH_MIN..=PITCH_MAX {
            let ref_start = window_start.saturating_sub(lag);
            if ref_start + lag > buf.len() {
                continue;
            }

            let mut cross: f64 = 0.0;
            let mut energy_ref: f64 = 0.0;
            let mut energy_win: f64 = 0.0;
            for i in 0..lag {
                let a = buf[window_start + i] as f64;
                let b = buf[ref_start + i] as f64;
                cross += a * b;
                energy_ref += b * b;
                energy_win += a * a;
            }

            if energy_ref < 1.0 || energy_win < 1.0 {
                continue;
            }

            let norm = cross / (energy_win.sqrt() * energy_ref.sqrt());
            if !found_strong {
                if norm > best_corr {
                    best_corr = norm;
                    best_period = lag;
                }
                // Once we find a strong correlation (above 0.5 threshold),
                // lock in the shortest period. Only replace if a significantly
                // better (>5% improvement) correlation is found at a longer lag.
                if best_corr >= 0.5 {
                    found_strong = true;
                }
            } else if norm > best_corr * 1.05 {
                // Substantially better correlation — update
                best_corr = norm;
                best_period = lag;
            }
        }

        // Bug #89: Raise pitch correlation threshold from 0.3 to 0.5 to
        // reject weak/noisy correlations that produce poor concealment.
        if best_corr < 0.5 {
            return self.samples_per_packet.min(PITCH_MAX).max(PITCH_MIN);
        }

        best_period
    }

    /// Generate `n` samples by repeating the last pitch period from
    /// history, applying overlap-add crossfade at each period boundary
    /// and scaling by `gain`.
    fn generate_pitch_repeat(&self, n: usize, gain: f32) -> Vec<i16> {
        let period = self.pitch_period;
        if period == 0 || self.history_valid == 0 {
            return vec![0i16; n];
        }

        // Extract two consecutive pitch periods from history tail for OLA.
        // `prev_period` is the one before `last_period`.
        let need = period * 2;
        let tail = self.read_history_tail(need.min(self.history_valid));

        // If tail is shorter than one period, just repeat what we have.
        let last_period: Vec<i16> = if tail.len() >= period {
            tail[tail.len() - period..].to_vec()
        } else {
            tail.clone()
        };

        let prev_period: Vec<i16> = if tail.len() >= period * 2 {
            tail[tail.len() - period * 2..tail.len() - period].to_vec()
        } else {
            last_period.clone()
        };

        // Bug #11: When history < 2 periods, prev_period and last_period are
        // identical, making OLA blending useless (crossfading a signal with itself
        // just wastes CPU). Skip OLA and use last_period directly in that case.
        let template = if prev_period == last_period {
            last_period.clone()
        } else {
            build_ola_period(&prev_period, &last_period, OLA_WINDOW)
        };

        // Tile the template to fill `n` samples, with gain applied.
        // Apply crossfade at each pitch period boundary to avoid clicks.
        let mut out = Vec::with_capacity(n);
        let tlen = template.len();
        if tlen == 0 {
            return vec![0i16; n];
        }
        let ola = OLA_WINDOW.min(tlen);
        for i in 0..n {
            let pos = i % tlen;
            let mut s = template[pos] as f32 * gain;
            // At period boundaries, crossfade between end of previous
            // period and start of next period to avoid discontinuities.
            if pos < ola && i >= tlen {
                let w = hann_weight(pos, ola);
                let prev_pos = tlen - ola + pos;
                let prev_s = template[prev_pos] as f32 * gain;
                s = prev_s * (1.0 - w) + s * w;
            }
            out.push(clamp_i16(s));
        }

        out
    }
}

// ----------------------------------------------------------------------
//  Free-standing helper functions
// ----------------------------------------------------------------------

/// Build one pitch-period template by overlap-add crossfading the tail
/// of `prev` with the head of `cur`. Both slices should be one pitch
/// period long. The crossfade uses a raised-cosine (Hann) window of
/// length `ola_len`.
fn build_ola_period(prev: &[i16], cur: &[i16], ola_len: usize) -> Vec<i16> {
    let period = cur.len();
    if period == 0 {
        return Vec::new();
    }
    let mut out = cur.to_vec();

    // Crossfade region: blend tail of `prev` with head of `cur`.
    let ola = ola_len.min(period).min(prev.len());
    if ola > 0 {
        let prev_offset = prev.len() - ola;
        for i in 0..ola {
            let w = hann_weight(i, ola); // 0.0 -> 1.0
            let from_prev = prev[prev_offset + i] as f32 * (1.0 - w);
            let from_cur = cur[i] as f32 * w;
            out[i] = clamp_i16(from_prev + from_cur);
        }
    }

    out
}

/// Apply an overlap-add crossfade in-place: blend `old[0..len]` into
/// `frame[0..len]`, fading `old` out and `frame` in.
fn apply_crossfade(old: &[i16], frame: &mut [i16], len: usize) {
    let len = len.min(old.len()).min(frame.len());
    for i in 0..len {
        let w = hann_weight(i, len); // 0.0 -> 1.0
        let blended = old[i] as f32 * (1.0 - w) + frame[i] as f32 * w;
        frame[i] = clamp_i16(blended);
    }
}

/// Raised-cosine (Hann) weight for position `i` in a window of length `len`.
/// Returns 0.0 at `i == 0` and approaches 1.0 at `i == len - 1`.
#[inline]
fn hann_weight(i: usize, len: usize) -> f32 {
    if len <= 1 {
        return 1.0;
    }
    // Bug #90: Use (len - 1) in denominator to get proper Hann window that
    // reaches 1.0 at the last sample. Clamp to max(1) to avoid division by zero.
    0.5 * (1.0 - (std::f32::consts::PI * i as f32 / (len - 1).max(1) as f32).cos())
}

/// Clamp an f32 to the i16 range and round.
#[inline]
fn clamp_i16(v: f32) -> i16 {
    v.round().clamp(i16::MIN as f32, i16::MAX as f32) as i16
}

// ======================================================================
//  Tests
// ======================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::f64::consts::PI;

    // ----- helper: generate a pure sine tone -----
    fn sine_tone(freq_hz: f64, sample_rate: f64, num_samples: usize, amplitude: f64) -> Vec<i16> {
        (0..num_samples)
            .map(|i| {
                let t = i as f64 / sample_rate;
                (amplitude * (2.0 * PI * freq_hz * t).sin()) as i16
            })
            .collect()
    }

    // ----- helper: RMS energy -----
    fn rms(samples: &[i16]) -> f64 {
        if samples.is_empty() {
            return 0.0;
        }
        let sum: f64 = samples.iter().map(|&s| (s as f64) * (s as f64)).sum();
        (sum / samples.len() as f64).sqrt()
    }

    // ----- basic API compatibility tests -----

    #[test]
    fn test_new_and_conceal_returns_correct_length() {
        let plc = &mut PacketLossConcealer::new(160);
        let frame = plc.conceal();
        assert_eq!(frame.len(), 160);
    }

    #[test]
    fn test_conceal_n_returns_correct_length() {
        let plc = &mut PacketLossConcealer::new(160);
        let frame = plc.conceal_n(80);
        assert_eq!(frame.len(), 80);
    }

    #[test]
    fn test_conceal_zero_length() {
        let plc = &mut PacketLossConcealer::new(160);
        let frame = plc.conceal_n(0);
        assert!(frame.is_empty());
    }

    #[test]
    fn test_update_resets_state() {
        let mut plc = PacketLossConcealer::new(160);
        let tone = sine_tone(200.0, 8000.0, 320, 10000.0);
        plc.update(&tone[..160]);
        // Conceal a few frames to bump conceal_count and decay gain.
        plc.conceal();
        plc.conceal();
        assert!(plc.conceal_count > 0);
        assert!(plc.gain < 1.0);
        // Now feed a good frame.
        plc.update(&tone[160..320]);
        assert_eq!(plc.conceal_count, 0);
        assert_eq!(plc.gain, 1.0);
    }

    // ----- backward compat: same assertions as the old test_plc -----

    #[test]
    fn test_plc_backward_compat() {
        let mut plc = PacketLossConcealer::new(160);

        // Update with good samples (ascending ramp).
        let samples: Vec<i16> = (0..160).map(|i| (i * 100) as i16).collect();
        plc.update(&samples);

        // Conceal first loss.
        let concealed1 = plc.conceal();
        assert_eq!(concealed1.len(), 160);

        // Multiple losses should decay further.
        let concealed2 = plc.conceal();
        assert!(rms(&concealed2) <= rms(&concealed1) + 1.0);
    }

    // ----- pitch detection tests -----

    #[test]
    fn test_pitch_detection_200hz() {
        let mut plc = PacketLossConcealer::new(160);
        // 200Hz at 8kHz => period = 40 samples
        let tone = sine_tone(200.0, 8000.0, HISTORY_LEN + 160, 10000.0);
        plc.update(&tone);

        let period = plc.detect_pitch();
        // Allow +/- 2 samples tolerance.
        assert!(
            (period as i32 - 40).unsigned_abs() <= 2,
            "Expected pitch ~40, got {}",
            period
        );
    }

    #[test]
    fn test_pitch_detection_100hz() {
        let mut plc = PacketLossConcealer::new(160);
        // 100Hz at 8kHz => period = 80 samples
        let tone = sine_tone(100.0, 8000.0, HISTORY_LEN + 160, 10000.0);
        plc.update(&tone);

        let period = plc.detect_pitch();
        // Allow +/- 4 samples tolerance for autocorrelation-based detection
        assert!(
            (period as i32 - 80).unsigned_abs() <= 4,
            "Expected pitch ~80, got {}",
            period
        );
    }

    #[test]
    fn test_pitch_detection_320hz() {
        let mut plc = PacketLossConcealer::new(160);
        // 320Hz at 8kHz => period = 25 samples (exact integer)
        let tone = sine_tone(320.0, 8000.0, HISTORY_LEN + 160, 10000.0);
        plc.update(&tone);

        let period = plc.detect_pitch();
        assert!(
            (period as i32 - 25).unsigned_abs() <= 2,
            "Expected pitch ~25, got {}",
            period
        );
    }

    #[test]
    fn test_pitch_detection_silence_returns_default() {
        let mut plc = PacketLossConcealer::new(160);
        // Feed silence.
        let silence = vec![0i16; HISTORY_LEN + 160];
        plc.update(&silence);

        let period = plc.detect_pitch();
        // Should return the default (clamped samples_per_packet).
        assert!(period >= PITCH_MIN && period <= PITCH_MAX);
    }

    // ----- concealment quality tests -----

    #[test]
    fn test_concealed_frame_has_energy() {
        let mut plc = PacketLossConcealer::new(160);
        let tone = sine_tone(200.0, 8000.0, 480, 10000.0);
        plc.update(&tone);

        let frame = plc.conceal();
        // Concealed frame should have significant energy (not silence).
        assert!(
            rms(&frame) > 1000.0,
            "Concealed frame RMS {} is too low",
            rms(&frame)
        );
    }

    #[test]
    fn test_gain_decay_over_successive_frames() {
        let mut plc = PacketLossConcealer::new(160);
        let tone = sine_tone(200.0, 8000.0, 480, 10000.0);
        plc.update(&tone);

        let mut prev_rms = f64::MAX;
        for i in 0..5 {
            let frame = plc.conceal();
            let r = rms(&frame);
            if i > 0 {
                assert!(
                    r < prev_rms + 50.0, // small tolerance for OLA effects
                    "Frame {} RMS {} should be <= previous {}",
                    i,
                    r,
                    prev_rms
                );
            }
            prev_rms = r;
        }
    }

    #[test]
    fn test_fades_to_silence_after_max_concealment() {
        let mut plc = PacketLossConcealer::new(160);
        let tone = sine_tone(200.0, 8000.0, 480, 10000.0);
        plc.update(&tone);

        // Conceal well beyond the limit.
        let mut last_frame = Vec::new();
        for _ in 0..20 {
            last_frame = plc.conceal();
        }

        // After many frames, output should be silence.
        assert!(
            rms(&last_frame) < 1.0,
            "After prolonged concealment, RMS {} should be ~0",
            rms(&last_frame)
        );
    }

    // ----- overlap-add / recovery tests -----

    #[test]
    fn test_recovery_crossfade() {
        let mut plc = PacketLossConcealer::new(160);
        let tone = sine_tone(200.0, 8000.0, 640, 10000.0);

        // Feed two good frames.
        plc.update(&tone[..160]);
        plc.update(&tone[160..320]);

        // Lose a frame.
        let concealed = plc.conceal();
        assert_eq!(concealed.len(), 160);

        // Recover with a real frame — the update should store an overlap
        // buffer internally.
        plc.update(&tone[480..640]);

        // The overlap_buf should have been populated and then consumed
        // during update (it is used on the next conceal, but clears itself
        // when we update with a good frame after concealment).
        // Verify that state is clean after recovery.
        assert_eq!(plc.conceal_count, 0);
        assert_eq!(plc.gain, 1.0);
    }

    #[test]
    fn test_overlap_add_crossfade_fn() {
        let old: Vec<i16> = vec![10000; OLA_WINDOW];
        let mut frame: Vec<i16> = vec![0; OLA_WINDOW];
        apply_crossfade(&old, &mut frame, OLA_WINDOW);

        // At position 0, weight ~0 => mostly old.
        assert!(frame[0].abs() > 4000, "Start should be mostly old signal");
        // At last position, weight ~1 => mostly new (0).
        assert!(
            frame[OLA_WINDOW - 1].abs() < 2000,
            "End should be mostly new signal"
        );
    }

    // ----- hann_weight tests -----

    #[test]
    fn test_hann_weight_boundaries() {
        let w0 = hann_weight(0, 16);
        let w_last = hann_weight(15, 16);
        assert!(w0 < 0.05, "hann_weight(0, 16) = {} should be near 0", w0);
        assert!(
            w_last > 0.95,
            "hann_weight(15, 16) = {} should be near 1",
            w_last
        );
    }

    #[test]
    fn test_hann_weight_midpoint() {
        // Bug #90: With (len-1) denominator, the true midpoint of a 16-sample
        // window is at index 7.5 (non-integer). Index 8 is slightly above 0.5.
        // Use a wider tolerance to accommodate the proper Hann window formula.
        let w_mid = hann_weight(8, 16);
        assert!(
            (w_mid - 0.5).abs() < 0.1,
            "hann_weight(8, 16) = {} should be approximately 0.5",
            w_mid
        );
    }

    #[test]
    fn test_hann_weight_len_one() {
        assert_eq!(hann_weight(0, 1), 1.0);
    }

    // ----- clamp_i16 tests -----

    #[test]
    fn test_clamp_i16_in_range() {
        assert_eq!(clamp_i16(0.0), 0);
        assert_eq!(clamp_i16(100.6), 101);
        assert_eq!(clamp_i16(-100.4), -100);
    }

    #[test]
    fn test_clamp_i16_overflow() {
        assert_eq!(clamp_i16(40000.0), i16::MAX);
        assert_eq!(clamp_i16(-40000.0), i16::MIN);
    }

    // ----- history buffer tests -----

    #[test]
    fn test_history_circular_wrap() {
        let mut plc = PacketLossConcealer::new(160);
        // Write more than HISTORY_LEN samples.
        let big = sine_tone(200.0, 8000.0, HISTORY_LEN * 3, 5000.0);
        plc.update(&big);

        assert_eq!(plc.history_valid, HISTORY_LEN);
        // read_history_tail should return the last HISTORY_LEN samples.
        let tail = plc.read_history_tail(HISTORY_LEN);
        assert_eq!(tail.len(), HISTORY_LEN);
        // They should match the end of `big`.
        let expected = &big[big.len() - HISTORY_LEN..];
        assert_eq!(&tail, expected);
    }

    #[test]
    fn test_history_partial_fill() {
        let mut plc = PacketLossConcealer::new(160);
        let short = vec![42i16; 50];
        plc.update(&short);

        assert_eq!(plc.history_valid, 50);
        let tail = plc.read_history_tail(50);
        assert_eq!(tail, short);
    }

    // ----- build_ola_period tests -----

    #[test]
    fn test_build_ola_period_constant_signal() {
        // With a constant signal, OLA blending should produce the same
        // constant value throughout (prev tail == cur head == same value).
        let period: Vec<i16> = vec![5000; 40];
        let result = build_ola_period(&period, &period, OLA_WINDOW);
        assert_eq!(result.len(), 40);
        for i in 0..40 {
            assert!(
                (result[i] as i32 - 5000).unsigned_abs() <= 1,
                "At {}: got {} expected 5000",
                i,
                result[i],
            );
        }
    }

    #[test]
    fn test_build_ola_period_blends_correctly() {
        // Verify the OLA function produces a smooth blend.
        // `prev` is all 10000, `cur` is all -10000.
        // The crossfade region should transition smoothly from
        // 10000 -> -10000 over OLA_WINDOW samples, then the rest
        // of `cur` should be -10000.
        let prev = vec![10000i16; 40];
        let cur = vec![-10000i16; 40];
        let result = build_ola_period(&prev, &cur, OLA_WINDOW);
        assert_eq!(result.len(), 40);

        // First sample: mostly prev (weight ~0), so near 10000.
        assert!(result[0] > 5000, "Start should favor prev, got {}", result[0]);
        // Last OLA sample: mostly cur (weight ~1), so near -10000.
        assert!(
            result[OLA_WINDOW - 1] < -5000,
            "End of OLA should favor cur, got {}",
            result[OLA_WINDOW - 1]
        );
        // Samples beyond OLA region: pure cur.
        for i in OLA_WINDOW..40 {
            assert_eq!(result[i], -10000, "Beyond OLA at {}: got {}", i, result[i]);
        }
    }

    #[test]
    fn test_build_ola_period_empty() {
        let result = build_ola_period(&[], &[], OLA_WINDOW);
        assert!(result.is_empty());
    }

    // ----- integration: conceal-then-recover cycle -----

    #[test]
    fn test_conceal_recover_cycle() {
        let mut plc = PacketLossConcealer::new(160);
        let tone = sine_tone(200.0, 8000.0, 960, 10000.0);

        // Feed 3 good frames.
        for i in 0..3 {
            plc.update(&tone[i * 160..(i + 1) * 160]);
        }

        // Lose 2 frames.
        let c1 = plc.conceal();
        let c2 = plc.conceal();
        assert_eq!(c1.len(), 160);
        assert_eq!(c2.len(), 160);
        assert!(rms(&c1) > 100.0);
        assert!(rms(&c2) > 100.0);
        // c2 should be quieter than c1.
        assert!(rms(&c2) < rms(&c1) + 50.0);

        // Recover.
        plc.update(&tone[5 * 160..6 * 160]);
        assert_eq!(plc.conceal_count, 0);

        // Next conceal after recovery should be full strength again.
        let c3 = plc.conceal();
        assert!(rms(&c3) > 1000.0);
    }

    // ----- edge cases -----

    #[test]
    fn test_conceal_before_any_update() {
        // PLC should not panic even if conceal is called with no prior audio.
        let mut plc = PacketLossConcealer::new(160);
        let frame = plc.conceal();
        assert_eq!(frame.len(), 160);
        // History is all zeros, so concealed frame should be silence.
        assert!(rms(&frame) < 1.0);
    }

    #[test]
    fn test_update_with_empty_slice() {
        let mut plc = PacketLossConcealer::new(160);
        plc.update(&[]);
        // Should not panic or change state.
        assert_eq!(plc.history_valid, 0);
    }

    #[test]
    fn test_very_small_frame_size() {
        let mut plc = PacketLossConcealer::new(20);
        let tone = sine_tone(200.0, 8000.0, 400, 5000.0);
        plc.update(&tone);
        let frame = plc.conceal();
        assert_eq!(frame.len(), 20);
    }

    #[test]
    fn test_large_frame_size() {
        let mut plc = PacketLossConcealer::new(320);
        let tone = sine_tone(200.0, 8000.0, 640, 5000.0);
        plc.update(&tone);
        let frame = plc.conceal();
        assert_eq!(frame.len(), 320);
    }

    #[test]
    fn test_max_conceal_frames_calculated_correctly() {
        // 160 samples at 8kHz = 20ms per frame.
        // 60ms / 20ms = 3 frames.
        let plc = PacketLossConcealer::new(160);
        assert_eq!(plc.max_conceal_frames, 3);

        // 80 samples at 8kHz = 10ms per frame.
        // 60ms / 10ms = 6 frames.
        let plc2 = PacketLossConcealer::new(80);
        assert_eq!(plc2.max_conceal_frames, 6);
    }

    #[test]
    fn test_consecutive_losses_silence_boundary() {
        // Verify the exact frame at which concealment transitions to silence.
        // For 160 samples/frame at 8kHz (20ms), max_conceal_frames = 3.
        // Frames 1-3 should have energy; frame 4+ should be zero.
        let mut plc = PacketLossConcealer::new(160);
        assert_eq!(plc.max_conceal_frames, 3);

        let tone = sine_tone(200.0, 8000.0, 600, 10000.0);
        plc.update(&tone);

        // Frames 1-3: should have non-zero energy
        for i in 1..=3 {
            let frame = plc.conceal();
            assert!(
                rms(&frame) > 100.0,
                "Conceal frame {} should have energy, got RMS {}",
                i,
                rms(&frame)
            );
        }

        // Frame 4: should be silence (past max_conceal_frames)
        let frame4 = plc.conceal();
        assert!(
            rms(&frame4) < 1.0,
            "Conceal frame 4 should be silence, got RMS {}",
            rms(&frame4)
        );

        // Frame 5+: should remain silence
        let frame5 = plc.conceal();
        assert!(rms(&frame5) < 1.0);
    }

    #[test]
    fn test_reset_clears_history() {
        let mut plc = PacketLossConcealer::new(160);
        let tone = sine_tone(200.0, 8000.0, 480, 10000.0);
        plc.update(&tone);
        assert!(plc.history_valid > 0);

        plc.reset();
        assert_eq!(plc.history_valid, 0);
        assert_eq!(plc.conceal_count, 0);
        assert_eq!(plc.gain, 1.0);

        // After reset, concealment should produce silence (no history)
        let frame = plc.conceal();
        assert!(rms(&frame) < 1.0, "Post-reset conceal should be silence");
    }

    #[test]
    fn test_pitch_periodicity_in_concealed_output() {
        // Verify that the concealed output exhibits periodicity at
        // approximately the detected pitch.
        let mut plc = PacketLossConcealer::new(160);
        // 200Hz => period 40 samples.
        let tone = sine_tone(200.0, 8000.0, 600, 10000.0);
        plc.update(&tone);

        let frame = plc.conceal();
        let period = plc.pitch_period;

        // Check autocorrelation of the concealed frame at the detected period.
        if frame.len() > period * 2 {
            let mut corr: f64 = 0.0;
            let mut energy: f64 = 0.0;
            let check_len = frame.len() - period;
            for i in 0..check_len {
                corr += frame[i] as f64 * frame[i + period] as f64;
                energy += frame[i] as f64 * frame[i] as f64;
            }
            if energy > 0.0 {
                let norm = corr / energy;
                assert!(
                    norm > 0.5,
                    "Concealed frame should be periodic at pitch {}; norm_corr = {}",
                    period,
                    norm
                );
            }
        }
    }
}
