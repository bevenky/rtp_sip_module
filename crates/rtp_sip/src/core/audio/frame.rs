//! Audio frame representation
//!
//! AudioFrame is the primary audio data container passed between
//! Python and Rust. It contains L16 PCM samples at 16kHz mono.

/// Audio frame containing PCM samples
#[derive(Debug, Clone)]
pub struct AudioFrame {
    /// PCM samples as bytes (L16, little-endian, mono)
    pub samples: Vec<u8>,
    /// Sample rate in Hz (always 16000 for STT compatibility)
    pub sample_rate: u32,
    /// Number of channels (always 1 = mono)
    pub channels: u8,
    /// RTP timestamp
    pub timestamp: u64,
    /// Sequence number (for ordering)
    pub sequence: u64,
}

impl AudioFrame {
    /// Create a new audio frame
    pub fn new(samples: Vec<u8>, sample_rate: u32) -> Self {
        Self {
            samples,
            sample_rate,
            channels: 1,
            timestamp: 0,
            sequence: 0,
        }
    }

    /// Create a frame with metadata
    pub fn with_metadata(
        samples: Vec<u8>,
        sample_rate: u32,
        timestamp: u64,
        sequence: u64,
    ) -> Self {
        Self {
            samples,
            sample_rate,
            channels: 1,
            timestamp,
            sequence,
        }
    }

    /// Create a frame from raw i16 samples
    pub fn from_samples(samples: &[i16], sample_rate: u32) -> Self {
        let bytes: Vec<u8> = samples
            .iter()
            .flat_map(|&s| s.to_le_bytes())
            .collect();

        Self::new(bytes, sample_rate)
    }

    /// Get samples as i16 slice
    pub fn as_i16(&self) -> Vec<i16> {
        self.samples
            .chunks_exact(2)
            .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
            .collect()
    }

    /// Frame duration in milliseconds
    pub fn duration_ms(&self) -> u32 {
        let num_samples = self.samples.len() / 2; // 2 bytes per sample
        (num_samples as u32 * 1000) / self.sample_rate
    }

    /// Number of samples in the frame
    pub fn num_samples(&self) -> usize {
        self.samples.len() / 2
    }

    /// Check if frame is empty
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Create an empty frame
    pub fn empty() -> Self {
        Self::new(Vec::new(), 16000)
    }

    /// Create a 20ms frame of silence at 16kHz
    pub fn silence_20ms() -> Self {
        // 20ms @ 16kHz = 320 samples = 640 bytes
        Self::new(vec![0u8; 640], 16000)
    }

    /// Create a 20ms frame of silence at 8kHz
    pub fn silence_20ms_8k() -> Self {
        // 20ms @ 8kHz = 160 samples = 320 bytes
        Self::new(vec![0u8; 320], 8000)
    }
}

impl Default for AudioFrame {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_from_samples() {
        let samples = vec![0i16, 1000, -1000, 32767, -32768];
        let frame = AudioFrame::from_samples(&samples, 16000);

        assert_eq!(frame.samples.len(), 10); // 5 samples * 2 bytes
        assert_eq!(frame.sample_rate, 16000);
        assert_eq!(frame.channels, 1);
    }

    #[test]
    fn test_frame_as_i16() {
        let samples = vec![0i16, 1000, -1000];
        let frame = AudioFrame::from_samples(&samples, 16000);
        let recovered = frame.as_i16();

        assert_eq!(recovered, samples);
    }

    #[test]
    fn test_frame_duration() {
        // 320 samples @ 16kHz = 20ms
        let frame = AudioFrame::silence_20ms();
        assert_eq!(frame.duration_ms(), 20);
        assert_eq!(frame.num_samples(), 320);
    }

    #[test]
    fn test_frame_duration_8k() {
        // 160 samples @ 8kHz = 20ms
        let frame = AudioFrame::silence_20ms_8k();
        assert_eq!(frame.duration_ms(), 20);
        assert_eq!(frame.num_samples(), 160);
    }
}
