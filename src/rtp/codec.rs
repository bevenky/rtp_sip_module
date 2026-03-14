//! G.711 codec wrapper using audio-codec-algorithms crate

use crate::error::{Result, RtpSipError};
use audio_codec_algorithms::{decode_alaw, decode_ulaw, encode_alaw, encode_ulaw};

/// Supported codec types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecType {
    /// G.711 μ-law (PCMU) - RTP payload type 0
    Pcmu,
    /// G.711 A-law (PCMA) - RTP payload type 8
    Pcma,
}

impl CodecType {
    /// Get the RTP payload type for this codec
    pub fn payload_type(&self) -> u8 {
        match self {
            CodecType::Pcmu => 0,
            CodecType::Pcma => 8,
        }
    }

    /// Get the sample rate in Hz
    pub fn sample_rate(&self) -> u32 {
        8000 // G.711 is always 8kHz
    }

    /// Get samples per packet for the given ptime.
    /// Bug #26: Previously hardcoded to 160 (20ms at 8kHz), now takes ptime_ms
    /// to support variable packet sizes (e.g. 10ms, 30ms).
    pub fn samples_per_frame(&self, ptime_ms: u32) -> usize {
        (self.sample_rate() * ptime_ms / 1000) as usize
    }

    /// Parse codec from string
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "PCMU" | "ULAW" | "G711U" => Ok(CodecType::Pcmu),
            "PCMA" | "ALAW" | "G711A" => Ok(CodecType::Pcma),
            _ => Err(RtpSipError::Codec(format!(
                "Unsupported codec: {}. Use PCMU or PCMA",
                s
            ))),
        }
    }

    /// Get codec name for SDP
    pub fn sdp_name(&self) -> &'static str {
        match self {
            CodecType::Pcmu => "PCMU",
            CodecType::Pcma => "PCMA",
        }
    }
}

impl std::fmt::Display for CodecType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.sdp_name())
    }
}

/// G.711 codec implementation using audio-codec-algorithms
pub struct G711Codec {
    codec_type: CodecType,
}

impl G711Codec {
    /// Create a new G.711 codec
    pub fn new(codec_type: CodecType) -> Self {
        Self { codec_type }
    }

    /// Get the codec type
    pub fn codec_type(&self) -> CodecType {
        self.codec_type
    }

    /// Encode PCM samples (i16) to G.711 bytes
    pub fn encode(&self, samples: &[i16]) -> Vec<u8> {
        match self.codec_type {
            CodecType::Pcmu => samples.iter().map(|&s| encode_ulaw(s)).collect(),
            CodecType::Pcma => samples.iter().map(|&s| encode_alaw(s)).collect(),
        }
    }

    /// Decode G.711 bytes to PCM samples (i16)
    pub fn decode(&self, data: &[u8]) -> Vec<i16> {
        match self.codec_type {
            CodecType::Pcmu => data.iter().map(|&b| decode_ulaw(b)).collect(),
            CodecType::Pcma => data.iter().map(|&b| decode_alaw(b)).collect(),
        }
    }

    /// Check if a G.711 frame is silence or near-silence.
    /// Bug #65: Uses 95% threshold for better alignment with energy-based VAD.
    /// Bug #109: Uses a threshold-based approach: decode each byte and check
    /// if |amplitude| <= NEAR_SILENCE_THRESHOLD. This is more robust than
    /// hardcoding specific byte values, which may be incorrect for A-law
    /// due to the non-monotonic encoding table.
    pub fn is_silence_frame(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return true;
        }
        /// Amplitude threshold for near-silence detection.
        /// Samples with |decoded amplitude| <= this value are considered silent.
        /// 8 covers the first few quantization steps in both mu-law and A-law.
        const NEAR_SILENCE_THRESHOLD: i16 = 8;

        let silence_count = data
            .iter()
            .filter(|&&b| {
                let amplitude = match self.codec_type {
                    CodecType::Pcmu => decode_ulaw(b),
                    CodecType::Pcma => decode_alaw(b),
                };
                amplitude.abs() <= NEAR_SILENCE_THRESHOLD
            })
            .count();
        // Bug #26: Avoid integer division truncation by cross-multiplying
        silence_count * 100 >= data.len() * 95
    }

    /// Get the silence byte value for this codec.
    pub fn silence_byte(&self) -> u8 {
        match self.codec_type {
            CodecType::Pcmu => 0xFF, // mu-law positive zero
            CodecType::Pcma => 0xD5, // A-law positive zero
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ulaw_roundtrip() {
        let codec = G711Codec::new(CodecType::Pcmu);

        // Test various sample values
        let samples: Vec<i16> = vec![0, 100, 1000, 10000, 32000, -100, -1000, -10000, -32000];
        let encoded = codec.encode(&samples);
        let decoded = codec.decode(&encoded);

        // G.711 is lossy, but should be reasonably close
        for (orig, dec) in samples.iter().zip(decoded.iter()) {
            let diff = (*orig as i32 - *dec as i32).abs();
            // Allow up to ~3% error for non-zero values
            if *orig != 0 {
                assert!(
                    diff < orig.abs() as i32 / 10 + 100,
                    "orig={}, dec={}, diff={}",
                    orig,
                    dec,
                    diff
                );
            }
        }
    }

    #[test]
    fn test_alaw_roundtrip() {
        let codec = G711Codec::new(CodecType::Pcma);

        let samples: Vec<i16> = vec![0, 100, 1000, 10000, 32000, -100, -1000, -10000, -32000];
        let encoded = codec.encode(&samples);
        let decoded = codec.decode(&encoded);

        for (orig, dec) in samples.iter().zip(decoded.iter()) {
            let diff = (*orig as i32 - *dec as i32).abs();
            if *orig != 0 {
                assert!(
                    diff < orig.abs() as i32 / 10 + 100,
                    "orig={}, dec={}, diff={}",
                    orig,
                    dec,
                    diff
                );
            }
        }
    }

    #[test]
    fn test_codec_type_from_str() {
        assert_eq!(CodecType::from_str("PCMU").unwrap(), CodecType::Pcmu);
        assert_eq!(CodecType::from_str("pcmu").unwrap(), CodecType::Pcmu);
        assert_eq!(CodecType::from_str("ULAW").unwrap(), CodecType::Pcmu);
        assert_eq!(CodecType::from_str("PCMA").unwrap(), CodecType::Pcma);
        assert_eq!(CodecType::from_str("alaw").unwrap(), CodecType::Pcma);
        assert!(CodecType::from_str("OPUS").is_err());
    }

    #[test]
    fn test_payload_type() {
        assert_eq!(CodecType::Pcmu.payload_type(), 0);
        assert_eq!(CodecType::Pcma.payload_type(), 8);
    }

    // === Bug #65: Silence detection threshold at 95% ===

    #[test]
    fn test_is_silence_frame_all_silence() {
        let ulaw = G711Codec::new(CodecType::Pcmu);
        let alaw = G711Codec::new(CodecType::Pcma);

        // All mu-law silence
        let ulaw_silence = vec![0xFFu8; 160];
        assert!(ulaw.is_silence_frame(&ulaw_silence));

        // All A-law silence
        let alaw_silence = vec![0xD5u8; 160];
        assert!(alaw.is_silence_frame(&alaw_silence));

        // Negative zero variants
        let ulaw_neg_silence = vec![0x7Fu8; 160];
        assert!(ulaw.is_silence_frame(&ulaw_neg_silence));

        let alaw_neg_silence = vec![0x55u8; 160];
        assert!(alaw.is_silence_frame(&alaw_neg_silence));
    }

    #[test]
    fn test_is_silence_frame_not_silence() {
        let ulaw = G711Codec::new(CodecType::Pcmu);

        // Random non-silence data
        let data: Vec<u8> = (0..160).map(|i| (i % 128) as u8).collect();
        assert!(!ulaw.is_silence_frame(&data));
    }

    #[test]
    fn test_is_silence_frame_threshold_95() {
        let ulaw = G711Codec::new(CodecType::Pcmu);

        // 94% silence -- should NOT be detected (threshold is >=95%)
        let mut data = vec![0xFFu8; 94];
        data.extend(vec![0x00u8; 6]);
        assert_eq!(data.len(), 100);
        assert!(
            !ulaw.is_silence_frame(&data),
            "94% silence should NOT trigger detection at 95% threshold"
        );

        // 95% silence -- should be detected
        let mut data = vec![0xFFu8; 95];
        data.extend(vec![0x00u8; 5]);
        assert_eq!(data.len(), 100);
        assert!(
            ulaw.is_silence_frame(&data),
            "95% silence should trigger detection at 95% threshold"
        );
    }

    #[test]
    fn test_is_silence_frame_90_percent_not_enough() {
        // Bug #65 regression: 90% was the old threshold, now it's 95%
        let ulaw = G711Codec::new(CodecType::Pcmu);

        let mut data = vec![0xFFu8; 90];
        data.extend(vec![0x00u8; 10]);
        assert_eq!(data.len(), 100);
        assert!(
            !ulaw.is_silence_frame(&data),
            "90% silence should NOT trigger detection at 95% threshold"
        );
    }

    #[test]
    fn test_is_silence_frame_empty() {
        let codec = G711Codec::new(CodecType::Pcmu);
        assert!(codec.is_silence_frame(&[]));
    }

    #[test]
    fn test_silence_byte() {
        let ulaw = G711Codec::new(CodecType::Pcmu);
        assert_eq!(ulaw.silence_byte(), 0xFF);

        let alaw = G711Codec::new(CodecType::Pcma);
        assert_eq!(alaw.silence_byte(), 0xD5);
    }
}
