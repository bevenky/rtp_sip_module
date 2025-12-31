//! G.711 codec wrapper using audio-codec-algorithms crate

use crate::error::{Result, SipRunnerError};
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

    /// Get samples per packet (20ms frame)
    pub fn samples_per_frame(&self) -> usize {
        160 // 20ms at 8kHz = 160 samples
    }

    /// Parse codec from string
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "PCMU" | "ULAW" | "G711U" => Ok(CodecType::Pcmu),
            "PCMA" | "ALAW" | "G711A" => Ok(CodecType::Pcma),
            _ => Err(SipRunnerError::Codec(format!(
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
}
