//! Audio codec types
//!
//! Codec encoding/decoding is handled by libfs internally.
//! This module just provides the codec type enumeration.

/// Supported audio codecs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// G.711 u-law (PCMU) - 8kHz
    Pcmu,
    /// G.711 A-law (PCMA) - 8kHz
    Pcma,
    /// Linear 16-bit PCM (L16)
    L16,
}

impl Codec {
    /// Get RTP payload type for this codec
    pub fn payload_type(&self) -> u8 {
        match self {
            Codec::Pcmu => 0,
            Codec::Pcma => 8,
            Codec::L16 => 11,
        }
    }

    /// Parse codec from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "pcmu" | "ulaw" | "mulaw" | "audio/x-mulaw" | "audio/pcmu" => Some(Codec::Pcmu),
            "pcma" | "alaw" | "audio/x-alaw" | "audio/pcma" => Some(Codec::Pcma),
            "l16" | "audio/l16" | "audio/x-l16" | "raw" => Some(Codec::L16),
            _ => None,
        }
    }

    /// Get sample rate for this codec
    pub fn sample_rate(&self) -> u32 {
        match self {
            Codec::Pcmu | Codec::Pcma => 8000,
            Codec::L16 => 16000, // Default for STT
        }
    }
}

impl Default for Codec {
    fn default() -> Self {
        Codec::Pcmu
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codec_payload_types() {
        assert_eq!(Codec::Pcmu.payload_type(), 0);
        assert_eq!(Codec::Pcma.payload_type(), 8);
    }

    #[test]
    fn test_codec_from_str() {
        assert_eq!(Codec::from_str("pcmu"), Some(Codec::Pcmu));
        assert_eq!(Codec::from_str("PCMA"), Some(Codec::Pcma));
        assert_eq!(Codec::from_str("l16"), Some(Codec::L16));
    }
}
