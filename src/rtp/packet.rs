//! RTP packet handling using the rtp crate (webrtc-rs)

use crate::error::{Result, RtpSipError};
use bytes::Bytes;
use rtp::packet::Packet;
use rtp::header::Header;
use webrtc_util::marshal::{Marshal, Unmarshal};

/// Re-export the rtp crate's Packet for convenience
pub use rtp::packet::Packet as RtpPacket;

/// RTP packet builder for convenient packet creation
pub struct RtpPacketBuilder {
    payload_type: u8,
    ssrc: u32,
    sequence: u16,
    timestamp: u32,
}

impl RtpPacketBuilder {
    /// Create a new builder with random initial sequence and timestamp
    pub fn new(payload_type: u8, ssrc: u32) -> Self {
        Self {
            payload_type,
            ssrc,
            sequence: rand::random(),
            timestamp: rand::random(),
        }
    }

    /// Create a new builder with specified initial sequence and timestamp
    pub fn with_initial(
        payload_type: u8,
        ssrc: u32,
        initial_sequence: u16,
        initial_timestamp: u32,
    ) -> Self {
        Self {
            payload_type,
            ssrc,
            sequence: initial_sequence,
            timestamp: initial_timestamp,
        }
    }

    /// Build the next packet with given payload
    pub fn build(&mut self, payload: Bytes, samples: u32) -> Packet {
        let header = Header {
            version: 2,
            padding: false,
            extension: false,
            marker: false,
            payload_type: self.payload_type,
            sequence_number: self.sequence,
            timestamp: self.timestamp,
            ssrc: self.ssrc,
            csrc: vec![],
            extension_profile: 0,
            extensions: vec![],
            extensions_padding: 0,
        };

        let packet = Packet {
            header,
            payload,
        };

        // Increment sequence (wraps at 65535)
        self.sequence = self.sequence.wrapping_add(1);
        // Increment timestamp by number of samples
        debug_assert!(samples > 0, "timestamp advance with zero samples");
        self.timestamp = self.timestamp.wrapping_add(samples);

        packet
    }

    /// Build the next packet with given payload and marker bit
    pub fn build_with_marker(&mut self, payload: Bytes, samples: u32, marker: bool) -> Packet {
        let header = Header {
            version: 2,
            padding: false,
            extension: false,
            marker,
            payload_type: self.payload_type,
            sequence_number: self.sequence,
            timestamp: self.timestamp,
            ssrc: self.ssrc,
            csrc: vec![],
            extension_profile: 0,
            extensions: vec![],
            extensions_padding: 0,
        };

        let packet = Packet {
            header,
            payload,
        };

        self.sequence = self.sequence.wrapping_add(1);
        self.timestamp = self.timestamp.wrapping_add(samples);

        packet
    }

    /// Get current sequence number
    pub fn sequence(&self) -> u16 {
        self.sequence
    }

    /// Consume and return the next sequence number (post-increments).
    ///
    /// This is used by the DTMF sender so that DTMF packets share
    /// the same monotonic sequence-number space as audio packets
    /// (RFC 4733 §2.5).
    pub fn next_sequence(&mut self) -> u16 {
        let seq = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        seq
    }

    /// Set the current sequence number.
    ///
    /// Used after a batch of DTMF packets have consumed sequence numbers
    /// from an external counter that was seeded from this builder.
    pub fn set_sequence(&mut self, seq: u16) {
        self.sequence = seq;
    }

    /// Get current timestamp
    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Get SSRC
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }
}

/// Parse an RTP packet from bytes
pub fn parse_rtp_packet(data: &[u8]) -> Result<Packet> {
    Packet::unmarshal(&mut data.to_vec().as_slice())
        .map_err(|e| RtpSipError::Rtp(format!("Failed to parse RTP packet: {}", e)))
}

/// Serialize an RTP packet to bytes
pub fn serialize_rtp_packet(packet: &Packet) -> Result<Bytes> {
    packet.marshal()
        .map_err(|e| RtpSipError::Rtp(format!("Failed to serialize RTP packet: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_builder() {
        let mut builder = RtpPacketBuilder::with_initial(0, 0x12345678, 0, 0);

        let packet1 = builder.build(Bytes::from(vec![0xFF; 160]), 160);
        assert_eq!(packet1.header.sequence_number, 0);
        assert_eq!(packet1.header.timestamp, 0);
        assert_eq!(packet1.header.ssrc, 0x12345678);
        assert_eq!(packet1.header.payload_type, 0);

        let packet2 = builder.build(Bytes::from(vec![0xFF; 160]), 160);
        assert_eq!(packet2.header.sequence_number, 1);
        assert_eq!(packet2.header.timestamp, 160);

        let packet3 = builder.build(Bytes::from(vec![0xFF; 160]), 160);
        assert_eq!(packet3.header.sequence_number, 2);
        assert_eq!(packet3.header.timestamp, 320);
    }

    #[test]
    fn test_packet_serialize_parse_roundtrip() {
        let mut builder = RtpPacketBuilder::with_initial(0, 0x12345678, 12345, 0xABCDEF00);
        let payload = Bytes::from(vec![0xFF; 160]);
        let original = builder.build(payload.clone(), 160);

        let serialized = serialize_rtp_packet(&original).unwrap();
        let parsed = parse_rtp_packet(&serialized).unwrap();

        assert_eq!(parsed.header.version, 2);
        assert_eq!(parsed.header.payload_type, 0);
        assert_eq!(parsed.header.sequence_number, 12345);
        assert_eq!(parsed.header.timestamp, 0xABCDEF00);
        assert_eq!(parsed.header.ssrc, 0x12345678);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_packet_with_marker() {
        let mut builder = RtpPacketBuilder::with_initial(0, 0x12345678, 0, 0);
        let packet = builder.build_with_marker(Bytes::from(vec![0xFF; 160]), 160, true);

        assert!(packet.header.marker);

        let serialized = serialize_rtp_packet(&packet).unwrap();
        let parsed = parse_rtp_packet(&serialized).unwrap();

        assert!(parsed.header.marker);
    }
}
