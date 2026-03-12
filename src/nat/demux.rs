//! Extended packet demultiplexing for NAT-traversal-aware sockets
//!
//! When a socket carries RTP, RTCP, STUN, and TURN ChannelData,
//! this module distinguishes them per RFC 5764 Section 5.1.2:
//!
//! ```text
//! Bits 0-1  | Meaning
//! ----------|------------------
//! 00        | STUN (check magic cookie at bytes 4-7)
//! 01        | TURN ChannelData (0x4000-0x7FFE)
//! 10        | RTP or RTCP (use PT to distinguish)
//! 11        | RTP (version 2 + padding bit)
//! ```

use super::stun::message::MAGIC_COOKIE;
use super::turn::message::is_valid_channel;

/// Extended demux result
#[derive(Debug, PartialEq, Eq)]
pub enum DemuxResult<'a> {
    /// RTP media packet
    Rtp(&'a [u8]),
    /// RTCP control packet
    Rtcp(&'a [u8]),
    /// STUN message (binding request/response/indication)
    Stun(&'a [u8]),
    /// TURN ChannelData framing
    TurnChannelData(&'a [u8]),
    /// Packet too short to classify
    TooShort,
}

/// Demultiplex an incoming packet on a shared RTP/STUN/TURN socket.
///
/// This extends the existing `demux_rtp_rtcp` with STUN and TURN awareness.
pub fn demux_packet(data: &[u8]) -> DemuxResult<'_> {
    if data.len() < 4 {
        return DemuxResult::TooShort;
    }

    let top_bits = data[0] >> 6;

    match top_bits {
        0b00 => {
            // Could be STUN — check magic cookie at bytes 4-7
            if data.len() >= 8 {
                let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                if cookie == MAGIC_COOKIE {
                    return DemuxResult::Stun(data);
                }
            }
            // Not STUN — unusual but treat as opaque data (could be DTLS in WebRTC)
            DemuxResult::TooShort
        }
        0b01 => {
            // TURN ChannelData — validate channel number is in range 0x4000-0x7FFE
            let channel = u16::from_be_bytes([data[0], data[1]]);
            if is_valid_channel(channel) {
                DemuxResult::TurnChannelData(data)
            } else {
                // Top bits = 01 but invalid channel range — treat as unknown
                DemuxResult::Rtp(data)
            }
        }
        0b10 | 0b11 => {
            // RTP version 2 — distinguish RTP from RTCP per RFC 5761.
            // RTCP packet types use the FULL second byte (not masked):
            // 200-204 (SR, RR, SDES, BYE, APP), 205-211 (RTPFB, PSFB, etc.)
            // In RTP, byte 1 = marker(1) + PT(7), so RTCP 200-211 maps to
            // RTP marker=1 + PT=72-83. RFC 5761 forbids these RTP PTs.
            if data.len() < 2 {
                return DemuxResult::TooShort;
            }
            let byte1 = data[1];
            if (200..=211).contains(&byte1) {
                DemuxResult::Rtcp(data)
            } else {
                DemuxResult::Rtp(data)
            }
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_demux_stun() {
        // STUN Binding Request: top 2 bits = 00, magic cookie at bytes 4-7
        let mut data = [0u8; 20];
        data[0] = 0x00; // top 2 bits = 00
        data[1] = 0x01; // Binding Request
        data[2] = 0x00;
        data[3] = 0x00; // length = 0
        data[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        // Transaction ID follows...

        assert!(matches!(demux_packet(&data), DemuxResult::Stun(_)));
    }

    #[test]
    fn test_demux_rtp() {
        // RTP: version=2, PT=0 (PCMU)
        let data = [0x80, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(matches!(demux_packet(&data), DemuxResult::Rtp(_)));
    }

    #[test]
    fn test_demux_rtcp_sr() {
        // RTCP SR: version=2, PT=200
        let data = [0x80, 200, 0x00, 0x06, 0, 0, 0, 0];
        assert!(matches!(demux_packet(&data), DemuxResult::Rtcp(_)));
    }

    #[test]
    fn test_demux_rtcp_rr() {
        // RTCP RR: version=2, PT=201
        let data = [0x80, 201, 0x00, 0x01, 0, 0, 0, 0];
        assert!(matches!(demux_packet(&data), DemuxResult::Rtcp(_)));
    }

    #[test]
    fn test_demux_turn_channel_data() {
        // TURN ChannelData: top 2 bits = 01 (channel 0x4000)
        let data = [0x40, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04];
        assert!(matches!(demux_packet(&data), DemuxResult::TurnChannelData(_)));
    }

    #[test]
    fn test_demux_too_short() {
        assert!(matches!(demux_packet(&[0x80]), DemuxResult::TooShort));
        assert!(matches!(demux_packet(&[]), DemuxResult::TooShort));
    }

    #[test]
    fn test_demux_invalid_turn_channel() {
        // Top bits = 01 but channel 0x7FFF is out of TURN range (max 0x7FFE)
        let data = [0x7F, 0xFF, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04];
        assert!(matches!(demux_packet(&data), DemuxResult::Rtp(_)));

        // Channel 0x3FFF — below TURN range but top bits still 00 (handled by STUN path)
        // Channel 0x41FF — valid TURN range
        let data2 = [0x41, 0xFF, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04];
        assert!(matches!(demux_packet(&data2), DemuxResult::TurnChannelData(_)));
    }

    #[test]
    fn test_demux_rtp_with_marker() {
        // RTP with marker bit: version=2, marker=1, PT=96
        let data = [0x80, 0xE0, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
        // PT = 0xE0 & 0x7F = 96 (dynamic)
        assert!(matches!(demux_packet(&data), DemuxResult::Rtp(_)));
    }
}
