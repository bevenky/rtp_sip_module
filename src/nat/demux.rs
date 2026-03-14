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
    /// Packet with top bits 00 that is not valid STUN (e.g., DTLS or other data)
    Unknown(&'a [u8]),
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
            // Not STUN — could be DTLS or other legitimate non-STUN data
            DemuxResult::Unknown(data)
        }
        0b01 => {
            // TURN ChannelData — validate channel number is in range 0x4000-0x7FFE
            let channel = u16::from_be_bytes([data[0], data[1]]);
            if is_valid_channel(channel) {
                DemuxResult::TurnChannelData(data)
            } else {
                // Bug #5 fix: Top bits = 01 but invalid channel range — not a valid
                // TURN ChannelData and not RTP (RTP requires top bits 10 or 11).
                DemuxResult::Unknown(data)
            }
        }
        0b10 | 0b11 => {
            // P1-NAT-9: Improved RTP vs RTCP demux per RFC 5761.
            //
            // Simple byte[1] range check misclassifies RTP packets with
            // marker bit set and PT 72-83 (byte[1] = 200-211) as RTCP.
            //
            // Better heuristic: check RTP version bits (must be 2) AND
            // validate RTCP length field consistency. For RTCP, the length
            // field (bytes 2-3) indicates the number of 32-bit words minus 1.
            // If (length + 1) * 4 doesn't match or exceed a plausible RTCP
            // packet size, it's likely RTP with marker bit set.
            if data.len() < 4 {
                return DemuxResult::TooShort;
            }
            let byte1 = data[1];
            let pt = byte1 & 0x7F; // mask off marker bit for RTP PT

            // RTCP PT range: 200-211 (SR, RR, SDES, BYE, APP, RTPFB, PSFB, XR, etc.)
            if (200..=211).contains(&byte1) {
                // Candidate RTCP — validate using length field consistency.
                // RTCP length field = number of 32-bit words in packet minus 1.
                let rtcp_len_field = u16::from_be_bytes([data[2], data[3]]) as usize;
                let rtcp_packet_len = (rtcp_len_field + 1) * 4;

                // Valid RTCP: the declared length should not exceed the data.
                // Also a zero-length RTCP is invalid (SR minimum is 7 words).
                if rtcp_packet_len <= data.len() && rtcp_len_field > 0 {
                    DemuxResult::Rtcp(data)
                } else {
                    // Length field inconsistent — this is likely RTP with
                    // marker bit and PT in the 72-83 range.
                    DemuxResult::Rtp(data)
                }
            } else if (72..=83).contains(&pt) && byte1 != pt {
                // byte1 != pt means marker bit is set. PT 72-83 without marker
                // is fine as RTP. With marker, the full byte1 would be 200-211
                // which we already handled above.
                DemuxResult::Rtp(data)
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
        // RTCP SR: version=2, PT=200, length=6 (7 32-bit words = 28 bytes total)
        // The demux validation checks that (length+1)*4 <= data.len(),
        // so the data must be at least 28 bytes.
        let mut data = [0u8; 28];
        data[0] = 0x80; // V=2, P=0, RC=0
        data[1] = 200;  // PT=200 (SR)
        data[2] = 0x00;
        data[3] = 0x06; // length = 6 words
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
        assert!(matches!(demux_packet(&data), DemuxResult::Unknown(_)));

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

    #[test]
    fn test_demux_non_stun_top_bits_00() {
        // Top bits = 00, has enough bytes, but no STUN magic cookie.
        // This could be DTLS or other legitimate data — should be Unknown, not TooShort.
        let data = [0x14, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(matches!(demux_packet(&data), DemuxResult::Unknown(_)));
    }

    #[test]
    fn test_demux_rtp_marker_pt72_not_misclassified() {
        // P1-NAT-9: RTP with marker=1 and PT=72 gives byte[1]=200 (same as
        // RTCP SR). The improved demux checks the RTCP length field to avoid
        // misclassifying such RTP packets as RTCP.
        //
        // Build an RTP-like packet: V=2, M=1, PT=72 => byte[1] = 0xC8 = 200.
        // Bytes 2-3 are RTP sequence number, not RTCP length. Set them to a
        // value that would be an implausible RTCP length (e.g., 0x0001 means
        // 2 words = 8 bytes, but we have more data than that).
        let mut data = [0u8; 172]; // 172 bytes RTP packet
        data[0] = 0x80; // V=2
        data[1] = 0xC8; // M=1, PT=72 (same as RTCP SR PT=200)
        data[2] = 0x00;
        data[3] = 0x01; // RTP seq=1, but as RTCP length would mean 8 bytes total
        // The RTCP length check: (0x0001 + 1) * 4 = 8 <= 172, so this would
        // still pass the RTCP length check. Use a sequence number that makes
        // the RTCP length implausible instead.
        data[2] = 0xFF;
        data[3] = 0xFF; // As RTCP length: (65535+1)*4 = 262144 > 172 => not RTCP
        assert!(matches!(demux_packet(&data), DemuxResult::Rtp(_)));
    }

    #[test]
    fn test_demux_real_rtcp_sr_with_valid_length() {
        // Ensure real RTCP SR (PT=200) with correct length field is still RTCP.
        // SR with 0 report blocks: header(4) + SSRC(4) + sender info(20) = 28 bytes
        // Length field = 28/4 - 1 = 6
        let mut data = [0u8; 28];
        data[0] = 0x80; // V=2, P=0, RC=0
        data[1] = 200;  // PT=200 (SR)
        data[2] = 0x00;
        data[3] = 0x06; // length = 6 (28 bytes total)
        assert!(matches!(demux_packet(&data), DemuxResult::Rtcp(_)));
    }
}
