//! RTCP (RTP Control Protocol) implementation
//!
//! Implements RFC 3550 Section 6: SR, RR, SDES, BYE packets.
//! Patterns inspired by rtcp-types crate (zero-copy parsing, builder pattern).
//!
//! # Supported Packet Types
//!
//! - **Sender Report (SR, PT=200)**: Sent by active senders with NTP/RTP timestamp
//!   mapping, packet/octet counts, and receiver report blocks.
//! - **Receiver Report (RR, PT=201)**: Sent by receivers with loss/jitter statistics.
//! - **Source Description (SDES, PT=202)**: CNAME for source identification.
//! - **Goodbye (BYE, PT=203)**: Session teardown notification.
//!
//! # RTCP Timing (RFC 3550 Section 6.2)
//!
//! RTCP is sent at regular intervals (default 5s, randomized 0.5x-1.5x) to avoid
//! synchronization. The interval adapts based on session bandwidth and participant count.
//!
//! # Deferred TODOs
//!
//! - P2-RTCP-1: Bandwidth-based RTCP interval calculation (currently fixed 5s base)
//! - P2-RTCP-3: Burst/gap loss tracking for XR burst_density/gap_density fields
//! - P2-RTCP-4: Cap DLSR to prevent stale values from producing bogus RTT
//! - P2-RTCP-6: Jitter inflation guard (filter out clock-rate mismatches)

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// RTCP packet type constants (RFC 3550)
pub const PT_SR: u8 = 200;
pub const PT_RR: u8 = 201;
pub const PT_SDES: u8 = 202;
pub const PT_BYE: u8 = 203;
pub const PT_APP: u8 = 204;
/// RTCP Extended Reports (RFC 3611)
pub const PT_XR: u8 = 207;

// NTP epoch offset: seconds between 1900-01-01 and 1970-01-01
const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;

// SDES item types
const SDES_CNAME: u8 = 1;

// RFC 3550 Appendix A.1: Sequence number validation constants
const MAX_DROPOUT: u16 = 3000;
const MAX_MISORDER: u16 = 100;

/// NTP timestamp (64-bit: 32-bit seconds + 32-bit fraction since 1900)
#[derive(Debug, Clone, Copy, Default)]
pub struct NtpTimestamp {
    /// Seconds since 1900-01-01
    pub seconds: u32,
    /// Fractional seconds (1/2^32 of a second)
    pub fraction: u32,
}

impl NtpTimestamp {
    /// Create NTP timestamp from current system time
    pub fn now() -> Self {
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            seconds: (since_epoch.as_secs() + NTP_EPOCH_OFFSET) as u32,
            fraction: ((since_epoch.subsec_nanos() as u64 * (1u64 << 32)) / 1_000_000_000) as u32,
        }
    }

    /// Get the "middle 32 bits" used as LSR in report blocks
    pub fn compact(&self) -> u32 {
        ((self.seconds & 0xFFFF) << 16) | ((self.fraction >> 16) & 0xFFFF)
    }

    /// Write to buffer (8 bytes)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&self.seconds.to_be_bytes());
        buf[4..8].copy_from_slice(&self.fraction.to_be_bytes());
    }

    /// Parse from buffer (8 bytes)
    pub fn parse(buf: &[u8]) -> Self {
        Self {
            seconds: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            fraction: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        }
    }
}

/// RTCP Report Block (24 bytes) — used in SR and RR
#[derive(Debug, Clone, Default)]
pub struct ReportBlock {
    /// SSRC of the source being reported on
    pub ssrc: u32,
    /// Fraction of packets lost since last report (0-255, divide by 256)
    pub fraction_lost: u8,
    /// Cumulative packets lost (signed 24-bit)
    pub cumulative_lost: i32,
    /// Extended highest sequence number received
    pub extended_highest_seq: u32,
    /// Inter-arrival jitter (in timestamp units)
    pub jitter: u32,
    /// Last SR timestamp (compact NTP from last received SR)
    pub last_sr: u32,
    /// Delay since last SR (units of 1/65536 seconds)
    pub delay_since_last_sr: u32,
}

impl ReportBlock {
    /// Size of a report block in bytes
    pub const SIZE: usize = 24;

    /// Write to buffer (24 bytes)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&self.ssrc.to_be_bytes());
        // Fraction lost (8 bits) + cumulative lost (24 bits, signed)
        buf[4] = self.fraction_lost;
        let cum = self.cumulative_lost & 0x00FF_FFFF;
        buf[5] = ((cum >> 16) & 0xFF) as u8;
        buf[6] = ((cum >> 8) & 0xFF) as u8;
        buf[7] = (cum & 0xFF) as u8;
        buf[8..12].copy_from_slice(&self.extended_highest_seq.to_be_bytes());
        buf[12..16].copy_from_slice(&self.jitter.to_be_bytes());
        buf[16..20].copy_from_slice(&self.last_sr.to_be_bytes());
        buf[20..24].copy_from_slice(&self.delay_since_last_sr.to_be_bytes());
    }

    /// Parse from buffer (24 bytes)
    pub fn parse(buf: &[u8]) -> Self {
        let ssrc = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let fraction_lost = buf[4];
        // 24-bit signed: sign-extend from 24 to 32 bits
        let cum_raw = ((buf[5] as i32) << 16) | ((buf[6] as i32) << 8) | (buf[7] as i32);
        let cumulative_lost = if cum_raw & 0x0080_0000 != 0 {
            cum_raw | (0xFF << 24) // sign extend
        } else {
            cum_raw
        };
        Self {
            ssrc,
            fraction_lost,
            cumulative_lost,
            extended_highest_seq: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            jitter: u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
            last_sr: u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]),
            delay_since_last_sr: u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]),
        }
    }
}

/// Parsed RTCP packet (any type)
#[derive(Debug)]
pub enum RtcpPacket {
    SenderReport(SenderReport),
    ReceiverReport(ReceiverReport),
    SourceDescription(SourceDescription),
    Goodbye(Goodbye),
    ExtendedReport(ExtendedReport),
    Unknown { packet_type: u8 },
}

/// Extended Report (PT=207, RFC 3611)
#[derive(Debug, Clone)]
pub struct ExtendedReport {
    pub ssrc: u32,
    /// Parsed VoIP Metrics block (block type 7), if present
    pub voip_metrics: Option<VoipMetricsBlock>,
}

/// VoIP Metrics report block as received from remote (RFC 3611 Section 4.7)
#[derive(Debug, Clone)]
pub struct VoipMetricsBlock {
    /// SSRC of the source being reported on
    pub source_ssrc: u32,
    /// The metrics data
    pub metrics: VoipMetrics,
}

/// Sender Report (PT=200)
#[derive(Debug, Clone)]
pub struct SenderReport {
    pub ssrc: u32,
    pub ntp_timestamp: NtpTimestamp,
    pub rtp_timestamp: u32,
    pub packet_count: u32,
    pub octet_count: u32,
    pub report_blocks: Vec<ReportBlock>,
}

/// Receiver Report (PT=201)
#[derive(Debug, Clone)]
pub struct ReceiverReport {
    pub ssrc: u32,
    pub report_blocks: Vec<ReportBlock>,
}

/// Source Description (PT=202)
#[derive(Debug, Clone)]
pub struct SourceDescription {
    pub chunks: Vec<SdesChunk>,
}

/// SDES chunk (one per SSRC)
#[derive(Debug, Clone)]
pub struct SdesChunk {
    pub ssrc: u32,
    pub cname: Option<String>,
}

/// Goodbye (PT=203)
#[derive(Debug, Clone)]
pub struct Goodbye {
    pub sources: Vec<u32>,
    pub reason: Option<String>,
}

// ============================================================================
// Parsing
// ============================================================================

/// Parse a compound RTCP packet (may contain multiple sub-packets)
pub fn parse_rtcp_compound(data: &[u8]) -> Vec<RtcpPacket> {
    let mut packets = Vec::new();
    let mut offset = 0;

    while offset + 4 <= data.len() {
        let version = (data[offset] >> 6) & 0x03;
        if version != 2 {
            break;
        }
        let has_padding = (data[offset] & 0x20) != 0;
        let rc = (data[offset] & 0x1F) as usize;
        let pt = data[offset + 1];
        let length_words = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        let packet_len = (length_words + 1) * 4; // length field is in 32-bit words minus 1

        if offset + packet_len > data.len() {
            break;
        }

        // P1-RTCP-2: Handle padding bit. RFC 3550 Section 6.4.1 says the padding
        // bit is only meaningful on the last sub-packet in a compound packet.
        // The last byte of the padded packet contains the pad count.
        let effective_end = if has_padding && packet_len >= 5 {
            let pad_count = data[offset + packet_len - 1] as usize;
            if pad_count > 0 && pad_count < packet_len - 4 {
                offset + packet_len - pad_count
            } else {
                offset + packet_len
            }
        } else {
            offset + packet_len
        };

        let payload = &data[offset..effective_end];

        match pt {
            PT_SR => {
                if let Some(sr) = parse_sender_report(payload, rc) {
                    packets.push(RtcpPacket::SenderReport(sr));
                }
            }
            PT_RR => {
                if let Some(rr) = parse_receiver_report(payload, rc) {
                    packets.push(RtcpPacket::ReceiverReport(rr));
                }
            }
            PT_SDES => {
                if let Some(sdes) = parse_sdes(payload, rc) {
                    packets.push(RtcpPacket::SourceDescription(sdes));
                }
            }
            PT_BYE => {
                if let Some(bye) = parse_bye(payload, rc) {
                    packets.push(RtcpPacket::Goodbye(bye));
                }
            }
            PT_XR => {
                if let Some(xr) = parse_xr(payload) {
                    packets.push(RtcpPacket::ExtendedReport(xr));
                }
            }
            _ => {
                packets.push(RtcpPacket::Unknown { packet_type: pt });
            }
        }

        offset += packet_len;
    }

    packets
}

fn parse_sender_report(data: &[u8], rc: usize) -> Option<SenderReport> {
    if data.len() < 28 {
        return None; // 4 header + 4 SSRC + 20 sender info
    }
    let ssrc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ntp_timestamp = NtpTimestamp::parse(&data[8..16]);
    let rtp_timestamp = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
    let packet_count = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
    let octet_count = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);

    let mut report_blocks = Vec::with_capacity(rc);
    for i in 0..rc {
        let rb_offset = 28 + i * ReportBlock::SIZE;
        if rb_offset + ReportBlock::SIZE > data.len() {
            break;
        }
        report_blocks.push(ReportBlock::parse(&data[rb_offset..]));
    }

    Some(SenderReport {
        ssrc,
        ntp_timestamp,
        rtp_timestamp,
        packet_count,
        octet_count,
        report_blocks,
    })
}

fn parse_receiver_report(data: &[u8], rc: usize) -> Option<ReceiverReport> {
    if data.len() < 8 {
        return None; // 4 header + 4 SSRC
    }
    let ssrc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    let mut report_blocks = Vec::with_capacity(rc);
    for i in 0..rc {
        let rb_offset = 8 + i * ReportBlock::SIZE;
        if rb_offset + ReportBlock::SIZE > data.len() {
            break;
        }
        report_blocks.push(ReportBlock::parse(&data[rb_offset..]));
    }

    Some(ReceiverReport {
        ssrc,
        report_blocks,
    })
}

fn parse_sdes(data: &[u8], sc: usize) -> Option<SourceDescription> {
    let mut chunks = Vec::with_capacity(sc);
    let mut offset = 4; // skip header

    for _ in 0..sc {
        if offset + 4 > data.len() {
            break;
        }
        let ssrc = u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        offset += 4;

        let mut cname = None;

        // Parse SDES items
        loop {
            if offset >= data.len() {
                break;
            }
            let item_type = data[offset];
            if item_type == 0 {
                // End of items — skip to next 32-bit boundary
                offset += 1;
                offset = (offset + 3) & !3;
                break;
            }
            if offset + 2 > data.len() {
                break;
            }
            let item_len = data[offset + 1] as usize;
            if offset + 2 + item_len > data.len() {
                break;
            }
            if item_type == SDES_CNAME {
                cname = String::from_utf8(data[offset + 2..offset + 2 + item_len].to_vec()).ok();
            }
            offset += 2 + item_len;
        }

        chunks.push(SdesChunk { ssrc, cname });
    }

    Some(SourceDescription { chunks })
}

fn parse_bye(data: &[u8], sc: usize) -> Option<Goodbye> {
    let mut sources = Vec::with_capacity(sc);
    let mut offset = 4; // skip header

    for _ in 0..sc {
        if offset + 4 > data.len() {
            break;
        }
        sources.push(u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]));
        offset += 4;
    }

    // Optional reason string
    // Bug #51: Changed from `offset + 1 < data.len()` to allow empty reason (length byte=0)
    let reason = if offset < data.len() {
        let reason_len = data[offset] as usize;
        if offset + 1 + reason_len <= data.len() {
            String::from_utf8(data[offset + 1..offset + 1 + reason_len].to_vec()).ok()
        } else {
            None
        }
    } else {
        None
    };

    Some(Goodbye { sources, reason })
}

/// Parse an RTCP XR packet (PT=207, RFC 3611)
///
/// Iterates over report blocks. Currently parses block type 7 (VoIP Metrics).
fn parse_xr(data: &[u8]) -> Option<ExtendedReport> {
    if data.len() < 8 {
        return None; // 4 header + 4 SSRC minimum
    }
    let ssrc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    let mut voip_metrics = None;
    let mut offset = 8;

    // Iterate over XR report blocks
    while offset + 4 <= data.len() {
        let block_type = data[offset];
        // data[offset+1] is type-specific
        let block_length_words = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        let block_data_len = block_length_words * 4; // block_length is in 32-bit words

        if offset + 4 + block_data_len > data.len() {
            break;
        }

        if block_type == VoipMetrics::BLOCK_TYPE {
            // VoIP Metrics block: 4-byte block header + 4 bytes source SSRC + 28 bytes metrics
            let body = &data[offset + 4..offset + 4 + block_data_len];
            if body.len() >= 32 {
                let source_ssrc = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                if let Some(metrics) = VoipMetrics::parse(&body[4..]) {
                    voip_metrics = Some(VoipMetricsBlock {
                        source_ssrc,
                        metrics,
                    });
                }
            }
        }

        offset += 4 + block_data_len;
    }

    Some(ExtendedReport { ssrc, voip_metrics })
}

// ============================================================================
// Building
// ============================================================================

/// Write RTCP common header (4 bytes)
fn write_header(buf: &mut [u8], version: u8, padding: bool, rc: u8, pt: u8, length_words: u16) {
    buf[0] = (version << 6)
        | if padding { 0x20 } else { 0 }
        | (rc & 0x1F);
    buf[1] = pt;
    buf[2..4].copy_from_slice(&length_words.to_be_bytes());
}

/// Build a Sender Report packet
///
/// Returns the number of bytes written. Buffer must be at least
/// `28 + report_blocks.len() * 24` bytes.
///
/// P2-RTCP-8: Private -- use `build_compound_sr` or `RtcpSession::build_rtcp` instead.
fn build_sender_report(
    buf: &mut [u8],
    ssrc: u32,
    ntp: NtpTimestamp,
    rtp_timestamp: u32,
    packet_count: u32,
    octet_count: u32,
    report_blocks: &[ReportBlock],
) -> usize {
    let rc = report_blocks.len().min(31) as u8;
    let length_words = (6 + rc as u16 * 6) as u16; // (28 + rc*24) / 4 - 1
    write_header(buf, 2, false, rc, PT_SR, length_words);
    buf[4..8].copy_from_slice(&ssrc.to_be_bytes());
    ntp.write_to(&mut buf[8..16]);
    buf[16..20].copy_from_slice(&rtp_timestamp.to_be_bytes());
    buf[20..24].copy_from_slice(&packet_count.to_be_bytes());
    buf[24..28].copy_from_slice(&octet_count.to_be_bytes());

    for (i, rb) in report_blocks.iter().take(31).enumerate() {
        rb.write_to(&mut buf[28 + i * 24..]);
    }

    28 + rc as usize * 24
}

/// Build a Receiver Report packet
///
/// P2-RTCP-8: Private -- use `build_compound_rr` or `RtcpSession::build_rtcp` instead.
fn build_receiver_report(
    buf: &mut [u8],
    ssrc: u32,
    report_blocks: &[ReportBlock],
) -> usize {
    let rc = report_blocks.len().min(31) as u8;
    let length_words = (1 + rc as u16 * 6) as u16; // (8 + rc*24) / 4 - 1
    write_header(buf, 2, false, rc, PT_RR, length_words);
    buf[4..8].copy_from_slice(&ssrc.to_be_bytes());

    for (i, rb) in report_blocks.iter().take(31).enumerate() {
        rb.write_to(&mut buf[8 + i * 24..]);
    }

    8 + rc as usize * 24
}

/// Build an SDES packet with CNAME
///
/// P2-RTCP-8: Private -- use `build_compound_sr`/`build_compound_rr` instead.
fn build_sdes_cname(buf: &mut [u8], ssrc: u32, cname: &str) -> usize {
    let cname_bytes = cname.as_bytes();
    let cname_len = cname_bytes.len().min(255);
    // Items: CNAME type (1) + length (1) + value (N) + null terminator (1)
    let items_len = 2 + cname_len + 1;
    // Pad to 32-bit boundary
    let padded_items_len = (items_len + 3) & !3;
    let total_len = 4 + 4 + padded_items_len; // header + SSRC + items
    let length_words = (total_len / 4 - 1) as u16;

    write_header(buf, 2, false, 1, PT_SDES, length_words); // SC=1
    buf[4..8].copy_from_slice(&ssrc.to_be_bytes());
    buf[8] = SDES_CNAME;
    buf[9] = cname_len as u8;
    buf[10..10 + cname_len].copy_from_slice(&cname_bytes[..cname_len]);
    // Zero-fill remaining (null terminator + padding)
    for b in buf[10 + cname_len..4 + 4 + padded_items_len].iter_mut() {
        *b = 0;
    }

    total_len
}

/// Build a BYE packet
///
/// P2-RTCP-8: Private -- use `RtcpSession::build_bye` instead.
fn build_bye(buf: &mut [u8], sources: &[u32], reason: Option<&str>) -> usize {
    let sc = sources.len().min(31) as u8;
    let sources_len = sc as usize * 4;
    let reason_len = reason.map_or(0, |r| {
        let len = r.len().min(255);
        // 1 byte length + string + pad to 32-bit boundary
        let raw = 1 + len;
        (raw + 3) & !3
    });
    let total_len = 4 + sources_len + reason_len;
    let length_words = (total_len / 4 - 1) as u16;

    write_header(buf, 2, false, sc, PT_BYE, length_words);

    for (i, &ssrc) in sources.iter().take(31).enumerate() {
        buf[4 + i * 4..8 + i * 4].copy_from_slice(&ssrc.to_be_bytes());
    }

    if let Some(reason_str) = reason {
        let offset = 4 + sources_len;
        let len = reason_str.len().min(255);
        buf[offset] = len as u8;
        buf[offset + 1..offset + 1 + len].copy_from_slice(&reason_str.as_bytes()[..len]);
        // Zero-pad
        for b in buf[offset + 1 + len..4 + sources_len + reason_len].iter_mut() {
            *b = 0;
        }
    }

    total_len
}

/// Build a compound RTCP packet (SR/RR + SDES, as required by RFC 3550)
///
/// Returns total bytes written into `buf`.
pub fn build_compound_sr(
    buf: &mut [u8],
    ssrc: u32,
    ntp: NtpTimestamp,
    rtp_timestamp: u32,
    packet_count: u32,
    octet_count: u32,
    report_blocks: &[ReportBlock],
    cname: &str,
) -> usize {
    let sr_len = build_sender_report(buf, ssrc, ntp, rtp_timestamp, packet_count, octet_count, report_blocks);
    let sdes_len = build_sdes_cname(&mut buf[sr_len..], ssrc, cname);
    sr_len + sdes_len
}

/// Build a compound RTCP packet (RR + SDES)
pub fn build_compound_rr(
    buf: &mut [u8],
    ssrc: u32,
    report_blocks: &[ReportBlock],
    cname: &str,
) -> usize {
    let rr_len = build_receiver_report(buf, ssrc, report_blocks);
    let sdes_len = build_sdes_cname(&mut buf[rr_len..], ssrc, cname);
    rr_len + sdes_len
}

// ============================================================================
// RTCP XR — Extended Reports (RFC 3611)
// ============================================================================

/// VoIP Metrics Report Block per RFC 3611 Section 4.7
///
/// Contains detailed quality metrics for voice-over-IP streams including
/// loss/discard rates, burst/gap statistics, delay metrics, signal/noise
/// levels, and R-factor/MOS scores.
#[derive(Debug, Clone, Default)]
pub struct VoipMetrics {
    /// Fraction of RTP packets lost (0-255, /256)
    pub loss_rate: u8,
    /// Fraction of RTP packets discarded (0-255, /256)
    pub discard_rate: u8,
    /// Fraction of RTP packets in burst periods (0-255, /256)
    pub burst_density: u8,
    /// Fraction of RTP packets in gap periods (0-255, /256)
    pub gap_density: u8,
    /// Mean burst duration in milliseconds
    pub burst_duration: u16,
    /// Mean gap duration in milliseconds
    pub gap_duration: u16,
    /// Round-trip delay in milliseconds
    pub round_trip_delay: u16,
    /// End system delay in milliseconds
    pub end_system_delay: u16,
    /// Voice signal level relative to 0 dBm (dBm)
    pub signal_level: u8,
    /// Noise level relative to 0 dBm (dBm)
    pub noise_level: u8,
    /// Residual Echo Return Loss Enhancement (dB)
    pub rerl: u8,
    /// Gap threshold (number of lost/discarded frames to enter burst)
    pub gmin: u8,
    /// R-factor (ITU-T G.107, 0-127, 127=unknown)
    pub r_factor: u8,
    /// External R-factor (0-127, 127=unknown)
    pub ext_r_factor: u8,
    /// MOS listening quality (10-50 scaled by 10, 127=unknown)
    pub mos_lq: u8,
    /// MOS conversational quality (10-50 scaled by 10, 127=unknown)
    pub mos_cq: u8,
    /// Receiver configuration byte
    pub rx_config: u8,
    /// Nominal jitter buffer delay in milliseconds
    pub jb_nominal: u16,
    /// Maximum jitter buffer delay in milliseconds
    pub jb_maximum: u16,
    /// Absolute maximum jitter buffer delay in milliseconds
    pub jb_abs_max: u16,
}

impl VoipMetrics {
    /// Block type for VoIP Metrics (RFC 3611 Section 4.7)
    pub const BLOCK_TYPE: u8 = 7;

    /// Size of the VoIP Metrics block (excluding block header)
    /// Bug #16: VoIP Metrics body is 28 bytes, not 32.
    pub const BLOCK_SIZE: usize = 28;

    /// Write the VoIP Metrics block body (28 bytes) to a buffer.
    /// Bug #16: Removed spurious 4-byte zero padding that caused overflow
    /// when called with a correctly-sized 28-byte slice.
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0] = self.loss_rate;
        buf[1] = self.discard_rate;
        buf[2] = self.burst_density;
        buf[3] = self.gap_density;
        buf[4..6].copy_from_slice(&self.burst_duration.to_be_bytes());
        buf[6..8].copy_from_slice(&self.gap_duration.to_be_bytes());
        buf[8..10].copy_from_slice(&self.round_trip_delay.to_be_bytes());
        buf[10..12].copy_from_slice(&self.end_system_delay.to_be_bytes());
        buf[12] = self.signal_level;
        buf[13] = self.noise_level;
        buf[14] = self.rerl;
        buf[15] = self.gmin;
        buf[16] = self.r_factor;
        buf[17] = self.ext_r_factor;
        buf[18] = self.mos_lq;
        buf[19] = self.mos_cq;
        buf[20] = self.rx_config;
        buf[21] = 0; // reserved
        buf[22..24].copy_from_slice(&self.jb_nominal.to_be_bytes());
        buf[24..26].copy_from_slice(&self.jb_maximum.to_be_bytes());
        buf[26..28].copy_from_slice(&self.jb_abs_max.to_be_bytes());
    }

    /// Parse a VoIP Metrics block body (28 bytes).
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 28 {
            return None;
        }
        Some(Self {
            loss_rate: buf[0],
            discard_rate: buf[1],
            burst_density: buf[2],
            gap_density: buf[3],
            burst_duration: u16::from_be_bytes([buf[4], buf[5]]),
            gap_duration: u16::from_be_bytes([buf[6], buf[7]]),
            round_trip_delay: u16::from_be_bytes([buf[8], buf[9]]),
            end_system_delay: u16::from_be_bytes([buf[10], buf[11]]),
            signal_level: buf[12],
            noise_level: buf[13],
            rerl: buf[14],
            gmin: buf[15],
            r_factor: buf[16],
            ext_r_factor: buf[17],
            mos_lq: buf[18],
            mos_cq: buf[19],
            rx_config: buf[20],
            jb_nominal: u16::from_be_bytes([buf[22], buf[23]]),
            jb_maximum: u16::from_be_bytes([buf[24], buf[25]]),
            jb_abs_max: if buf.len() >= 28 {
                u16::from_be_bytes([buf[26], buf[27]])
            } else {
                0
            },
        })
    }
}

/// Build an RTCP XR packet with a VoIP Metrics report block (RFC 3611).
///
/// Returns the number of bytes written. Buffer must be at least
/// `8 + 4 + 4 + 28 = 44` bytes (header + SSRC + block header + block body).
/// Bug #16: VoIP Metrics body is 28 bytes, not 32.
///
/// P2-RTCP-8: Private -- use `RtcpSession::build_rtcp` which appends XR automatically.
fn build_xr_voip_metrics(
    buf: &mut [u8],
    ssrc: u32,
    remote_ssrc: u32,
    metrics: &VoipMetrics,
) -> usize {
    // XR packet:
    // - 4 bytes common header (V=2, PT=207)
    // - 4 bytes SSRC of packet sender
    // - 4 bytes block header (BT=7, type-specific=0, block_length=7)
    // - 4 bytes SSRC of source being reported
    // - 28 bytes VoIP Metrics data
    // Total = 44 bytes = 11 32-bit words, length field = 10
    let total_len = 44;
    let length_words = (total_len / 4 - 1) as u16;

    write_header(buf, 2, false, 0, PT_XR, length_words);
    buf[4..8].copy_from_slice(&ssrc.to_be_bytes());

    // Block header: BT=7, type-specific=0, block_length=8
    // Bug #R11-5: RFC 3611 §3 defines block_length as "including the header, in
    // 32-bit words minus one". Total = 36 bytes (4 header + 4 SSRC + 28 metrics)
    // = 9 words, so block_length = 9 - 1 = 8. Was incorrectly 7 (body only).
    buf[8] = VoipMetrics::BLOCK_TYPE;
    buf[9] = 0; // type-specific
    buf[10..12].copy_from_slice(&8u16.to_be_bytes()); // block_length in 32-bit words

    // SSRC of source
    buf[12..16].copy_from_slice(&remote_ssrc.to_be_bytes());

    // Bug #16: Fixed slice to [16..44] (28 bytes) instead of [16..48] (32 bytes)
    metrics.write_to(&mut buf[16..44]);

    total_len
}

// ============================================================================
// RTCP Session — stateful tracker for a single RTP stream
// ============================================================================

/// RTCP statistics for a single RTP stream
///
/// Tracks send/receive statistics and generates SR/RR packets.
/// Follows RFC 3550 Section 6 for timing and Section A.3 for loss calculation.
pub struct RtcpSession {
    /// Our SSRC
    pub local_ssrc: u32,
    /// CNAME for SDES
    pub cname: String,

    // --- Sender state ---
    /// Total RTP packets sent
    pub packets_sent: u32,
    /// Total RTP payload bytes sent
    pub octets_sent: u32,
    /// Last RTP timestamp sent
    pub last_rtp_timestamp: u32,

    // --- Receiver state (per remote SSRC) ---
    /// Remote SSRC we're tracking
    pub remote_ssrc: Option<u32>,
    /// Total RTP packets received from remote
    pub packets_received: u32,
    /// Expected packets (based on sequence numbers)
    pub expected_packets: u32,
    /// Highest extended sequence number received
    pub highest_ext_seq: u32,
    /// Sequence number cycles (wraparound counter)
    pub seq_cycles: u32,
    /// Highest sequence number received (16-bit)
    pub highest_seq: u16,
    /// Whether we've received our first packet
    pub first_packet_received: bool,
    /// Base sequence number (first packet) -- stored as u32 to avoid truncation
    /// when computing expected_packets across multiple wraparounds (P2-RTCP-2).
    pub base_seq: u32,

    // --- Jitter calculation (RFC 3550 A.8) ---
    /// Inter-arrival jitter estimate (in timestamp units)
    pub jitter: f64,
    /// Last packet's RTP timestamp
    pub last_recv_rtp_ts: u32,
    /// Last packet's arrival time
    pub last_recv_time: Option<Instant>,

    // --- Loss calculation ---
    /// Packets received at last RR
    pub last_rr_packets_received: u32,
    /// Expected packets at last RR
    pub last_rr_expected_packets: u32,

    // --- RTT calculation ---
    /// Last SR NTP timestamp received from remote (compact form)
    pub last_sr_ntp_compact: u32,
    /// When we received the last SR
    pub last_sr_received_at: Option<Instant>,
    /// Calculated round-trip time
    pub rtt: Option<Duration>,
    /// P1-RTCP-4: Monotonic instant when we last sent our own SR.
    /// Used instead of NTP wall clock for local DLSR to avoid clock-jump issues.
    pub last_sr_sent_at: Option<Instant>,

    // --- Clock rate (for jitter calculation) ---
    /// RTP clock rate in Hz (e.g. 8000, 16000, 48000). Defaults to 8000.
    pub clock_rate: u32,

    // --- Jitter buffer config (P1-RTCP-5) ---
    /// Nominal jitter buffer delay in milliseconds (for XR reports).
    /// Defaults to 0 (unknown) if not configured.
    pub jb_nominal_ms: u16,
    /// Maximum jitter buffer delay in milliseconds (for XR reports).
    /// Defaults to 0 (unknown) if not configured.
    pub jb_maximum_ms: u16,

    // --- Remote VoIP Metrics (P1-RTCP-6) ---
    /// Most recently received VoIP Metrics from remote via RTCP XR
    pub remote_voip_metrics: Option<VoipMetricsBlock>,

    // --- RTCP timing ---
    /// RTCP send interval (default 5s, randomized per RFC 3550 Section 6.2).
    ///
    /// P2-RTCP-1: The interval now factors in bandwidth fraction and participant
    /// count per RFC 3550 Section 6.2. The base interval is computed as:
    ///   interval = avg_rtcp_size / (rtcp_bw * rtcp_bandwidth_fraction)
    /// where rtcp_bw = session_bw * rtcp_bandwidth_fraction / num_participants.
    /// This ensures RTCP does not exceed its share of session bandwidth.
    pub rtcp_interval: Duration,
    /// Last time we sent RTCP
    pub last_rtcp_sent: Instant,
    /// P2-RTCP-1: Fraction of session bandwidth allocated to RTCP (default 0.05 = 5%)
    pub rtcp_bandwidth_fraction: f64,
    /// P2-RTCP-1: Number of participants in the session (default 2 for point-to-point)
    pub num_participants: u32,

    // --- P2-RTCP-3: Burst-aware loss tracking ---
    /// Sliding window of received/lost indicators for the last 256 packets.
    /// true = received, false = lost. Index 0 is the most recent.
    pub loss_window: [bool; 256],
    /// Number of valid entries in loss_window
    pub loss_window_len: usize,
    /// P2-RTCP-3: Burst density (fraction of lost packets within loss bursts, 0-256 scale)
    pub burst_density: u8,
    /// P2-RTCP-3: Gap density (fraction of lost packets within gaps between bursts, 0-256 scale)
    pub gap_density: u8,
}

impl RtcpSession {
    /// Create a new RTCP session with default clock rate (8000 Hz).
    pub fn new(local_ssrc: u32, cname: String) -> Self {
        Self::with_clock_rate(local_ssrc, cname, 8000)
    }

    /// Create a new RTCP session with a specific clock rate.
    pub fn with_clock_rate(local_ssrc: u32, cname: String, clock_rate: u32) -> Self {
        let interval = Self::randomized_interval(Duration::from_secs(5));
        Self {
            local_ssrc,
            cname,
            packets_sent: 0,
            octets_sent: 0,
            last_rtp_timestamp: 0,
            remote_ssrc: None,
            packets_received: 0,
            expected_packets: 0,
            highest_ext_seq: 0,
            seq_cycles: 0,
            highest_seq: 0,
            first_packet_received: false,
            base_seq: 0,
            jitter: 0.0,
            last_recv_rtp_ts: 0,
            last_recv_time: None,
            last_rr_packets_received: 0,
            last_rr_expected_packets: 0,
            last_sr_ntp_compact: 0,
            last_sr_received_at: None,
            rtt: None,
            last_sr_sent_at: None,
            clock_rate,
            jb_nominal_ms: 0,
            jb_maximum_ms: 0,
            remote_voip_metrics: None,
            rtcp_interval: interval,
            // P2-RTCP-7: Initialize last_rtcp_sent to now minus half-interval
            // so the first RTCP is sent sooner (within half the normal interval).
            last_rtcp_sent: Instant::now() - interval / 2,
            rtcp_bandwidth_fraction: 0.05,
            num_participants: 2,
            loss_window: [true; 256],
            loss_window_len: 0,
            burst_density: 0,
            gap_density: 0,
        }
    }

    /// Randomize RTCP interval per RFC 3550 Section 6.2 (0.5x to 1.5x)
    ///
    /// Bug #108: Note that `rand::random::<f64>()` produces values in the
    /// half-open range [0.0, 1.0), so the resulting factor is in [0.5, 1.5)
    /// rather than the RFC's closed range [0.5, 1.5]. The difference is
    /// negligible in practice since 1.5 is never exactly produced by any
    /// finite-precision RNG, and the timer variance is purely cosmetic.
    fn randomized_interval(base: Duration) -> Duration {
        let factor = 0.5 + rand::random::<f64>();
        Duration::from_secs_f64(base.as_secs_f64() * factor)
    }

    /// P2-RTCP-1: Compute RTCP interval based on bandwidth and participant count.
    ///
    /// Per RFC 3550 Section 6.2, the interval is:
    ///   Td = max(Tmin, n * avg_size / rtcp_bw)
    /// where n = num_participants, rtcp_bw = session_bw * bw_fraction.
    /// We use a fixed avg_size of 100 bytes (typical compound SR+SDES).
    pub fn compute_bandwidth_interval(&self) -> Duration {
        let avg_rtcp_size: f64 = 100.0; // bytes
        // Session bandwidth: approximate from clock rate (G.711 = 64kbps for 8kHz)
        let session_bw_bps = (self.clock_rate as f64) * 8.0; // rough approximation
        let rtcp_bw = session_bw_bps * self.rtcp_bandwidth_fraction;

        if rtcp_bw <= 0.0 {
            return Duration::from_secs(5);
        }

        let n = self.num_participants.max(1) as f64;
        let td_secs = (n * avg_rtcp_size * 8.0) / rtcp_bw;
        // RFC 3550: minimum interval is 5 seconds (unless reduced-size RTCP)
        let td_secs = td_secs.max(5.0);

        Self::randomized_interval(Duration::from_secs_f64(td_secs))
    }

    /// P2-RTCP-1: Set the RTCP bandwidth fraction (default 0.05 = 5%)
    pub fn set_rtcp_bandwidth_fraction(&mut self, fraction: f64) {
        self.rtcp_bandwidth_fraction = fraction.clamp(0.001, 0.25);
        self.rtcp_interval = self.compute_bandwidth_interval();
    }

    /// P2-RTCP-1: Set the number of participants (default 2)
    pub fn set_num_participants(&mut self, n: u32) {
        self.num_participants = n.max(1);
        self.rtcp_interval = self.compute_bandwidth_interval();
    }

    /// P2-RTCP-3: Record a packet reception status in the sliding window.
    /// `received` = true if the packet was received, false if lost.
    pub fn record_loss_event(&mut self, received: bool) {
        // Shift window: move everything right by 1
        for i in (1..256).rev() {
            self.loss_window[i] = self.loss_window[i - 1];
        }
        self.loss_window[0] = received;
        if self.loss_window_len < 256 {
            self.loss_window_len += 1;
        }

        // Recompute burst and gap density
        self.compute_burst_gap_density();
    }

    /// P2-RTCP-3: Compute burst_density and gap_density from the loss window.
    ///
    /// A "burst" is a contiguous region containing at least one lost packet
    /// where no more than 1 received packet separates lost ones.
    /// A "gap" is a contiguous region of mostly received packets.
    fn compute_burst_gap_density(&mut self) {
        if self.loss_window_len < 2 {
            self.burst_density = 0;
            self.gap_density = 0;
            return;
        }

        let len = self.loss_window_len;
        let mut burst_lost = 0u32;
        let mut burst_total = 0u32;
        let mut gap_lost = 0u32;
        let mut gap_total = 0u32;
        let mut in_burst = false;

        for i in 0..len {
            let received = self.loss_window[i];
            if !received {
                // Lost packet
                if !in_burst {
                    in_burst = true;
                }
                burst_lost += 1;
                burst_total += 1;
            } else {
                // Received packet
                if in_burst {
                    // Check if burst continues (next packet also lost?)
                    let next_lost = if i + 1 < len { !self.loss_window[i + 1] } else { false };
                    if next_lost {
                        // Still in burst (isolated received between lost)
                        burst_total += 1;
                    } else {
                        // Burst ended
                        in_burst = false;
                        gap_total += 1;
                    }
                } else {
                    gap_total += 1;
                }
            }
        }

        // Density = fraction * 256 (RFC 3611 scale)
        self.burst_density = if burst_total > 0 {
            ((burst_lost as u64 * 256) / burst_total as u64).min(255) as u8
        } else {
            0
        };
        self.gap_density = if gap_total > 0 {
            ((gap_lost as u64 * 256) / gap_total as u64).min(255) as u8
        } else {
            0
        };
    }

    /// Record that we sent an RTP packet
    pub fn record_rtp_sent(&mut self, payload_bytes: u32, rtp_timestamp: u32) {
        self.packets_sent += 1;
        self.octets_sent += payload_bytes;
        self.last_rtp_timestamp = rtp_timestamp;
    }

    /// Record that we received an RTP packet (updates jitter, loss tracking)
    pub fn record_rtp_received(&mut self, ssrc: u32, seq: u16, rtp_timestamp: u32) {
        let now = Instant::now();

        // Track remote SSRC
        if self.remote_ssrc.is_none() || self.remote_ssrc == Some(ssrc) {
            self.remote_ssrc = Some(ssrc);
        } else {
            // SSRC changed — reset receiver state
            self.reset_receiver(ssrc);
        }

        self.packets_received += 1;

        // Sequence number tracking with wraparound (RFC 3550 Appendix A.1)
        if !self.first_packet_received {
            self.base_seq = seq as u32;
            self.highest_seq = seq;
            self.seq_cycles = 0;
            self.first_packet_received = true;
        } else {
            // P1-RTCP-1: Three-branch validation per RFC 3550 Appendix A.1
            let udelta = seq.wrapping_sub(self.highest_seq);
            if udelta < MAX_DROPOUT {
                // In order or small forward jump (normal case)
                if seq < self.highest_seq {
                    // Wraparound
                    self.seq_cycles += 1;
                }
                self.highest_seq = seq;
            } else if udelta <= 0xFFFFu16.wrapping_sub(MAX_MISORDER) {
                // Large jump forward -- the sequence has jumped too far.
                // Could be a new source or severely disrupted stream.
                // Reset statistics with this packet as the new base.
                self.base_seq = seq as u32;
                self.highest_seq = seq;
                self.seq_cycles = 0;
                self.packets_received = 1;
                self.last_rr_packets_received = 0;
                self.last_rr_expected_packets = 0;
            }
            // else: udelta > 0xFFFF - MAX_MISORDER, i.e. small negative offset
            // -- this is a reordered/duplicate packet, ignore for seq tracking
        }

        self.highest_ext_seq = ((self.seq_cycles as u32) << 16) | (self.highest_seq as u32);
        self.expected_packets = self.highest_ext_seq.saturating_sub(self.base_seq) + 1;

        // Jitter calculation (RFC 3550 Appendix A.8)
        if let Some(last_time) = self.last_recv_time {
            let arrival_diff_us = now.duration_since(last_time).as_micros() as i64;
            // Convert to timestamp units using the actual clock rate
            let arrival_diff_ts = (arrival_diff_us * self.clock_rate as i64) / 1_000_000;
            // Bug #17: Cast via i32 first to get correct sign extension.
            // wrapping_sub on u32 returns u32; `as i64` zero-extends, which is
            // wrong for negative differences. `as i32 as i64` sign-extends.
            let rtp_diff_ts = rtp_timestamp.wrapping_sub(self.last_recv_rtp_ts) as i32 as i64;
            let d = (arrival_diff_ts - rtp_diff_ts).abs() as f64;
            self.jitter += (d - self.jitter) / 16.0;
        }

        self.last_recv_rtp_ts = rtp_timestamp;
        self.last_recv_time = Some(now);
    }

    /// Process an incoming RTCP packet (extract RTT from SR, etc.)
    ///
    /// Returns true if an SSRC collision was detected (P2-RTCP-5).
    pub fn process_incoming_rtcp(&mut self, data: &[u8]) -> bool {
        let mut collision = false;
        for packet in parse_rtcp_compound(data) {
            match packet {
                RtcpPacket::SenderReport(sr) => {
                    // P2-RTCP-5: SSRC collision detection -- if we see our own SSRC
                    // from a different source, flag a collision.
                    if sr.ssrc == self.local_ssrc {
                        collision = true;
                    }

                    // Store LSR for RTT calculation in our next RR
                    self.last_sr_ntp_compact = sr.ntp_timestamp.compact();
                    self.last_sr_received_at = Some(Instant::now());

                    // Extract RTT from report blocks targeting our SSRC
                    for rb in &sr.report_blocks {
                        if rb.ssrc == self.local_ssrc && rb.last_sr != 0 {
                            self.calculate_rtt(rb);
                        }
                    }
                }
                RtcpPacket::ReceiverReport(rr) => {
                    // P2-RTCP-5: SSRC collision detection
                    if rr.ssrc == self.local_ssrc {
                        collision = true;
                    }

                    for rb in &rr.report_blocks {
                        if rb.ssrc == self.local_ssrc && rb.last_sr != 0 {
                            self.calculate_rtt(rb);
                        }
                    }
                }
                RtcpPacket::ExtendedReport(xr) => {
                    // P1-RTCP-6: Store remote's VoIP metrics
                    if let Some(vm) = xr.voip_metrics {
                        self.remote_voip_metrics = Some(vm);
                    }
                }
                _ => {}
            }
        }
        collision
    }

    /// Calculate RTT from a report block
    ///
    /// P1-RTCP-4: Uses monotonic Instant when available to avoid clock-jump
    /// vulnerabilities. Falls back to NTP wall clock if no monotonic record.
    ///
    /// RTT = now_compact - LSR - DLSR  (standard NTP-based)
    /// Or: RTT = monotonic_elapsed - DLSR_duration  (monotonic-based)
    fn calculate_rtt(&mut self, rb: &ReportBlock) {
        let rtt_duration = if let Some(sent_at) = self.last_sr_sent_at {
            // P1-RTCP-4: Monotonic path -- immune to wall-clock jumps.
            // The report block's LSR should match our last sent SR's compact NTP.
            // DLSR is in 1/65536 sec units.
            let elapsed = sent_at.elapsed();
            let dlsr_us = (rb.delay_since_last_sr as u64 * 1_000_000) >> 16;
            let dlsr = Duration::from_micros(dlsr_us);
            elapsed.checked_sub(dlsr)
        } else {
            // Fallback: NTP wall-clock based RTT
            let now_compact = NtpTimestamp::now().compact();
            let rtt_compact = now_compact.wrapping_sub(rb.last_sr).wrapping_sub(rb.delay_since_last_sr);
            let rtt_us = (rtt_compact as u64 * 1_000_000) >> 16;
            Some(Duration::from_micros(rtt_us))
        };

        if let Some(rtt) = rtt_duration {
            if rtt.as_micros() < 30_000_000 {
                // Sanity check: RTT < 30 seconds
                // Exponential moving average: 0.7 * old + 0.3 * new
                self.rtt = Some(match self.rtt {
                    Some(old) => Duration::from_secs_f64(old.as_secs_f64() * 0.7 + rtt.as_secs_f64() * 0.3),
                    None => rtt,
                });
            }
        }
    }

    /// Check if it's time to send RTCP
    pub fn should_send_rtcp(&self) -> bool {
        self.last_rtcp_sent.elapsed() >= self.rtcp_interval
    }

    /// Build a compound RTCP packet (SR/RR + SDES + XR)
    ///
    /// Returns bytes written. Buffer should be at least 512 bytes.
    /// Includes RTCP XR VoIP Metrics report block (RFC 3611) after
    /// the mandatory SR/RR + SDES compound.
    pub fn build_rtcp(&mut self, buf: &mut [u8]) -> usize {
        let mut len = if self.packets_sent > 0 {
            // We're a sender -- build SR + SDES
            let ntp = NtpTimestamp::now();
            let report_blocks = self.build_report_blocks();
            // P1-RTCP-4: Record monotonic instant alongside the NTP timestamp
            self.last_sr_sent_at = Some(Instant::now());
            build_compound_sr(
                buf,
                self.local_ssrc,
                ntp,
                self.last_rtp_timestamp,
                self.packets_sent,
                self.octets_sent,
                &report_blocks,
                &self.cname,
            )
        } else {
            // Receiver only — build RR + SDES
            let report_blocks = self.build_report_blocks();
            build_compound_rr(buf, self.local_ssrc, &report_blocks, &self.cname)
        };

        // Append RTCP XR with VoIP Metrics (RFC 3611) if we have a remote SSRC
        if self.remote_ssrc.is_some() && len + 48 <= buf.len() {
            let xr_len = self.build_xr(&mut buf[len..]);
            len += xr_len;
        }

        self.last_rtcp_sent = Instant::now();
        // R17: Use compute_bandwidth_interval() instead of hardcoded 5s base.
        // This respects the configured bandwidth fraction and participant count.
        self.rtcp_interval = self.compute_bandwidth_interval();

        // Save current counters for next loss calculation
        self.last_rr_packets_received = self.packets_received;
        self.last_rr_expected_packets = self.expected_packets;

        len
    }

    /// Build a BYE packet
    pub fn build_bye(&self, buf: &mut [u8], reason: Option<&str>) -> usize {
        build_bye(buf, &[self.local_ssrc], reason)
    }

    /// Build an RTCP XR packet with VoIP Metrics (RFC 3611).
    ///
    /// Returns the number of bytes written. Buffer must be at least 48 bytes.
    /// Populates metrics from current session state (loss, jitter, RTT, R-factor, MOS).
    ///
    /// P2-RTCP-8: Private -- called automatically from `build_rtcp`.
    fn build_xr(&self, buf: &mut [u8]) -> usize {
        let remote_ssrc = match self.remote_ssrc {
            Some(s) => s,
            None => return 0,
        };

        let loss = self.loss_percent();
        let r = self.r_factor();
        let mos = self.mos();

        let rtt_ms = self.rtt.map(|d| d.as_millis() as u16).unwrap_or(0);

        // Scale MOS from 1.0-4.5 to 10-50 (x10), or 127 if unavailable
        let mos_scaled = if mos >= 1.0 && mos <= 4.5 {
            (mos * 10.0).round() as u8
        } else {
            127
        };

        // Scale R-factor to 0-127 range, 127=unknown
        let r_scaled = if r >= 0.0 && r <= 100.0 {
            r.round() as u8
        } else {
            127
        };

        // Loss rate: fraction of packets lost (0-255, /256)
        let loss_rate = ((loss / 100.0) * 256.0).round().clamp(0.0, 255.0) as u8;

        let metrics = VoipMetrics {
            loss_rate,
            discard_rate: 0,
            burst_density: 0,
            gap_density: 0,
            burst_duration: 0,
            gap_duration: 0,
            round_trip_delay: rtt_ms,
            // P1-RTCP-5: end_system_delay should reflect jitter buffer config,
            // not network jitter. Use jb_nominal_ms as best approximation.
            end_system_delay: self.jb_nominal_ms,
            signal_level: 127, // unknown
            noise_level: 127,  // unknown
            rerl: 127,         // unknown
            gmin: 16,          // default gap threshold
            r_factor: r_scaled,
            ext_r_factor: 127,
            mos_lq: mos_scaled,
            mos_cq: mos_scaled,
            rx_config: 0,
            // P1-RTCP-5: jb_nominal and jb_maximum should come from actual
            // jitter buffer configuration, not network jitter estimate.
            jb_nominal: self.jb_nominal_ms,
            jb_maximum: self.jb_maximum_ms,
            jb_abs_max: if self.jb_maximum_ms > 0 { self.jb_maximum_ms } else { 1000 },
        };

        build_xr_voip_metrics(buf, self.local_ssrc, remote_ssrc, &metrics)
    }

    /// Build report blocks for the remote SSRC
    fn build_report_blocks(&self) -> Vec<ReportBlock> {
        let remote_ssrc = match self.remote_ssrc {
            Some(s) => s,
            None => return vec![],
        };

        // Loss calculation (RFC 3550 Appendix A.3)
        let expected = self.expected_packets;
        let received = self.packets_received;
        let cumulative_lost = (expected as i32 - received as i32).max(-0x7F_FFFF).min(0x7F_FFFF);

        let expected_interval = expected.saturating_sub(self.last_rr_expected_packets);
        let received_interval = received.saturating_sub(self.last_rr_packets_received);
        let lost_interval = expected_interval as i32 - received_interval as i32;
        let fraction_lost = if expected_interval == 0 || lost_interval <= 0 {
            0u8
        } else {
            // Bug #10: Use u64 intermediate to prevent u32 overflow on lost * 256
            ((lost_interval as u64 * 256) / expected_interval as u64).min(255) as u8
        };

        // DLSR calculation
        let delay_since_last_sr = match self.last_sr_received_at {
            Some(t) => {
                let elapsed = t.elapsed();
                // Convert to 1/65536 seconds
                // Bug #9: Clamp fractional part to 65535 to prevent overflow
                ((elapsed.as_secs().min(65535) as u64) << 16 | ((elapsed.subsec_micros() as u64 * 65536) / 1_000_000).min(65535)) as u32
            }
            None => 0,
        };

        vec![ReportBlock {
            ssrc: remote_ssrc,
            fraction_lost,
            cumulative_lost,
            extended_highest_seq: self.highest_ext_seq,
            jitter: self.jitter as u32,
            last_sr: self.last_sr_ntp_compact,
            delay_since_last_sr,
        }]
    }

    /// Reset receiver state (on SSRC change)
    pub fn reset_receiver(&mut self, new_ssrc: u32) {
        self.remote_ssrc = Some(new_ssrc);
        self.packets_received = 0;
        self.expected_packets = 0;
        self.highest_ext_seq = 0;
        self.seq_cycles = 0;
        self.highest_seq = 0;
        self.first_packet_received = false;
        self.base_seq = 0;
        self.jitter = 0.0;
        self.last_recv_rtp_ts = 0;
        self.last_recv_time = None;
        self.last_rr_packets_received = 0;
        self.last_rr_expected_packets = 0;
        self.last_sr_ntp_compact = 0;
        self.last_sr_received_at = None;
        self.rtt = None;
    }

    /// Get current RTT estimate
    pub fn rtt(&self) -> Option<Duration> {
        self.rtt
    }

    /// Get current jitter in milliseconds
    pub fn jitter_ms(&self) -> f64 {
        self.jitter / (self.clock_rate as f64 / 1000.0)
    }

    /// Get packet loss percentage
    pub fn loss_percent(&self) -> f64 {
        if self.expected_packets == 0 {
            return 0.0;
        }
        let lost = self.expected_packets as f64 - self.packets_received as f64;
        (lost / self.expected_packets as f64 * 100.0).max(0.0)
    }

    /// Calculate R-factor per ITU-T G.107 (simplified E-model)
    ///
    /// R = 93.2 - Id - Ie_eff - If
    /// Where:
    ///   Id = delay impairment (based on one-way delay)
    ///   Ie_eff = equipment impairment (codec-dependent + packet loss)
    ///   If = simultaneous impairment factor (default 0 for G.711)
    pub fn r_factor(&self) -> f64 {
        let loss = self.loss_percent();
        let jitter_ms = self.jitter_ms();
        let rtt_ms = self.rtt.map(|r| r.as_secs_f64() * 1000.0).unwrap_or(0.0);

        // One-way delay estimate: RTT/2 + jitter buffer delay estimate
        let one_way_delay = rtt_ms / 2.0 + jitter_ms;

        // Delay impairment (Id) — simplified from ITU-T G.107 Section 7.4
        // Id increases rapidly above 150ms
        let id = if one_way_delay < 100.0 {
            0.0
        } else {
            0.024 * one_way_delay + 0.11 * (one_way_delay - 177.3).max(0.0)
        };

        // Equipment impairment (Ie_eff) — for G.711 (Ie=0)
        // Packet loss impairment: Ie_eff = Ie + (95 - Ie) * loss / (loss + Bpl)
        // For G.711: Ie=0, Bpl=25.1 (burst ratio = 1)
        let ie = 0.0_f64; // G.711 equipment impairment
        let bpl = 25.1_f64; // Packet loss robustness factor for G.711
        let ie_eff = ie + (95.0 - ie) * loss / (loss + bpl);

        // R = 93.2 - Id - Ie_eff
        let r = (93.2 - id - ie_eff).clamp(0.0, 100.0);
        r
    }

    /// Calculate MOS (Mean Opinion Score) from R-factor per ITU-T G.107
    ///
    /// MOS = 1 + 0.035*R + R*(R-60)*(100-R)*7e-6
    /// Range: 1.0 (bad) to 4.5 (excellent)
    pub fn mos(&self) -> f64 {
        let r = self.r_factor();
        if r <= 0.0 {
            return 1.0;
        }
        if r > 100.0 {
            return 4.5;
        }
        // Bug #52: Clamp to [1.0, 4.5] — cubic can slightly exceed 4.5 near R≈93
        (1.0 + 0.035 * r + r * (r - 60.0) * (100.0 - r) * 7.0e-6).clamp(1.0, 4.5)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntp_timestamp_compact() {
        let ntp = NtpTimestamp {
            seconds: 0x12345678,
            fraction: 0xABCDEF00,
        };
        // Compact = (seconds & 0xFFFF) << 16 | (fraction >> 16)
        assert_eq!(ntp.compact(), 0x5678ABCD);
    }

    #[test]
    fn test_ntp_timestamp_roundtrip() {
        let ntp = NtpTimestamp { seconds: 12345, fraction: 67890 };
        let mut buf = [0u8; 8];
        ntp.write_to(&mut buf);
        let parsed = NtpTimestamp::parse(&buf);
        assert_eq!(parsed.seconds, ntp.seconds);
        assert_eq!(parsed.fraction, ntp.fraction);
    }

    #[test]
    fn test_report_block_roundtrip() {
        let rb = ReportBlock {
            ssrc: 0x12345678,
            fraction_lost: 25,
            cumulative_lost: 100,
            extended_highest_seq: 50000,
            jitter: 320,
            last_sr: 0xAABBCCDD,
            delay_since_last_sr: 65536, // 1 second
        };
        let mut buf = [0u8; 24];
        rb.write_to(&mut buf);
        let parsed = ReportBlock::parse(&buf);

        assert_eq!(parsed.ssrc, rb.ssrc);
        assert_eq!(parsed.fraction_lost, rb.fraction_lost);
        assert_eq!(parsed.cumulative_lost, rb.cumulative_lost);
        assert_eq!(parsed.extended_highest_seq, rb.extended_highest_seq);
        assert_eq!(parsed.jitter, rb.jitter);
        assert_eq!(parsed.last_sr, rb.last_sr);
        assert_eq!(parsed.delay_since_last_sr, rb.delay_since_last_sr);
    }

    #[test]
    fn test_report_block_negative_loss() {
        let rb = ReportBlock {
            cumulative_lost: -5, // More received than expected (duplicates)
            ..Default::default()
        };
        let mut buf = [0u8; 24];
        rb.write_to(&mut buf);
        let parsed = ReportBlock::parse(&buf);
        assert_eq!(parsed.cumulative_lost, -5);
    }

    #[test]
    fn test_build_parse_sender_report() {
        let mut buf = [0u8; 256];
        let ntp = NtpTimestamp { seconds: 100, fraction: 200 };
        let rb = ReportBlock {
            ssrc: 0xAABBCCDD,
            fraction_lost: 10,
            cumulative_lost: 5,
            extended_highest_seq: 1000,
            jitter: 160,
            last_sr: 0x11223344,
            delay_since_last_sr: 32768,
        };
        let len = build_sender_report(&mut buf, 0x12345678, ntp, 16000, 100, 16000, &[rb]);

        assert_eq!(len, 28 + 24); // header + sender info + 1 report block

        let packets = parse_rtcp_compound(&buf[..len]);
        assert_eq!(packets.len(), 1);
        if let RtcpPacket::SenderReport(sr) = &packets[0] {
            assert_eq!(sr.ssrc, 0x12345678);
            assert_eq!(sr.ntp_timestamp.seconds, 100);
            assert_eq!(sr.rtp_timestamp, 16000);
            assert_eq!(sr.packet_count, 100);
            assert_eq!(sr.octet_count, 16000);
            assert_eq!(sr.report_blocks.len(), 1);
            assert_eq!(sr.report_blocks[0].ssrc, 0xAABBCCDD);
            assert_eq!(sr.report_blocks[0].fraction_lost, 10);
        } else {
            panic!("Expected SenderReport");
        }
    }

    #[test]
    fn test_build_parse_receiver_report() {
        let mut buf = [0u8; 256];
        let len = build_receiver_report(&mut buf, 0x11111111, &[]);

        let packets = parse_rtcp_compound(&buf[..len]);
        assert_eq!(packets.len(), 1);
        if let RtcpPacket::ReceiverReport(rr) = &packets[0] {
            assert_eq!(rr.ssrc, 0x11111111);
            assert_eq!(rr.report_blocks.len(), 0);
        } else {
            panic!("Expected ReceiverReport");
        }
    }

    #[test]
    fn test_build_parse_sdes() {
        let mut buf = [0u8; 256];
        let len = build_sdes_cname(&mut buf, 0x12345678, "user@host.example.com");

        let packets = parse_rtcp_compound(&buf[..len]);
        assert_eq!(packets.len(), 1);
        if let RtcpPacket::SourceDescription(sdes) = &packets[0] {
            assert_eq!(sdes.chunks.len(), 1);
            assert_eq!(sdes.chunks[0].ssrc, 0x12345678);
            assert_eq!(sdes.chunks[0].cname.as_deref(), Some("user@host.example.com"));
        } else {
            panic!("Expected SourceDescription");
        }
    }

    #[test]
    fn test_build_parse_bye() {
        let mut buf = [0u8; 256];
        let len = build_bye(&mut buf, &[0x12345678, 0xAABBCCDD], Some("session ended"));

        let packets = parse_rtcp_compound(&buf[..len]);
        assert_eq!(packets.len(), 1);
        if let RtcpPacket::Goodbye(bye) = &packets[0] {
            assert_eq!(bye.sources, vec![0x12345678, 0xAABBCCDD]);
            assert_eq!(bye.reason.as_deref(), Some("session ended"));
        } else {
            panic!("Expected Goodbye");
        }
    }

    #[test]
    fn test_compound_sr_sdes() {
        let mut buf = [0u8; 256];
        let ntp = NtpTimestamp::now();
        let len = build_compound_sr(&mut buf, 0x12345678, ntp, 16000, 100, 16000, &[], "test@host");

        let packets = parse_rtcp_compound(&buf[..len]);
        assert_eq!(packets.len(), 2);
        assert!(matches!(&packets[0], RtcpPacket::SenderReport(_)));
        assert!(matches!(&packets[1], RtcpPacket::SourceDescription(_)));
    }

    #[test]
    fn test_rtcp_session_jitter_tracking() {
        let mut session = RtcpSession::new(0x11111111, "test@host".to_string());

        // Simulate receiving packets at 20ms intervals (160 samples at 8kHz)
        for i in 0..10u16 {
            session.record_rtp_received(0x22222222, i, i as u32 * 160);
            // Small delay to simulate real timing
            std::thread::sleep(Duration::from_millis(1));
        }

        assert_eq!(session.packets_received, 10);
        assert_eq!(session.remote_ssrc, Some(0x22222222));
        assert!(session.first_packet_received);
        // Jitter should be low for regularly spaced packets
        assert!(session.jitter_ms() < 100.0, "jitter_ms={}", session.jitter_ms());
    }

    #[test]
    fn test_rtcp_session_loss_tracking() {
        let mut session = RtcpSession::new(0x11111111, "test@host".to_string());

        // Receive packets with gaps (skip seq 2 and 5)
        for seq in [0u16, 1, 3, 4, 6, 7, 8, 9] {
            session.record_rtp_received(0x22222222, seq, seq as u32 * 160);
        }

        // Expected: 10 (seq 0-9), received: 8, lost: 2
        assert_eq!(session.packets_received, 8);
        assert_eq!(session.expected_packets, 10);
        assert!((session.loss_percent() - 20.0).abs() < 0.1);
    }

    #[test]
    fn test_rtcp_session_build_rtcp() {
        let mut session = RtcpSession::new(0x11111111, "test@host".to_string());

        // Record some sent packets
        session.record_rtp_sent(160, 0);
        session.record_rtp_sent(160, 160);

        // Record some received packets
        session.record_rtp_received(0x22222222, 0, 0);
        session.record_rtp_received(0x22222222, 1, 160);

        // Build RTCP
        let mut buf = [0u8; 512];
        let len = session.build_rtcp(&mut buf);
        assert!(len > 0);

        // Parse it back
        let packets = parse_rtcp_compound(&buf[..len]);
        assert_eq!(packets.len(), 3); // SR + SDES + XR
        assert!(matches!(&packets[0], RtcpPacket::SenderReport(_)));
        assert!(matches!(&packets[1], RtcpPacket::SourceDescription(_)));
        assert!(matches!(&packets[2], RtcpPacket::ExtendedReport(_)));

        if let RtcpPacket::SenderReport(sr) = &packets[0] {
            assert_eq!(sr.ssrc, 0x11111111);
            assert_eq!(sr.packet_count, 2);
            assert_eq!(sr.octet_count, 320);
            assert_eq!(sr.report_blocks.len(), 1);
            assert_eq!(sr.report_blocks[0].ssrc, 0x22222222);
        }
    }

    #[test]
    fn test_sequence_wraparound_tracking() {
        let mut session = RtcpSession::new(0x11111111, "test@host".to_string());

        // Start near wraparound
        session.record_rtp_received(0x22222222, 65534, 0);
        session.record_rtp_received(0x22222222, 65535, 160);
        session.record_rtp_received(0x22222222, 0, 320);     // wraparound
        session.record_rtp_received(0x22222222, 1, 480);

        assert_eq!(session.packets_received, 4);
        assert_eq!(session.seq_cycles, 1); // One wraparound detected
        assert_eq!(session.highest_seq, 1);
    }

    #[test]
    fn test_mos_perfect_conditions() {
        let session = RtcpSession::new(0x12345678, "test@host".to_string());
        // No loss, no jitter, no delay
        let mos = session.mos();
        assert!(mos > 4.0, "Perfect conditions MOS should be > 4.0, got {}", mos);
        assert!(mos <= 4.5, "MOS should not exceed 4.5, got {}", mos);
    }

    #[test]
    fn test_mos_with_loss() {
        let mut session = RtcpSession::new(0x12345678, "test@host".to_string());
        // Simulate 10% packet loss
        session.remote_ssrc = Some(0xABCDEF01);
        session.first_packet_received = true;
        session.base_seq = 0;
        session.highest_seq = 99;
        session.highest_ext_seq = 99;
        session.expected_packets = 100;
        session.packets_received = 90; // 10% loss

        let mos = session.mos();
        assert!(mos < 4.0, "10% loss should degrade MOS below 4.0, got {}", mos);
        assert!(mos > 1.0, "MOS should still be above 1.0, got {}", mos);

        let r = session.r_factor();
        assert!(r < 93.0, "R-factor should be below 93 with loss, got {}", r);
    }

    #[test]
    fn test_r_factor_range() {
        let session = RtcpSession::new(0x12345678, "test@host".to_string());
        let r = session.r_factor();
        assert!(r >= 0.0 && r <= 100.0, "R-factor must be 0-100, got {}", r);
    }

    #[test]
    fn test_parse_empty_input() {
        // parse_rtcp_compound must handle empty input without panic
        let packets = parse_rtcp_compound(&[]);
        assert!(packets.is_empty());
    }

    #[test]
    fn test_parse_truncated_packet() {
        // 3 bytes is too short to even read the RTCP header (need 4)
        let packets = parse_rtcp_compound(&[0x80, 0xC8, 0x00]);
        assert!(packets.is_empty());
    }

    #[test]
    fn test_parse_malformed_length_exceeds_data() {
        // Version 2, PT=200 (SR), but length field says 100 words (400 bytes)
        // while we only provide 8 bytes total. Should not panic.
        let mut buf = [0u8; 8];
        buf[0] = 0x80; // V=2, P=0, RC=0
        buf[1] = PT_SR;
        buf[2..4].copy_from_slice(&100u16.to_be_bytes()); // bogus length
        buf[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
        let packets = parse_rtcp_compound(&buf);
        assert!(packets.is_empty(), "Should skip packet with length exceeding data");
    }

    #[test]
    fn test_parse_wrong_version_stops_parsing() {
        // Version 3 (invalid) should cause parser to stop
        let mut buf = [0u8; 8];
        buf[0] = 0xC0; // V=3
        buf[1] = PT_SR;
        buf[2..4].copy_from_slice(&1u16.to_be_bytes());
        let packets = parse_rtcp_compound(&buf);
        assert!(packets.is_empty());
    }

    #[test]
    fn test_xr_voip_metrics_roundtrip() {
        let metrics = VoipMetrics {
            loss_rate: 25,
            discard_rate: 3,
            burst_density: 10,
            gap_density: 200,
            burst_duration: 500,
            gap_duration: 2000,
            round_trip_delay: 45,
            end_system_delay: 20,
            signal_level: 80,
            noise_level: 40,
            rerl: 12,
            gmin: 16,
            r_factor: 85,
            ext_r_factor: 127,
            mos_lq: 42,
            mos_cq: 41,
            rx_config: 0,
            jb_nominal: 30,
            jb_maximum: 60,
            jb_abs_max: 1000,
        };

        let mut buf = [0u8; 48];
        let len = build_xr_voip_metrics(&mut buf, 0x11111111, 0x22222222, &metrics);
        assert_eq!(len, 44);

        // Verify the XR header
        assert_eq!(buf[1], PT_XR); // packet type 207
        // Verify sender SSRC
        assert_eq!(
            u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            0x11111111
        );
        // Verify block type
        assert_eq!(buf[8], VoipMetrics::BLOCK_TYPE); // BT=7
        // Verify source SSRC
        assert_eq!(
            u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
            0x22222222
        );

        // Parse the metrics back from the body (starts at offset 16)
        let parsed = VoipMetrics::parse(&buf[16..44]).unwrap();
        assert_eq!(parsed.loss_rate, 25);
        assert_eq!(parsed.round_trip_delay, 45);
        assert_eq!(parsed.r_factor, 85);
        assert_eq!(parsed.mos_lq, 42);
        assert_eq!(parsed.jb_abs_max, 1000);
    }

    #[test]
    fn test_receiver_report_no_blocks() {
        // RR with zero report blocks (receiver hasn't gotten any RTP yet)
        let mut buf = [0u8; 64];
        let len = build_receiver_report(&mut buf, 0xAAAAAAAA, &[]);
        assert_eq!(len, 8); // just header + SSRC

        let packets = parse_rtcp_compound(&buf[..len]);
        assert_eq!(packets.len(), 1);
        if let RtcpPacket::ReceiverReport(rr) = &packets[0] {
            assert_eq!(rr.ssrc, 0xAAAAAAAA);
            assert!(rr.report_blocks.is_empty());
        } else {
            panic!("Expected ReceiverReport");
        }
    }
}
