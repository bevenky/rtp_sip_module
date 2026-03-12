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
    Unknown { packet_type: u8 },
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
        let _padding = (data[offset] & 0x20) != 0;
        let rc = (data[offset] & 0x1F) as usize;
        let pt = data[offset + 1];
        let length_words = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        let packet_len = (length_words + 1) * 4; // length field is in 32-bit words minus 1

        if offset + packet_len > data.len() {
            break;
        }

        let payload = &data[offset..offset + packet_len];

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
    let reason = if offset + 1 < data.len() {
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
pub fn build_sender_report(
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
pub fn build_receiver_report(
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
pub fn build_sdes_cname(buf: &mut [u8], ssrc: u32, cname: &str) -> usize {
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
pub fn build_bye(buf: &mut [u8], sources: &[u32], reason: Option<&str>) -> usize {
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
    pub const BLOCK_SIZE: usize = 32;

    /// Write the VoIP Metrics block body (32 bytes) to a buffer.
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
        // Pad to 32 bytes
        buf[28..32].fill(0);
    }

    /// Parse a VoIP Metrics block body (32 bytes).
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
/// `8 + 4 + 4 + 32 = 48` bytes (header + SSRC + block header + block body).
pub fn build_xr_voip_metrics(
    buf: &mut [u8],
    ssrc: u32,
    remote_ssrc: u32,
    metrics: &VoipMetrics,
) -> usize {
    // XR packet:
    // - 4 bytes common header (V=2, PT=207)
    // - 4 bytes SSRC of packet sender
    // - 4 bytes block header (BT=7, type-specific=0, block_length=8)
    // - 4 bytes SSRC of source being reported
    // - 28 bytes VoIP Metrics data
    // Total = 44 bytes = 11 32-bit words, length field = 10
    let total_len = 44;
    let length_words = (total_len / 4 - 1) as u16;

    write_header(buf, 2, false, 0, PT_XR, length_words);
    buf[4..8].copy_from_slice(&ssrc.to_be_bytes());

    // Block header: BT=7, type-specific=0, block_length=8 (32 bytes / 4)
    buf[8] = VoipMetrics::BLOCK_TYPE;
    buf[9] = 0; // type-specific
    buf[10..12].copy_from_slice(&8u16.to_be_bytes()); // block_length in 32-bit words

    // SSRC of source
    buf[12..16].copy_from_slice(&remote_ssrc.to_be_bytes());

    // VoIP Metrics data (28 bytes starting at offset 16)
    metrics.write_to(&mut buf[16..48]);

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
    pub seq_cycles: u16,
    /// Highest sequence number received (16-bit)
    pub highest_seq: u16,
    /// Whether we've received our first packet
    pub first_packet_received: bool,
    /// Base sequence number (first packet)
    pub base_seq: u16,

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

    // --- RTCP timing ---
    /// RTCP send interval (default 5s, randomized)
    pub rtcp_interval: Duration,
    /// Last time we sent RTCP
    pub last_rtcp_sent: Instant,
}

impl RtcpSession {
    /// Create a new RTCP session
    pub fn new(local_ssrc: u32, cname: String) -> Self {
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
            rtcp_interval: Self::randomized_interval(Duration::from_secs(5)),
            last_rtcp_sent: Instant::now(),
        }
    }

    /// Randomize RTCP interval per RFC 3550 Section 6.2 (0.5x to 1.5x)
    fn randomized_interval(base: Duration) -> Duration {
        let factor = 0.5 + rand::random::<f64>();
        Duration::from_secs_f64(base.as_secs_f64() * factor)
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
            self.base_seq = seq;
            self.highest_seq = seq;
            self.seq_cycles = 0;
            self.first_packet_received = true;
        } else {
            let udelta = seq.wrapping_sub(self.highest_seq);
            if udelta < 0x8000 {
                // In order or small forward jump
                if seq < self.highest_seq {
                    // Wraparound
                    self.seq_cycles += 1;
                }
                self.highest_seq = seq;
            }
            // else: duplicate or reorder, don't update highest
        }

        self.highest_ext_seq = ((self.seq_cycles as u32) << 16) | (self.highest_seq as u32);
        self.expected_packets = self.highest_ext_seq - self.base_seq as u32 + 1;

        // Jitter calculation (RFC 3550 Appendix A.8)
        if let Some(last_time) = self.last_recv_time {
            let arrival_diff_us = now.duration_since(last_time).as_micros() as i64;
            // Convert to timestamp units (8000 Hz = 8 samples per ms)
            let arrival_diff_ts = (arrival_diff_us * 8) / 1000;
            let rtp_diff_ts = rtp_timestamp.wrapping_sub(self.last_recv_rtp_ts) as i64;
            let d = (arrival_diff_ts - rtp_diff_ts).abs() as f64;
            self.jitter += (d - self.jitter) / 16.0;
        }

        self.last_recv_rtp_ts = rtp_timestamp;
        self.last_recv_time = Some(now);
    }

    /// Process an incoming RTCP packet (extract RTT from SR, etc.)
    pub fn process_incoming_rtcp(&mut self, data: &[u8]) {
        for packet in parse_rtcp_compound(data) {
            match packet {
                RtcpPacket::SenderReport(sr) => {
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
                    for rb in &rr.report_blocks {
                        if rb.ssrc == self.local_ssrc && rb.last_sr != 0 {
                            self.calculate_rtt(rb);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Calculate RTT from a report block
    ///
    /// RTT = now_compact - LSR - DLSR
    fn calculate_rtt(&mut self, rb: &ReportBlock) {
        let now_compact = NtpTimestamp::now().compact();
        let rtt_compact = now_compact.wrapping_sub(rb.last_sr).wrapping_sub(rb.delay_since_last_sr);
        // Convert from compact NTP (1/65536 sec) to Duration
        let rtt_us = (rtt_compact as u64 * 1_000_000) >> 16;
        if rtt_us < 30_000_000 {
            // Sanity check: RTT < 30 seconds
            let rtt = Duration::from_micros(rtt_us);
            // Exponential moving average: 0.7 * old + 0.3 * new (FreeSWITCH pattern)
            self.rtt = Some(match self.rtt {
                Some(old) => Duration::from_secs_f64(old.as_secs_f64() * 0.7 + rtt.as_secs_f64() * 0.3),
                None => rtt,
            });
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
            // We're a sender — build SR + SDES
            let ntp = NtpTimestamp::now();
            let report_blocks = self.build_report_blocks();
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
        self.rtcp_interval = Self::randomized_interval(Duration::from_secs(5));

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
    pub fn build_xr(&self, buf: &mut [u8]) -> usize {
        let remote_ssrc = match self.remote_ssrc {
            Some(s) => s,
            None => return 0,
        };

        let loss = self.loss_percent();
        let r = self.r_factor();
        let mos = self.mos();

        let rtt_ms = self.rtt.map(|d| d.as_millis() as u16).unwrap_or(0);
        let jitter_ms_val = self.jitter_ms();

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
            end_system_delay: jitter_ms_val.round().clamp(0.0, 65535.0) as u16,
            signal_level: 127, // unknown
            noise_level: 127,  // unknown
            rerl: 127,         // unknown
            gmin: 16,          // default gap threshold
            r_factor: r_scaled,
            ext_r_factor: 127,
            mos_lq: mos_scaled,
            mos_cq: mos_scaled,
            rx_config: 0,
            jb_nominal: jitter_ms_val.round().clamp(0.0, 65535.0) as u16,
            jb_maximum: (jitter_ms_val * 2.0).round().clamp(0.0, 65535.0) as u16,
            jb_abs_max: 1000, // 1 second max
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

        let expected_interval = expected - self.last_rr_expected_packets;
        let received_interval = received - self.last_rr_packets_received;
        let lost_interval = expected_interval as i32 - received_interval as i32;
        let fraction_lost = if expected_interval == 0 || lost_interval <= 0 {
            0u8
        } else {
            ((lost_interval as u32 * 256) / expected_interval).min(255) as u8
        };

        // DLSR calculation
        let delay_since_last_sr = match self.last_sr_received_at {
            Some(t) => {
                let elapsed = t.elapsed();
                // Convert to 1/65536 seconds
                ((elapsed.as_secs() << 16) | ((elapsed.subsec_micros() as u64 * 65536) / 1_000_000)) as u32
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
        self.jitter / 8.0 // 8000 Hz = 8 timestamp units per ms
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
        1.0 + 0.035 * r + r * (r - 60.0) * (100.0 - r) * 7.0e-6
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
        assert!(matches!(&packets[2], RtcpPacket::Unknown { packet_type: 207 }));

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
}
