//! RFC 2833/4733 DTMF over RTP (telephone-event)
//!
//! Implements DTMF signaling via RTP payload type (typically 101) for telephone-event.
//! Works identically for inbound and outbound calls.
//!
//! # Payload Format (4 bytes)
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     event     |E|R| volume    |          duration            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//! - **event**: 0-9 = digits, 10 = *, 11 = #, 12-15 = A-D
//! - **E**: End bit (1 = final packet for this event)
//! - **R**: Reserved (must be 0)
//! - **volume**: Power level in dBm0 (0-63, typically 10)
//! - **duration**: In timestamp units (at 8000Hz, 160 = 20ms)
//!
//! # Edge Cases Handled (Send & Receive)
//!
//! ## Marker Bit (First Packet)
//! - **RFC 4733 Section 2.5**: First packet of new digit MUST have marker bit set.
//! - Helps receiver detect digit boundaries, especially after packet loss.
//! - We always set marker on first packet of each digit.
//!
//! ## End Bit Redundancy
//! - **RFC 4733 Section 2.5**: End packet MUST be sent 3 times for reliability.
//! - Packet loss of end packet causes digit to "hang" (duration keeps increasing).
//! - We send end packet 3x with same sequence number increment each time.
//!
//! ## Timestamp Handling
//! - **Constant timestamp during digit**: All packets for one digit share same timestamp.
//! - Duration field increases in each packet, timestamp stays constant.
//! - New digit = new timestamp (advanced by previous digit's duration).
//!
//! ## Sanity Checking (Receive)
//! - **Stuck stream detection**: If we receive same timestamp too many times (8000+),
//!   assume stream is broken and reset detector state.
//! - **Event code validation**: Codes > 15 rejected (not DTMF).
//! - **Deduplication**: Only report digit on END packet, ignore intermediate packets.
//!
//! ## Interoperability Considerations
//!
//! ### Variable Payload Type
//! - Usually 101, but can be any dynamic PT (96-127).
//! - Negotiate from SDP `a=rtpmap:XX telephone-event/8000`.
//! - Some older systems use 96 or 100.
//!
//! ### Clock Rate
//! - Always 8000Hz for telephone-event, regardless of audio codec rate.
//! - Duration conversion: 8 timestamp units = 1ms.
//!
//! ### Volume Level
//! - Default 10 dBm0 (per Orc implementation).
//! - Some systems ignore this field entirely.
//! - Some require specific values for detection.
//!
//! ### Packet Interval
//! - Typically 20ms (same as audio).
//! - Some systems send more frequently (10ms) for better reliability.
//!
//! # Known Limitations
//!
//! - **Flash (event 16)**: Recognized but not fully supported.
//! - **Events 17-255**: Not implemented (fax tones, etc).
//! - **Concurrent digits**: Not supported (would need multiple SSRC).

use bytes::Bytes;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, Ordering};
use std::time::Instant;

use crate::error::{Result, RtpSipError};

/// Default payload type for telephone-event (RFC 4733)
pub const TELEPHONE_EVENT_PT: u8 = 101;

/// Default volume level (10 dBm0)
pub const DEFAULT_VOLUME: u8 = 10;

/// Sample rate for telephone-event (8000 Hz)
pub const TELEPHONE_EVENT_RATE: u32 = 8000;

/// Sanity check limit for detecting stuck/invalid streams.
/// At 8kHz with 20ms packets, 1500 packets = ~30 seconds.
/// Beyond this, assume stream is broken and reset.
const DTMF_SANITY_LIMIT: u32 = 1500;

/// Maximum duration for a single DTMF digit (30 seconds at 8kHz = 240,000 samples).
/// Most DTMF digits are < 1 second. Beyond 30 seconds, assume stuck stream.
const DTMF_MAX_DURATION: u32 = 30 * 8000;

/// Default timeout for missing END packets (5 seconds in milliseconds).
/// If no END packet is received within this time after the first packet of a
/// digit, the digit is force-completed with whatever duration was accumulated.
const DTMF_END_TIMEOUT_MS: u32 = 5000;

/// Minimum DTMF duration (50ms) used when clamping detected digit durations.
const DTMF_MIN_DURATION_MS: u32 = 50;

/// DTMF event codes per RFC 4733
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DtmfEvent {
    Digit0 = 0,
    Digit1 = 1,
    Digit2 = 2,
    Digit3 = 3,
    Digit4 = 4,
    Digit5 = 5,
    Digit6 = 6,
    Digit7 = 7,
    Digit8 = 8,
    Digit9 = 9,
    Star = 10,
    Pound = 11,
    A = 12,
    B = 13,
    C = 14,
    D = 15,
}

impl DtmfEvent {
    /// Convert from character to DTMF event
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            '0' => Some(Self::Digit0),
            '1' => Some(Self::Digit1),
            '2' => Some(Self::Digit2),
            '3' => Some(Self::Digit3),
            '4' => Some(Self::Digit4),
            '5' => Some(Self::Digit5),
            '6' => Some(Self::Digit6),
            '7' => Some(Self::Digit7),
            '8' => Some(Self::Digit8),
            '9' => Some(Self::Digit9),
            '*' => Some(Self::Star),
            '#' => Some(Self::Pound),
            'A' | 'a' => Some(Self::A),
            'B' | 'b' => Some(Self::B),
            'C' | 'c' => Some(Self::C),
            'D' | 'd' => Some(Self::D),
            _ => None,
        }
    }

    /// Convert from event code to DTMF event
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Digit0),
            1 => Some(Self::Digit1),
            2 => Some(Self::Digit2),
            3 => Some(Self::Digit3),
            4 => Some(Self::Digit4),
            5 => Some(Self::Digit5),
            6 => Some(Self::Digit6),
            7 => Some(Self::Digit7),
            8 => Some(Self::Digit8),
            9 => Some(Self::Digit9),
            10 => Some(Self::Star),
            11 => Some(Self::Pound),
            12 => Some(Self::A),
            13 => Some(Self::B),
            14 => Some(Self::C),
            15 => Some(Self::D),
            _ => None,
        }
    }

    /// Convert to character
    pub fn to_char(self) -> char {
        match self {
            Self::Digit0 => '0',
            Self::Digit1 => '1',
            Self::Digit2 => '2',
            Self::Digit3 => '3',
            Self::Digit4 => '4',
            Self::Digit5 => '5',
            Self::Digit6 => '6',
            Self::Digit7 => '7',
            Self::Digit8 => '8',
            Self::Digit9 => '9',
            Self::Star => '*',
            Self::Pound => '#',
            Self::A => 'A',
            Self::B => 'B',
            Self::C => 'C',
            Self::D => 'D',
        }
    }

    /// Get the event code
    pub fn code(self) -> u8 {
        self as u8
    }
}

/// Parsed DTMF payload from RTP packet (4 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtmfPayload {
    /// DTMF event (digit)
    pub event: u8,
    /// End bit - true if this is the final packet for this event
    pub is_end: bool,
    /// Volume level (0-63 dBm0)
    pub volume: u8,
    /// Duration in timestamp units (at 8000Hz)
    pub duration: u16,
}

impl DtmfPayload {
    /// Create a new DTMF payload
    pub fn new(event: DtmfEvent, is_end: bool, duration: u16) -> Self {
        Self {
            event: event.code(),
            is_end,
            volume: DEFAULT_VOLUME,
            duration,
        }
    }

    /// Parse DTMF payload from 4 bytes
    /// packet[0] = event
    /// packet[1] = E|R|volume (E=end bit, R=reserved)
    /// packet[2..3] = duration (big-endian)
    ///
    /// # Edge Cases Handled
    ///
    /// - **4-byte offset padding**: Some VoIP equipment sends DTMF with
    ///   4 bytes of zero padding before the actual payload. We detect this by
    ///   checking if first 4 bytes are all zero and payload is 8+ bytes.
    /// - **Invalid event codes**: Event > 15 rejected (not DTMF).
    /// - **All-zero payload**: Rejected as invalid (malformed packets from
    ///   certain SBCs/gateways).
    pub fn parse(packet: &[u8]) -> Option<Self> {
        if packet.len() < 4 {
            return None;
        }

        // Edge case: detect 4-byte padding offset
        // Some SBCs/gateways send [0,0,0,0,event,flags,dur_hi,dur_lo]
        let offset = if packet.len() >= 8
            && packet[0] == 0
            && packet[1] == 0
            && packet[2] == 0
            && packet[3] == 0
            && packet[4] <= 15
        {
            4 // Skip 4-byte padding
        } else {
            0
        };

        let data = &packet[offset..];
        if data.len() < 4 {
            return None;
        }

        let event = data[0];
        // Validate event code (0-15 for DTMF)
        if event > 15 {
            return None;
        }

        // Bug #R8-2: Removed dead all-zero payload check. The previous condition
        // (data[0] > 15) could never be true after the event > 15 early return above.
        // All-zero payloads [0,0,0,0] are valid Digit '0' per RFC 4733 (event=0).

        let is_end = (data[1] & 0x80) != 0;
        let volume = data[1] & 0x3F;
        let duration = ((data[2] as u16) << 8) | (data[3] as u16);

        Some(Self {
            event,
            is_end,
            volume,
            duration,
        })
    }

    /// Serialize to 4-byte payload
    pub fn serialize(&self) -> [u8; 4] {
        // Bug #R6-4: Validate event code is in valid DTMF range (0-15)
        debug_assert!(self.event <= 15, "Invalid DTMF event code: {}", self.event);
        let mut out = [0u8; 4];
        out[0] = self.event;
        out[1] = (if self.is_end { 0x80 } else { 0x00 }) | (self.volume & 0x3F);
        out[2] = (self.duration >> 8) as u8;
        out[3] = (self.duration & 0xFF) as u8;
        out
    }

    /// Convert duration from milliseconds to timestamp units (at 8000Hz)
    pub fn ms_to_timestamp(ms: u32) -> u16 {
        // 8000 samples/sec * ms / 1000 = 8 * ms
        ms.saturating_mul(8).min(u16::MAX as u32) as u16
    }

    /// Convert duration from timestamp units to milliseconds
    pub fn timestamp_to_ms(ts: u16) -> u32 {
        ts as u32 / 8
    }

    /// Get event as char (if valid)
    pub fn to_char(&self) -> Option<char> {
        DtmfEvent::from_code(self.event).map(|e| e.to_char())
    }
}

/// RTP bug flags for device-specific workarounds
///
/// These flags enable compatibility modes for devices that don't fully comply
/// with RFC 4733 (DTMF over RTP). They can be:
/// 1. Auto-detected from User-Agent header via `RtpBugFlags::detect_from_user_agent()`
/// 2. Manually configured via struct fields
///
/// # Auto-Detection
///
/// Call `detect_from_user_agent()` with the remote party's User-Agent header:
/// ```ignore
/// let bugs = RtpBugFlags::detect_from_user_agent("Sonus/5.0");
/// sender.set_rtp_bugs(bugs);
/// ```
///
/// # Known Device Issues
///
/// ## Sonus Gateways/SBCs
/// Sonus devices expect INCORRECT RFC 2833 behavior:
/// - Timestamp should increment with each packet (RFC says constant)
/// - No marker bit on first packet
/// Without this workaround, Sonus won't detect DTMF digits properly.
///
/// ## Cisco Devices
/// Some Cisco endpoints skip the marker bit on DTMF packets.
/// We detect and adapt to this when receiving DTMF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RtpBugFlags {
    /// Sonus DTMF timestamp bug workaround.
    ///
    /// # The Problem
    /// Per RFC 4733, all packets for a single DTMF digit should have the
    /// SAME timestamp, with only the duration field incrementing. This allows
    /// receivers to reconstruct duration even if packets are lost.
    ///
    /// Sonus devices incorrectly expect timestamp to INCREMENT with each packet.
    /// They won't detect DTMF if we send correct RFC 4733 packets.
    ///
    /// # The Workaround
    /// When enabled:
    /// - Timestamp increments by 160 (20ms at 8kHz) per packet
    /// - Marker bit is disabled on first packet
    /// - Duration field behavior unchanged
    ///
    /// # Detection
    /// Auto-detected when User-Agent contains "Sonus" (case-insensitive).
    pub sonus_dtmf_timestamp: bool,

    /// Never send marker bit on DTMF packets.
    ///
    /// # The Problem
    /// RFC 4733 requires marker bit on the first packet of each DTMF event.
    /// Some endpoints mishandle this and either:
    /// - Ignore packets with marker bit
    /// - Treat marker as start of new digit (causing duplicates)
    ///
    /// # The Workaround
    /// When enabled, marker bit is never set on DTMF packets.
    ///
    /// # Detection
    /// Auto-detected when User-Agent contains "Cisco" (case-insensitive).
    /// Also enabled when `sonus_dtmf_timestamp` is enabled (Sonus also
    /// requires no marker bit).
    pub never_send_marker: bool,
}

impl RtpBugFlags {
    /// Auto-detect RTP bug workarounds from User-Agent header.
    ///
    /// This should be called when a call is established, using the
    /// User-Agent header from the remote party's SIP messages.
    ///
    /// # Detected Devices
    ///
    /// | User-Agent Pattern | Flags Enabled |
    /// |-------------------|---------------|
    /// | Contains "Sonus" | `sonus_dtmf_timestamp`, `never_send_marker` |
    /// | Contains "Cisco" | `never_send_marker` |
    ///
    /// # Example
    ///
    /// ```
    /// use rtpsip::rtp::dtmf::RtpBugFlags;
    ///
    /// // Sonus device detected
    /// let bugs = RtpBugFlags::detect_from_user_agent("Sonus-SBC/5.1.0");
    /// assert!(bugs.sonus_dtmf_timestamp);
    /// assert!(bugs.never_send_marker);
    ///
    /// // Cisco device detected
    /// let bugs = RtpBugFlags::detect_from_user_agent("Cisco-Gateway/IOS-12.x");
    /// assert!(!bugs.sonus_dtmf_timestamp);
    /// assert!(bugs.never_send_marker);
    ///
    /// // Unknown device - no workarounds
    /// let bugs = RtpBugFlags::detect_from_user_agent("Orc-PBX/1.0");
    /// assert!(!bugs.sonus_dtmf_timestamp);
    /// assert!(!bugs.never_send_marker);
    /// ```
    pub fn detect_from_user_agent(user_agent: &str) -> Self {
        let ua_lower = user_agent.to_lowercase();
        let mut flags = Self::default();

        // Sonus gateways/SBCs require incorrect DTMF timestamp handling
        if ua_lower.contains("sonus") {
            flags.sonus_dtmf_timestamp = true;
            flags.never_send_marker = true;
        }

        // Cisco devices may skip marker bit handling
        if ua_lower.contains("cisco") {
            flags.never_send_marker = true;
        }

        flags
    }

    /// Check if any workarounds are enabled
    pub fn has_workarounds(&self) -> bool {
        self.sonus_dtmf_timestamp || self.never_send_marker
    }

    /// Merge with another set of flags (OR operation)
    pub fn merge(&mut self, other: &Self) {
        self.sonus_dtmf_timestamp |= other.sonus_dtmf_timestamp;
        self.never_send_marker |= other.never_send_marker;
    }
}

/// RFC 2833 DTMF sender state
///
/// Manages the out_digit_packet and duration tracking.
/// Works for both inbound and outbound calls.
///
/// # Usage Pattern
///
/// ```ignore
/// let mut sender = DtmfSender::new(ssrc);
/// let mut seq: u16 = packet_builder.sequence();  // shared with audio
/// let audio_ts: u32 = packet_builder.timestamp(); // snapshot audio timestamp
///
/// // Send digit '5' for 100ms
/// let packets = sender.generate_digit('5', 100, 20, &mut seq, audio_ts)?;
/// packet_builder.set_sequence(seq); // sync back
/// for packet in packets {
///     socket.send(&packet.to_rtp_bytes()).await?;
///     tokio::time::sleep(Duration::from_millis(20)).await;
/// }
/// ```
///
/// # Packet Generation (Normal Mode)
///
/// For a 100ms digit with 20ms intervals:
/// 1. **Packet 1**: Marker=1, Duration=0, End=0
/// 2. **Packet 2**: Marker=0, Duration=160, End=0
/// 3. **Packet 3**: Marker=0, Duration=320, End=0
/// 4. **Packet 4**: Marker=0, Duration=480, End=0
/// 5. **Packet 5**: Marker=0, Duration=640, End=0
/// 6. **Packet 6-8**: Marker=0, Duration=800, End=1 (3x for redundancy)
///
/// # Sonus Mode (RTP_BUG_SONUS_SEND_INVALID_TIMESTAMP_2833)
///
/// Sonus devices expect INCORRECT behavior:
/// - Timestamp increments with each packet (should be constant per RFC)
/// - No marker bit on first packet
/// - Duration may be same or increment (we reset to 0)
///
/// This is WRONG per RFC 4733, but required for Sonus compatibility.
///
/// # Edge Cases
///
/// - **Inter-digit gap**: Automatically handled. Timestamp advances after each digit.
/// - **Very long digits**: Duration capped at u16::MAX (8.19 seconds at 8kHz).
/// - **Rapid succession**: Each digit gets unique timestamp.
pub struct DtmfSender {
    /// Payload type (typically 101)
    payload_type: u8,
    /// SSRC for RTP packets
    ssrc: u32,
    /// Timestamp for current digit (stays constant during digit in normal mode).
    /// Initialized from the audio RTP stream's timestamp when a digit starts
    /// (RFC 4733 §2.5).
    digit_timestamp: u32,
    /// Current digit being sent (None = idle)
    out_digit: Option<DtmfEvent>,
    /// Duration sent so far (in timestamp units)
    out_digit_sofar: u32,
    /// Total duration for current digit
    out_digit_dur: u32,
    /// RTP bug workaround flags (Sonus, etc)
    rtp_bugs: RtpBugFlags,
}

impl DtmfSender {
    /// Create a new DTMF sender
    pub fn new(ssrc: u32) -> Self {
        Self {
            payload_type: TELEPHONE_EVENT_PT,
            ssrc,
            digit_timestamp: 0,
            out_digit: None,
            out_digit_sofar: 0,
            out_digit_dur: 0,
            rtp_bugs: RtpBugFlags::default(),
        }
    }

    /// Create with custom payload type
    pub fn with_payload_type(ssrc: u32, payload_type: u8) -> Self {
        let mut sender = Self::new(ssrc);
        sender.payload_type = payload_type;
        sender
    }

    /// Create with RTP bug workaround flags
    pub fn with_rtp_bugs(ssrc: u32, rtp_bugs: RtpBugFlags) -> Self {
        let mut sender = Self::new(ssrc);
        sender.rtp_bugs = rtp_bugs;
        sender
    }

    /// Set RTP bug workaround flags
    pub fn set_rtp_bugs(&mut self, rtp_bugs: RtpBugFlags) {
        self.rtp_bugs = rtp_bugs;
    }

    /// Get current RTP bug flags
    pub fn rtp_bugs(&self) -> RtpBugFlags {
        self.rtp_bugs
    }

    /// Enable Sonus device workaround
    ///
    /// Sonus devices expect INCORRECT RFC 2833 behavior:
    /// - Timestamp increments with each packet (should be constant)
    /// - No marker bit on first packet
    pub fn enable_sonus_mode(&mut self) {
        self.rtp_bugs.sonus_dtmf_timestamp = true;
        self.rtp_bugs.never_send_marker = true;
    }

    /// Get payload type
    pub fn payload_type(&self) -> u8 {
        self.payload_type
    }

    /// Start sending a new digit.
    ///
    /// `seq` is a mutable reference to the shared RTP sequence counter
    /// (from `RtpPacketBuilder`). `audio_timestamp` is the current audio
    /// RTP timestamp at the moment the digit starts — per RFC 4733 §2.5 the
    /// DTMF event timestamp must be drawn from the audio stream.
    /// `interval_ms` is the ptime in milliseconds (typically 20ms) — the initial
    /// packet duration matches one ptime interval, just like FreeSWITCH.
    ///
    /// Returns the packets to send immediately (first packet with marker bit).
    /// If a digit is already in progress, it is properly ended first (Bug #30).
    pub fn start_digit(
        &mut self,
        digit: char,
        duration_ms: u32,
        seq: &mut u16,
        audio_timestamp: u32,
        interval_ms: u32,
    ) -> Result<Vec<DtmfPacket>> {
        let event = DtmfEvent::from_char(digit)
            .ok_or_else(|| RtpSipError::Rtp(format!("Invalid DTMF digit: {}", digit)))?;

        // Bug #30: If a digit is already in progress, end it first to avoid
        // silently overwriting it (which would leak the old digit without END
        // packets and leave the receiver hanging).
        let mut prefix_packets = Vec::new();
        if self.out_digit.is_some() {
            prefix_packets = self.end_digit(seq);
        }

        // Initialize the DTMF timestamp from the audio stream (RFC 4733 §2.5).
        self.digit_timestamp = audio_timestamp;

        // Bug #34: Store the raw u32 duration (ms * 8) instead of going through
        // ms_to_timestamp() which clamps to u16 and breaks digits > 8.19s.
        // The u16 clamping is deferred to DtmfPayload construction time.
        self.out_digit = Some(event);
        // Bug #62: Use saturating_mul to prevent overflow for adversarially large values
        self.out_digit_dur = duration_ms.saturating_mul(8);
        self.out_digit_sofar = 0;

        // Bug #28: Use a non-zero initial duration. The first packet should
        // carry one interval worth of duration rather than 0, which some
        // receivers interpret as an empty/invalid digit.
        // Bug #R6-7: Derive from actual ptime instead of hardcoding 160 (20ms).
        // FreeSWITCH uses samples_per_interval for this, matching the ptime.
        let initial_duration = DtmfPayload::ms_to_timestamp(interval_ms.max(1));
        let payload = DtmfPayload::new(event, false, initial_duration);
        let packet = self.build_packet(&payload, true, seq);

        // Track that we already sent `initial_duration` worth of audio so
        // the next continue_digit() call advances from here instead of
        // re-sending the same duration (which caused a duration plateau).
        self.out_digit_sofar = initial_duration as u32;

        prefix_packets.push(packet);
        Ok(prefix_packets)
    }

    /// Continue sending current digit (call every 20ms).
    ///
    /// `seq` is a mutable reference to the shared RTP sequence counter.
    /// Returns packet to send, or None if digit is complete.
    pub fn continue_digit(&mut self, interval_ms: u32, seq: &mut u16) -> Option<DtmfPacket> {
        let digit = self.out_digit?;
        let total = self.out_digit_dur;

        // Check if digit is already complete BEFORE incrementing to prevent
        // unbounded growth of out_digit_sofar (Bug #10: u32 wrap after ~26M calls
        // would re-enter intermediate state producing garbage packets).
        if self.out_digit_sofar >= total {
            return None;
        }

        let interval_ts = DtmfPayload::ms_to_timestamp(interval_ms) as u32;
        self.out_digit_sofar += interval_ts;
        let sofar = self.out_digit_sofar;

        if sofar >= total {
            // Bug #27: Do NOT emit an end packet here. Let end_digit() be the
            // sole source of end packets to avoid duplicate END sequences
            // (continue_digit was emitting one, then end_digit three more).
            None
        } else {
            // Intermediate packet
            let payload = DtmfPayload::new(digit, false, sofar.min(u16::MAX as u32) as u16);
            Some(self.build_packet(&payload, false, seq))
        }
    }

    /// Check if we're done with current digit
    pub fn is_complete(&self) -> bool {
        self.out_digit.is_none() || self.out_digit_sofar >= self.out_digit_dur
    }

    /// End current digit (generates final packets with end bit).
    ///
    /// `seq` is a mutable reference to the shared RTP sequence counter.
    pub fn end_digit(&mut self, seq: &mut u16) -> Vec<DtmfPacket> {
        let mut packets = Vec::new();

        if let Some(digit) = self.out_digit.take() {
            // Bug #29: Use the actual accumulated duration, not the total
            // requested duration.  If the digit was cut short (e.g., by
            // start_digit overriding it), we report what was actually sent.
            let actual_dur = self.out_digit_sofar;
            let payload = DtmfPayload::new(digit, true, actual_dur.min(u16::MAX as u32) as u16);

            if self.rtp_bugs.sonus_dtmf_timestamp {
                // Bug #R6-8: In Sonus mode, each END packet gets its own
                // incrementing timestamp and sequence number, matching
                // FreeSWITCH's rtp_common_write() behavior for Sonus devices.
                // Sonus expects every RTP packet (including END redundancy)
                // to have a unique, incrementing timestamp.
                for _ in 0..3 {
                    packets.push(self.build_packet(&payload, false, seq));
                }
            } else {
                // Normal (RFC-compliant) mode: Build the end packet once and
                // clone for the 3 redundant retransmissions.
                // RFC 4733 §2.5.1.3: All 3 redundant END packets must share
                // the SAME sequence number as the first END packet.
                let base_packet = self.build_packet(&payload, false, seq);
                let end_seq = base_packet.sequence;
                packets.push(base_packet.clone());
                for _ in 0..2 {
                    let mut retransmit = base_packet.clone();
                    retransmit.sequence = end_seq;
                    packets.push(retransmit);
                }
            }

            // Bug #31: In Sonus mode, timestamps were already advanced
            // per-packet by build_packet, so skip the additional advance
            // here to avoid double-advancing.
            if !self.rtp_bugs.sonus_dtmf_timestamp {
                // Normal mode: advance digit_timestamp for next digit
                self.digit_timestamp = self.digit_timestamp.wrapping_add(self.out_digit_dur);
            }
        }

        packets
    }

    /// Generate all packets for a complete digit (convenience method).
    ///
    /// `seq` is a mutable reference to the shared RTP sequence counter.
    /// `audio_timestamp` is the current audio RTP timestamp — the DTMF event
    /// timestamp is drawn from the audio stream per RFC 4733 §2.5.
    pub fn generate_digit(
        &mut self,
        digit: char,
        duration_ms: u32,
        interval_ms: u32,
        seq: &mut u16,
        audio_timestamp: u32,
    ) -> Result<Vec<DtmfPacket>> {
        let mut packets = self.start_digit(digit, duration_ms, seq, audio_timestamp, interval_ms)?;

        let num_intervals = ((duration_ms + interval_ms - 1) / interval_ms).max(1);
        for _ in 0..num_intervals {
            if let Some(packet) = self.continue_digit(interval_ms, seq) {
                packets.push(packet);
            }
        }

        packets.extend(self.end_digit(seq));
        Ok(packets)
    }

    fn build_packet(&mut self, payload: &DtmfPayload, marker: bool, seq: &mut u16) -> DtmfPacket {
        let s = *seq;
        *seq = seq.wrapping_add(1);

        // Sonus mode: increment timestamp with each packet (WRONG per RFC 4733)
        // Normal mode: same timestamp throughout digit
        let ts = if self.rtp_bugs.sonus_dtmf_timestamp {
            // Sonus expects timestamp to increment by 160 (20ms at 8kHz) per packet
            let t = self.digit_timestamp;
            self.digit_timestamp = self.digit_timestamp.wrapping_add(160);
            t
        } else {
            self.digit_timestamp
        };

        // Apply marker bit rules
        let actual_marker = if self.rtp_bugs.never_send_marker || self.rtp_bugs.sonus_dtmf_timestamp {
            // Sonus mode or never_send_marker: disable marker bit
            false
        } else {
            marker
        };

        DtmfPacket {
            payload_type: self.payload_type,
            sequence: s,
            timestamp: ts,
            ssrc: self.ssrc,
            marker: actual_marker,
            payload: payload.serialize(),
        }
    }
}

/// A single DTMF RTP packet ready to send
#[derive(Debug, Clone)]
pub struct DtmfPacket {
    pub payload_type: u8,
    pub sequence: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub marker: bool,
    pub payload: [u8; 4],
}

impl DtmfPacket {
    /// Serialize to RTP packet bytes
    pub fn to_rtp_bytes(&self) -> Bytes {
        let mut buf = Vec::with_capacity(16);

        // RTP header (12 bytes)
        buf.push(0x80); // V=2, P=0, X=0, CC=0
        buf.push((if self.marker { 0x80 } else { 0x00 }) | (self.payload_type & 0x7F));
        buf.push((self.sequence >> 8) as u8);
        buf.push((self.sequence & 0xFF) as u8);
        buf.push((self.timestamp >> 24) as u8);
        buf.push((self.timestamp >> 16) as u8);
        buf.push((self.timestamp >> 8) as u8);
        buf.push((self.timestamp & 0xFF) as u8);
        buf.push((self.ssrc >> 24) as u8);
        buf.push((self.ssrc >> 16) as u8);
        buf.push((self.ssrc >> 8) as u8);
        buf.push((self.ssrc & 0xFF) as u8);
        // Payload (4 bytes)
        buf.extend_from_slice(&self.payload);

        Bytes::from(buf)
    }
}

/// Minimum interdigit gap in timestamp units (80ms at 8kHz = 640 samples).
/// Packets arriving within this gap after an END are suppressed to prevent
/// overlap between consecutive DTMF digits.
const DTMF_INTERDIGIT_GAP: u32 = 640;

/// RFC 2833 DTMF detector
///
/// Tracks incoming DTMF events with sanity checking and deduplication.
/// Works for both inbound and outbound calls.
///
/// # Detection Strategy
///
/// 1. **Wait for END packet**: Only report digit when End bit is set.
///    This ensures we have the complete duration.
/// 2. **Timestamp-based digit identification**: Same timestamp = same digit.
///    New timestamp = new digit (even if same event code).
/// 3. **Deduplication**: Multiple end packets (redundancy) for same digit
///    are ignored after first detection.
///
/// # Edge Cases Handled
///
/// ## Packet Loss
/// - **Lost intermediate packets**: Duration jumps but still detected on END.
/// - **Lost END packets**: Digit not reported (no false positives).
/// - **Lost first packet**: Marker bit helps, but detection still works.
///
/// ## Stuck Streams
/// - Some broken implementations send same packet repeatedly.
/// - We count consecutive same-timestamp packets.
/// - After 1500 packets (~30 seconds at 20ms), reset state.
///
/// ## Duration Wraparound ("flip" mechanism)
/// - 16-bit duration field wraps at 0xFFFF (~8.19 seconds at 8kHz).
/// - When duration decreases while timestamp stays same, we accumulate.
/// - Detection threshold: when duration > 0xFC17 (~7.9s) and then decreases.
///
/// ## Interdigit Overlap Protection
/// - After an END packet, new digits arriving within 80ms (640 samples at
///   8kHz) are suppressed to prevent glitchy duplicate detection at digit
///   boundaries.
///
/// ## 4-Byte Payload Offset
/// - Some SBCs/gateways send DTMF with 4 bytes of zero padding.
/// - Auto-detected in DtmfPayload::parse().
///
/// ## All-Zero Payload
/// - Rejected as invalid (malformed packet from certain equipment).
/// - Auto-rejected in DtmfPayload::parse().
///
/// ## Out-of-Order Packets
/// - Handled by timestamp tracking, not sequence number.
/// - Reordered packets for same digit still have same timestamp.
///
/// ## 30-Second Digit Timeout
/// - Maximum duration for any single digit is 30 seconds.
/// - Beyond this, assume stream error and reset.
///
/// # Usage
///
/// ```ignore
/// let detector = DtmfDetector::new();
///
/// // In RTP receive loop:
/// if let Some(digit) = detector.process_rtp(payload_type, seq, ts, &payload) {
///     println!("Detected: {} ({}ms)", digit.digit, digit.duration_ms);
/// }
///
/// // Or poll the queue:
/// while let Some(digit) = detector.pop_digit() {
///     handle_dtmf(digit);
/// }
/// ```
pub struct DtmfDetector {
    /// Last received digit sequence number
    in_digit_seq: AtomicU16,
    /// Highest sequence number seen for the current in-progress digit.
    /// Used to reject reordered RTP packets within a digit (Bug #26).
    prev_seq: AtomicU16,
    /// Last received digit timestamp
    in_digit_ts: AtomicU32,
    /// Previous timestamp for comparison
    last_in_digit_ts: AtomicU32,
    /// Sanity counter for detecting stuck streams
    in_digit_sanity: AtomicU32,
    /// Last detected duration
    last_duration: AtomicU16,
    /// Duration accumulator for wraparound ("flip" mechanism)
    /// When 16-bit duration wraps, we add 0xFFFF to this
    duration_flip: AtomicU32,
    /// Current digit being detected
    current_digit: Mutex<Option<DtmfEvent>>,
    /// Payload type to detect (0 = any dynamic PT 96-127)
    expected_pt: u8,
    /// Latched payload type: once the first DTMF packet is accepted with
    /// expected_pt=0 (any dynamic PT), the PT is latched here so that
    /// subsequent packets must use the same PT. 0 means not yet latched.
    latched_pt: AtomicU8,
    /// Queue for detected digits (Bug #84: VecDeque for O(1) pop_front)
    detected_queue: Mutex<VecDeque<DetectedDtmf>>,
    /// Timestamp of the last END packet, for interdigit overlap protection.
    /// 0 means no previous END has been seen.
    last_end_timestamp: AtomicU32,
    /// RTP timestamp of the first packet for the current in-progress digit.
    /// Used together with `end_timeout_ms` to detect permanently lost END packets.
    first_packet_ts: AtomicU32,
    /// Timeout in milliseconds for missing END packets. If the current digit has
    /// been accumulating for longer than this (measured via RTP timestamps), it is
    /// force-completed. Default: 5000ms.
    end_timeout_ms: u32,
    /// Bug #33: Wall-clock time when the current in-progress digit started.
    /// Used as a secondary timeout mechanism that fires even if no new RTP
    /// packets arrive (the RTP-timestamp-based check only runs when a new
    /// packet is processed).
    digit_start_time: Mutex<Option<Instant>>,
}

impl DtmfDetector {
    /// Create a new DTMF detector
    pub fn new() -> Self {
        Self {
            in_digit_seq: AtomicU16::new(0),
            prev_seq: AtomicU16::new(0),
            in_digit_ts: AtomicU32::new(0),
            last_in_digit_ts: AtomicU32::new(0),
            in_digit_sanity: AtomicU32::new(0),
            last_duration: AtomicU16::new(0),
            duration_flip: AtomicU32::new(0),
            current_digit: Mutex::new(None),
            expected_pt: TELEPHONE_EVENT_PT,
            latched_pt: AtomicU8::new(0),
            detected_queue: Mutex::new(VecDeque::new()),
            last_end_timestamp: AtomicU32::new(0),
            first_packet_ts: AtomicU32::new(0),
            end_timeout_ms: DTMF_END_TIMEOUT_MS,
            digit_start_time: Mutex::new(None),
        }
    }

    /// Create with specific payload type (0 = accept any dynamic PT)
    pub fn with_payload_type(pt: u8) -> Self {
        let mut detector = Self::new();
        detector.expected_pt = pt;
        detector
    }

    /// Set the expected payload type explicitly (e.g., from SDP negotiation).
    /// This also latches the PT so that dynamic-PT auto-detection is bypassed.
    pub fn set_expected_pt(&mut self, pt: u8) {
        self.expected_pt = pt;
        self.latched_pt.store(pt, Ordering::Relaxed);
    }

    /// Set the timeout for missing END packets (ms). If the current digit has
    /// been accumulating for longer than this, it is force-completed.
    pub fn set_end_timeout_ms(&mut self, ms: u32) {
        self.end_timeout_ms = ms;
    }

    /// Reset the detector state (full reset, including detected queue)
    pub fn reset(&self) {
        self.in_digit_seq.store(0, Ordering::Relaxed);
        self.prev_seq.store(0, Ordering::Relaxed);
        self.in_digit_ts.store(0, Ordering::Relaxed);
        self.last_in_digit_ts.store(0, Ordering::Relaxed);
        self.in_digit_sanity.store(0, Ordering::Relaxed);
        self.last_duration.store(0, Ordering::Relaxed);
        self.duration_flip.store(0, Ordering::Relaxed);
        *self.current_digit.lock() = None;
        self.detected_queue.lock().clear();
        self.last_end_timestamp.store(0, Ordering::Relaxed);
        self.first_packet_ts.store(0, Ordering::Relaxed);
        *self.digit_start_time.lock() = None;
        // Note: latched_pt is intentionally NOT reset — once latched, the PT
        // should persist across digit boundaries.
    }

    /// Bug #85: Reset detection state but preserve the detected digit queue.
    /// Used internally from `process_rtp` so that already-detected digits
    /// are not lost when the detector resets due to sanity/timeout checks.
    fn reset_state(&self) {
        self.in_digit_seq.store(0, Ordering::Relaxed);
        self.prev_seq.store(0, Ordering::Relaxed);
        self.in_digit_ts.store(0, Ordering::Relaxed);
        self.last_in_digit_ts.store(0, Ordering::Relaxed);
        self.in_digit_sanity.store(0, Ordering::Relaxed);
        self.last_duration.store(0, Ordering::Relaxed);
        self.duration_flip.store(0, Ordering::Relaxed);
        *self.current_digit.lock() = None;
        // Note: detected_queue is intentionally NOT cleared here
        self.last_end_timestamp.store(0, Ordering::Relaxed);
        self.first_packet_ts.store(0, Ordering::Relaxed);
        *self.digit_start_time.lock() = None;
    }

    /// Process incoming RTP packet
    ///
    /// Call this for every RTP packet. Returns detected digit on END packet.
    ///
    /// # Edge Cases Handled
    ///
    /// - Duration wraparound: 16-bit field wraps at ~8.19 seconds. We detect
    ///   when duration decreases while timestamp stays same and accumulate.
    /// - 30-second timeout: Digits longer than 30 seconds trigger reset.
    /// - Stuck stream: Same timestamp for 1500+ packets triggers reset.
    pub fn process_rtp(
        &self,
        payload_type: u8,
        sequence: u16,
        timestamp: u32,
        payload: &[u8],
    ) -> Option<DetectedDtmf> {
        // Check payload type
        if self.expected_pt != 0 {
            if payload_type != self.expected_pt {
                return None;
            }
        } else {
            // expected_pt == 0: accept any dynamic PT (96-127), but once the
            // first DTMF packet is accepted, latch that PT so all subsequent
            // packets must use the same one (Bug #43).
            if payload_type < 96 || payload_type > 127 {
                return None;
            }
            let latched = self.latched_pt.load(Ordering::Relaxed);
            if latched != 0 && payload_type != latched {
                return None;
            }
        }

        let dtmf = DtmfPayload::parse(payload)?;
        let event = DtmfEvent::from_code(dtmf.event)?;

        // Bug #43: Latch the payload type on the first valid DTMF packet when
        // expected_pt == 0 (dynamic PT mode).
        if self.expected_pt == 0 {
            let _ = self.latched_pt.compare_exchange(
                0,
                payload_type,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }

        // Interdigit overlap protection: suppress new digits arriving within
        // 80ms (640 samples at 8kHz) of the last END packet.
        let last_end_ts = self.last_end_timestamp.load(Ordering::Relaxed);
        if last_end_ts != 0 {
            if timestamp == last_end_ts {
                // Same timestamp as previous END — this is a redundant END
                // packet or continuation of the same digit.  Allow it only
                // if it carries the END bit (redundancy); otherwise drop.
                if !dtmf.is_end {
                    return None;
                }
            } else {
                let gap = timestamp.wrapping_sub(last_end_ts);
                // Only enforce gap for small forward differences (not wraparound)
                if gap < DTMF_INTERDIGIT_GAP && gap < 0x8000_0000 {
                    return None;
                }
            }
        }

        // Bug #26: Guard against reordered RTP packets within a digit.
        // If the sequence number is not advancing (i.e., seq <= prev_seq for the
        // current digit), the packet is out of order and its duration value could
        // corrupt the detected duration. Ignore it.
        // We use wrapping arithmetic: a seq that is "behind" prev_seq by less than
        // half the 16-bit space is considered reordered.
        let prev = self.prev_seq.load(Ordering::Relaxed);
        if prev != 0 && timestamp == self.in_digit_ts.load(Ordering::Relaxed) {
            let diff = sequence.wrapping_sub(prev);
            if diff == 0 || diff > 0x8000 {
                // Duplicate or reordered packet within the same digit — ignore
                return None;
            }
        }

        let last_ts = self.in_digit_ts.swap(timestamp, Ordering::Relaxed);
        let _last_seq = self.in_digit_seq.swap(sequence, Ordering::Relaxed);
        self.prev_seq.store(sequence, Ordering::Relaxed);

        // Sanity check: detect out-of-order or stuck streams
        if timestamp == last_ts {
            let sanity = self.in_digit_sanity.fetch_add(1, Ordering::Relaxed);
            if sanity > DTMF_SANITY_LIMIT {
                // Stream appears stuck (same timestamp for 30+ seconds), reset
                // Bug #85: Use reset_state() to preserve already-detected digits
                self.reset_state();
                return None;
            }
        } else {
            self.in_digit_sanity.store(0, Ordering::Relaxed);
        }

        // Bug #42 + Bug #33: Missing END timeout.  If a digit has been in-progress
        // for longer than end_timeout_ms, force-complete it.  This handles
        // permanently lost END packets.
        //
        // Bug #33: We now check BOTH RTP-timestamp-based elapsed time AND
        // wall-clock elapsed time (via digit_start_time).  The wall-clock check
        // ensures timeout fires even if no new RTP packets arrive (the
        // RTP-timestamp check only runs when a new packet is processed).
        {
            let mut timeout_current = self.current_digit.lock();
            if timeout_current.is_some() {
                let first_ts = self.first_packet_ts.load(Ordering::Relaxed);
                let rtp_timeout = if first_ts != 0 {
                    let elapsed_samples = timestamp.wrapping_sub(first_ts);
                    // Bug #62: Use saturating_mul to prevent overflow for adversarially large values
                    let timeout_samples = self.end_timeout_ms.saturating_mul(8); // 8 samples per ms at 8kHz
                    // Guard against backwards timestamps (wrapping_sub produces
                    // a very large value for backwards jumps)
                    elapsed_samples > timeout_samples && elapsed_samples < 0x8000_0000
                } else {
                    false
                };

                // Bug #33: Also check wall-clock time
                let wall_timeout = self
                    .digit_start_time
                    .lock()
                    .map(|t| t.elapsed().as_millis() as u32 > self.end_timeout_ms)
                    .unwrap_or(false);

                if rtp_timeout || wall_timeout {
                    let flip = self.duration_flip.load(Ordering::Relaxed);
                    let old_duration =
                        self.last_duration.load(Ordering::Relaxed) as u32 + flip;
                    let duration_ms =
                        (old_duration / 8).max(DTMF_MIN_DURATION_MS);
                    let digit = timeout_current.take().unwrap();
                    let old_ts = self.last_in_digit_ts.load(Ordering::Relaxed);
                    let result = DetectedDtmf {
                        digit: digit.to_char(),
                        event: digit,
                        duration_ms,
                        is_end: false,
                    };
                    self.duration_flip.store(0, Ordering::Relaxed);
                    self.last_duration.store(0, Ordering::Relaxed);
                    self.last_end_timestamp.store(old_ts, Ordering::Relaxed);
                    self.first_packet_ts.store(0, Ordering::Relaxed);
                    *self.digit_start_time.lock() = None;
                    self.detected_queue.lock().push_back(result);
                    // Fall through — the current packet may start a new digit
                }
            }
            drop(timeout_current);
        }

        // Check for new digit (timestamp changed)
        let mut current = self.current_digit.lock();
        if timestamp != self.last_in_digit_ts.load(Ordering::Relaxed) {
            // Bug #R6-6: Force-complete previous digit before overwriting.
            // Without this, if a new digit arrives before the 5-second timeout
            // fires, the previous digit is silently lost.
            if let Some(prev_digit) = current.take() {
                let flip = self.duration_flip.load(Ordering::Relaxed);
                let old_duration =
                    self.last_duration.load(Ordering::Relaxed) as u32 + flip;
                let duration_ms =
                    (old_duration / 8).max(DTMF_MIN_DURATION_MS);
                let result = DetectedDtmf {
                    digit: prev_digit.to_char(),
                    event: prev_digit,
                    duration_ms,
                    is_end: false,
                };
                // Bug R15-2 fix: Update last_end_timestamp for interdigit gap protection.
                // Must be done before last_in_digit_ts is overwritten below.
                // Matches the timeout path (line 1140) and END packet path (line 1264).
                let old_ts = self.last_in_digit_ts.load(Ordering::Relaxed);
                self.last_end_timestamp.store(old_ts, Ordering::Relaxed);
                self.first_packet_ts.store(0, Ordering::Relaxed);
                *self.digit_start_time.lock() = None;
                self.detected_queue.lock().push_back(result);
            }
            // New digit starting - reset duration tracking
            *current = Some(event);
            self.last_in_digit_ts.store(timestamp, Ordering::Relaxed);
            self.last_duration.store(0, Ordering::Relaxed);
            self.duration_flip.store(0, Ordering::Relaxed);
            // Bug #26: Reset prev_seq for the new digit
            self.prev_seq.store(sequence, Ordering::Relaxed);
            // Bug #42: record the RTP timestamp of the first packet for timeout
            self.first_packet_ts.store(timestamp, Ordering::Relaxed);
            // Bug #33: record wall-clock time for secondary timeout
            *self.digit_start_time.lock() = Some(Instant::now());
        } else if let Some(ref current_event) = *current {
            // Bug #63: Same timestamp but different event code — this is corrupt
            // or malformed. Log a warning and reject the packet.
            if event != *current_event {
                tracing::warn!(
                    "DTMF event code changed within same timestamp: {:?} -> {:?}",
                    current_event, event
                );
                return None;
            }
        }

        // Track duration with wraparound detection ("flip" mechanism)
        // 16-bit duration field wraps at 0xFFFF (~8.19 seconds at 8kHz)
        let last_dur = self.last_duration.swap(dtmf.duration, Ordering::Relaxed);

        // Bug #40: Detect wraparound with reordering guard.
        // Only trigger wraparound if:
        //   1. Duration actually decreased (dtmf.duration < last_dur), AND
        //   2. The old duration was in the upper half of the 16-bit range
        //      (last_dur > 0x8000 ~= 4 seconds), making a wrap plausible, AND
        //   3. The new duration is dramatically smaller (new < old/2),
        //      distinguishing a genuine wrap from out-of-order packets with
        //      slightly decreasing durations.
        // The old threshold (last_dur > 0xFC17) was too conservative and too
        // narrow — it only caught wraps from ~7.9s+.  The new guard catches
        // wraps from 4s+ while rejecting reordering artifacts.
        // Bug #R9-2: Use >= to catch wraparound when last_dur is exactly 0x8000
        if dtmf.duration < last_dur
            && last_dur >= 0x8000
            && dtmf.duration < last_dur / 2
        {
            // Duration wrapped around, accumulate 0xFFFF
            self.duration_flip.fetch_add(0xFFFF, Ordering::Relaxed);
        }

        // Calculate total duration including any wraparound
        let flip = self.duration_flip.load(Ordering::Relaxed);
        let total_duration = dtmf.duration as u32 + flip;

        // 30-second maximum duration sanity check (most digits are < 1 second)
        if total_duration > DTMF_MAX_DURATION {
            // Bug #85: Use reset_state() to preserve already-detected digits
            self.reset_state();
            return None;
        }

        // Only report on END packet
        if dtmf.is_end && current.is_some() {
            // Bug #41: Reject END packets with zero accumulated duration.
            // An END packet with duration=0 (and no prior intermediate packets)
            // indicates a spurious/malformed packet. Accepting it would report
            // a digit with zero duration, causing spurious detection.
            if total_duration == 0 {
                current.take(); // discard the in-progress digit
                self.duration_flip.store(0, Ordering::Relaxed);
                self.first_packet_ts.store(0, Ordering::Relaxed);
                *self.digit_start_time.lock() = None;
                return None;
            }

            let digit = current.take().unwrap();
            // Convert total duration (in timestamp units) to ms
            // At 8kHz: ms = total_duration / 8
            // Bug #61: Clamp to minimum duration, same as the timeout path does.
            let duration_ms = (total_duration / 8).max(DTMF_MIN_DURATION_MS);
            let result = DetectedDtmf {
                digit: digit.to_char(),
                event: digit,
                duration_ms,
                is_end: true,
            };

            // Reset flip for next digit
            self.duration_flip.store(0, Ordering::Relaxed);

            // Reset first_packet_ts for next digit
            self.first_packet_ts.store(0, Ordering::Relaxed);

            // Bug #33: Clear wall-clock timer
            *self.digit_start_time.lock() = None;

            // Record end timestamp for interdigit overlap protection
            self.last_end_timestamp.store(timestamp, Ordering::Relaxed);

            // Queue it
            self.detected_queue.lock().push_back(result.clone());

            return Some(result);
        }

        None
    }

    /// Pop detected digit from queue
    /// Bug #84: Uses VecDeque::pop_front() for O(1) instead of Vec::remove(0) which is O(n)
    pub fn pop_digit(&self) -> Option<DetectedDtmf> {
        self.detected_queue.lock().pop_front()
    }

    /// Check if there are detected digits waiting
    pub fn has_digits(&self) -> bool {
        !self.detected_queue.lock().is_empty()
    }
}

impl Default for DtmfDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Detected DTMF event
#[derive(Debug, Clone)]
pub struct DetectedDtmf {
    /// DTMF digit character
    pub digit: char,
    /// DTMF event
    pub event: DtmfEvent,
    /// Duration in milliseconds
    pub duration_ms: u32,
    /// Whether this was detected from end packet
    pub is_end: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dtmf_event_from_char() {
        assert_eq!(DtmfEvent::from_char('0'), Some(DtmfEvent::Digit0));
        assert_eq!(DtmfEvent::from_char('9'), Some(DtmfEvent::Digit9));
        assert_eq!(DtmfEvent::from_char('*'), Some(DtmfEvent::Star));
        assert_eq!(DtmfEvent::from_char('#'), Some(DtmfEvent::Pound));
        assert_eq!(DtmfEvent::from_char('A'), Some(DtmfEvent::A));
        assert_eq!(DtmfEvent::from_char('a'), Some(DtmfEvent::A));
        assert_eq!(DtmfEvent::from_char('X'), None);
    }

    #[test]
    fn test_dtmf_payload_parse() {
        // Event 1, end=true, volume=10, duration=160
        let data = [1, 0x8A, 0, 160];
        let payload = DtmfPayload::parse(&data).unwrap();
        assert_eq!(payload.event, 1);
        assert!(payload.is_end);
        assert_eq!(payload.volume, 10);
        assert_eq!(payload.duration, 160);

        // Event 2, end=false, volume=0, duration=160
        let data = [2, 0x00, 0, 160];
        let payload = DtmfPayload::parse(&data).unwrap();
        assert_eq!(payload.event, 2);
        assert!(!payload.is_end);

        // Invalid event code (>15)
        let data = [20, 0x80, 10, 100];
        assert!(DtmfPayload::parse(&data).is_none());

        // Too short
        let data = [1, 0x80, 10];
        assert!(DtmfPayload::parse(&data).is_none());

        // Duration 800 = 0x0320
        let data = [2, 0x8A, 3, 32];
        let payload = DtmfPayload::parse(&data).unwrap();
        assert_eq!(payload.duration, 800);
    }

    #[test]
    fn test_dtmf_payload_serialize() {
        let payload = DtmfPayload::new(DtmfEvent::Digit5, true, 160);
        let bytes = payload.serialize();

        assert_eq!(bytes[0], 5);
        assert_eq!(bytes[1] & 0x80, 0x80); // end bit
        assert_eq!(bytes[1] & 0x3F, DEFAULT_VOLUME);
        assert_eq!((bytes[2] as u16) << 8 | bytes[3] as u16, 160);
    }

    #[test]
    fn test_dtmf_payload_roundtrip() {
        let original = DtmfPayload::new(DtmfEvent::Star, true, 320);
        let bytes = original.serialize();
        let parsed = DtmfPayload::parse(&bytes).unwrap();

        assert_eq!(parsed.event, original.event);
        assert_eq!(parsed.is_end, original.is_end);
        assert_eq!(parsed.duration, original.duration);
    }

    #[test]
    fn test_dtmf_duration_conversion() {
        assert_eq!(DtmfPayload::ms_to_timestamp(100), 800);
        assert_eq!(DtmfPayload::timestamp_to_ms(800), 100);
        assert_eq!(DtmfPayload::ms_to_timestamp(20), 160);
        assert_eq!(DtmfPayload::timestamp_to_ms(160), 20);
    }

    #[test]
    fn test_dtmf_sender_generate_digit() {
        let mut sender = DtmfSender::new(0x12345678);
        let mut seq: u16 = 1000;
        let audio_ts: u32 = 48000;
        let packets = sender.generate_digit('5', 100, 20, &mut seq, audio_ts).unwrap();

        // Should have multiple packets
        assert!(packets.len() >= 3); // At least start + end*3

        // First packet should have marker
        assert!(packets[0].marker);

        // All packets should have same timestamp (drawn from audio stream)
        let ts = packets[0].timestamp;
        assert_eq!(ts, audio_ts);
        for packet in &packets {
            assert_eq!(packet.timestamp, ts);
        }

        // Sequence numbers: non-END packets should be monotonically increasing;
        // the last 3 END packets must share the SAME sequence number per RFC 4733 §2.5.1.3.
        assert_eq!(packets[0].sequence, 1000);
        let n = packets.len();
        // Non-END packets are monotonically increasing
        for i in 1..n.saturating_sub(3) {
            assert_eq!(packets[i].sequence, packets[i - 1].sequence.wrapping_add(1));
        }
        // Last 3 END packets share the same sequence number
        assert!(n >= 3);
        let end_seq = packets[n - 3].sequence;
        assert_eq!(packets[n - 2].sequence, end_seq);
        assert_eq!(packets[n - 1].sequence, end_seq);

        // The shared seq counter should have been advanced by (total - 2)
        // since the 3 END packets consume only 1 sequence number.
        let non_end_count = n - 3;
        let expected_seq = 1000u16.wrapping_add(non_end_count as u16 + 1);
        assert_eq!(seq, expected_seq);

        // Last 3 packets should have end bit
        let last_payload = DtmfPayload::parse(&packets[packets.len() - 1].payload).unwrap();
        assert!(last_payload.is_end);
    }

    #[test]
    fn test_dtmf_detector() {
        let detector = DtmfDetector::new();

        // Simulate receiving DTMF digit '5' with increasing duration
        let ts = 1000u32;

        // Intermediate packets (no detection yet)
        let payload1 = [5, 0x0A, 0, 160]; // duration=160, no end
        let result = detector.process_rtp(101, 1, ts, &payload1);
        assert!(result.is_none());

        let payload2 = [5, 0x0A, 1, 64]; // duration=320, no end
        let result = detector.process_rtp(101, 2, ts, &payload2);
        assert!(result.is_none());

        // End packet - should detect
        let payload3 = [5, 0x8A, 3, 32]; // duration=800, end=true
        let result = detector.process_rtp(101, 3, ts, &payload3);
        assert!(result.is_some());
        assert_eq!(result.unwrap().digit, '5');
    }

    #[test]
    fn test_dtmf_detector_new_digit() {
        let detector = DtmfDetector::new();

        // First digit '5'
        let payload1 = [5, 0x8A, 0, 160]; // end=true
        let result = detector.process_rtp(101, 1, 1000, &payload1);
        assert!(result.is_some());
        assert_eq!(result.unwrap().digit, '5');

        // New digit '6' with different timestamp
        let payload2 = [6, 0x8A, 0, 160]; // end=true
        let result = detector.process_rtp(101, 2, 2000, &payload2);
        assert!(result.is_some());
        assert_eq!(result.unwrap().digit, '6');
    }

    #[test]
    fn test_dtmf_detector_wrong_pt() {
        let detector = DtmfDetector::new(); // expects PT 101

        let payload = [5, 0x8A, 0, 160];
        let result = detector.process_rtp(0, 1, 1000, &payload);
        assert!(result.is_none());
    }

    // === Device Compatibility Edge Case Tests ===

    #[test]
    fn test_dtmf_payload_4byte_offset() {
        // Edge case: some SBCs/gateways send 4 bytes of zero padding
        // [0,0,0,0,event,flags,dur_hi,dur_lo]
        let data_with_padding = [0, 0, 0, 0, 5, 0x8A, 0, 160];
        let payload = DtmfPayload::parse(&data_with_padding).unwrap();
        assert_eq!(payload.event, 5);
        assert!(payload.is_end);
        assert_eq!(payload.duration, 160);
    }

    #[test]
    fn test_dtmf_payload_all_zero_is_digit_zero() {
        // Bug #R10-3: All-zero payload [0,0,0,0] is valid Digit '0' per RFC 4733
        // (event=0, is_end=false, volume=0, duration=0). Updated from is_none()
        // after Bug #R8-2 removed the dead all-zero rejection code.
        let data = [0, 0, 0, 0];
        let payload = DtmfPayload::parse(&data).unwrap();
        assert_eq!(payload.event, 0); // Digit '0'
        assert!(!payload.is_end);
        assert_eq!(payload.volume, 0);
        assert_eq!(payload.duration, 0);
    }

    #[test]
    fn test_dtmf_detector_duration_wraparound() {
        // "Flip" mechanism: 16-bit duration wraps at 0xFFFF (~8.19 seconds)
        let detector = DtmfDetector::new();
        let ts = 1000u32;

        // Send packets with increasing duration approaching wrap
        let payload1 = [5, 0x0A, 0xFC, 0x00]; // duration=0xFC00 (~7.9 sec)
        detector.process_rtp(101, 1, ts, &payload1);

        let payload2 = [5, 0x0A, 0xFF, 0x00]; // duration=0xFF00 (~8.1 sec)
        detector.process_rtp(101, 2, ts, &payload2);

        // Duration wraps around (went from 0xFF00 to 0x0100)
        let payload3 = [5, 0x0A, 0x01, 0x00]; // duration=0x0100 (after wrap)
        detector.process_rtp(101, 3, ts, &payload3);

        // End packet with wrapped duration
        let payload4 = [5, 0x8A, 0x02, 0x00]; // duration=0x0200, end=true
        let result = detector.process_rtp(101, 4, ts, &payload4);

        // Should have detected the wraparound and accumulated
        assert!(result.is_some());
        let detected = result.unwrap();
        assert_eq!(detected.digit, '5');
        // Total should be 0x0200 + 0xFFFF = 0x101FF = 65,791 samples
        // At 8kHz: 65,791 / 8 = ~8223ms
        assert!(detected.duration_ms > 8000);
    }

    #[test]
    fn test_sonus_mode_timestamp_increment() {
        // Sonus devices expect timestamp to increment with each packet (WRONG per RFC)
        let mut sender = DtmfSender::new(0x12345678);
        sender.enable_sonus_mode();

        let mut seq: u16 = 0;
        let audio_ts: u32 = 48000;
        let packets = sender.generate_digit('5', 100, 20, &mut seq, audio_ts).unwrap();

        // In Sonus mode, timestamps should increment (unlike normal mode)
        assert!(packets.len() >= 3);

        // Check that timestamps are different between packets
        let ts1 = packets[0].timestamp;
        let ts2 = packets[1].timestamp;

        // First timestamp should come from the audio stream
        assert_eq!(ts1, audio_ts, "Sonus mode should start from audio timestamp");

        // In Sonus mode: timestamp increments by 160 (20ms at 8kHz) per packet
        assert_ne!(ts1, ts2, "Sonus mode should have different timestamps per packet");
        assert_eq!(ts2.wrapping_sub(ts1), 160, "Sonus mode should increment by 160");
    }

    #[test]
    fn test_sonus_mode_no_marker_bit() {
        // Sonus mode should disable marker bit
        let mut sender = DtmfSender::new(0x12345678);
        sender.enable_sonus_mode();

        let mut seq: u16 = 0;
        let packets = sender.generate_digit('5', 100, 20, &mut seq, 48000).unwrap();

        // In Sonus mode, NO packet should have marker bit (even first one)
        for packet in &packets {
            assert!(!packet.marker, "Sonus mode should never set marker bit");
        }
    }

    #[test]
    fn test_normal_mode_constant_timestamp() {
        // Normal mode: all packets for one digit have same timestamp
        let mut sender = DtmfSender::new(0x12345678);
        let mut seq: u16 = 0;
        let audio_ts: u32 = 48000;
        let packets = sender.generate_digit('5', 100, 20, &mut seq, audio_ts).unwrap();

        assert!(packets.len() >= 3);

        let ts = packets[0].timestamp;
        assert_eq!(ts, audio_ts, "DTMF timestamp should come from audio stream");
        for packet in &packets {
            assert_eq!(packet.timestamp, ts, "Normal mode should have constant timestamp");
        }
    }

    #[test]
    fn test_normal_mode_marker_on_first() {
        // Normal mode: first packet should have marker bit
        let mut sender = DtmfSender::new(0x12345678);
        let mut seq: u16 = 0;
        let packets = sender.generate_digit('5', 100, 20, &mut seq, 48000).unwrap();

        assert!(packets[0].marker, "Normal mode should set marker on first packet");

        // Subsequent packets should NOT have marker
        for packet in packets.iter().skip(1) {
            assert!(!packet.marker, "Normal mode should not set marker on subsequent packets");
        }
    }

    #[test]
    fn test_rtp_bug_flags() {
        // Test RtpBugFlags struct
        let mut flags = RtpBugFlags::default();
        assert!(!flags.sonus_dtmf_timestamp);
        assert!(!flags.never_send_marker);

        flags.sonus_dtmf_timestamp = true;
        flags.never_send_marker = true;

        let sender = DtmfSender::with_rtp_bugs(0x12345678, flags);
        assert!(sender.rtp_bugs().sonus_dtmf_timestamp);
        assert!(sender.rtp_bugs().never_send_marker);
    }

    #[test]
    fn test_auto_detect_sonus() {
        // Sonus devices should trigger both workarounds
        let flags = RtpBugFlags::detect_from_user_agent("Sonus-SBC/5.1.0");
        assert!(flags.sonus_dtmf_timestamp);
        assert!(flags.never_send_marker);
        assert!(flags.has_workarounds());

        // Case insensitive
        let flags = RtpBugFlags::detect_from_user_agent("SONUS_GATEWAY");
        assert!(flags.sonus_dtmf_timestamp);

        let flags = RtpBugFlags::detect_from_user_agent("sonus");
        assert!(flags.sonus_dtmf_timestamp);
    }

    #[test]
    fn test_auto_detect_cisco() {
        // Cisco devices should only trigger marker bit workaround
        let flags = RtpBugFlags::detect_from_user_agent("Cisco-Gateway/IOS-12.x");
        assert!(!flags.sonus_dtmf_timestamp);
        assert!(flags.never_send_marker);
        assert!(flags.has_workarounds());

        // Case insensitive
        let flags = RtpBugFlags::detect_from_user_agent("CISCO_IOS");
        assert!(flags.never_send_marker);
    }

    #[test]
    fn test_auto_detect_unknown() {
        // Unknown devices should have no workarounds
        let flags = RtpBugFlags::detect_from_user_agent("Orc-PBX/1.0");
        assert!(!flags.sonus_dtmf_timestamp);
        assert!(!flags.never_send_marker);
        assert!(!flags.has_workarounds());

        let flags = RtpBugFlags::detect_from_user_agent("Asterisk/16.0");
        assert!(!flags.has_workarounds());

        let flags = RtpBugFlags::detect_from_user_agent("");
        assert!(!flags.has_workarounds());
    }

    #[test]
    fn test_rtp_bug_flags_merge() {
        let mut flags1 = RtpBugFlags::default();
        flags1.sonus_dtmf_timestamp = true;

        let mut flags2 = RtpBugFlags::default();
        flags2.never_send_marker = true;

        flags1.merge(&flags2);
        assert!(flags1.sonus_dtmf_timestamp);
        assert!(flags1.never_send_marker);
    }

    #[test]
    fn test_dtmf_packet_to_rtp_bytes() {
        let packet = DtmfPacket {
            payload_type: 101,
            sequence: 0x1234,
            timestamp: 0xABCDEF00,
            ssrc: 0x12345678,
            marker: true,
            payload: [5, 0x8A, 0, 160],
        };

        let bytes = packet.to_rtp_bytes();

        assert_eq!(bytes[0], 0x80); // V=2
        assert_eq!(bytes[1], 0x80 | 101); // M=1, PT=101
        assert_eq!((bytes[2] as u16) << 8 | bytes[3] as u16, 0x1234); // seq
        assert_eq!(bytes[12], 5); // event
        assert_eq!(bytes[13], 0x8A); // end + volume
    }

    // === Interdigit Overlap Protection Tests ===

    #[test]
    fn test_dtmf_interdigit_overlap_same_timestamp() {
        // After an END packet, non-END packets at the same timestamp should
        // be suppressed (they are late arrivals for the already-completed digit).
        let detector = DtmfDetector::new();

        // Digit '5' with END at timestamp 1000
        let end_payload = [5, 0x8A, 0, 160]; // end=true
        let result = detector.process_rtp(101, 1, 1000, &end_payload);
        assert!(result.is_some());

        // Non-END packet at the same timestamp — should be suppressed
        let late_payload = [5, 0x0A, 0, 200]; // end=false, same ts
        let result = detector.process_rtp(101, 2, 1000, &late_payload);
        assert!(result.is_none());
    }

    #[test]
    fn test_dtmf_interdigit_gap_too_short() {
        // A new digit arriving within 80ms (640 samples) after the last END
        // should be suppressed.
        let detector = DtmfDetector::new();

        // First digit END at timestamp 1000
        let end_payload = [5, 0x8A, 0, 160];
        let result = detector.process_rtp(101, 1, 1000, &end_payload);
        assert!(result.is_some());

        // New digit at timestamp 1000 + 320 (only 40ms gap) — too close
        let new_digit = [6, 0x8A, 0, 160]; // end=true
        let result = detector.process_rtp(101, 2, 1320, &new_digit);
        assert!(result.is_none(), "Digit within interdigit gap should be suppressed");
    }

    #[test]
    fn test_dtmf_interdigit_gap_sufficient() {
        // A new digit arriving >= 80ms (640 samples) after the last END
        // should be accepted.
        let detector = DtmfDetector::new();

        // First digit END at timestamp 1000
        let end_payload = [5, 0x8A, 0, 160];
        let result = detector.process_rtp(101, 1, 1000, &end_payload);
        assert!(result.is_some());

        // New digit at timestamp 1000 + 800 (100ms gap) — sufficient
        let new_digit = [6, 0x8A, 0, 160]; // end=true
        let result = detector.process_rtp(101, 2, 1800, &new_digit);
        assert!(result.is_some(), "Digit beyond interdigit gap should be accepted");
        assert_eq!(result.unwrap().digit, '6');
    }

    // === Bug #40: DTMF duration wraparound threshold too conservative ===

    #[test]
    fn test_bug40_no_false_wraparound_on_reordering() {
        // Out-of-order packets with slightly decreasing duration should NOT
        // trigger wraparound detection.  The old threshold (last_dur > 0xFC17)
        // would false-trigger; the new reordering guard requires new_duration
        // < old_duration/2 or new_duration < 0x1000.
        let detector = DtmfDetector::new();
        let ts = 5000u32;

        // Packet with duration=1000
        let p1 = [5, 0x0A, 0x03, 0xE8]; // duration=1000
        detector.process_rtp(101, 1, ts, &p1);

        // Out-of-order packet arrives with duration=800 (slightly less, NOT wrap)
        let p2 = [5, 0x0A, 0x03, 0x20]; // duration=800
        detector.process_rtp(101, 2, ts, &p2);

        // End packet with duration=1200
        let p3 = [5, 0x8A, 0x04, 0xB0]; // duration=1200, end=true
        let result = detector.process_rtp(101, 3, ts, &p3);

        assert!(result.is_some());
        let detected = result.unwrap();
        assert_eq!(detected.digit, '5');
        // Duration should be 1200/8 = 150ms.
        // No wraparound accumulation should have happened.
        assert!(
            detected.duration_ms < 1000,
            "Should not have accumulated wraparound: got {}ms",
            detected.duration_ms
        );
    }

    #[test]
    fn test_bug40_genuine_wraparound_still_detected() {
        // A genuine wraparound (duration goes from 0xFF00 to 0x0100) should
        // still be detected because 0x0100 < 0xFF00/2 and 0x0100 < 0x1000.
        let detector = DtmfDetector::new();
        let ts = 5000u32;

        // Duration approaching wrap
        let p1 = [5, 0x0A, 0xFF, 0x00]; // duration=0xFF00
        detector.process_rtp(101, 1, ts, &p1);

        // Duration wraps around
        let p2 = [5, 0x0A, 0x01, 0x00]; // duration=0x0100 (after wrap)
        detector.process_rtp(101, 2, ts, &p2);

        // End packet with wrapped duration
        let p3 = [5, 0x8A, 0x02, 0x00]; // duration=0x0200, end=true
        let result = detector.process_rtp(101, 3, ts, &p3);

        assert!(result.is_some());
        let detected = result.unwrap();
        assert_eq!(detected.digit, '5');
        // Total should be 0x0200 + 0xFFFF = 0x101FF = 66047 samples
        // At 8kHz: 66047 / 8 = 8255ms
        assert!(
            detected.duration_ms > 8000,
            "Genuine wraparound should accumulate: got {}ms",
            detected.duration_ms
        );
    }

    // === Bug #41: DTMF zero-duration END accepted ===

    #[test]
    fn test_bug41_zero_duration_end_rejected() {
        // An END packet with duration=0 should be rejected (return None),
        // not accepted and reported as a digit.
        let detector = DtmfDetector::new();

        // END packet with duration=0
        let p1 = [5, 0x80, 0, 0]; // event=5, end=true, volume=0, duration=0
        let result = detector.process_rtp(101, 1, 1000, &p1);
        assert!(
            result.is_none(),
            "END packet with zero accumulated duration should be rejected"
        );

        // Verify no digit was queued
        assert!(
            !detector.has_digits(),
            "Zero-duration END should not queue a digit"
        );
    }

    #[test]
    fn test_bug41_nonzero_duration_end_still_works() {
        // Ensure normal END packets with duration > 0 still work after the fix.
        let detector = DtmfDetector::new();

        let p1 = [5, 0x0A, 0, 160]; // duration=160, no end
        detector.process_rtp(101, 1, 1000, &p1);

        let p2 = [5, 0x8A, 1, 64]; // duration=320, end=true
        let result = detector.process_rtp(101, 2, 1000, &p2);
        assert!(result.is_some(), "Normal END with duration > 0 should work");
        assert_eq!(result.unwrap().digit, '5');
    }

    // === Bug #42: DTMF missing END timeout ===

    #[test]
    fn test_bug42_missing_end_timeout_force_completes() {
        // If END is permanently lost, the digit should be force-completed after
        // the timeout expires (measured via RTP timestamps).
        let mut detector = DtmfDetector::new();
        detector.set_end_timeout_ms(1000); // 1 second timeout for faster testing

        let start_ts: u32 = 10000;

        // First packet of digit '5'
        let p1 = [5, 0x0A, 0, 160]; // duration=160, no end
        let result = detector.process_rtp(101, 1, start_ts, &p1);
        assert!(result.is_none());

        // More packets, still no END
        let p2 = [5, 0x0A, 1, 64]; // duration=320, no end
        let result = detector.process_rtp(101, 2, start_ts, &p2);
        assert!(result.is_none());

        // Now a packet arrives much later (1.5 seconds later = 12000 samples at 8kHz).
        // This exceeds the 1000ms timeout (8000 samples).
        // This could be a completely different packet (e.g., audio), but we
        // simulate it as a new DTMF digit with a different timestamp.
        let late_ts = start_ts + 12000; // 1.5s later
        let p3 = [6, 0x0A, 0, 160]; // different digit, no end
        let result = detector.process_rtp(101, 3, late_ts, &p3);

        // The old digit '5' should have been force-completed via timeout
        // The new packet for '6' starts a new digit (returns None)
        assert!(result.is_none(), "New digit packet itself returns None");

        // Check that '5' was force-completed and queued
        let queued = detector.pop_digit();
        assert!(
            queued.is_some(),
            "Timed-out digit '5' should have been force-completed and queued"
        );
        assert_eq!(queued.unwrap().digit, '5');
    }

    #[test]
    fn test_bug42_no_premature_timeout() {
        // Packets arriving within the timeout should NOT trigger force-completion.
        let mut detector = DtmfDetector::new();
        detector.set_end_timeout_ms(5000); // 5 second timeout

        let start_ts: u32 = 10000;

        // First packet of digit '5'
        let p1 = [5, 0x0A, 0, 160];
        detector.process_rtp(101, 1, start_ts, &p1);

        // Packet arrives 1 second later at the SAME digit timestamp (within timeout)
        // Note: in normal DTMF, all packets of one digit share the same RTP timestamp.
        // The timeout is checked by comparing incoming RTP timestamp vs first_packet_ts.
        // A packet with the same ts won't trigger timeout since elapsed=0.
        let p2 = [5, 0x0A, 0x1F, 0x40]; // duration=8000 (1s)
        let result = detector.process_rtp(101, 2, start_ts, &p2);
        assert!(result.is_none(), "Should not timeout within window");

        // No force-completion should have happened
        assert!(!detector.has_digits(), "No premature timeout should occur");

        // Normal END arrives
        let p3 = [5, 0x8A, 0x1F, 0x40]; // duration=8000, end=true
        let result = detector.process_rtp(101, 3, start_ts, &p3);
        assert!(result.is_some(), "Normal END should still work");
        assert_eq!(result.unwrap().digit, '5');
    }

    // === Bug #43: DTMF dynamic PT accepts any 96-127 ===

    #[test]
    fn test_bug43_dynamic_pt_latching() {
        // When expected_pt=0, the first DTMF packet's PT should be latched.
        // Subsequent packets with a different PT should be rejected.
        let detector = DtmfDetector::with_payload_type(0);

        // First packet with PT=96 — should be accepted and latch PT=96
        let p1 = [5, 0x8A, 0, 160]; // end=true, duration=160
        let result = detector.process_rtp(96, 1, 1000, &p1);
        assert!(result.is_some(), "First dynamic PT packet should be accepted");
        assert_eq!(result.unwrap().digit, '5');

        // Second packet with PT=100 — should be rejected (PT latched to 96)
        let p2 = [6, 0x8A, 0, 160]; // end=true
        let result = detector.process_rtp(100, 2, 2000, &p2);
        assert!(
            result.is_none(),
            "Packet with different PT than latched should be rejected"
        );

        // Third packet with PT=96 — should be accepted (matches latched PT)
        let p3 = [7, 0x8A, 0, 160]; // end=true
        let result = detector.process_rtp(96, 3, 3000, &p3);
        assert!(result.is_some(), "Packet with latched PT should be accepted");
        assert_eq!(result.unwrap().digit, '7');
    }

    #[test]
    fn test_bug43_set_expected_pt_overrides() {
        // set_expected_pt() should allow explicit SDP-based configuration
        // and bypass dynamic PT detection entirely.
        let mut detector = DtmfDetector::with_payload_type(0);

        // Explicitly set PT from SDP
        detector.set_expected_pt(110);

        // Packet with PT=110 — should be accepted
        let p1 = [5, 0x8A, 0, 160];
        let result = detector.process_rtp(110, 1, 1000, &p1);
        assert!(result.is_some(), "Packet matching set_expected_pt should be accepted");

        // Packet with PT=96 — should be rejected
        let p2 = [6, 0x8A, 0, 160];
        let result = detector.process_rtp(96, 2, 2000, &p2);
        assert!(
            result.is_none(),
            "Packet not matching set_expected_pt should be rejected"
        );
    }

    #[test]
    fn test_bug43_non_dynamic_pt_still_rejected() {
        // Even with expected_pt=0, non-dynamic PTs (< 96 or > 127) should
        // still be rejected before latching.
        let detector = DtmfDetector::with_payload_type(0);

        let p1 = [5, 0x8A, 0, 160];
        let result = detector.process_rtp(50, 1, 1000, &p1);
        assert!(result.is_none(), "Non-dynamic PT should be rejected");

        let result = detector.process_rtp(128, 2, 2000, &p1);
        assert!(result.is_none(), "PT > 127 should be rejected");
    }

    #[test]
    fn test_bug43_latched_pt_survives_reset() {
        // Latched PT should persist across reset() calls because the PT
        // negotiated via SDP doesn't change mid-call.
        let detector = DtmfDetector::with_payload_type(0);

        // Latch PT=96
        let p1 = [5, 0x8A, 0, 160];
        detector.process_rtp(96, 1, 1000, &p1);

        // Reset detector state (e.g., due to stuck stream)
        detector.reset();

        // PT=96 should still be accepted
        let p2 = [6, 0x8A, 0, 160];
        let result = detector.process_rtp(96, 2, 3000, &p2);
        assert!(result.is_some(), "Latched PT should survive reset");

        // PT=100 should still be rejected
        let p3 = [7, 0x8A, 0, 160];
        let result = detector.process_rtp(100, 3, 4000, &p3);
        assert!(result.is_none(), "Non-latched PT should still be rejected after reset");
    }

    // === Bug #10: out_digit_sofar unbounded increment ===

    #[test]
    fn test_bug10_continue_digit_returns_none_after_complete() {
        // After a digit is complete (sofar >= total), continue_digit() must
        // return None and must NOT increment out_digit_sofar any further.
        let mut sender = DtmfSender::new(0x12345678);
        let mut seq: u16 = 0;

        // Start a 60ms digit (= 480 timestamp units at 8kHz)
        sender.start_digit('5', 60, &mut seq, 48000, 20).unwrap();

        // Call continue_digit with 20ms intervals until the digit completes.
        // 60ms / 20ms = 3 intervals needed to reach completion.
        let mut packets = Vec::new();
        for _ in 0..3 {
            if let Some(pkt) = sender.continue_digit(20, &mut seq) {
                packets.push(pkt);
            }
        }

        // Digit should now be complete
        assert!(sender.is_complete(), "Digit should be complete after 3 intervals");

        // Further calls to continue_digit must return None
        for i in 0..100 {
            assert!(
                sender.continue_digit(20, &mut seq).is_none(),
                "continue_digit should return None after completion (call #{})",
                i
            );
        }

        // Verify out_digit_sofar did NOT continue incrementing.
        // If the bug were present, 100 extra calls * 160 ts = 16000 additional.
        // We check via is_complete() which reads the field — it should still be
        // complete, but more importantly, we verify the value hasn't wrapped.
        let sofar = sender.out_digit_sofar;
        let total = sender.out_digit_dur;
        assert!(
            sofar <= total + 160, // Allow at most one interval overshoot from the completing call
            "out_digit_sofar should not grow unboundedly: sofar={}, total={}",
            sofar,
            total
        );
    }

    #[test]
    fn test_bug10_sofar_does_not_increment_after_completion() {
        // Targeted test: verify the exact value of out_digit_sofar stays stable
        // after the digit is done.
        let mut sender = DtmfSender::new(0xDEADBEEF);
        let mut seq: u16 = 0;

        // Start a 40ms digit (= 320 timestamp units)
        sender.start_digit('1', 40, &mut seq, 48000, 20).unwrap();

        // Two 20ms intervals => sofar reaches 320 (== total), digit complete
        sender.continue_digit(20, &mut seq);
        sender.continue_digit(20, &mut seq);
        assert!(sender.is_complete());

        let sofar_after_complete = sender.out_digit_sofar;

        // Call continue_digit many more times
        for _ in 0..500 {
            let result = sender.continue_digit(20, &mut seq);
            assert!(result.is_none(), "Must return None after completion");
        }

        let sofar_after_extra_calls = sender.out_digit_sofar;
        assert_eq!(
            sofar_after_complete, sofar_after_extra_calls,
            "out_digit_sofar must not change after digit is complete"
        );
    }
}
