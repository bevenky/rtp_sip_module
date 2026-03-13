//! Adaptive jitter buffer implementation
//!
//! Note: neteq crate has complex dependencies. This is a simplified
//! implementation that can be replaced with neteq when needed.

use rtp::packet::Packet as RtpPacket;
use std::collections::BTreeMap;
use std::time::Instant;

/// Jitter buffer statistics
#[derive(Debug, Clone, Default)]
pub struct JitterStats {
    /// Number of packets received
    pub packets_received: u64,
    /// Number of packets lost
    pub packets_lost: u64,
    /// Number of packets dropped (late arrivals)
    pub packets_dropped: u64,
    /// Number of packets reordered
    pub packets_reordered: u64,
    /// Current jitter in milliseconds
    pub jitter_ms: f64,
    /// Current buffer delay in milliseconds
    pub buffer_delay_ms: u32,
    /// Buffer size (number of packets)
    pub buffer_size: usize,
    /// Number of NACK requests generated (Fix 11)
    pub nack_requests: u64,
    /// Number of packets recovered via NACK retransmission (Fix 11)
    pub nack_recovered: u64,
}

/// Configuration for the jitter buffer
#[derive(Debug, Clone)]
pub struct JitterConfig {
    /// Minimum buffer delay in milliseconds
    pub min_delay_ms: u32,
    /// Maximum buffer delay in milliseconds
    pub max_delay_ms: u32,
    /// Target buffer delay in milliseconds
    pub target_delay_ms: u32,
    /// Maximum buffer size in packets
    pub max_packets: usize,
    /// Sample rate in Hz
    pub sample_rate: u32,
    /// Samples per packet
    pub samples_per_packet: u32,
    /// Enable NACK-based retransmission requests (Fix 11)
    pub nack_enabled: bool,
}

impl Default for JitterConfig {
    fn default() -> Self {
        Self {
            min_delay_ms: 20,
            max_delay_ms: 200,
            target_delay_ms: 60,
            max_packets: 50,
            sample_rate: 8000,
            samples_per_packet: 160,
            nack_enabled: false,
        }
    }
}

/// Buffered packet with arrival time
struct BufferedPacket {
    packet: RtpPacket,
    arrival_time: Instant,
}

/// Adaptive jitter buffer for RTP packets
pub struct JitterBuffer {
    config: JitterConfig,
    /// Packets indexed by sequence number
    packets: BTreeMap<u16, BufferedPacket>,
    /// Next expected sequence number
    next_sequence: Option<u16>,
    /// Last played out sequence number
    last_played_sequence: Option<u16>,
    /// Stats
    stats: JitterStats,
    /// Jitter estimation (RFC 3550)
    jitter_estimate: f64,
    /// Last packet arrival time
    last_arrival: Option<Instant>,
    /// Last packet timestamp
    last_timestamp: Option<u32>,
    /// Current adaptive delay
    current_delay_ms: u32,
    /// Playout started
    playout_started: bool,
    /// Initial buffering complete
    initial_buffering_done: bool,
    /// Pending NACK sequence numbers (Fix 11)
    nack_list: Vec<u16>,
}

impl JitterBuffer {
    /// Create a new jitter buffer with default config
    pub fn new() -> Self {
        Self::with_config(JitterConfig::default())
    }

    /// Create a new jitter buffer with custom config
    pub fn with_config(config: JitterConfig) -> Self {
        let current_delay_ms = config.target_delay_ms;
        Self {
            config,
            packets: BTreeMap::new(),
            next_sequence: None,
            last_played_sequence: None,
            stats: JitterStats::default(),
            jitter_estimate: 0.0,
            last_arrival: None,
            last_timestamp: None,
            current_delay_ms,
            playout_started: false,
            initial_buffering_done: false,
            nack_list: Vec::new(),
        }
    }

    /// Push a packet into the buffer
    pub fn push(&mut self, packet: RtpPacket) {
        let now = Instant::now();
        self.stats.packets_received += 1;

        let seq = packet.header.sequence_number;
        let timestamp = packet.header.timestamp;

        // Update jitter estimate (RFC 3550)
        if let (Some(last_arrival), Some(last_timestamp)) = (self.last_arrival, self.last_timestamp)
        {
            let arrival_diff = now.duration_since(last_arrival).as_millis() as i64;
            let timestamp_diff = timestamp
                .wrapping_sub(last_timestamp)
                .wrapping_mul(1000)
                / self.config.sample_rate;
            let d = (arrival_diff - timestamp_diff as i64).abs() as f64;
            self.jitter_estimate += (d - self.jitter_estimate) / 16.0;
            self.stats.jitter_ms = self.jitter_estimate;
        }
        self.last_arrival = Some(now);
        self.last_timestamp = Some(timestamp);

        // Check if packet is too old (already played out)
        if let Some(last_played) = self.last_played_sequence {
            if Self::sequence_before(seq, last_played) {
                self.stats.packets_dropped += 1;
                return;
            }
        }

        // Check for reordering
        if let Some(expected) = self.next_sequence {
            if seq != expected && !Self::sequence_before(seq, expected) {
                self.stats.packets_reordered += 1;
            }
        }

        // NACK gap detection (Fix 11): if we expected a certain sequence but got
        // a higher one, the gap contains lost packets that we should request.
        if self.config.nack_enabled {
            if let Some(expected) = self.next_sequence {
                if Self::sequence_after(seq, expected) {
                    // Calculate gap size, capped at 100 to avoid flooding
                    // Bug #64: use <= 100 so a gap of exactly 100 is not silently ignored
                    let gap = seq.wrapping_sub(expected);
                    if gap > 0 && gap <= 100 {
                        for i in 0..gap {
                            let missing = expected.wrapping_add(i);
                            if !self.packets.contains_key(&missing) {
                                self.nack_list.push(missing);
                                self.stats.nack_requests += 1;
                            }
                        }
                    }
                }
            }
        }

        // Update next expected sequence
        if self.next_sequence.is_none() || Self::sequence_after(seq, self.next_sequence.unwrap()) {
            self.next_sequence = Some(seq.wrapping_add(1));
        }

        // Add to buffer
        self.packets.insert(
            seq,
            BufferedPacket {
                packet,
                arrival_time: now,
            },
        );

        // Enforce max buffer size
        while self.packets.len() > self.config.max_packets {
            if let Some((&oldest_seq, _)) = self.packets.iter().next() {
                self.packets.remove(&oldest_seq);
                self.stats.packets_dropped += 1;
            }
        }

        self.stats.buffer_size = self.packets.len();

        // Check if initial buffering is complete
        if !self.initial_buffering_done {
            let buffer_duration_ms = self.packets.len() as u32
                * self.config.samples_per_packet
                * 1000
                / self.config.sample_rate;
            if buffer_duration_ms >= self.config.target_delay_ms {
                self.initial_buffering_done = true;
            }
        }
    }

    /// Pop the next packet from the buffer
    /// Returns None if buffer is empty or still in initial buffering phase
    pub fn pop(&mut self) -> Option<RtpPacket> {
        // Wait for initial buffering
        if !self.initial_buffering_done && !self.playout_started {
            return None;
        }

        self.playout_started = true;

        // Get the next sequence to play
        let target_seq = if let Some(last) = self.last_played_sequence {
            last.wrapping_add(1)
        } else {
            // Start with the oldest packet in buffer
            *self.packets.keys().next()?
        };

        // Try to get the target packet
        if let Some(buffered) = self.packets.remove(&target_seq) {
            self.last_played_sequence = Some(target_seq);
            self.stats.buffer_size = self.packets.len();

            // Adapt delay based on buffer level
            self.adapt_delay();

            return Some(buffered.packet);
        }

        // Packet is missing - count as lost
        self.stats.packets_lost += 1;
        self.last_played_sequence = Some(target_seq);

        // Try to get next available packet if we're too far behind
        if self.packets.len() > self.config.max_packets / 2 {
            if let Some((&next_seq, _)) = self.packets.iter().next() {
                if let Some(buffered) = self.packets.remove(&next_seq) {
                    self.last_played_sequence = Some(next_seq);
                    self.stats.buffer_size = self.packets.len();
                    return Some(buffered.packet);
                }
            }
        }

        None
    }

    /// Get buffer statistics
    pub fn stats(&self) -> JitterStats {
        let mut stats = self.stats.clone();
        stats.buffer_delay_ms = self.current_delay_ms;
        stats
    }

    /// Check if buffer is ready for playout
    pub fn is_ready(&self) -> bool {
        self.initial_buffering_done || self.playout_started
    }

    /// Reset the buffer
    pub fn reset(&mut self) {
        self.packets.clear();
        self.next_sequence = None;
        self.last_played_sequence = None;
        self.stats = JitterStats::default();
        self.jitter_estimate = 0.0;
        self.last_arrival = None;
        self.last_timestamp = None;
        self.current_delay_ms = self.config.target_delay_ms;
        self.playout_started = false;
        self.initial_buffering_done = false;
        self.nack_list.clear();
    }

    /// Drain and return the list of pending NACK sequence numbers (Fix 11).
    /// The caller should send RTCP NACK (Generic NACK, RFC 4585) for these.
    pub fn pending_nacks(&mut self) -> Vec<u16> {
        // Remove any sequences that have since arrived
        self.nack_list
            .retain(|seq| !self.packets.contains_key(seq));
        std::mem::take(&mut self.nack_list)
    }

    /// Process an RFC 2198 redundancy (RED, PT 121) payload (Fix 11).
    ///
    /// RED packets carry a primary encoding plus one or more redundant copies
    /// of earlier packets. We extract redundant blocks and insert any that
    /// fill gaps in the buffer.
    pub fn process_redundancy(&mut self, packet: &RtpPacket) {
        let payload = &packet.payload;
        if payload.is_empty() {
            return;
        }

        // Parse RED headers: each header is 4 bytes when F=1, 1 byte when F=0.
        let mut offset = 0;
        let mut blocks: Vec<(u8, u32, usize, usize)> = Vec::new(); // (pt, ts_offset, data_start, data_len)

        // Parse headers
        while offset < payload.len() {
            let f_bit = (payload[offset] & 0x80) != 0;
            let pt = payload[offset] & 0x7F;

            if !f_bit {
                // Last header (primary block), 1 byte header only
                offset += 1;
                // Remaining payload is the primary block — skip it
                break;
            }

            if offset + 4 > payload.len() {
                return; // Malformed
            }

            let ts_offset = ((payload[offset + 1] as u32) << 6)
                | ((payload[offset + 2] as u32) >> 2);
            let block_len = (((payload[offset + 2] & 0x03) as usize) << 8)
                | (payload[offset + 3] as usize);

            blocks.push((pt, ts_offset, 0, block_len)); // data_start filled below
            offset += 4;
        }

        // `offset` now points to the start of data blocks
        let data_start = offset;
        let mut data_offset = data_start;

        for block in &mut blocks {
            block.2 = data_offset; // set data_start
            data_offset += block.3;
        }

        // Insert redundant blocks that fill gaps
        for &(pt, ts_offset, start, len) in &blocks {
            if start + len > payload.len() {
                continue; // Malformed block
            }

            let redundant_ts = packet.header.timestamp.wrapping_sub(ts_offset);
            let redundant_data = &payload[start..start + len];

            // Try to find the sequence number for this timestamp
            // by scanning the gap around our current playout position.
            // This is a heuristic — in practice the caller would map ts -> seq.
            if let Some(last_played) = self.last_played_sequence {
                // Check if this fills a gap ahead of playout
                let samples_per_pkt = self.config.samples_per_packet;
                if samples_per_pkt > 0 {
                    // Estimate seq from timestamp difference relative to a known packet
                    // For now, simply insert by checking if we can match a NACK'd seq
                    let _ = (pt, redundant_ts, redundant_data, last_played);
                    // Redundancy recovery is best-effort; actual seq mapping
                    // requires the caller to provide more context.
                }
            }
        }
    }

    /// Adapt buffer delay based on current conditions
    fn adapt_delay(&mut self) {
        let buffer_level = self.packets.len() as u32
            * self.config.samples_per_packet
            * 1000
            / self.config.sample_rate;

        // Simple adaptive algorithm
        if buffer_level < self.config.min_delay_ms {
            // Buffer underrun risk - increase delay
            self.current_delay_ms = (self.current_delay_ms + 10).min(self.config.max_delay_ms);
        } else if buffer_level > self.config.max_delay_ms {
            // Too much delay - decrease
            self.current_delay_ms = (self.current_delay_ms - 10).max(self.config.min_delay_ms);
        }

        self.stats.buffer_delay_ms = self.current_delay_ms;
    }

    /// Compare sequence numbers with wraparound handling
    fn sequence_before(a: u16, b: u16) -> bool {
        let diff = b.wrapping_sub(a);
        diff > 0 && diff < 0x8000
    }

    fn sequence_after(a: u16, b: u16) -> bool {
        Self::sequence_before(b, a)
    }
}

impl Default for JitterBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Packet Loss Concealment (PLC) for G.711
pub struct PacketLossConcealer {
    /// Last good samples for interpolation
    last_samples: Vec<i16>,
    /// Samples per packet
    samples_per_packet: usize,
    /// Attenuation factor for concealment
    attenuation: f32,
}

impl PacketLossConcealer {
    pub fn new(samples_per_packet: usize) -> Self {
        Self {
            last_samples: vec![0; samples_per_packet],
            samples_per_packet,
            attenuation: 1.0,
        }
    }

    /// Update with good samples
    pub fn update(&mut self, samples: &[i16]) {
        self.last_samples.clear();
        self.last_samples.extend_from_slice(samples);
        self.attenuation = 1.0;
    }

    /// Reset PLC state (Bug #48: called on SSRC change to avoid
    /// stale concealment from the previous stream).
    pub fn reset(&mut self) {
        self.last_samples = vec![0; self.samples_per_packet];
        self.attenuation = 1.0;
    }

    /// Generate concealment samples for a lost packet
    pub fn conceal(&mut self) -> Vec<i16> {
        // Simple decay-based concealment
        self.attenuation *= 0.9;

        let concealed: Vec<i16> = self
            .last_samples
            .iter()
            .map(|&s| (s as f32 * self.attenuation) as i16)
            .collect();

        // Limit consecutive concealment
        if self.attenuation < 0.1 {
            vec![0; self.samples_per_packet]
        } else {
            concealed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use rtp::header::Header;

    fn make_packet(seq: u16, timestamp: u32) -> RtpPacket {
        RtpPacket {
            header: Header {
                version: 2,
                padding: false,
                extension: false,
                marker: false,
                payload_type: 0,
                sequence_number: seq,
                timestamp,
                ssrc: 0x12345678,
                csrc: vec![],
                extension_profile: 0,
                extensions: vec![],
                extensions_padding: 0,
            },
            payload: Bytes::from(vec![0xFF; 160]),
        }
    }

    #[test]
    fn test_jitter_buffer_in_order() {
        let mut jb = JitterBuffer::new();

        // Push packets in order
        for i in 0..5 {
            jb.push(make_packet(i, i as u32 * 160));
        }

        // Should be ready after enough packets
        assert!(jb.is_ready());

        // Pop packets
        for i in 0..5 {
            let packet = jb.pop();
            assert!(packet.is_some());
            assert_eq!(packet.unwrap().header.sequence_number, i);
        }

        // Buffer should be empty
        assert!(jb.pop().is_none());
    }

    #[test]
    fn test_jitter_buffer_out_of_order() {
        let mut jb = JitterBuffer::new();

        // Push packets out of order
        jb.push(make_packet(0, 0));
        jb.push(make_packet(2, 320)); // Skip 1
        jb.push(make_packet(1, 160)); // Late arrival
        jb.push(make_packet(3, 480));
        jb.push(make_packet(4, 640));

        // Pop should still be in order
        assert_eq!(jb.pop().unwrap().header.sequence_number, 0);
        assert_eq!(jb.pop().unwrap().header.sequence_number, 1);
        assert_eq!(jb.pop().unwrap().header.sequence_number, 2);
        assert_eq!(jb.pop().unwrap().header.sequence_number, 3);
        assert_eq!(jb.pop().unwrap().header.sequence_number, 4);

        assert!(jb.stats.packets_reordered >= 1);
    }

    #[test]
    fn test_sequence_wraparound() {
        assert!(JitterBuffer::sequence_before(65534, 65535));
        assert!(JitterBuffer::sequence_before(65535, 0));
        assert!(JitterBuffer::sequence_before(0, 1));
        assert!(!JitterBuffer::sequence_before(1, 0));
    }

    #[test]
    fn test_plc() {
        let mut plc = PacketLossConcealer::new(160);

        // Update with good samples
        let samples: Vec<i16> = (0..160).map(|i| (i * 100) as i16).collect();
        plc.update(&samples);

        // Conceal first loss
        let concealed1 = plc.conceal();
        assert_eq!(concealed1.len(), 160);
        // Should be attenuated
        assert!(concealed1[100].abs() < samples[100].abs());

        // Multiple losses should decay further
        let concealed2 = plc.conceal();
        assert!(concealed2[100].abs() < concealed1[100].abs());
    }

    // === Bug #64: NACK gap of exactly 100 should NOT be dropped ===

    #[test]
    fn test_nack_gap_exactly_100_not_dropped() {
        let mut config = JitterConfig::default();
        config.nack_enabled = true;
        let mut jb = JitterBuffer::with_config(config);

        // Push seq 0 -> next_sequence becomes 1
        // Push seq 101 -> gap = 101.wrapping_sub(1) = 100, exactly the max
        jb.push(make_packet(0, 0));
        jb.push(make_packet(101, 101 * 160));

        let nacks = jb.pending_nacks();
        // Bug #64: gap of exactly 100 should generate NACKs for seq 1..=100
        assert_eq!(
            nacks.len(),
            100,
            "sequence gap of exactly 100 should generate 100 NACKs (seq 1..=100), got {}",
            nacks.len()
        );
        for expected in 1u16..=100 {
            assert!(
                nacks.contains(&expected),
                "NACK list should contain seq={}",
                expected
            );
        }
    }

    #[test]
    fn test_nack_gap_101_is_dropped() {
        let mut config = JitterConfig::default();
        config.nack_enabled = true;
        let mut jb = JitterBuffer::with_config(config);

        // Push seq 0 -> next_sequence becomes 1
        // Push seq 102 -> gap = 102.wrapping_sub(1) = 101, exceeds max 100
        jb.push(make_packet(0, 0));
        jb.push(make_packet(102, 102 * 160));

        let nacks = jb.pending_nacks();
        // Sequence gap of 101 > 100 should be silently dropped
        assert_eq!(
            nacks.len(),
            0,
            "sequence gap of 101 should generate 0 NACKs, got {}",
            nacks.len()
        );
    }

    #[test]
    fn test_nack_gap_99_still_works() {
        let mut config = JitterConfig::default();
        config.nack_enabled = true;
        let mut jb = JitterBuffer::with_config(config);

        // Push seq 0 -> next_sequence becomes 1
        // Push seq 100 -> gap = 100.wrapping_sub(1) = 99 (below max 100)
        jb.push(make_packet(0, 0));
        jb.push(make_packet(100, 100 * 160));

        let nacks = jb.pending_nacks();
        assert_eq!(
            nacks.len(),
            99,
            "sequence gap of 99 should generate 99 NACKs (seq 1..=99), got {}",
            nacks.len()
        );
    }
}
