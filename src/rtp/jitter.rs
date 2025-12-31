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
}
