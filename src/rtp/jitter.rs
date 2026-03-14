//! Adaptive jitter buffer implementation
//!
//! Note: neteq crate has complex dependencies. This is a simplified
//! implementation that can be replaced with neteq when needed.

use bytes::Bytes;
use rtp::packet::Packet as RtpPacket;
use std::collections::BTreeMap;
use std::collections::VecDeque;
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
    /// Number of duplicate packets received
    pub packets_duplicated: u64,
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
    /// Bug #88: Number of consecutive pops that must fail to find the expected
    /// sequence before counting a packet as lost. Default 2.
    pub max_wait_before_loss: u32,
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
            max_wait_before_loss: 2,
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
    /// Bug #53: Changed from Vec to VecDeque so that eviction of oldest entries
    /// uses O(1) pop_front() instead of O(n) Vec::remove(0).
    nack_list: VecDeque<u16>,
    /// Bug #88: Consecutive pop misses for the expected sequence number.
    /// Only count as lost after `config.max_wait_before_loss` consecutive misses.
    consecutive_miss: u32,
    /// P1-JB-5: Pop counter for batched adaptation (evaluate every 250 pops)
    pop_count: u32,
    /// P2-JB-5: Running count of consecutive high-fill observations for drift detection.
    drift_high_count: u32,
    /// P2-JB-5: Running count of consecutive low-fill observations for drift detection.
    drift_low_count: u32,
    /// R18: Separate counter for drift detection that is NOT reset with pop_count.
    /// pop_count resets at 250 for adapt_delay batching, so using pop_count % 500
    /// for drift checks was dead code.
    drift_check_count: u32,
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
            nack_list: VecDeque::new(),
            consecutive_miss: 0,
            pop_count: 0,
            drift_high_count: 0,
            drift_low_count: 0,
            drift_check_count: 0,
        }
    }

    /// Push a packet into the buffer
    pub fn push(&mut self, packet: RtpPacket) {
        let now = Instant::now();
        self.stats.packets_received += 1;

        let seq = packet.header.sequence_number;
        let timestamp = packet.header.timestamp;

        // Bug #R9-1: Check if packet is too old BEFORE updating jitter/timestamps.
        // Previously, jitter calculation and last_arrival/last_timestamp were updated
        // unconditionally, then rejected packets corrupted the timing baseline.
        if let Some(last_played) = self.last_played_sequence {
            if Self::sequence_before(seq, last_played) || seq == last_played {
                self.stats.packets_dropped += 1;
                return;
            }
        }

        // Update jitter estimate (RFC 3550)
        // Bug #19: Only update jitter estimate when the packet's RTP timestamp
        // is newer than the last one, to avoid corrupting the estimate with
        // out-of-order packets.
        // RFC 3550 §6.4.1: Jitter MUST be calculated for every received packet.
        // Use u32 half-space comparison to handle timestamp wraparound safely.
        if let (Some(last_arrival), Some(last_timestamp)) = (self.last_arrival, self.last_timestamp)
        {
            let raw_diff = timestamp.wrapping_sub(last_timestamp);
            // Half-space check: if raw_diff > 0x80000000, this is a backward jump
            let ts_diff_samples = if raw_diff < 0x80000000 {
                raw_diff as i64
            } else {
                // backward: -(last_timestamp.wrapping_sub(timestamp)) as i64
                -(last_timestamp.wrapping_sub(timestamp) as i64)
            };

            // P1-JB-4: Timestamp jump detection — if the absolute timestamp
            // difference exceeds 5 seconds worth of samples, the stream has
            // likely been reset (hold/resume, SSRC change, etc.). Reset the
            // buffer to avoid stale state and corrupt jitter estimates.
            let jump_threshold = self.config.sample_rate as i64 * 5;
            if ts_diff_samples.abs() > jump_threshold {
                self.reset();
                // Re-insert this packet after reset
                self.stats.packets_received += 1;
                self.last_arrival = Some(now);
                self.last_timestamp = Some(timestamp);
                self.next_sequence = Some(seq.wrapping_add(1));
                self.packets.insert(
                    seq,
                    BufferedPacket {
                        packet,
                        arrival_time: now,
                    },
                );
                self.stats.buffer_size = self.packets.len();
                return;
            }

            let arrival_diff = now.duration_since(last_arrival).as_millis() as i64;
            let timestamp_diff =
                ts_diff_samples * 1000 / self.config.sample_rate as i64;
            let d = (arrival_diff - timestamp_diff).abs() as f64;
            self.jitter_estimate += (d - self.jitter_estimate) / 16.0;
            self.stats.jitter_ms = self.jitter_estimate;

            // P2-JB-4: Only update last_arrival/last_timestamp when the packet
            // timestamp is forward (not reordered). Reordered packets would
            // corrupt the jitter baseline, producing inflated or negative diffs
            // for the next in-order packet.
            if ts_diff_samples >= 0 {
                self.last_arrival = Some(now);
                self.last_timestamp = Some(timestamp);
            }
        } else {
            self.last_arrival = Some(now);
            self.last_timestamp = Some(timestamp);
        }

        // Check for reordering: a packet is reordered when it arrives
        // before the expected sequence (out of order) but is still within
        // the playout window (not too old to have been already played).
        if let Some(expected) = self.next_sequence {
            if Self::sequence_before(seq, expected) {
                // Only count as reordered if it hasn't already been played out
                let within_window = match self.last_played_sequence {
                    Some(last_played) => !Self::sequence_before(seq, last_played),
                    None => true,
                };
                if within_window {
                    self.stats.packets_reordered += 1;
                }
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
                                // Bug #87: Cap NACK list at 500 entries to prevent
                                // unbounded growth. Remove oldest entries when full.
                                if self.nack_list.len() >= 500 {
                                    self.nack_list.pop_front();
                                }
                                self.nack_list.push_back(missing);
                                self.stats.nack_requests += 1;
                            }
                        }
                    }
                }
            }
        }

        // R17: Duplicate detection BEFORE next_sequence update.
        // Previously, the duplicate check was after the next_sequence update,
        // which meant a duplicate packet would advance next_sequence even
        // though it was discarded — corrupting gap/NACK calculations.
        if self.packets.contains_key(&seq) {
            self.stats.packets_duplicated += 1;
            return;
        }

        // Update next expected sequence
        // Bug #R10-2: Use !sequence_before instead of sequence_after so that
        // next_sequence is also updated when seq == next_sequence. Without this,
        // in-order packets (100, 101, 102...) leave next_sequence stale, causing
        // spurious NACK requests for already-received packets.
        if self.next_sequence.is_none() || !Self::sequence_before(seq, self.next_sequence.unwrap()) {
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

        // Enforce max buffer size: evict the truly oldest packet using
        // wraparound-aware sequence comparison, not the numerically smallest key.
        while self.packets.len() > self.config.max_packets {
            let oldest_seq = {
                let mut keys = self.packets.keys();
                let mut oldest = *keys.next().unwrap();
                for &k in keys {
                    if Self::sequence_before(k, oldest) {
                        oldest = k;
                    }
                }
                oldest
            };
            self.packets.remove(&oldest_seq);
            self.stats.packets_dropped += 1;
        }

        self.stats.buffer_size = self.packets.len();

        // Check if initial buffering is complete
        if !self.initial_buffering_done {
            // Bug #42: Use u64 intermediate arithmetic to prevent u32 overflow
            // when packets.len() * samples_per_packet * 1000 exceeds u32::MAX.
            let buffer_duration_ms = (self.packets.len() as u64
                * self.config.samples_per_packet as u64
                * 1000
                / self.config.sample_rate as u64) as u32;
            if buffer_duration_ms >= self.current_delay_ms.min(self.config.target_delay_ms) {
                self.initial_buffering_done = true;
            }
        }
    }

    /// Pop the next packet from the buffer
    /// Returns None if buffer is empty or still in initial buffering phase
    ///
    /// P1-JB-5: current_delay_ms influences playout via the initial buffering
    /// threshold (in push). Adaptation is batched (every 250 pops) with a
    /// hysteresis band of +/- 1 ptime around the target to prevent oscillation.
    pub fn pop(&mut self) -> Option<RtpPacket> {
        // Wait for initial buffering. P1-JB-5: The initial_buffering_done
        // flag is controlled by current_delay_ms in push(), so the adaptive
        // delay directly influences when playout begins.
        if !self.initial_buffering_done && !self.playout_started {
            return None;
        }

        self.playout_started = true;
        self.pop_count += 1;
        self.drift_check_count += 1;

        // R18: Make adaptive delay influence steady-state playout.
        // If the buffer has grown beyond twice the adaptive delay, skip one
        // packet to reduce latency. The hold-off check (buffer too low) is
        // applied below only when the target packet is missing, to avoid
        // starving the consumer when packets are available.
        if self.initial_buffering_done {
            let buffer_duration_ms = if self.config.sample_rate > 0 {
                (self.packets.len() as u64
                    * self.config.samples_per_packet as u64
                    * 1000
                    / self.config.sample_rate as u64) as u32
            } else {
                0
            };

            if buffer_duration_ms > self.current_delay_ms * 2 && self.current_delay_ms > 0 {
                // Buffer is overfull — skip one packet to reduce latency.
                // Find and remove the oldest packet.
                let oldest_seq = {
                    let mut keys = self.packets.keys();
                    if let Some(first) = keys.next() {
                        let mut oldest = *first;
                        for &k in keys {
                            if Self::sequence_before(k, oldest) {
                                oldest = k;
                            }
                        }
                        Some(oldest)
                    } else {
                        None
                    }
                };
                if let Some(seq) = oldest_seq {
                    self.packets.remove(&seq);
                    self.stats.packets_dropped += 1;
                    self.stats.buffer_size = self.packets.len();
                }
            }
        }

        // Get the next sequence to play
        let target_seq = if let Some(last) = self.last_played_sequence {
            last.wrapping_add(1)
        } else {
            // Start with the truly oldest packet using wraparound-aware comparison
            let mut keys = self.packets.keys();
            let first = keys.next()?;
            let mut oldest = *first;
            for &k in keys {
                if Self::sequence_before(k, oldest) {
                    oldest = k;
                }
            }
            oldest
        };

        // Try to get the target packet
        if let Some(buffered) = self.packets.remove(&target_seq) {
            self.last_played_sequence = Some(target_seq);
            self.stats.buffer_size = self.packets.len();
            self.consecutive_miss = 0;

            // P1-JB-5: Adapt delay every 250 pops instead of every pop
            if self.pop_count >= 250 {
                self.pop_count = 0;
                self.adapt_delay();
            }

            // P2-JB-5: Clock drift detection every 500 pops.
            // Compare buffer fill vs target. If consistently high, the
            // remote clock is faster than ours (skip one packet to catch up).
            // If consistently low, remote clock is slower (insert PLC).
            // R17: Use playout cadence instead of packets_received (arrival
            // cadence) to detect drift relative to our own clock.
            // R18: Use drift_check_count (never reset) instead of pop_count
            // (reset at 250 for adapt_delay batching) so this check actually fires.
            if self.drift_check_count % 500 == 0 && self.drift_check_count > 0 {
                let fill = self.packets.len();
                let target_pkts = (self.config.target_delay_ms as usize)
                    / ((self.config.samples_per_packet * 1000 / self.config.sample_rate) as usize).max(1);
                if fill > target_pkts + 2 {
                    self.drift_high_count += 1;
                    self.drift_low_count = 0;
                    // After 3 consecutive high observations, skip one packet
                    if self.drift_high_count >= 3 {
                        tracing::debug!("JB: clock drift detected (buffer overfull), skipping packet");
                        self.drift_high_count = 0;
                        // R17: Actually skip one packet by advancing last_played_sequence.
                        // This causes the next pop() to target seq+2 instead of seq+1,
                        // allowing playout to catch up with the remote clock.
                        // R18: Remove the skipped packet from the buffer and count it
                        // in stats. Without this, the packet remains orphaned in the
                        // HashMap, wasting memory and skewing buffer_size.
                        if let Some(lps) = self.last_played_sequence {
                            let skipped_seq = lps.wrapping_add(1);
                            if self.packets.remove(&skipped_seq).is_some() {
                                self.stats.packets_dropped += 1;
                                self.stats.buffer_size = self.packets.len();
                            }
                            self.last_played_sequence = Some(skipped_seq);
                        }
                    }
                } else if fill < target_pkts.saturating_sub(2) && target_pkts > 2 {
                    self.drift_low_count += 1;
                    self.drift_high_count = 0;
                    if self.drift_low_count >= 3 {
                        tracing::debug!("JB: clock drift detected (buffer underfull), PLC recommended");
                        self.drift_low_count = 0;
                    }
                } else {
                    self.drift_high_count = 0;
                    self.drift_low_count = 0;
                }
            }

            return Some(buffered.packet);
        }

        // R18: When the target packet is missing and the buffer is below
        // half the adaptive delay, hold off playout to give the packet more
        // time to arrive. This makes current_delay_ms influence steady-state
        // playout without starving consumers when packets are available.
        if self.initial_buffering_done && self.config.sample_rate > 0 {
            let buffer_duration_ms = (self.packets.len() as u64
                * self.config.samples_per_packet as u64
                * 1000
                / self.config.sample_rate as u64) as u32;
            if buffer_duration_ms < self.current_delay_ms / 2 {
                return None;
            }
        }

        // Bug #88: Only count as lost after max_wait_before_loss consecutive
        // pops fail to find the expected sequence. This avoids premature loss
        // counting for packets that are merely late.
        self.consecutive_miss += 1;
        if self.consecutive_miss < self.config.max_wait_before_loss {
            return None;
        }

        // Packet is missing - count as lost
        self.consecutive_miss = 0;
        self.stats.packets_lost += 1;
        self.last_played_sequence = Some(target_seq);

        // Try to get next available packet if we're too far behind
        // Use wraparound-aware scan (same as eviction/playout) instead of
        // BTreeMap iteration order, which picks numerically smallest key and
        // breaks near u16 wraparound (Bug #12).
        if self.packets.len() > self.config.max_packets / 2 {
            let oldest_seq = {
                let mut keys = self.packets.keys();
                let mut oldest = *keys.next().unwrap();
                for &k in keys {
                    if Self::sequence_before(k, oldest) {
                        oldest = k;
                    }
                }
                oldest
            };
            if let Some(buffered) = self.packets.remove(&oldest_seq) {
                // P1-JB-7: Count all skipped sequences between target_seq
                // and oldest_seq as lost. Without this, catch-up skips hide
                // packet loss from the statistics (and from PLC upstream).
                let skipped = oldest_seq.wrapping_sub(target_seq.wrapping_add(1));
                if skipped > 0 && skipped < 0x8000 {
                    self.stats.packets_lost += skipped as u64;
                }
                self.last_played_sequence = Some(oldest_seq);
                self.stats.buffer_size = self.packets.len();
                return Some(buffered.packet);
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

    /// Bug #18: Reset initial buffering state so the next push can trigger
    /// immediate playout. Called when an incoming marker bit signals a stream
    /// restart (e.g. after hold/resume or talk-spurt boundary).
    /// P2-JB-6: Also clear stale packets when resetting initial buffering,
    /// since a marker bit indicates a stream restart and old packets are no
    /// longer relevant.
    pub fn reset_initial_buffering(&mut self) {
        self.initial_buffering_done = false;
        self.packets.clear();
        self.stats.buffer_size = 0;
        // R18-P2: Also reset sequence tracking so the next push doesn't
        // try to play from a stale sequence position. Without this, the
        // jitter buffer would skip packets or report false losses after
        // a marker-bit triggered reset.
        self.last_played_sequence = None;
        self.next_sequence = None;
    }

    /// Bug #19: Check whether a sequence number is already in the buffer
    /// (duplicate detection).
    pub fn contains_seq(&self, seq: u16) -> bool {
        self.packets.contains_key(&seq)
    }

    /// Get the last played sequence number (for gap detection)
    pub fn last_played_sequence(&self) -> Option<u16> {
        self.last_played_sequence
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
        self.consecutive_miss = 0;
        self.pop_count = 0;
        self.drift_high_count = 0;
        self.drift_low_count = 0;
        self.drift_check_count = 0;
    }

    /// Drain and return the list of pending NACK sequence numbers (Fix 11).
    /// The caller should send RTCP NACK (Generic NACK, RFC 4585) for these.
    pub fn pending_nacks(&mut self) -> Vec<u16> {
        // Remove any sequences that have since arrived
        self.nack_list
            .retain(|seq| !self.packets.contains_key(seq));
        // P1-JB-6: Also filter out sequences that have already been played out.
        // Requesting retransmission for these is pointless — they would arrive
        // too late and be dropped.
        if let Some(last_played) = self.last_played_sequence {
            self.nack_list
                .retain(|&seq| !Self::sequence_before(seq, last_played) && seq != last_played);
        }
        self.nack_list.drain(..).collect()
    }

    /// Process an RFC 2198 redundancy (RED, PT 121) payload (Fix 11).
    ///
    /// RED packets carry a primary encoding plus one or more redundant copies
    /// of earlier packets. We extract redundant blocks and insert any that
    /// fill gaps in the buffer.
    // TODO: Implement actual RED packet insertion
    #[allow(dead_code)]
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

        // P2-JB-2: Insert redundant blocks that fill gaps in the buffer.
        // Map timestamp offset to estimated sequence number and insert.
        for &(pt, ts_offset, start, len) in &blocks {
            if start + len > payload.len() {
                continue; // Malformed block
            }

            let redundant_ts = packet.header.timestamp.wrapping_sub(ts_offset);
            let redundant_data = &payload[start..start + len];

            // Estimate the sequence number from the timestamp offset.
            // Each packet covers `samples_per_packet` timestamp units.
            let samples_per_pkt = self.config.samples_per_packet;
            if samples_per_pkt == 0 {
                continue;
            }

            // How many packets back is this redundant block?
            let packets_back = ts_offset / samples_per_pkt;
            let estimated_seq = packet.header.sequence_number
                .wrapping_sub(packets_back as u16)
                .wrapping_sub(1); // redundant blocks are before the primary

            // Only insert if this fills a gap (not already in buffer and not yet played)
            if let Some(last_played) = self.last_played_sequence {
                if Self::sequence_before(estimated_seq, last_played) || estimated_seq == last_played {
                    continue; // Already played, too late
                }
            }

            if !self.packets.contains_key(&estimated_seq) {
                // Build a synthetic RTP packet with the redundant payload
                let mut header = packet.header.clone();
                header.sequence_number = estimated_seq;
                header.timestamp = redundant_ts;
                header.payload_type = pt;
                header.marker = false;

                let synthetic = RtpPacket {
                    header,
                    payload: Bytes::copy_from_slice(redundant_data),
                };

                self.packets.insert(estimated_seq, BufferedPacket {
                    packet: synthetic,
                    arrival_time: Instant::now(),
                });
                self.stats.nack_recovered += 1;
            }
        }
    }

    /// Adapt buffer delay based on current conditions.
    ///
    /// P1-JB-5: Uses a hysteresis band of +/- 1 ptime around the jitter-informed
    /// target to prevent oscillation. Only adjusts when the buffer level is
    /// outside the hysteresis band, and uses smaller adjustment steps (5ms)
    /// for smoother convergence.
    fn adapt_delay(&mut self) {
        // Bug #42: Use u64 intermediate arithmetic to prevent u32 overflow
        let buffer_level = (self.packets.len() as u64
            * self.config.samples_per_packet as u64
            * 1000
            / self.config.sample_rate as u64) as u32;

        // Bug #20: Incorporate jitter estimate into delay calculation.
        // Use 2x jitter as the target, clamped to [min_delay, max_delay].
        let jitter_target = (self.stats.jitter_ms * 2.0) as u32;
        let adaptive_target = jitter_target.clamp(self.config.min_delay_ms, self.config.max_delay_ms);

        // P1-JB-5: Hysteresis band of +/- 1 ptime around the target.
        // Only adjust when buffer_level falls outside this band.
        let ptime_ms = if self.config.sample_rate > 0 {
            (self.config.samples_per_packet as u64 * 1000 / self.config.sample_rate as u64) as u32
        } else {
            20
        };
        let hysteresis = ptime_ms.max(1);
        let low_threshold = adaptive_target.saturating_sub(hysteresis);
        let high_threshold = adaptive_target.saturating_add(hysteresis);

        if buffer_level < low_threshold {
            // Buffer underrun risk - increase delay (smaller 5ms steps for stability)
            self.current_delay_ms = (self.current_delay_ms + 5).min(self.config.max_delay_ms);
        } else if buffer_level > high_threshold {
            // Too much delay - decrease
            self.current_delay_ms = self.current_delay_ms.saturating_sub(5).max(self.config.min_delay_ms);
        }
        // Within hysteresis band — no adjustment

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
