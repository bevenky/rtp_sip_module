//! RTP Engine for sending and receiving audio
//!
//! Includes:
//! - Fix 4:  RTP media timeout detection with broadcast notification
//! - Fix 5:  Comfort Noise (RFC 3389) completeness — CN pacing + dBov
//! - Fix 6:  RTCP-mux support (RFC 5761) — RTP+RTCP on same port
//! - Fix 7:  Codec asymmetry — separate send/receive codecs
//! - Fix 8:  Ptime negotiation — variable packet size
//! - Fix 9:  SSRC collision recovery — jitter buffer + RTCP reset
//! - Fix 10: Marker bit on stream restart (hold/resume)
//! - Fix 27: Port exhaustion / recycling — global port pool
//! - Fix 31: CN noise level parsing (RFC 3389 dBov byte)
//! - Bug #47: Audio codec payload type validation
//! - Bug #48: Complete SSRC collision recovery (reset all stream state)
//! - Bug #49: Timestamp normalizer uses configured ptime instead of hardcoded 20ms
//! - Bug #50: hold_media_timeout_ms config verified working (same root cause as Bug #2)

use crate::error::{Result, RtpSipError};
use crate::rtp::codec::{CodecType, G711Codec};
use crate::rtp::dtmf::{DetectedDtmf, DtmfDetector, DtmfSender, RtpBugFlags, TELEPHONE_EVENT_PT};
use crate::rtp::jitter::{JitterBuffer, JitterConfig, JitterStats, PacketLossConcealer};
use crate::rtp::packet::{parse_rtp_packet, serialize_rtp_packet, RtpPacketBuilder};
use bytes::Bytes;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc};
use tokio::time::Duration;

// ========== Fix 27: Global RTP port pool ==========

use std::sync::OnceLock;

static ALLOCATED_PORTS: OnceLock<parking_lot::Mutex<HashSet<u16>>> = OnceLock::new();

fn get_port_pool() -> &'static parking_lot::Mutex<HashSet<u16>> {
    ALLOCATED_PORTS.get_or_init(|| parking_lot::Mutex::new(HashSet::new()))
}

/// Allocate an even-numbered RTP port from the range.
/// Returns None if all ports are exhausted or the range is invalid.
pub fn allocate_rtp_port(start: u16, end: u16) -> Option<u16> {
    // Bug #16: Validate that end > start to avoid underflow
    if end <= start {
        tracing::error!(start, end, "Invalid port range: end must be greater than start");
        return None;
    }

    // Bug #37: Use saturating_add to prevent u16 overflow when start is odd near MAX
    let start = if start % 2 != 0 { start.saturating_add(1) } else { start };
    if start >= end {
        return None;
    }

    let mut allocated = get_port_pool().lock();
    // Start from a random offset to avoid always getting the same port
    // Bug #16: Ensure range_size is at least 1 to avoid division by zero
    // Bug #38 / Bug #R11-1: Count even ports in [start, end] inclusive.
    // (end - start) / 2 + 1 correctly handles all cases:
    //   start=10000, end=10002 → (2/2)+1 = 2 ports: 10000, 10002
    //   start=10000, end=10004 → (4/2)+1 = 3 ports: 10000, 10002, 10004
    let range_size = ((((end - start) / 2) + 1) as usize).max(1);
    let offset = rand::random::<usize>() % range_size;
    for i in 0..range_size {
        let idx = (offset + i) % range_size;
        let port = start + (idx as u16) * 2; // even ports only
        if !allocated.contains(&port) {
            allocated.insert(port);
            return Some(port);
        }
    }
    None
}

/// Release a port back to the pool.
pub fn release_rtp_port(port: u16) {
    get_port_pool().lock().remove(&port);
}

/// Normalizes remote RTP timestamps to a local timebase.
///
/// After call transfer or hold/resume the remote may restart timestamps
/// from a completely different base. This struct detects large
/// discontinuities and recomputes the offset so the jitter buffer
/// sees a smooth, monotonic timestamp stream.
struct TimestampNormalizer {
    /// Our own running timestamp counter (starts at 0, incremented by
    /// the number of samples expected per packet).
    local_base_ts: u32,
    /// The first remote timestamp we observed (used to compute the initial offset).
    remote_base_ts: Option<u32>,
    /// Signed offset: normalized = ((remote as i64).wrapping_add(ts_offset)) as u32.
    ts_offset: i64,
    /// Last remote timestamp seen (for discontinuity detection).
    last_remote_ts: Option<u32>,
    /// Sample rate used to decide what counts as a "large" jump.
    sample_rate: u32,
    /// Ptime in milliseconds (Bug #49: used for discontinuity recovery instead
    /// of hardcoded 20ms).
    ptime_ms: u32,
}

impl TimestampNormalizer {
    fn new(sample_rate: u32) -> Self {
        Self {
            local_base_ts: 0,
            remote_base_ts: None,
            ts_offset: 0,
            last_remote_ts: None,
            sample_rate,
            ptime_ms: 20,
        }
    }

    fn with_ptime(sample_rate: u32, ptime_ms: u32) -> Self {
        Self {
            local_base_ts: 0,
            remote_base_ts: None,
            ts_offset: 0,
            last_remote_ts: None,
            sample_rate,
            ptime_ms,
        }
    }

    /// Get the number of samples per packet based on configured ptime.
    fn samples_per_packet(&self) -> u32 {
        self.sample_rate * self.ptime_ms / 1000
    }

    /// Update the ptime (e.g. after SDP renegotiation).
    fn set_ptime(&mut self, ptime_ms: u32) {
        self.ptime_ms = ptime_ms;
    }

    /// Feed a remote timestamp and return the normalized timestamp.
    fn normalize(&mut self, remote_ts: u32) -> u32 {
        // 5 seconds worth of samples — anything larger is a discontinuity.
        let max_delta: u32 = self.sample_rate * 5;

        match self.remote_base_ts {
            None => {
                // First packet ever — establish the mapping.
                self.remote_base_ts = Some(remote_ts);
                self.ts_offset = self.local_base_ts as i64 - remote_ts as i64;
                self.last_remote_ts = Some(remote_ts);
                ((remote_ts as i64).wrapping_add(self.ts_offset)) as u32
            }
            Some(_) => {
                // Check for discontinuity against the last seen timestamp.
                if let Some(last) = self.last_remote_ts {
                    let fwd_delta = remote_ts.wrapping_sub(last);
                    let bwd_delta = last.wrapping_sub(remote_ts);

                    // Bug #14: Distinguish true backward jumps from wrapped-forward.
                    // If bwd_delta < max_delta, this is a genuine backward jump
                    // (e.g. stream reset), not a huge forward wrap.
                    let is_discontinuity = if bwd_delta < max_delta && bwd_delta < fwd_delta {
                        // True backward jump exceeding zero — always a discontinuity
                        true
                    } else {
                        fwd_delta > max_delta
                    };

                    if is_discontinuity {
                        // Large jump detected — reset the mapping.
                        // local_base_ts is where we "would have been" had the stream
                        // continued seamlessly (i.e. last normalised ts + one ptime).
                        // Bug #49: Use configured ptime instead of hardcoded 20ms
                        self.local_base_ts = ((last as i64).wrapping_add(self.ts_offset)) as u32;
                        self.local_base_ts = self.local_base_ts
                            .wrapping_add(self.samples_per_packet());
                        self.ts_offset = self.local_base_ts as i64 - remote_ts as i64;
                        self.remote_base_ts = Some(remote_ts);
                    }
                }

                self.last_remote_ts = Some(remote_ts);
                ((remote_ts as i64).wrapping_add(self.ts_offset)) as u32
            }
        }
    }

    /// Reset the normalizer (e.g. on SSRC change).
    /// Bug #41: Also reset local_base_ts to 0 to avoid stale timestamp base
    /// after SSRC change. The old comment "keep local_base_ts so that we
    /// continue from where we left off" caused the normalizer to produce
    /// timestamps with a stale offset when a new SSRC started a fresh stream.
    fn reset(&mut self) {
        self.remote_base_ts = None;
        self.ts_offset = 0;
        self.last_remote_ts = None;
        self.local_base_ts = 0;
    }
}

/// Comfort Noise payload type (RFC 3389)
const CN_PAYLOAD_TYPE: u8 = 13;

/// Default CN pacing multiplier: send CN every this many ptimes.
/// (e.g. 60 * 20ms = 1200ms at 20ms ptime).
const CN_PACING_PTIMES: u32 = 60;

/// Default CN noise level: 65 dBov (very quiet background noise).
const CN_DEFAULT_NOISE_LEVEL: u8 = 65;

/// RTCP payload types for mux discrimination (RFC 5761)
const RTCP_PT_MIN: u8 = 200;
/// Bug #25: Include RTCP-FB (205), PSFB (206), XR (207), and registered types up to 211
const RTCP_PT_MAX_RANGE: u8 = 211;

/// Check whether a packet is RTCP based on the second byte (payload type).
/// RTCP uses the full 8-bit PT field in byte 1 (values 200-211 per RFC 5761 §4),
/// including RTPFB (205, RFC 4585) and PSFB (206, RFC 4585).
fn is_rtcp_packet(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    let pt_byte = data[1];
    pt_byte >= RTCP_PT_MIN && pt_byte <= RTCP_PT_MAX_RANGE
}

/// RTP Engine configuration
#[derive(Debug, Clone)]
pub struct RtpEngineConfig {
    /// Codec type to use for sending
    pub codec: CodecType,
    /// SSRC (auto-generated if None)
    pub ssrc: Option<u32>,
    /// Jitter buffer config
    pub jitter_config: JitterConfig,
    /// Receive buffer size for channel
    pub recv_buffer_size: usize,
    /// DTMF buffer size for channel
    pub dtmf_buffer_size: usize,
    /// Enable RFC 2833 DTMF detection
    pub enable_dtmf: bool,
    /// DTMF payload type (default 101)
    pub dtmf_payload_type: u8,
    /// Media timeout in milliseconds (Fix 4, default 30000 = 30s)
    pub media_timeout_ms: u64,
    /// Enable RTCP-mux (RFC 5761): RTP and RTCP on the same port (Fix 6)
    pub rtcp_mux: bool,
    /// Receive codec type — if different from send codec (Fix 7, None = same as send)
    pub recv_codec: Option<CodecType>,
    /// Ptime in milliseconds (Fix 8, default 20ms)
    pub ptime_ms: u32,
    /// Send silence RTP packets when idle (Fix 14, default false)
    /// Prevents carriers/Sonus from timing out and dropping the call
    pub send_silence_when_idle: bool,
    /// Media timeout during hold in milliseconds (Bug #50, default 1800000 = 30 minutes)
    pub hold_media_timeout_ms: u64,
    /// Audio payload type for receive validation (Bug #47).
    /// When set to `Some(pt)`, non-DTMF/CN packets whose PT does not match
    /// are silently dropped (with a warning logged on the first mismatch).
    /// `None` means no filtering — accept any audio PT.
    pub audio_payload_type: Option<u8>,
}

impl Default for RtpEngineConfig {
    fn default() -> Self {
        Self {
            codec: CodecType::Pcmu,
            ssrc: None,
            jitter_config: JitterConfig::default(),
            recv_buffer_size: 100,
            dtmf_buffer_size: 32,
            enable_dtmf: true,
            dtmf_payload_type: TELEPHONE_EVENT_PT,
            media_timeout_ms: 30_000,
            rtcp_mux: false,
            recv_codec: None,
            ptime_ms: 20,
            send_silence_when_idle: false,
            hold_media_timeout_ms: 1_800_000,
            audio_payload_type: None,
        }
    }
}

/// RTP Engine for sending and receiving audio
pub struct RtpEngine {
    /// UDP socket
    socket: Arc<UdpSocket>,
    /// Local address
    local_addr: SocketAddr,
    /// Remote address
    remote_addr: Mutex<Option<SocketAddr>>,
    /// Send codec
    codec: G711Codec,
    /// Receive codec (Fix 7 — may differ from send codec)
    recv_codec: Mutex<G711Codec>,
    /// Packet builder for sending
    packet_builder: Mutex<RtpPacketBuilder>,
    /// SSRC
    ssrc: u32,
    /// Running flag
    running: AtomicBool,
    /// Jitter buffer
    jitter_buffer: Mutex<JitterBuffer>,
    /// Packet loss concealer
    plc: Mutex<PacketLossConcealer>,
    /// Config
    config: RtpEngineConfig,
    /// Receive channel sender (for background task)
    recv_tx: mpsc::Sender<Vec<i16>>,
    /// Receive channel receiver
    recv_rx: Mutex<mpsc::Receiver<Vec<i16>>>,
    /// RFC 2833 DTMF sender (behind Mutex for bug flag updates after User-Agent detection)
    dtmf_sender: Mutex<DtmfSender>,
    /// RFC 2833 DTMF detector
    dtmf_detector: Arc<DtmfDetector>,
    /// DTMF channel sender (for background task)
    dtmf_tx: mpsc::Sender<DetectedDtmf>,
    /// DTMF channel receiver
    dtmf_rx: Mutex<mpsc::Receiver<DetectedDtmf>>,

    // === Fix 4: Media timeout ===
    /// Timestamp of last received RTP packet
    last_rtp_received: Mutex<Option<Instant>>,
    /// Media timeout duration
    media_timeout_ms: u64,
    /// Broadcast sender for timeout notifications
    timeout_tx: broadcast::Sender<()>,

    // === Fix 5: Comfort Noise pacing ===
    /// Timestamp of last CN packet sent
    last_cn_timestamp: Mutex<Option<Instant>>,

    // === Fix 6: RTCP-mux ===
    /// Whether RTCP-mux is enabled
    rtcp_mux: AtomicBool,

    // === Fix 9: SSRC collision ===
    /// Tracked remote SSRC
    remote_ssrc: Mutex<Option<u32>>,

    // === Fix 10: Marker bit on restart ===
    /// Force marker bit on the next outgoing audio packet
    force_marker: AtomicBool,

    // === Fix 8: Ptime ===
    /// Packet time in milliseconds
    ptime_ms: AtomicU32,

    // === Fix 13: RTP timestamp normalization ===
    /// Normalizes remote RTP timestamps across hold/resume and call transfers
    timestamp_normalizer: Mutex<TimestampNormalizer>,

    // === Fix 14: Silence sending when idle ===
    /// Whether to send silence packets when no audio is being sent
    send_silence_when_idle: bool,
    /// Timestamp of last audio packet sent
    last_audio_sent: Mutex<Option<Instant>>,

    // === Fix 27: Port recycling ===
    /// Port allocated from the global port pool (if any), released on stop/drop.
    /// Bug #95: Uses parking_lot::Mutex instead of std::sync::Mutex
    allocated_port: Mutex<Option<u16>>,

    // === Fix 31: CN noise level ===
    /// Last received Comfort Noise level in dBov (0 = max noise, 127 = silence, RFC 3389)
    /// Bug #95: Uses parking_lot::Mutex instead of std::sync::Mutex
    last_cn_level: Mutex<Option<u8>>,

    /// Whether we are currently in a CNG silence period.
    /// When this is true and voice resumes, the marker bit must be set on the
    /// first audio packet (per RFC 3389 §4.1).
    in_cn_silence: AtomicBool,

    // === Bug #47: Audio payload type validation ===
    /// Negotiated audio payload type for receive filtering (None = accept any)
    audio_payload_type: Option<u8>,
    /// Whether we have already warned about an audio PT mismatch
    audio_pt_mismatch_warned: AtomicBool,

    // === Bug #24: Media timeout fires repeatedly ===
    /// Whether the timeout has already fired (prevents repeated broadcasts)
    timeout_fired: AtomicBool,

    // === Bug #50: Hold-specific media timeout ===
    /// Media timeout during hold (ms, default 1800000 = 30 minutes)
    hold_media_timeout_ms: u64,
    /// Whether currently in hold state (from SDP a=sendonly/a=inactive)
    is_on_hold: AtomicBool,

    // === Bug #94: Rate-limited warning for recv_tx.try_send drops ===
    /// Counter for dropped audio frames due to full recv channel
    recv_drop_count: AtomicU64,
}

impl RtpEngine {
    /// Create a new RTP engine bound to the specified address
    pub async fn new(local_addr: SocketAddr, config: RtpEngineConfig) -> Result<Self> {
        let socket = UdpSocket::bind(local_addr).await?;
        let actual_addr = socket.local_addr()?;

        let ssrc = config.ssrc.unwrap_or_else(rand::random);
        let codec = G711Codec::new(config.codec);
        let recv_codec_type = config.recv_codec.unwrap_or(config.codec);
        let recv_codec = G711Codec::new(recv_codec_type);
        let packet_builder = RtpPacketBuilder::new(config.codec.payload_type(), ssrc);

        let (recv_tx, recv_rx) = mpsc::channel(config.recv_buffer_size);
        let (dtmf_tx, dtmf_rx) = mpsc::channel(config.dtmf_buffer_size);
        let (timeout_tx, _) = broadcast::channel(16);

        // Create DTMF sender and detector with configured payload type
        let dtmf_sender = DtmfSender::with_payload_type(ssrc, config.dtmf_payload_type);
        let dtmf_detector = Arc::new(DtmfDetector::with_payload_type(config.dtmf_payload_type));

        let media_timeout_ms = config.media_timeout_ms;
        let hold_media_timeout_ms = config.hold_media_timeout_ms;
        let rtcp_mux = config.rtcp_mux;
        let ptime_ms = config.ptime_ms;
        let send_silence_when_idle = config.send_silence_when_idle;
        let audio_payload_type = config.audio_payload_type;
        let sample_rate = config.codec.sample_rate();

        Ok(Self {
            socket: Arc::new(socket),
            local_addr: actual_addr,
            remote_addr: Mutex::new(None),
            codec,
            recv_codec: Mutex::new(recv_codec),
            packet_builder: Mutex::new(packet_builder),
            ssrc,
            running: AtomicBool::new(false),
            jitter_buffer: Mutex::new(JitterBuffer::with_config(config.jitter_config.clone())),
            plc: Mutex::new(PacketLossConcealer::new(
                config.codec.samples_per_frame(config.ptime_ms),
            )),
            config,
            recv_tx,
            recv_rx: Mutex::new(recv_rx),
            dtmf_sender: Mutex::new(dtmf_sender),
            dtmf_detector,
            dtmf_tx,
            dtmf_rx: Mutex::new(dtmf_rx),
            last_rtp_received: Mutex::new(None),
            media_timeout_ms,
            timeout_tx,
            last_cn_timestamp: Mutex::new(None),
            rtcp_mux: AtomicBool::new(rtcp_mux),
            remote_ssrc: Mutex::new(None),
            force_marker: AtomicBool::new(false),
            ptime_ms: AtomicU32::new(ptime_ms),
            timestamp_normalizer: Mutex::new(TimestampNormalizer::with_ptime(sample_rate, ptime_ms)),
            send_silence_when_idle,
            last_audio_sent: Mutex::new(None),
            allocated_port: Mutex::new(None),
            last_cn_level: Mutex::new(None),
            recv_drop_count: AtomicU64::new(0),
            in_cn_silence: AtomicBool::new(false),
            audio_payload_type,
            audio_pt_mismatch_warned: AtomicBool::new(false),
            timeout_fired: AtomicBool::new(false),
            hold_media_timeout_ms,
            is_on_hold: AtomicBool::new(false),
        })
    }

    /// Create with default config
    pub async fn with_defaults(local_addr: SocketAddr) -> Result<Self> {
        Self::new(local_addr, RtpEngineConfig::default()).await
    }

    /// Get local address
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get SSRC
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Get send codec type
    pub fn codec_type(&self) -> CodecType {
        self.config.codec
    }

    /// Set remote endpoint address
    pub fn set_remote(&self, addr: SocketAddr) {
        *self.remote_addr.lock() = Some(addr);
    }

    /// Get remote endpoint address
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        *self.remote_addr.lock()
    }

    /// Set RTP bug workaround flags for DTMF sender
    ///
    /// Called after User-Agent header is detected to enable device-specific
    /// workarounds (Sonus, Cisco, etc). See `RtpBugFlags::detect_from_user_agent()`.
    pub fn set_rtp_bug_flags(&self, flags: RtpBugFlags) {
        self.dtmf_sender.lock().set_rtp_bugs(flags);
    }

    /// Get current RTP bug flags
    pub fn rtp_bug_flags(&self) -> RtpBugFlags {
        self.dtmf_sender.lock().rtp_bugs()
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    // ========== Fix 4: Media Timeout ==========

    /// Get the instant of the last received RTP packet
    pub fn last_rtp_received(&self) -> Option<Instant> {
        *self.last_rtp_received.lock()
    }

    /// Check whether the media stream has timed out
    /// Bug #R11-2: Use effective_media_timeout() to respect hold state.
    /// Previously used raw media_timeout_ms, which would incorrectly report
    /// timeout during hold when the hold timeout (30min) should apply.
    pub fn is_media_timed_out(&self) -> bool {
        if let Some(last) = *self.last_rtp_received.lock() {
            last.elapsed() >= self.effective_media_timeout()
        } else {
            false
        }
    }

    /// Subscribe to media timeout notifications.
    /// A message is sent on the channel when the media timeout fires.
    pub fn media_timeout_rx(&self) -> broadcast::Receiver<()> {
        self.timeout_tx.subscribe()
    }

    // ========== Fix 31: CN noise level ==========

    /// Get the last received Comfort Noise level in dBov (RFC 3389).
    /// 0 = maximum noise, 127 = digital silence. Returns `None` if no CN
    /// packet has been received yet.
    pub fn last_cn_level(&self) -> Option<u8> {
        // Bug #95: parking_lot::Mutex never poisons, so just .lock()
        *self.last_cn_level.lock()
    }

    /// Compute a PCM amplitude from the last received CN level (Fix 31).
    /// Uses a simple mapping: `amplitude = (127 - level) * 2`, giving a rough
    /// i16 sample range suitable for generating low-level comfort noise.
    /// Returns 0 if no CN level has been received.
    pub fn cn_amplitude(&self) -> i16 {
        match self.last_cn_level() {
            Some(level) => ((127u16.saturating_sub(level as u16)) * 2) as i16,
            None => 0,
        }
    }

    // ========== Fix 6: RTCP-mux ==========

    /// Enable or disable RTCP-mux (RFC 5761)
    pub fn enable_rtcp_mux(&self, enabled: bool) {
        self.rtcp_mux.store(enabled, Ordering::Relaxed);
    }

    /// Check if RTCP-mux is enabled
    pub fn is_rtcp_mux_enabled(&self) -> bool {
        self.rtcp_mux.load(Ordering::Relaxed)
    }

    // ========== Fix 7: Codec Asymmetry ==========

    /// Set the receive codec (different from send codec)
    pub fn set_recv_codec(&self, codec_type: CodecType) {
        *self.recv_codec.lock() = G711Codec::new(codec_type);
    }

    /// Get the current receive codec type
    pub fn recv_codec_type(&self) -> CodecType {
        self.recv_codec.lock().codec_type()
    }

    // ========== Fix 8: Ptime ==========

    /// Get the current ptime in milliseconds
    pub fn ptime(&self) -> u32 {
        self.ptime_ms.load(Ordering::Relaxed)
    }

    /// Set the ptime in milliseconds
    pub fn set_ptime(&self, ptime_ms: u32) {
        self.ptime_ms.store(ptime_ms, Ordering::Relaxed);
        // Bug #49: Keep timestamp normalizer in sync with current ptime
        self.timestamp_normalizer.lock().set_ptime(ptime_ms);
    }

    /// Get samples per packet based on current ptime and codec sample rate
    pub fn samples_per_packet(&self) -> u32 {
        let ptime = self.ptime_ms.load(Ordering::Relaxed);
        self.config.codec.sample_rate() * ptime / 1000
    }

    // ========== Bug #50: Hold-Specific Media Timeout ==========

    /// Set hold state (from SDP a=sendonly/a=inactive detection)
    pub fn set_hold_state(&self, on_hold: bool) {
        self.is_on_hold.store(on_hold, Ordering::Relaxed);
        tracing::debug!(on_hold, "RTP hold state changed");
    }

    /// Get current hold state
    pub fn is_on_hold(&self) -> bool {
        self.is_on_hold.load(Ordering::Relaxed)
    }

    /// Get effective media timeout based on hold state.
    /// Returns the hold timeout (default 30 min) when on hold,
    /// otherwise the normal media timeout (default 30s).
    pub fn effective_media_timeout(&self) -> Duration {
        if self.is_on_hold.load(Ordering::Relaxed) {
            Duration::from_millis(self.hold_media_timeout_ms)
        } else {
            Duration::from_millis(self.media_timeout_ms)
        }
    }

    // ========== Fix 9: SSRC Collision ==========

    /// Get the currently tracked remote SSRC
    pub fn remote_ssrc(&self) -> Option<u32> {
        *self.remote_ssrc.lock()
    }

    // ========== Bug #48: Full stream state reset ==========

    /// Reset all stream-processing state.
    ///
    /// This must be called whenever the remote SSRC changes (SSRC collision
    /// recovery). Previously only the jitter buffer was reset; this method
    /// also resets the DTMF detector, PLC, timestamp normalizer, and the
    /// audio PT mismatch warning flag so they don't carry stale state from
    /// the old stream.
    pub fn reset_stream_state(&self) {
        self.jitter_buffer.lock().reset();
        self.dtmf_detector.reset();
        self.plc.lock().reset();
        self.timestamp_normalizer.lock().reset();
        // Reset the audio PT mismatch warning so it fires again for the new stream
        self.audio_pt_mismatch_warned.store(false, Ordering::Relaxed);
        tracing::debug!("Full stream state reset (jitter buffer, DTMF detector, PLC, timestamp normalizer)");
    }

    // ========== Fix 10: Marker Bit Restart ==========

    /// Request that the next outgoing audio packet carries the marker bit
    /// (e.g. after hold/resume or stream restart).
    pub fn request_marker(&self) {
        self.force_marker.store(true, Ordering::Relaxed);
    }

    // ========== Core Engine Methods ==========

    /// Start the receive loop
    pub fn start(self: &Arc<Self>) -> Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(RtpSipError::AlreadyStarted);
        }

        let engine = self.clone();
        let dtmf_detector = self.dtmf_detector.clone();
        let dtmf_tx = self.dtmf_tx.clone();
        let dtmf_enabled = self.config.enable_dtmf;
        let dtmf_pt = self.config.dtmf_payload_type;

        // === Fix 4: Spawn media timeout check task ===
        // === Bug #2/#50 fix: dynamically read the effective timeout
        // based on current hold state instead of using a captured value. ===
        {
            let engine_timeout = self.clone();
            let timeout_tx = self.timeout_tx.clone();
            tokio::spawn(async move {
                let check_interval = Duration::from_secs(5);
                while engine_timeout.running.load(Ordering::Relaxed) {
                    tokio::time::sleep(check_interval).await;
                    let effective_timeout = engine_timeout.effective_media_timeout();
                    if let Some(last) = *engine_timeout.last_rtp_received.lock() {
                        if last.elapsed() >= effective_timeout {
                            // Bug #24: Only broadcast on transition from not-fired to fired
                            if !engine_timeout.timeout_fired.swap(true, Ordering::SeqCst) {
                                let _ = timeout_tx.send(());
                            }
                        }
                    }
                }
            });
        }

        // === Fix 14: Spawn silence-when-idle task ===
        // Bug #36: Note: Silence task and user send_audio both acquire packet_builder lock,
        // which serializes them. Race is benign as parking_lot::Mutex ensures ordering.
        if self.send_silence_when_idle {
            let engine_silence = self.clone();
            tokio::spawn(async move {
                while engine_silence.running.load(Ordering::Relaxed) {
                    // Bug #17: Read ptime inside the loop so dynamic changes are picked up
                    let ptime_ms = engine_silence.ptime_ms.load(Ordering::Relaxed);
                    let samples_per_pkt = engine_silence.samples_per_packet() as usize;
                    let interval = Duration::from_millis(ptime_ms as u64);
                    tokio::time::sleep(interval).await;
                    let should_send = {
                        let last = engine_silence.last_audio_sent.lock();
                        match *last {
                            Some(t) => t.elapsed() > interval,
                            None => true, // No audio ever sent — send silence
                        }
                    };
                    if should_send {
                        if engine_silence.remote_addr().is_some() {
                            let silence = vec![0i16; samples_per_pkt];
                            let _ = engine_silence.send_audio(&silence).await;
                        }
                    }
                }
            });
        }

        // Spawn receive task
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];

            while engine.running.load(Ordering::Relaxed) {
                match tokio::time::timeout(
                    Duration::from_millis(100),
                    engine.socket.recv_from(&mut buf),
                )
                .await
                {
                    Ok(Ok((len, _addr))) => {
                        let data = &buf[..len];

                        // Minimum RTP header size check (12 bytes per RFC 3550)
                        if data.len() < 12 {
                            continue;
                        }

                        // === Fix 6: RTCP-mux discrimination ===
                        // When RTCP-mux is enabled, check if this is an RTCP packet.
                        // RTCP packets have payload type 200-204 or 207 in the second byte.
                        // The full byte is used (no masking) because RTCP PT values (>=200)
                        // have bit 7 set and masking with 0x7F would prevent identification.
                        if engine.rtcp_mux.load(Ordering::Relaxed) && is_rtcp_packet(data) {
                            // Bug #24: Log RTCP packet type instead of silently dropping.
                            // TODO: Forward RTCP to RtcpSession for SR/RR/BYE processing
                            let rtcp_pt = data[1];
                            tracing::debug!(
                                rtcp_payload_type = rtcp_pt,
                                len = data.len(),
                                "Received RTCP packet on muxed port (not yet processed)"
                            );
                            continue;
                        }

                        if let Ok(mut packet) = parse_rtp_packet(data) {
                            // Bug #12: Reject packets with invalid RTP version
                            if packet.header.version != 2 {
                                continue;
                            }

                            // RFC 3550 §5.1: Strip padding bytes when padding bit is set.
                            // The last byte of the payload indicates the total number of
                            // padding bytes (including itself) to remove.
                            if packet.header.padding && !packet.payload.is_empty() {
                                let pad_len =
                                    *packet.payload.last().unwrap() as usize;
                                if pad_len == 0 || pad_len > packet.payload.len() {
                                    continue; // malformed padding
                                }
                                packet.payload =
                                    packet.payload.slice(..packet.payload.len() - pad_len);
                            }

                            let pt = packet.header.payload_type;
                            let pkt_ssrc = packet.header.ssrc;

                            // Bug #39: Check own-SSRC collision BEFORE updating timeout
                            // to prevent spoofed/looped packets from keeping timeout alive
                            if pkt_ssrc == engine.ssrc {
                                tracing::warn!(
                                    ssrc = pkt_ssrc,
                                    "SSRC collision: received packet with our own SSRC, dropping"
                                );
                                continue;
                            }

                            // === Fix 4: Update last RTP received timestamp ===
                            *engine.last_rtp_received.lock() = Some(Instant::now());
                            // Bug #24: Clear timeout_fired flag when new RTP arrives
                            engine.timeout_fired.store(false, Ordering::SeqCst);

                            // === Fix 9 + Bug #48: SSRC collision detection ===
                            {
                                let mut remote = engine.remote_ssrc.lock();
                                if let Some(prev_ssrc) = *remote {
                                    if pkt_ssrc != prev_ssrc {
                                        tracing::warn!(
                                            "SSRC change: {} -> {}, resetting stream state",
                                            prev_ssrc,
                                            pkt_ssrc,
                                        );
                                        // Bug #48: Reset ALL stream state, not just the
                                        // jitter buffer. Drop the remote_ssrc lock first
                                        // to avoid deadlock since reset_stream_state
                                        // acquires other locks.
                                        *remote = Some(pkt_ssrc);
                                        drop(remote);
                                        engine.reset_stream_state();
                                    }
                                } else {
                                    *remote = Some(pkt_ssrc);
                                }
                            }

                            // Check if this is a DTMF packet (RFC 2833)
                            if dtmf_enabled && pt == dtmf_pt {
                                // Route to DTMF detector
                                if let Some(detected) = dtmf_detector.process_rtp(
                                    pt,
                                    packet.header.sequence_number,
                                    packet.header.timestamp,
                                    &packet.payload,
                                ) {
                                    let _ = dtmf_tx.try_send(detected);
                                }
                                continue; // Don't process as audio
                            }

                            // === Bug #47: Audio payload type validation ===
                            // After DTMF has been handled, check if the PT
                            // matches the negotiated audio codec PT. Skip
                            // CN packets (handled below) and unrecognized PTs.
                            if let Some(expected_audio_pt) = engine.audio_payload_type {
                                if pt != expected_audio_pt && pt != CN_PAYLOAD_TYPE {
                                    if !engine.audio_pt_mismatch_warned.swap(true, Ordering::Relaxed) {
                                        tracing::warn!(
                                            expected = expected_audio_pt,
                                            actual = pt,
                                            "Dropping packet with unexpected audio payload type"
                                        );
                                    }
                                    continue;
                                }
                            }

                            // === Fix 5 + Fix 31: Handle incoming Comfort Noise (PT 13) ===
                            if pt == CN_PAYLOAD_TYPE {
                                // Fix 31: Parse the first byte as noise level in dBov
                                // (RFC 3389: 0 = max noise, 127 = silence).
                                if !packet.payload.is_empty() {
                                    let level = packet.payload[0];
                                    {
                                        let mut cn = engine.last_cn_level.lock();
                                        *cn = Some(level);
                                    }
                                }

                                // Inbound CNG synthesis: use PLC to generate a smooth
                                // concealment frame instead of abrupt silence. The PLC
                                // produces a pitch-repeated fade-out from the last audio,
                                // which sounds better than hard silence or random noise.
                                let cng_audio = engine.plc.lock().conceal();
                                // Bug #94: Rate-limited warning on channel full
                                if let Err(mpsc::error::TrySendError::Full(_)) = engine.recv_tx.try_send(cng_audio) {
                                    let count = engine.recv_drop_count.fetch_add(1, Ordering::Relaxed) + 1;
                                    if count % 100 == 1 {
                                        tracing::warn!(
                                            total_drops = count,
                                            "recv_tx channel full, dropping audio frame"
                                        );
                                    }
                                }

                                continue;
                            }

                            // === Fix 13: Normalize remote timestamp before jitter buffer ===
                            let mut packet = packet;
                            packet.header.timestamp = engine
                                .timestamp_normalizer
                                .lock()
                                .normalize(packet.header.timestamp);

                            // Bug #40: Acquire jitter buffer lock once for marker-bit
                            // reset, duplicate detection, push, and pop instead of
                            // locking 3+ separate times per received packet.
                            // Bug #11: Pop in a loop until pop() returns None to drain
                            // multiple ready packets, preventing buffer growth under burst.
                            let popped_packets: Vec<rtp::packet::Packet> = {
                                let mut jb = engine.jitter_buffer.lock();

                                // Bug #18: Marker bit on incoming — reset jitter buffer
                                // initial buffering state to reduce latency on stream restart
                                if packet.header.marker {
                                    jb.reset_initial_buffering();
                                }

                                // Bug #19: Duplicate packet detection — skip if seq already buffered
                                if jb.contains_seq(packet.header.sequence_number) {
                                    continue;
                                }

                                // Push raw encoded packet to jitter buffer (decode only on pop)
                                jb.push(packet);

                                // Bug #11: Pop all available packets, not just one
                                let mut packets = Vec::new();
                                while let Some(jb_packet) = jb.pop() {
                                    packets.push(jb_packet);
                                }
                                packets
                            };

                            if !popped_packets.is_empty() {
                                for jb_packet in popped_packets {
                                    // === Fix 7: Decode with receive codec ===
                                    let samples = engine.recv_codec.lock().decode(&jb_packet.payload);
                                    // Update PLC with the decoded samples
                                    engine.plc.lock().update(&samples);
                                    // Bug #94: Rate-limited warning on channel full
                                    if let Err(mpsc::error::TrySendError::Full(_)) = engine.recv_tx.try_send(samples) {
                                        let count = engine.recv_drop_count.fetch_add(1, Ordering::Relaxed) + 1;
                                        if count % 100 == 1 {
                                            tracing::warn!(
                                                total_drops = count,
                                                "recv_tx channel full, dropping audio frame"
                                            );
                                        }
                                    }
                                }
                            } else {
                                // No packets popped — check if we should conceal
                                let jb_ready = engine.jitter_buffer.lock().is_ready();
                                if jb_ready {
                                    // Packet was lost, use PLC
                                    let audio = engine.plc.lock().conceal();
                                    if let Err(mpsc::error::TrySendError::Full(_)) = engine.recv_tx.try_send(audio) {
                                        let count = engine.recv_drop_count.fetch_add(1, Ordering::Relaxed) + 1;
                                        if count % 100 == 1 {
                                            tracing::warn!(
                                                total_drops = count,
                                                "recv_tx channel full, dropping audio frame"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("RTP receive error: {}", e);
                    }
                    Err(_) => {
                        // Timeout - continue loop
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop the engine
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);

        // === Fix 27: Release allocated port back to the pool ===
        // Bug #95: parking_lot::Mutex never poisons, so just .lock()
        if let Some(p) = self.allocated_port.lock().take() {
            release_rtp_port(p);
        }
    }

    /// Register an allocated port so it will be released on stop/drop (Fix 27).
    pub fn set_allocated_port(&self, port: u16) {
        *self.allocated_port.lock() = Some(port);
    }

    /// Send audio samples (PCM i16, 8kHz mono)
    pub async fn send_audio(&self, samples: &[i16]) -> Result<()> {
        let remote = self
            .remote_addr
            .lock()
            .ok_or(RtpSipError::NotConnected)?;

        // === Fix 10: Check if marker bit should be forced ===
        // Also set marker when transitioning from CN silence back to voice
        // (RFC 3389 §4.1: marker bit on first voice packet after CNG)
        let force = self.force_marker.swap(false, Ordering::Relaxed);
        let cn_resume = self.in_cn_silence.swap(false, Ordering::Relaxed);
        let marker = force || cn_resume;

        // Encode samples with the send codec
        let encoded = self.codec.encode(samples);

        // Build packet (with or without marker)
        let packet = if marker {
            self.packet_builder
                .lock()
                .build_with_marker(Bytes::from(encoded), samples.len() as u32, true)
        } else {
            self.packet_builder
                .lock()
                .build(Bytes::from(encoded), samples.len() as u32)
        };

        // Serialize and send
        let data = serialize_rtp_packet(&packet)?;
        self.socket.send_to(&data, remote).await?;

        // Track last audio send time for silence-when-idle (Fix 14)
        *self.last_audio_sent.lock() = Some(Instant::now());

        Ok(())
    }

    /// Send audio with marker bit set
    pub async fn send_audio_with_marker(&self, samples: &[i16], marker: bool) -> Result<()> {
        let remote = self
            .remote_addr
            .lock()
            .ok_or(RtpSipError::NotConnected)?;

        // Bug #8: Also consume force_marker and in_cn_silence flags
        let force = self.force_marker.swap(false, Ordering::Relaxed);
        let cn_resume = self.in_cn_silence.swap(false, Ordering::Relaxed);
        let effective_marker = marker || force || cn_resume;

        let encoded = self.codec.encode(samples);
        let packet = self
            .packet_builder
            .lock()
            .build_with_marker(Bytes::from(encoded), samples.len() as u32, effective_marker);

        let data = serialize_rtp_packet(&packet)?;
        self.socket.send_to(&data, remote).await?;

        // Track last audio send time for silence-when-idle (Fix 14)
        *self.last_audio_sent.lock() = Some(Instant::now());

        Ok(())
    }

    /// Send Comfort Noise packet (RFC 3389)
    ///
    /// Sends a CN packet with payload type 13 and a 2-byte payload
    /// `[noise_level, 0]`.
    ///
    /// Pacing: CN packets are sent at most every `60 * ptime_ms` milliseconds
    /// (e.g. 1200ms at 20ms ptime).
    ///
    /// If we previously received a CN packet from the remote (Fix 31), we
    /// echo that noise level; otherwise we compute from the supplied PCM samples.
    ///
    /// Sets the `in_cn_silence` flag so that the next `send_audio()` call
    /// will automatically set the marker bit (RFC 3389 §4.1).
    ///
    /// Returns `Ok(true)` if a packet was actually sent, `Ok(false)` if
    /// pacing suppressed the send.
    pub async fn send_comfort_noise(&self, samples: &[i16]) -> Result<bool> {
        let remote = self
            .remote_addr
            .lock()
            .ok_or(RtpSipError::NotConnected)?;

        // CN pacing: send every ~60 ptimes
        let cn_interval_ms = CN_PACING_PTIMES as u64
            * self.ptime_ms.load(Ordering::Relaxed) as u64;
        {
            let last_cn = self.last_cn_timestamp.lock();
            if let Some(last) = *last_cn {
                if last.elapsed().as_millis() < cn_interval_ms as u128 {
                    return Ok(false);
                }
            }
            // Bug #R8-3: Don't update timestamp here — update after successful send
            // to avoid suppressing retries when socket.send_to() fails.
        }

        // Fix 31: If we have a received CN level, echo it back; otherwise
        // use the default of 65 dBov.
        // Bug #95: parking_lot::Mutex never poisons, so just .lock()
        let dbov = match *self.last_cn_level.lock() {
            Some(level) => level,
            None => CN_DEFAULT_NOISE_LEVEL,
        };

        // 2-byte CN payload: [noise_level, 0] (RFC 3389)
        let cn_payload = vec![dbov, 0];

        // Bug #13: Set marker=true on the first CN packet of a silence period
        let is_first_cn = !self.in_cn_silence.load(Ordering::Relaxed);

        // Bug #14: Use samples_per_packet() for timestamp increment instead of
        // samples.len(), which may not match the configured ptime
        let mut packet = self.packet_builder.lock().build_with_marker(
            Bytes::from(cn_payload),
            self.samples_per_packet(),
            is_first_cn,
        );

        // Set the correct payload type for Comfort Noise before serialization
        packet.header.payload_type = CN_PAYLOAD_TYPE;

        let data = serialize_rtp_packet(&packet)?;
        self.socket.send_to(&data, remote).await?;

        // Bug #R8-3: Update CN pacing timestamp only after successful send
        *self.last_cn_timestamp.lock() = Some(Instant::now());

        // Mark that we're in CN silence — next voice packet gets marker bit
        self.in_cn_silence.store(true, Ordering::Relaxed);

        Ok(true)
    }

    /// Receive audio samples (PCM i16, 8kHz mono)
    /// Returns None if no audio is available
    pub fn recv_audio_try(&self) -> Result<Option<Vec<i16>>> {
        match self.recv_rx.lock().try_recv() {
            Ok(samples) => Ok(Some(samples)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(RtpSipError::ChannelClosed),
        }
    }

    /// Receive audio samples with timeout (blocking version for sync API)
    ///
    /// Note: This method blocks the thread. Only call from synchronous/blocking
    /// context, never from async tasks.
    pub fn recv_audio_blocking(&self, timeout: Duration) -> Result<Option<Vec<i16>>> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match self.recv_rx.lock().try_recv() {
                Ok(samples) => return Ok(Some(samples)),
                Err(mpsc::error::TryRecvError::Empty) => {
                    if std::time::Instant::now() >= deadline {
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    return Err(RtpSipError::ChannelClosed)
                }
            }
        }
    }

    /// Get jitter buffer statistics
    pub fn jitter_stats(&self) -> JitterStats {
        self.jitter_buffer.lock().stats()
    }

    /// Reset jitter buffer
    pub fn reset_jitter_buffer(&self) {
        self.jitter_buffer.lock().reset();
        self.plc
            .lock()
            .update(&vec![0i16; self.config.codec.samples_per_frame(self.config.ptime_ms)]);
    }

    // ========== RFC 2833 DTMF Methods ==========

    /// Send a DTMF digit via RFC 2833 (telephone-event)
    ///
    /// This sends the complete digit sequence (start, continuation, end packets).
    /// The digit is sent over approximately `duration_ms` milliseconds.
    pub async fn send_dtmf(&self, digit: char, duration_ms: u32) -> Result<()> {
        let remote = self
            .remote_addr
            .lock()
            .ok_or(RtpSipError::NotConnected)?;

        // Get shared sequence counter and current audio timestamp from packet_builder
        let (mut seq, audio_ts) = {
            let pb = self.packet_builder.lock();
            (pb.sequence(), pb.timestamp())
        };

        // Bug #R6-7: Use actual ptime instead of hardcoded 20ms, matching FreeSWITCH
        let ptime = self.ptime_ms.load(Ordering::Relaxed);
        // Generate all packets for this digit using configured ptime intervals
        // Uses shared sequence space per RFC 4733 §2.5
        let packets = self
            .dtmf_sender
            .lock()
            .generate_digit(digit, duration_ms, ptime, &mut seq, audio_ts)?;

        // Update the packet_builder's sequence to stay in sync
        {
            let mut pb = self.packet_builder.lock();
            pb.set_sequence(seq);
        }

        // Send packets with proper timing
        for (i, packet) in packets.iter().enumerate() {
            let data = packet.to_rtp_bytes();
            self.socket.send_to(&data, remote).await?;

            // Wait between packets (except for end packets which are sent rapidly)
            // Bug #R9-3: Use configured ptime instead of hardcoded 20ms
            if i < packets.len().saturating_sub(3) {
                let ptime = self.ptime_ms.load(Ordering::Relaxed) as u64;
                tokio::time::sleep(Duration::from_millis(ptime)).await;
            }
        }

        Ok(())
    }

    /// Send multiple DTMF digits with inter-digit delay
    pub async fn send_dtmf_string(
        &self,
        digits: &str,
        duration_ms: u32,
        inter_digit_ms: u32,
    ) -> Result<()> {
        if digits.is_empty() {
            return Ok(());
        }

        for (i, digit) in digits.chars().enumerate() {
            self.send_dtmf(digit, duration_ms).await?;

            // Inter-digit delay (except after last digit)
            if i < digits.len() - 1 {
                tokio::time::sleep(Duration::from_millis(inter_digit_ms as u64)).await;
            }
        }
        Ok(())
    }

    /// Receive detected DTMF digit (non-blocking)
    ///
    /// Returns None if no DTMF is available
    pub fn recv_dtmf_try(&self) -> Result<Option<DetectedDtmf>> {
        match self.dtmf_rx.lock().try_recv() {
            Ok(dtmf) => Ok(Some(dtmf)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(RtpSipError::ChannelClosed),
        }
    }

    /// Receive detected DTMF digit with timeout (blocking)
    pub fn recv_dtmf_blocking(&self, timeout: Duration) -> Result<Option<DetectedDtmf>> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match self.dtmf_rx.lock().try_recv() {
                Ok(dtmf) => return Ok(Some(dtmf)),
                Err(mpsc::error::TryRecvError::Empty) => {
                    if std::time::Instant::now() >= deadline {
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    return Err(RtpSipError::ChannelClosed)
                }
            }
        }
    }

    /// Check if DTMF detection is enabled
    pub fn is_dtmf_enabled(&self) -> bool {
        self.config.enable_dtmf
    }

    /// Get the configured DTMF payload type
    pub fn dtmf_payload_type(&self) -> u8 {
        self.config.dtmf_payload_type
    }

    /// Reset the DTMF detector state
    pub fn reset_dtmf_detector(&self) {
        self.dtmf_detector.reset();
    }
}

// ========== Fix 27: Drop impl for port recycling ==========

impl Drop for RtpEngine {
    fn drop(&mut self) {
        // Bug #25: Ensure running flag is set to false so background tasks stop
        self.running.store(false, Ordering::SeqCst);
        // Bug #95: parking_lot::Mutex never poisons, so just .lock()
        if let Some(p) = self.allocated_port.lock().take() {
            release_rtp_port(p);
        }
    }
}

// ========== Fix 5 helpers ==========

/// Compute RMS energy of PCM samples (used in tests)
#[cfg(test)]
fn compute_rms_energy(samples: &[i16]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let sum_sq: f64 = samples.iter().map(|&s| (s as f64) * (s as f64)).sum();
    (sum_sq / samples.len() as f64).sqrt()
}

/// Convert RMS amplitude to dBov (decibels relative to overload, RFC 3389).
/// Full-scale 16-bit audio (32767) = 0 dBov.
/// Returns a u8 noise level byte where 0 = full-scale, 127 = digital silence.
#[cfg(test)]
fn rms_to_dbov(rms: f64) -> u8 {
    if rms < 1.0 {
        return 127; // silence
    }
    let db = 20.0 * (rms / 32767.0).log10();
    let level = (-db).round() as i32;
    level.clamp(0, 127) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rtp_engine_creation() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let engine = RtpEngine::with_defaults(addr).await.unwrap();

        // Should bind to an ephemeral port
        assert_ne!(engine.local_addr().port(), 0);
        assert_eq!(engine.codec_type(), CodecType::Pcmu);
    }

    #[tokio::test]
    async fn test_rtp_engine_set_remote() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let engine = RtpEngine::with_defaults(addr).await.unwrap();

        assert!(engine.remote_addr().is_none());

        let remote: SocketAddr = "192.168.1.1:5004".parse().unwrap();
        engine.set_remote(remote);

        assert_eq!(engine.remote_addr(), Some(remote));
    }

    #[tokio::test]
    async fn test_rtp_loopback() {
        // Create two engines with shorter jitter buffer delay for testing
        let addr1: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let config = RtpEngineConfig {
            jitter_config: crate::rtp::jitter::JitterConfig {
                target_delay_ms: 20,
                min_delay_ms: 10,
                ..Default::default()
            },
            ..Default::default()
        };

        let engine1 = Arc::new(RtpEngine::new(addr1, config.clone()).await.unwrap());
        let engine2 = Arc::new(RtpEngine::new(addr2, config).await.unwrap());

        // Point them at each other
        engine1.set_remote(engine2.local_addr());
        engine2.set_remote(engine1.local_addr());

        // Start receivers
        engine1.start().unwrap();
        engine2.start().unwrap();

        // Send multiple packets to fill jitter buffer
        let samples: Vec<i16> = (0..160).map(|i| (i * 100) as i16).collect();
        for _ in 0..5 {
            engine1.send_audio(&samples).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Give time for packets to arrive
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Receive
        let received = engine2.recv_audio_blocking(Duration::from_millis(500)).unwrap();

        // G.711 is lossy, so we can't compare exactly
        assert!(received.is_some());
        let recv_samples = received.unwrap();
        assert_eq!(recv_samples.len(), 160);

        // Stop engines
        engine1.stop();
        engine2.stop();
    }

    #[tokio::test]
    async fn test_rtp_dtmf_loopback() {
        // Create two engines for DTMF loopback test
        let addr1: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let config = RtpEngineConfig {
            enable_dtmf: true,
            ..Default::default()
        };

        let engine1 = Arc::new(RtpEngine::new(addr1, config.clone()).await.unwrap());
        let engine2 = Arc::new(RtpEngine::new(addr2, config).await.unwrap());

        // Point them at each other
        engine1.set_remote(engine2.local_addr());
        engine2.set_remote(engine1.local_addr());

        // Start receivers
        engine1.start().unwrap();
        engine2.start().unwrap();

        // Send DTMF digit '5' from engine1
        engine1.send_dtmf('5', 100).await.unwrap();

        // Give time for packets to arrive and be processed
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Receive DTMF on engine2
        let detected = engine2.recv_dtmf_blocking(Duration::from_millis(500)).unwrap();
        assert!(detected.is_some());
        assert_eq!(detected.unwrap().digit, '5');

        // Stop engines
        engine1.stop();
        engine2.stop();
    }

    #[tokio::test]
    async fn test_rtp_dtmf_config() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // Test with DTMF enabled (default)
        let engine = RtpEngine::with_defaults(addr).await.unwrap();
        assert!(engine.is_dtmf_enabled());
        assert_eq!(engine.dtmf_payload_type(), 101);

        // Test with DTMF disabled
        let config = RtpEngineConfig {
            enable_dtmf: false,
            dtmf_payload_type: 96,
            ..Default::default()
        };
        let addr2: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let engine2 = RtpEngine::new(addr2, config).await.unwrap();
        assert!(!engine2.is_dtmf_enabled());
        assert_eq!(engine2.dtmf_payload_type(), 96);
    }

    // === Fix 4: Media timeout tests ===

    #[tokio::test]
    async fn test_media_timeout_initial() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = RtpEngineConfig {
            media_timeout_ms: 100,
            ..Default::default()
        };
        let engine = RtpEngine::new(addr, config).await.unwrap();

        // No RTP received yet — should not be timed out
        assert!(!engine.is_media_timed_out());
        assert!(engine.last_rtp_received().is_none());
    }

    #[tokio::test]
    async fn test_media_timeout_subscribe() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = RtpEngineConfig {
            media_timeout_ms: 100,
            ..Default::default()
        };
        let engine = RtpEngine::new(addr, config).await.unwrap();

        // Should be able to subscribe
        let _rx = engine.media_timeout_rx();
    }

    // === Fix 6: RTCP-mux tests ===

    #[tokio::test]
    async fn test_rtcp_mux_toggle() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let engine = RtpEngine::with_defaults(addr).await.unwrap();

        assert!(!engine.is_rtcp_mux_enabled());
        engine.enable_rtcp_mux(true);
        assert!(engine.is_rtcp_mux_enabled());
        engine.enable_rtcp_mux(false);
        assert!(!engine.is_rtcp_mux_enabled());
    }

    #[tokio::test]
    async fn test_rtcp_mux_config() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = RtpEngineConfig {
            rtcp_mux: true,
            ..Default::default()
        };
        let engine = RtpEngine::new(addr, config).await.unwrap();
        assert!(engine.is_rtcp_mux_enabled());
    }

    // === RTCP-mux demux identification tests ===

    #[test]
    fn test_is_rtcp_packet_identifies_all_rtcp_types() {
        // RTCP payload types: SR=200, RR=201, SDES=202, BYE=203, APP=204, XR=207
        let rtcp_pts: Vec<u8> = vec![200, 201, 202, 203, 204, 207];
        for pt in &rtcp_pts {
            // Minimal 12-byte RTCP-like packet: version=2, padding=0, RC=0, PT=<pt>
            let mut pkt = vec![0x80, *pt, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00];
            assert!(
                is_rtcp_packet(&pkt),
                "RTCP PT {} should be identified as RTCP",
                pt
            );
            // Also verify with padding bit set (byte 0 = 0xA0)
            pkt[0] = 0xA0;
            assert!(
                is_rtcp_packet(&pkt),
                "RTCP PT {} with padding should still be identified as RTCP",
                pt
            );
        }
    }

    #[test]
    fn test_is_rtcp_packet_rejects_rtp() {
        // Common RTP payload types should NOT be identified as RTCP
        let rtp_pts: Vec<u8> = vec![0, 8, 9, 96, 111, 127];
        for pt in &rtp_pts {
            // RTP packet with marker=0, PT=<pt>
            let pkt = vec![0x80, *pt, 0x00, 0x01, 0x00, 0x00, 0x00, 0xA0,
                           0x00, 0x00, 0x00, 0x01];
            assert!(
                !is_rtcp_packet(&pkt),
                "RTP PT {} should NOT be identified as RTCP",
                pt
            );
        }
    }

    #[test]
    fn test_is_rtcp_packet_rejects_short_data() {
        assert!(!is_rtcp_packet(&[]));
        assert!(!is_rtcp_packet(&[0x80]));
    }

    #[test]
    fn test_is_rtcp_packet_accepts_rtcpfb_types() {
        // PT 205 (RTPFB) and 206 (PSFB) are valid RTCP per RFC 4585
        for pt in [205u8, 206] {
            let pkt = vec![0x80, pt, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00];
            assert!(
                is_rtcp_packet(&pkt),
                "PT {} is valid RTCP (RTPFB/PSFB per RFC 4585)",
                pt
            );
        }
    }

    // === Fix 7: Codec asymmetry tests ===

    #[tokio::test]
    async fn test_codec_asymmetry() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = RtpEngineConfig {
            codec: CodecType::Pcmu,
            recv_codec: Some(CodecType::Pcma),
            ..Default::default()
        };
        let engine = RtpEngine::new(addr, config).await.unwrap();

        assert_eq!(engine.codec_type(), CodecType::Pcmu);
        assert_eq!(engine.recv_codec_type(), CodecType::Pcma);
    }

    #[tokio::test]
    async fn test_codec_asymmetry_set_recv() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let engine = RtpEngine::with_defaults(addr).await.unwrap();

        assert_eq!(engine.recv_codec_type(), CodecType::Pcmu);
        engine.set_recv_codec(CodecType::Pcma);
        assert_eq!(engine.recv_codec_type(), CodecType::Pcma);
    }

    // === Fix 8: Ptime tests ===

    #[tokio::test]
    async fn test_ptime_default() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let engine = RtpEngine::with_defaults(addr).await.unwrap();
        assert_eq!(engine.ptime(), 20);
        assert_eq!(engine.samples_per_packet(), 160);
    }

    #[tokio::test]
    async fn test_ptime_set() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = RtpEngineConfig {
            ptime_ms: 30,
            ..Default::default()
        };
        let engine = RtpEngine::new(addr, config).await.unwrap();
        assert_eq!(engine.ptime(), 30);
        assert_eq!(engine.samples_per_packet(), 240);

        engine.set_ptime(10);
        assert_eq!(engine.ptime(), 10);
        assert_eq!(engine.samples_per_packet(), 80);
    }

    // === Fix 9: SSRC collision tests ===

    #[tokio::test]
    async fn test_remote_ssrc_initial() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let engine = RtpEngine::with_defaults(addr).await.unwrap();
        assert!(engine.remote_ssrc().is_none());
    }

    // === Fix 10: Marker bit restart tests ===

    #[tokio::test]
    async fn test_force_marker() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let engine = RtpEngine::with_defaults(addr).await.unwrap();

        // Initially false
        assert!(!engine.force_marker.load(Ordering::Relaxed));

        engine.request_marker();
        assert!(engine.force_marker.load(Ordering::Relaxed));
    }

    // === Fix 5: Comfort noise helpers ===

    #[test]
    fn test_rms_energy() {
        // Silence
        let silence = vec![0i16; 160];
        assert_eq!(compute_rms_energy(&silence), 0.0);

        // Full scale
        let full = vec![32767i16; 160];
        let rms = compute_rms_energy(&full);
        assert!((rms - 32767.0).abs() < 1.0);

        // Empty
        assert_eq!(compute_rms_energy(&[]), 0.0);
    }

    #[test]
    fn test_rms_to_dbov() {
        // Full scale → 0 dBov
        assert_eq!(rms_to_dbov(32767.0), 0);
        // Silence → 127
        assert_eq!(rms_to_dbov(0.0), 127);
        // Half amplitude ≈ -6 dBov → 6
        let half_dbov = rms_to_dbov(32767.0 / 2.0);
        assert!(half_dbov >= 5 && half_dbov <= 7);
    }

    // === Fix 3: Empty DTMF string ===

    #[tokio::test]
    async fn test_send_dtmf_string_empty() {
        // Bug #3: send_dtmf_string("") must return Ok without panic or attempting
        // to send any packets.  Before the fix, an empty string could underflow
        // the `digits.len() - 1` subtraction in the inter-digit loop.
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = RtpEngineConfig {
            enable_dtmf: true,
            ..Default::default()
        };
        let engine = Arc::new(RtpEngine::new(addr, config).await.unwrap());
        let remote: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        engine.set_remote(remote);

        let result = engine.send_dtmf_string("", 100, 50).await;
        assert!(result.is_ok());
    }

    // === Fix 13: Timestamp normalization ===

    #[test]
    fn test_timestamp_normalizer_basic() {
        let mut norm = TimestampNormalizer::new(8000);

        // First packet establishes baseline — normalized output is predictable
        let n1 = norm.normalize(50000);
        // Second packet is one ptime later (160 samples = 20ms at 8kHz)
        let n2 = norm.normalize(50160);
        assert_eq!(n2.wrapping_sub(n1), 160, "Sequential packets must differ by exactly 160");
    }

    #[test]
    fn test_timestamp_normalizer_discontinuity_resets() {
        // Bug #13: After call transfer, remote timestamps jump to an entirely
        // different base.  The normalizer must detect the discontinuity (>5 sec
        // gap) and re-anchor so the jitter buffer sees a smooth stream.
        let mut norm = TimestampNormalizer::new(8000);

        // Establish baseline with a few packets
        let n1 = norm.normalize(1000);
        let n2 = norm.normalize(1160);
        assert_eq!(n2.wrapping_sub(n1), 160);

        // Simulate call transfer: remote timestamps jump by 10 seconds
        let jump_ts = 1160 + 80_000; // 10 seconds at 8kHz
        let n3 = norm.normalize(jump_ts);

        // After reset, the normalizer should place n3 right after n2
        // (n2 + one ptime = n2 + 160 for the assumed 20ms gap)
        assert_eq!(n3.wrapping_sub(n2), 160,
            "After discontinuity, normalizer must re-anchor seamlessly");

        // Further packets should continue smoothly from the new base
        let n4 = norm.normalize(jump_ts + 160);
        assert_eq!(n4.wrapping_sub(n3), 160);
    }

    #[test]
    fn test_timestamp_normalizer_reset_method() {
        let mut norm = TimestampNormalizer::new(8000);

        norm.normalize(5000);
        norm.normalize(5160);
        norm.reset();

        // After reset, next packet should re-establish the mapping
        // (remote_base_ts is None again).
        let n = norm.normalize(90000);
        // Just verify it doesn't panic and returns a value
        let _ = n;

        // Next sequential packet should still be smooth
        let n2 = norm.normalize(90160);
        assert_eq!(n2.wrapping_sub(n), 160);
    }

    // === Fix 27: Port allocation and release ===

    #[test]
    fn test_port_allocate_and_release() {
        // Bug #27: Ports must be recyclable.  Allocate a port from a tiny range,
        // release it, then re-allocate — the same port should come back because
        // the range only has one slot.
        let start: u16 = 40000;
        let end: u16 = 40002; // range has exactly one even port: 40000

        let port = allocate_rtp_port(start, end);
        assert_eq!(port, Some(start), "Should allocate the only available even port");

        // Pool is exhausted — next allocation must fail
        let port2 = allocate_rtp_port(start, end);
        assert!(port2.is_none(), "Pool should be exhausted");

        // Release and re-allocate
        release_rtp_port(port.unwrap());
        let port3 = allocate_rtp_port(start, end);
        assert_eq!(port3, Some(start), "Released port should be re-allocatable");

        // Clean up
        release_rtp_port(port3.unwrap());
    }

    #[test]
    fn test_port_allocation_returns_even() {
        let start: u16 = 40010;
        let end: u16 = 40020;

        let mut allocated = Vec::new();
        for _ in 0..5 {
            if let Some(p) = allocate_rtp_port(start, end) {
                assert_eq!(p % 2, 0, "RTP ports must be even");
                allocated.push(p);
            }
        }

        // Clean up
        for p in allocated {
            release_rtp_port(p);
        }
    }

    // === Fix 31: CN amplitude ===

    #[tokio::test]
    async fn test_cn_amplitude_no_cn_received() {
        // Before any CN packet is received, cn_amplitude() must return 0
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let engine = RtpEngine::with_defaults(addr).await.unwrap();
        assert_eq!(engine.cn_amplitude(), 0);
        assert!(engine.last_cn_level().is_none());
    }

    #[tokio::test]
    async fn test_cn_amplitude_values() {
        // Fix 31: Verify the dBov-to-amplitude mapping:
        //   amplitude = (127 - level) * 2
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let engine = RtpEngine::with_defaults(addr).await.unwrap();

        // Manually set CN level to simulate receiving a CN packet
        *engine.last_cn_level.lock() = Some(0); // max noise
        assert_eq!(engine.cn_amplitude(), 254); // (127-0)*2

        *engine.last_cn_level.lock() = Some(127); // digital silence
        assert_eq!(engine.cn_amplitude(), 0); // (127-127)*2

        *engine.last_cn_level.lock() = Some(60); // mid-level
        assert_eq!(engine.cn_amplitude(), 134); // (127-60)*2
    }

    // === Fix 14: Silence sending config ===

    #[tokio::test]
    async fn test_silence_when_idle_config() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // Default: disabled
        let engine = RtpEngine::with_defaults(addr).await.unwrap();
        assert!(!engine.send_silence_when_idle);

        // Enabled via config
        let addr2: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = RtpEngineConfig {
            send_silence_when_idle: true,
            ..Default::default()
        };
        let engine2 = RtpEngine::new(addr2, config).await.unwrap();
        assert!(engine2.send_silence_when_idle);
    }

    // === Bug #47: Audio payload type validation ===

    #[tokio::test]
    async fn test_audio_payload_type_default_none() {
        // Bug #47: Default config should not filter audio PTs
        let config = RtpEngineConfig::default();
        assert!(config.audio_payload_type.is_none());

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let engine = RtpEngine::with_defaults(addr).await.unwrap();
        assert!(engine.audio_payload_type.is_none());
    }

    #[tokio::test]
    async fn test_audio_payload_type_configured() {
        // Bug #47: When audio_payload_type is set, the engine stores it
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = RtpEngineConfig {
            audio_payload_type: Some(0), // PCMU
            ..Default::default()
        };
        let engine = RtpEngine::new(addr, config).await.unwrap();
        assert_eq!(engine.audio_payload_type, Some(0));
    }

    #[tokio::test]
    async fn test_audio_payload_type_validation_drops_mismatch() {
        // Bug #47: Loopback test — engine with audio_payload_type=0 (PCMU)
        // should drop packets from a sender using PT=8 (PCMA)
        let addr1: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // Sender uses PCMA (PT=8)
        let sender_config = RtpEngineConfig {
            codec: CodecType::Pcma,
            ..Default::default()
        };
        // Receiver expects PCMU (PT=0)
        let receiver_config = RtpEngineConfig {
            audio_payload_type: Some(0),
            jitter_config: crate::rtp::jitter::JitterConfig {
                target_delay_ms: 20,
                min_delay_ms: 10,
                ..Default::default()
            },
            ..Default::default()
        };

        let sender = Arc::new(RtpEngine::new(addr1, sender_config).await.unwrap());
        let receiver = Arc::new(RtpEngine::new(addr2, receiver_config).await.unwrap());

        sender.set_remote(receiver.local_addr());
        receiver.set_remote(sender.local_addr());

        sender.start().unwrap();
        receiver.start().unwrap();

        // Send packets with PT=8 (PCMA)
        let samples: Vec<i16> = (0..160).map(|i| (i * 100) as i16).collect();
        for _ in 0..5 {
            sender.send_audio(&samples).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Receiver should NOT have any audio — all dropped due to PT mismatch
        let received = receiver.recv_audio_try().unwrap();
        assert!(received.is_none(),
            "Packets with mismatched audio PT should be dropped");

        sender.stop();
        receiver.stop();
    }

    #[tokio::test]
    async fn test_audio_payload_type_validation_accepts_match() {
        // Bug #47: When audio_payload_type matches the sender's codec PT,
        // packets should be accepted normally
        let addr1: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let config = RtpEngineConfig {
            codec: CodecType::Pcmu,
            audio_payload_type: Some(0), // matches PCMU PT
            jitter_config: crate::rtp::jitter::JitterConfig {
                target_delay_ms: 20,
                min_delay_ms: 10,
                ..Default::default()
            },
            ..Default::default()
        };

        let sender = Arc::new(RtpEngine::new(addr1, config.clone()).await.unwrap());
        let receiver = Arc::new(RtpEngine::new(addr2, config).await.unwrap());

        sender.set_remote(receiver.local_addr());
        receiver.set_remote(sender.local_addr());

        sender.start().unwrap();
        receiver.start().unwrap();

        let samples: Vec<i16> = (0..160).map(|i| (i * 100) as i16).collect();
        for _ in 0..5 {
            sender.send_audio(&samples).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Receiver should have audio — PT matches
        let received = receiver.recv_audio_blocking(Duration::from_millis(500)).unwrap();
        assert!(received.is_some(),
            "Packets with matching audio PT should be accepted");

        sender.stop();
        receiver.stop();
    }

    // === Bug #48: SSRC collision full stream reset ===

    #[tokio::test]
    async fn test_reset_stream_state() {
        // Bug #48: reset_stream_state() should reset jitter buffer, DTMF
        // detector, PLC, and timestamp normalizer without panicking
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let engine = RtpEngine::with_defaults(addr).await.unwrap();

        // Populate some state
        engine.plc.lock().update(&vec![1000i16; 160]);
        engine.timestamp_normalizer.lock().normalize(5000);
        engine.timestamp_normalizer.lock().normalize(5160);
        engine.audio_pt_mismatch_warned.store(true, Ordering::Relaxed);

        // Reset should not panic and should clear the PT warning flag
        engine.reset_stream_state();

        assert!(!engine.audio_pt_mismatch_warned.load(Ordering::Relaxed),
            "audio_pt_mismatch_warned should be reset");

        // After reset, normalizer should re-establish mapping from scratch
        let n1 = engine.timestamp_normalizer.lock().normalize(90000);
        let n2 = engine.timestamp_normalizer.lock().normalize(90160);
        assert_eq!(n2.wrapping_sub(n1), 160,
            "After reset, normalizer should produce smooth timestamps");
    }

    #[tokio::test]
    async fn test_reset_stream_state_resets_plc() {
        // Bug #48: PLC state must be cleared on SSRC change so concealment
        // from the old stream doesn't bleed into the new one
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let engine = RtpEngine::with_defaults(addr).await.unwrap();

        // Feed loud audio into PLC
        let loud: Vec<i16> = vec![10000; 160];
        engine.plc.lock().update(&loud);

        // Concealment before reset should produce non-zero samples
        let concealed_before = engine.plc.lock().conceal();
        let has_nonzero_before = concealed_before.iter().any(|&s| s != 0);
        assert!(has_nonzero_before,
            "PLC concealment before reset should have non-zero samples");

        // Reset stream state
        engine.reset_stream_state();

        // After reset, PLC has no history — concealment should be silent
        let concealed_after = engine.plc.lock().conceal();
        let all_zero_after = concealed_after.iter().all(|&s| s == 0);
        assert!(all_zero_after,
            "PLC concealment after reset should be all zeros (no history)");
    }

    // === Bug #49: Timestamp normalizer uses configured ptime ===

    #[test]
    fn test_timestamp_normalizer_with_ptime_30ms() {
        // Bug #49: When ptime=30ms, discontinuity recovery should step by
        // 240 samples (8000 * 30 / 1000), not 160 (20ms)
        let mut norm = TimestampNormalizer::with_ptime(8000, 30);

        let n1 = norm.normalize(1000);
        let n2 = norm.normalize(1240); // 30ms at 8kHz = 240 samples
        assert_eq!(n2.wrapping_sub(n1), 240);

        // Simulate a large discontinuity (>5 sec)
        let jump_ts = 1240 + 80_000;
        let n3 = norm.normalize(jump_ts);

        // After discontinuity, the gap should be one ptime (240 samples for 30ms)
        assert_eq!(n3.wrapping_sub(n2), 240,
            "Bug #49: discontinuity recovery should use 30ms ptime (240 samples), not 20ms (160)");

        // Continue normally
        let n4 = norm.normalize(jump_ts + 240);
        assert_eq!(n4.wrapping_sub(n3), 240);
    }

    #[test]
    fn test_timestamp_normalizer_with_ptime_10ms() {
        // Bug #49: When ptime=10ms, discontinuity recovery should step by
        // 80 samples (8000 * 10 / 1000)
        let mut norm = TimestampNormalizer::with_ptime(8000, 10);

        let n1 = norm.normalize(2000);
        let n2 = norm.normalize(2080); // 10ms = 80 samples
        assert_eq!(n2.wrapping_sub(n1), 80);

        // Large jump
        let jump_ts = 2080 + 80_000;
        let n3 = norm.normalize(jump_ts);
        assert_eq!(n3.wrapping_sub(n2), 80,
            "Bug #49: discontinuity recovery should use 10ms ptime (80 samples)");
    }

    #[test]
    fn test_timestamp_normalizer_set_ptime_mid_stream() {
        // Bug #49: Changing ptime mid-stream via set_ptime() should affect
        // subsequent discontinuity recovery
        let mut norm = TimestampNormalizer::with_ptime(8000, 20);

        let n1 = norm.normalize(1000);
        let n2 = norm.normalize(1160);
        assert_eq!(n2.wrapping_sub(n1), 160);

        // Change ptime to 30ms
        norm.set_ptime(30);

        // Next discontinuity should use 30ms step (240 samples)
        let jump_ts = 1160 + 80_000;
        let n3 = norm.normalize(jump_ts);
        assert_eq!(n3.wrapping_sub(n2), 240,
            "After set_ptime(30), discontinuity recovery should use 240 samples");
    }

    #[tokio::test]
    async fn test_set_ptime_propagates_to_normalizer() {
        // Bug #49: RtpEngine::set_ptime() must propagate to the
        // TimestampNormalizer's internal ptime
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let engine = RtpEngine::with_defaults(addr).await.unwrap();

        // Default ptime should be 20ms
        assert_eq!(engine.timestamp_normalizer.lock().ptime_ms, 20);

        engine.set_ptime(30);
        assert_eq!(engine.timestamp_normalizer.lock().ptime_ms, 30);
    }

    // === Bug #50: hold_media_timeout_ms config is respected ===

    #[tokio::test]
    async fn test_hold_media_timeout_config_respected() {
        // Bug #50 (same root cause as Bug #2, now fixed): Verify that the
        // hold_media_timeout_ms config value is actually used by the engine.
        // The fix was to read effective_media_timeout() dynamically in the
        // timeout check task instead of capturing a static value.
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = RtpEngineConfig {
            media_timeout_ms: 1_000,
            hold_media_timeout_ms: 300_000, // 5 minutes
            ..Default::default()
        };
        let engine = RtpEngine::new(addr, config).await.unwrap();

        // Verify the config values are stored
        assert_eq!(engine.media_timeout_ms, 1_000);
        assert_eq!(engine.hold_media_timeout_ms, 300_000);

        // Normal mode uses media_timeout_ms
        assert_eq!(engine.effective_media_timeout(), Duration::from_millis(1_000));

        // Hold mode uses hold_media_timeout_ms
        engine.set_hold_state(true);
        assert_eq!(engine.effective_media_timeout(), Duration::from_millis(300_000));

        // Simulate: last RTP packet was 2 seconds ago.
        // In normal mode this exceeds 1s timeout.
        // In hold mode this is well within the 5 min timeout.
        *engine.last_rtp_received.lock() = Some(Instant::now() - Duration::from_secs(2));

        // On hold: 2s < 300s => not timed out
        let effective = engine.effective_media_timeout();
        let elapsed = engine.last_rtp_received.lock().unwrap().elapsed();
        assert!(elapsed < effective,
            "On hold: 2s elapsed should be less than 300s hold timeout");

        // Off hold: 2s > 1s => timed out
        engine.set_hold_state(false);
        let effective_normal = engine.effective_media_timeout();
        assert!(elapsed >= effective_normal,
            "Off hold: 2s elapsed should exceed 1s normal timeout");
    }

    #[tokio::test]
    async fn test_hold_state_management() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let engine = RtpEngine::with_defaults(addr).await.unwrap();

        // Initially not on hold
        assert!(!engine.is_on_hold());

        // Set hold
        engine.set_hold_state(true);
        assert!(engine.is_on_hold());

        // Unset hold
        engine.set_hold_state(false);
        assert!(!engine.is_on_hold());
    }

    #[tokio::test]
    async fn test_effective_media_timeout_normal_vs_hold() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = RtpEngineConfig {
            media_timeout_ms: 30_000,
            hold_media_timeout_ms: 1_800_000,
            ..Default::default()
        };
        let engine = RtpEngine::new(addr, config).await.unwrap();

        // Normal: 30 seconds
        assert_eq!(engine.effective_media_timeout(), Duration::from_millis(30_000));

        // On hold: 30 minutes
        engine.set_hold_state(true);
        assert_eq!(engine.effective_media_timeout(), Duration::from_millis(1_800_000));

        // Back to normal
        engine.set_hold_state(false);
        assert_eq!(engine.effective_media_timeout(), Duration::from_millis(30_000));
    }
}
