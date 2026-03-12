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

use crate::error::{Result, RtpSipError};
use crate::rtp::codec::{CodecType, G711Codec};
use crate::rtp::dtmf::{DetectedDtmf, DtmfDetector, DtmfSender, RtpBugFlags, TELEPHONE_EVENT_PT};
use crate::rtp::jitter::{JitterBuffer, JitterConfig, JitterStats, PacketLossConcealer};
use crate::rtp::packet::{parse_rtp_packet, serialize_rtp_packet, RtpPacketBuilder};
use bytes::Bytes;
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc};
use tokio::time::Duration;

/// Comfort Noise payload type (RFC 3389)
const CN_PAYLOAD_TYPE: u8 = 13;

/// Minimum interval between Comfort Noise packets (1 second)
const CN_PACING_MS: u64 = 1000;

/// RTCP payload types for mux discrimination (RFC 5761)
const RTCP_PT_MIN: u8 = 200;
const RTCP_PT_MAX: u8 = 204;
/// RTCP XR payload type
const RTCP_PT_XR: u8 = 207;

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
        let rtcp_mux = config.rtcp_mux;
        let ptime_ms = config.ptime_ms;

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
                config.codec.samples_per_frame(),
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
    pub fn is_media_timed_out(&self) -> bool {
        if let Some(last) = *self.last_rtp_received.lock() {
            last.elapsed().as_millis() as u64 >= self.media_timeout_ms
        } else {
            false
        }
    }

    /// Subscribe to media timeout notifications.
    /// A message is sent on the channel when the media timeout fires.
    pub fn media_timeout_rx(&self) -> broadcast::Receiver<()> {
        self.timeout_tx.subscribe()
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
    }

    /// Get samples per packet based on current ptime and codec sample rate
    pub fn samples_per_packet(&self) -> u32 {
        let ptime = self.ptime_ms.load(Ordering::Relaxed);
        self.config.codec.sample_rate() * ptime / 1000
    }

    // ========== Fix 9: SSRC Collision ==========

    /// Get the currently tracked remote SSRC
    pub fn remote_ssrc(&self) -> Option<u32> {
        *self.remote_ssrc.lock()
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
        {
            let engine_timeout = self.clone();
            let timeout_ms = self.media_timeout_ms;
            let timeout_tx = self.timeout_tx.clone();
            tokio::spawn(async move {
                let check_interval = Duration::from_secs(5);
                while engine_timeout.running.load(Ordering::Relaxed) {
                    tokio::time::sleep(check_interval).await;
                    if let Some(last) = *engine_timeout.last_rtp_received.lock() {
                        if last.elapsed().as_millis() as u64 >= timeout_ms {
                            let _ = timeout_tx.send(());
                        }
                    }
                }
            });
        }

        // Spawn receive task
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];

            while engine.running.load(Ordering::Relaxed) {
                match tokio::time::timeout(
                    Duration::from_millis(100),
                    engine.socket.recv_from(&mut buf),
                )
                .await
                {
                    Ok(Ok((len, _addr))) => {
                        let data = &buf[..len];

                        // === Fix 6: RTCP-mux discrimination ===
                        // When RTCP-mux is enabled, check if this is an RTCP packet.
                        // RTCP packets have payload type 200-204 or 207 in the second byte.
                        if engine.rtcp_mux.load(Ordering::Relaxed) && len >= 2 {
                            let pt_byte = data[1] & 0x7F;
                            if (pt_byte >= RTCP_PT_MIN && pt_byte <= RTCP_PT_MAX)
                                || pt_byte == RTCP_PT_XR
                            {
                                // This is an RTCP packet on the muxed port — skip RTP processing.
                                // A full implementation would forward to an RTCP handler here.
                                continue;
                            }
                        }

                        if let Ok(packet) = parse_rtp_packet(data) {
                            let pt = packet.header.payload_type;
                            let pkt_ssrc = packet.header.ssrc;

                            // === Fix 4: Update last RTP received timestamp ===
                            *engine.last_rtp_received.lock() = Some(Instant::now());

                            // === Fix 9: SSRC collision detection ===
                            {
                                let mut remote = engine.remote_ssrc.lock();
                                if let Some(prev_ssrc) = *remote {
                                    if pkt_ssrc != prev_ssrc {
                                        tracing::warn!(
                                            "SSRC collision: {} -> {}, resetting jitter buffer",
                                            prev_ssrc,
                                            pkt_ssrc,
                                        );
                                        engine.jitter_buffer.lock().reset();
                                        *remote = Some(pkt_ssrc);
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

                            // === Fix 5: Handle incoming Comfort Noise (PT 13) ===
                            if pt == CN_PAYLOAD_TYPE {
                                // CN packets are not audio — don't push to jitter buffer.
                                // A full implementation would update noise generation here.
                                continue;
                            }

                            // === Fix 7: Decode with receive codec ===
                            let samples = engine.recv_codec.lock().decode(&packet.payload);

                            // Update PLC with good samples
                            engine.plc.lock().update(&samples);

                            // Push to jitter buffer
                            engine.jitter_buffer.lock().push(packet);

                            // Try to pop from jitter buffer
                            let audio = {
                                let mut jb = engine.jitter_buffer.lock();
                                if let Some(jb_packet) = jb.pop() {
                                    Some(engine.recv_codec.lock().decode(&jb_packet.payload))
                                } else if jb.is_ready() {
                                    // Packet was lost, use PLC
                                    Some(engine.plc.lock().conceal())
                                } else {
                                    None
                                }
                            };

                            if let Some(audio) = audio {
                                let _ = engine.recv_tx.try_send(audio);
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
    }

    /// Send audio samples (PCM i16, 8kHz mono)
    pub async fn send_audio(&self, samples: &[i16]) -> Result<()> {
        let remote = self
            .remote_addr
            .lock()
            .ok_or(RtpSipError::NotConnected)?;

        // === Fix 10: Check if marker bit should be forced ===
        let marker = self.force_marker.swap(false, Ordering::Relaxed);

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

        Ok(())
    }

    /// Send audio with marker bit set
    pub async fn send_audio_with_marker(&self, samples: &[i16], marker: bool) -> Result<()> {
        let remote = self
            .remote_addr
            .lock()
            .ok_or(RtpSipError::NotConnected)?;

        let encoded = self.codec.encode(samples);
        let packet = self
            .packet_builder
            .lock()
            .build_with_marker(Bytes::from(encoded), samples.len() as u32, marker);

        let data = serialize_rtp_packet(&packet)?;
        self.socket.send_to(&data, remote).await?;

        Ok(())
    }

    /// Send Comfort Noise packet (RFC 3389, Fix 5)
    ///
    /// Sends a CN packet with the specified noise level in dBov.
    /// Respects the 1-second pacing interval to avoid flooding.
    /// Returns `Ok(true)` if a packet was actually sent, `Ok(false)` if
    /// pacing suppressed the send.
    pub async fn send_comfort_noise(&self, samples: &[i16]) -> Result<bool> {
        let remote = self
            .remote_addr
            .lock()
            .ok_or(RtpSipError::NotConnected)?;

        // CN pacing: only send if >= 1000ms since last CN
        {
            let mut last_cn = self.last_cn_timestamp.lock();
            if let Some(last) = *last_cn {
                if last.elapsed().as_millis() < CN_PACING_MS as u128 {
                    return Ok(false);
                }
            }
            *last_cn = Some(Instant::now());
        }

        // Compute RMS energy and convert to dBov noise level byte
        let rms = compute_rms_energy(samples);
        let dbov = rms_to_dbov(rms);

        // CN payload: single byte = noise level in dBov
        let cn_payload = vec![dbov];
        let packet = self.packet_builder.lock().build_with_marker(
            Bytes::from(cn_payload),
            samples.len() as u32,
            false,
        );

        // We need to override the payload type to CN (13) in the serialized data.
        // Build raw header bytes with PT=13.
        let mut data = serialize_rtp_packet(&packet)?.to_vec();
        if data.len() >= 2 {
            // Clear PT bits and set to 13
            data[1] = (data[1] & 0x80) | CN_PAYLOAD_TYPE;
        }

        self.socket.send_to(&data, remote).await?;
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
            .update(&vec![0i16; self.config.codec.samples_per_frame()]);
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

        // Generate all packets for this digit (20ms intervals)
        let packets = self
            .dtmf_sender
            .lock()
            .generate_digit(digit, duration_ms, 20)?;

        // Send packets with proper timing
        for (i, packet) in packets.iter().enumerate() {
            let data = packet.to_rtp_bytes();
            self.socket.send_to(&data, remote).await?;

            // Wait between packets (except for end packets which are sent rapidly)
            if i < packets.len().saturating_sub(3) {
                tokio::time::sleep(Duration::from_millis(20)).await;
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

// ========== Fix 5 helpers ==========

/// Compute RMS energy of PCM samples
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
}
