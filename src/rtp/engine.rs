//! RTP Engine for sending and receiving audio

use crate::error::{Result, RtpSipError};
use crate::rtp::codec::{CodecType, G711Codec};
use crate::rtp::dtmf::{DetectedDtmf, DtmfDetector, DtmfSender, RtpBugFlags, TELEPHONE_EVENT_PT};
use crate::rtp::jitter::{JitterBuffer, JitterConfig, JitterStats, PacketLossConcealer};
use crate::rtp::packet::{parse_rtp_packet, serialize_rtp_packet, RtpPacketBuilder};
use bytes::Bytes;
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Duration;

/// RTP Engine configuration
#[derive(Debug, Clone)]
pub struct RtpEngineConfig {
    /// Codec type to use
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
    /// Codec
    codec: G711Codec,
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
}

impl RtpEngine {
    /// Create a new RTP engine bound to the specified address
    pub async fn new(local_addr: SocketAddr, config: RtpEngineConfig) -> Result<Self> {
        let socket = UdpSocket::bind(local_addr).await?;
        let actual_addr = socket.local_addr()?;

        let ssrc = config.ssrc.unwrap_or_else(rand::random);
        let codec = G711Codec::new(config.codec);
        let packet_builder = RtpPacketBuilder::new(config.codec.payload_type(), ssrc);

        let (recv_tx, recv_rx) = mpsc::channel(config.recv_buffer_size);
        let (dtmf_tx, dtmf_rx) = mpsc::channel(config.dtmf_buffer_size);

        // Create DTMF sender and detector with configured payload type
        let dtmf_sender = DtmfSender::with_payload_type(ssrc, config.dtmf_payload_type);
        let dtmf_detector = Arc::new(DtmfDetector::with_payload_type(config.dtmf_payload_type));

        Ok(Self {
            socket: Arc::new(socket),
            local_addr: actual_addr,
            remote_addr: Mutex::new(None),
            codec,
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

    /// Get codec type
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
                        if let Ok(packet) = parse_rtp_packet(&buf[..len]) {
                            let pt = packet.header.payload_type;

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

                            // Decode audio
                            let samples = engine.codec.decode(&packet.payload);

                            // Update PLC with good samples
                            engine.plc.lock().update(&samples);

                            // Push to jitter buffer
                            engine.jitter_buffer.lock().push(packet);

                            // Try to pop from jitter buffer
                            let audio = {
                                let mut jb = engine.jitter_buffer.lock();
                                if let Some(jb_packet) = jb.pop() {
                                    Some(engine.codec.decode(&jb_packet.payload))
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

        // Encode samples
        let encoded = self.codec.encode(samples);

        // Build packet
        let packet = self
            .packet_builder
            .lock()
            .build(Bytes::from(encoded), samples.len() as u32);

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
}
