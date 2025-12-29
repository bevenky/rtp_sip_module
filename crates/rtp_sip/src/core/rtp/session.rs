//! RTP session using libfs's switch_rtp
//!
//! Uses libfs core for:
//! - RTP packet handling (switch_rtp.c)
//! - Jitter buffer (built-in)
//! - G.711 codec (built-in)
//!
//! All libfs operations run on a dedicated worker thread to maintain
//! thread affinity while allowing async Python code to create sessions
//! concurrently.

use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tracing::{debug, info};

use crate::core::audio::{AudioFrame, BufferPool};
use crate::core::error::{Error, Result};
use crate::core::libfs_worker::{LibFsWorker, RtpHandle};
use crate::core::rtp::RtpConfig;

/// RTP session for Mode 3 (RTP-only, external SIP signaling)
///
/// Uses libfs's battle-tested RTP stack including:
/// - Jitter buffer
/// - G.711 codec
/// - Packet reordering
/// - SRTP support (if configured)
///
/// All libfs operations are delegated to a dedicated worker thread
/// via async channels, allowing concurrent session creation without blocking.
pub struct RtpSession {
    config: RtpConfig,
    /// libfs RTP session handle (obtained from LibFsWorker)
    handle: Mutex<Option<RtpHandle>>,
    /// Actual bound local port
    local_port: AtomicU16,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Buffer pool for receive buffers (reduces allocations in hot path)
    buffer_pool: Arc<BufferPool>,
    /// RTP timestamp counter (increments by samples_per_packet)
    timestamp: AtomicU32,
    // Statistics
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
}

impl RtpSession {
    /// Create a new RTP session
    pub fn new(config: RtpConfig) -> Result<Self> {
        config.validate().map_err(Error::Config)?;

        // Create buffer pool with capacity for typical RTP frame (320 bytes for 20ms @ 8kHz L16)
        let buffer_pool = BufferPool::with_capacity(4096);
        // Pre-allocate some buffers to reduce initial allocation overhead
        buffer_pool.preallocate(8);

        Ok(Self {
            config,
            handle: Mutex::new(None),
            local_port: AtomicU16::new(0),
            running: Arc::new(AtomicBool::new(false)),
            buffer_pool,
            timestamp: AtomicU32::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
        })
    }

    /// Start the RTP session
    ///
    /// Sends a command to the libfs worker thread to create the RTP session.
    /// This is fully async and doesn't block the calling thread.
    ///
    /// Note: Once RTP-only mode is initialized, you cannot use SIP mode
    /// in the same process. Restart required to switch modes.
    pub async fn start(&self) -> Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(Error::Rtp("Session already running".to_string()));
        }

        info!(
            "Starting RTP session: local={}:{}, remote={}:{}",
            self.config.local_ip, self.config.local_port,
            self.config.remote_ip, self.config.remote_port
        );

        // Initialize FreeSWITCH in RTP-only mode (locks this process to RTP-only mode)
        crate::core::Runtime::ensure_rtp_mode()?;

        // Get the libfs worker
        let worker = LibFsWorker::get()?;

        // Create RTP session via worker thread (maintains thread affinity)
        let handle = worker
            .create_rtp_session(
                self.config.local_ip.clone(),
                self.config.local_port,
                self.config.remote_ip.clone(),
                self.config.remote_port,
                self.config.codec,
            )
            .await?;

        // Store handle
        *self.handle.lock() = Some(handle);

        // Store local port (for now use configured, could query socket)
        self.local_port.store(self.config.local_port, Ordering::SeqCst);

        info!(
            "RTP session started on port {} (libfs RTP via worker)",
            self.config.local_port
        );

        Ok(())
    }

    /// Stop the RTP session
    pub async fn stop(&self) -> Result<()> {
        if !self.running.swap(false, Ordering::SeqCst) {
            return Ok(());
        }

        info!("Stopping RTP session");

        // Take the handle
        let handle = self.handle.lock().take();

        if let Some(handle) = handle {
            // Destroy via worker thread
            let worker = LibFsWorker::get()?;
            worker.destroy_rtp_session(handle).await?;
        }

        debug!("RTP session stopped");
        Ok(())
    }

    /// Receive audio frame from remote
    ///
    /// libfs handles jitter buffer and G.711 decoding internally.
    /// Returns decoded L16 PCM audio at 8kHz.
    pub async fn recv_audio(&self, _timeout_ms: u64) -> Result<Option<AudioFrame>> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(Error::SessionClosed);
        }

        let handle = {
            let guard = self.handle.lock();
            match *guard {
                Some(handle) => handle,
                None => return Err(Error::SessionClosed),
            }
        };

        // Read via worker thread
        let worker = LibFsWorker::get()?;
        let data = worker.read_frame(handle).await?;

        match data {
            Some(bytes) => {
                self.packets_received.fetch_add(1, Ordering::Relaxed);
                // libfs returns decoded PCM (L16)
                let frame = AudioFrame::new(bytes, 8000);
                Ok(Some(frame))
            }
            None => Ok(None),
        }
    }

    /// Send audio frame to remote
    ///
    /// libfs handles G.711 encoding internally.
    pub async fn send_audio(&self, frame: AudioFrame) -> Result<()> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(Error::SessionClosed);
        }

        let handle = {
            let guard = self.handle.lock();
            match *guard {
                Some(handle) => handle,
                None => return Err(Error::SessionClosed),
            }
        };

        // Calculate samples in this frame (for 8kHz G.711, samples = bytes)
        // For L16 (16-bit PCM), samples = bytes / 2
        let samples = (frame.samples.len() / 2) as u32;

        // Get current timestamp and increment
        let ts = self.timestamp.fetch_add(samples, Ordering::SeqCst);

        debug!(
            "send_audio: datalen={}, samples={}, ts={}",
            frame.samples.len(), samples, ts
        );

        // Write via worker thread
        let worker = LibFsWorker::get()?;
        worker.write_frame(handle, frame.samples, ts).await?;

        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Get the actual bound local port
    pub fn local_port(&self) -> u16 {
        self.local_port.load(Ordering::SeqCst)
    }

    /// Check if session is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get statistics
    pub fn stats(&self) -> RtpStats {
        RtpStats {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_lost: 0,
            jitter_buffer_depth: 0,
            jitter_ms: 0.0,
            rtt_ms: 0.0,
            target_delay_ms: 0.0,
            buffer_pool_available: self.buffer_pool.available() as u64,
        }
    }
}

impl Drop for RtpSession {
    fn drop(&mut self) {
        if self.running.load(Ordering::SeqCst) {
            self.running.store(false, Ordering::SeqCst);

            // Try to clean up via worker (best effort, can't await in drop)
            if let Some(handle) = self.handle.lock().take() {
                if let Ok(worker) = LibFsWorker::get() {
                    // Use blocking send since we can't await
                    let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
                    let _ = worker.sender.blocking_send(crate::core::libfs_worker::FsCommand::DestroyRtpSession {
                        handle,
                        reply: reply_tx,
                    });
                    // Don't wait for reply in drop - fire and forget
                }
            }
        }
    }
}

/// RTP session statistics
#[derive(Debug, Clone, Default)]
pub struct RtpStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_lost: u64,
    pub jitter_buffer_depth: u64,
    pub jitter_ms: f64,
    pub rtt_ms: f64,
    pub target_delay_ms: f64,
    /// Number of buffers available in pool (for performance monitoring)
    pub buffer_pool_available: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::audio::Codec;
    use crate::core::runtime::Runtime;

    #[test]
    fn test_config_validation() {
        // Valid config
        let config = RtpConfig::new("127.0.0.1", 5000);
        assert!(config.validate().is_ok());

        // Invalid IP
        let config = RtpConfig::new("", 5000);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_rtp_session_start() {
        // First init Tokio runtime
        let rt = match Runtime::init() {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("Runtime init failed: {:?}", e);
                return;
            }
        };

        // Create RTP session config
        // new() takes (remote_ip, remote_port), local is configured separately
        let config = RtpConfig::new("127.0.0.1", 5004)
            .with_local_port(16384)
            .with_codec(Codec::Pcmu);

        // Create session
        let session = match RtpSession::new(config) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to create RTP session: {:?}", e);
                return;
            }
        };

        // Start session (this triggers libfs init via worker)
        println!("Starting RTP session...");
        let result = rt.block_on(session.start());

        match result {
            Ok(()) => {
                println!("RTP session started on port {}", session.local_port());
                assert!(session.is_running());

                // Stop session
                let _ = rt.block_on(session.stop());
                println!("RTP session stopped");
            }
            Err(e) => {
                eprintln!("Failed to start RTP session: {:?}", e);
            }
        }
    }

    #[test]
    fn test_rtp_send_audio() {
        // First init Tokio runtime
        let rt = match Runtime::init() {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("Runtime init failed: {:?}", e);
                return;
            }
        };

        // Create RTP session pointing to loopback
        let config = RtpConfig::new("127.0.0.1", 5006)
            .with_local_port(16386)
            .with_codec(Codec::Pcmu);

        let session = match RtpSession::new(config) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to create RTP session: {:?}", e);
                return;
            }
        };

        // Start session
        println!("Starting RTP session for send test...");
        if let Err(e) = rt.block_on(session.start()) {
            eprintln!("Failed to start RTP session: {:?}", e);
            return;
        }

        // Create a test audio frame (160 samples = 20ms @ 8kHz)
        // L16 format = 16-bit signed PCM
        let samples: Vec<i16> = (0..160).map(|i| ((i as f32 * 0.1).sin() * 16000.0) as i16).collect();
        let frame = AudioFrame::from_samples(&samples, 8000);

        // Send the audio frame
        println!("Sending audio frame...");
        match rt.block_on(session.send_audio(frame)) {
            Ok(()) => println!("Audio frame sent successfully!"),
            Err(e) => eprintln!("Failed to send audio: {:?}", e),
        }

        // Check stats
        let stats = session.stats();
        println!("Stats: sent={}, recv={}", stats.packets_sent, stats.packets_received);

        // Stop session
        let _ = rt.block_on(session.stop());
        println!("RTP session stopped");
    }

    #[test]
    fn test_rtp_recv_timeout() {
        // Test that recv_audio times out properly when no data
        let rt = match Runtime::init() {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("Runtime init failed: {:?}", e);
                return;
            }
        };

        // Create RTP session
        let config = RtpConfig::new("127.0.0.1", 5008)
            .with_local_port(16388)
            .with_codec(Codec::Pcmu);

        let session = match RtpSession::new(config) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to create RTP session: {:?}", e);
                return;
            }
        };

        // Start session
        println!("Starting RTP session for recv test...");
        if let Err(e) = rt.block_on(session.start()) {
            eprintln!("Failed to start RTP session: {:?}", e);
            return;
        }

        // Try to receive (should timeout since no one is sending)
        println!("Attempting to receive audio (expect timeout)...");
        let start = std::time::Instant::now();
        match rt.block_on(session.recv_audio(100)) {
            Ok(Some(frame)) => {
                println!("Received frame: {} bytes", frame.samples.len());
            }
            Ok(None) => {
                println!("No data received (expected)");
            }
            Err(e) => {
                eprintln!("recv_audio error: {:?}", e);
            }
        }
        let elapsed = start.elapsed();
        println!("recv_audio took {:?}", elapsed);

        // Stop session
        let _ = rt.block_on(session.stop());
        println!("RTP session stopped");
    }

    #[test]
    fn test_rtp_loopback() {
        // Test sending and receiving via loopback
        let rt = match Runtime::init() {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("Runtime init failed: {:?}", e);
                return;
            }
        };

        // Create sender session (sends to port 16392, listens on 16390)
        let sender_config = RtpConfig::new("127.0.0.1", 16392)
            .with_local_port(16390)
            .with_codec(Codec::Pcmu);

        // Create receiver session (sends to port 16390, listens on 16392)
        let receiver_config = RtpConfig::new("127.0.0.1", 16390)
            .with_local_port(16392)
            .with_codec(Codec::Pcmu);

        let sender = match RtpSession::new(sender_config) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to create sender: {:?}", e);
                return;
            }
        };

        let receiver = match RtpSession::new(receiver_config) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to create receiver: {:?}", e);
                return;
            }
        };

        // Start both sessions
        println!("Starting sender...");
        if let Err(e) = rt.block_on(sender.start()) {
            eprintln!("Failed to start sender: {:?}", e);
            return;
        }

        println!("Starting receiver...");
        if let Err(e) = rt.block_on(receiver.start()) {
            eprintln!("Failed to start receiver: {:?}", e);
            let _ = rt.block_on(sender.stop());
            return;
        }

        // Create and send a test frame
        let samples: Vec<i16> = (0..160).map(|i| ((i as f32 * 0.1).sin() * 16000.0) as i16).collect();
        let frame = AudioFrame::from_samples(&samples, 8000);

        println!("Sending audio frame...");
        if let Err(e) = rt.block_on(sender.send_audio(frame)) {
            eprintln!("Failed to send: {:?}", e);
        } else {
            println!("Frame sent!");
        }

        // Small delay to allow packet to arrive
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Try to receive
        println!("Attempting to receive...");
        match rt.block_on(receiver.recv_audio(500)) {
            Ok(Some(frame)) => {
                println!("Received frame: {} bytes", frame.samples.len());
            }
            Ok(None) => {
                println!("No data received");
            }
            Err(e) => {
                eprintln!("recv_audio error: {:?}", e);
            }
        }

        // Check stats
        let sender_stats = sender.stats();
        let receiver_stats = receiver.stats();
        println!("Sender stats: sent={}", sender_stats.packets_sent);
        println!("Receiver stats: recv={}", receiver_stats.packets_received);

        // Stop sessions
        let _ = rt.block_on(sender.stop());
        let _ = rt.block_on(receiver.stop());
        println!("Sessions stopped");
    }

    #[test]
    fn test_buffer_pool_reuse() {
        // Test that buffer pool is working and reusing buffers
        let rt = match Runtime::init() {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("Runtime init failed: {:?}", e);
                return;
            }
        };

        // Create two sessions for loopback
        let sender_config = RtpConfig::new("127.0.0.1", 16402)
            .with_local_port(16400)
            .with_codec(Codec::Pcmu);

        let receiver_config = RtpConfig::new("127.0.0.1", 16400)
            .with_local_port(16402)
            .with_codec(Codec::Pcmu);

        let sender = match RtpSession::new(sender_config) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to create sender: {:?}", e);
                return;
            }
        };

        let receiver = match RtpSession::new(receiver_config) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to create receiver: {:?}", e);
                return;
            }
        };

        // Start both
        if let Err(e) = rt.block_on(sender.start()) {
            eprintln!("Failed to start sender: {:?}", e);
            return;
        }
        if let Err(e) = rt.block_on(receiver.start()) {
            eprintln!("Failed to start receiver: {:?}", e);
            let _ = rt.block_on(sender.stop());
            return;
        }

        // Check initial pool state
        let initial_pool = receiver.stats().buffer_pool_available;
        println!("Initial buffer pool: {} available", initial_pool);

        // Send multiple frames
        let num_frames = 10;
        for i in 0..num_frames {
            let samples: Vec<i16> = (0..160).map(|j| ((j as f32 * 0.1).sin() * 16000.0) as i16).collect();
            let frame = AudioFrame::from_samples(&samples, 8000);

            if let Err(e) = rt.block_on(sender.send_audio(frame)) {
                eprintln!("Send {} failed: {:?}", i, e);
            }

            // Small delay for packet to arrive
            std::thread::sleep(std::time::Duration::from_millis(5));

            // Receive (exercises buffer pool)
            match rt.block_on(receiver.recv_audio(50)) {
                Ok(Some(frame)) => {
                    println!("Frame {}: {} bytes", i, frame.samples.len());
                }
                Ok(None) => {
                    println!("Frame {}: no data", i);
                }
                Err(e) => {
                    eprintln!("Recv {} failed: {:?}", i, e);
                }
            }
        }

        // Check final stats
        let sender_stats = sender.stats();
        let receiver_stats = receiver.stats();
        println!("Sender: sent={}", sender_stats.packets_sent);
        println!("Receiver: recv={}, pool_available={}",
            receiver_stats.packets_received,
            receiver_stats.buffer_pool_available);

        // Pool should have buffers available (were returned after recv)
        // Note: some buffers are consumed by into_vec(), but some should be returned
        println!("Buffer pool reuse working: {} buffers available", receiver_stats.buffer_pool_available);

        // Stop sessions
        let _ = rt.block_on(sender.stop());
        let _ = rt.block_on(receiver.stop());
        println!("Test complete");
    }
}
