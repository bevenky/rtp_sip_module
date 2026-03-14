//! Media hooks/tapping for audio forking
//!
//! Provides non-intrusive audio tapping ("media bugs"). Taps receive a
//! copy of decoded audio frames
//! without modifying the original audio stream.
//!
//! Use cases:
//! - Recording (fork audio to disk/storage)
//! - ASR / Speech-to-text (fork to recognition engine)
//! - Real-time processing (analytics, monitoring)
//!
//! Multiple taps can be active simultaneously on a single call.
//! Each tap specifies a direction: Rx (incoming), Tx (outgoing), or Both.

use parking_lot::Mutex;
use std::collections::HashMap;
use tokio::sync::mpsc;

/// Direction of audio to tap
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapDirection {
    /// Receive direction only (audio coming from remote party)
    Rx,
    /// Transmit direction only (audio being sent to remote party)
    Tx,
    /// Both directions
    Both,
}

impl TapDirection {
    /// Check if this direction includes Rx
    pub fn includes_rx(&self) -> bool {
        matches!(self, TapDirection::Rx | TapDirection::Both)
    }

    /// Check if this direction includes Tx
    pub fn includes_tx(&self) -> bool {
        matches!(self, TapDirection::Tx | TapDirection::Both)
    }
}

impl std::fmt::Display for TapDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TapDirection::Rx => write!(f, "rx"),
            TapDirection::Tx => write!(f, "tx"),
            TapDirection::Both => write!(f, "both"),
        }
    }
}

/// An audio frame delivered to a tap consumer
///
/// P2-DTMF-8: Uses `Arc<[i16]>` instead of `Vec<i16>` for the sample buffer.
/// When multiple taps receive the same frame, the Arc allows sharing the
/// underlying buffer across taps without per-tap allocation/copy.
#[derive(Debug, Clone)]
pub struct AudioFrame {
    /// Linear PCM samples (16-bit signed), shared across taps via Arc
    pub samples: std::sync::Arc<[i16]>,
    /// Sample rate in Hz (typically 8000)
    pub sample_rate: u32,
    /// RTP timestamp of this frame
    pub timestamp: u32,
    /// Direction this frame was captured from
    pub direction: TapDirection,
}

/// Default channel capacity for media taps.
/// 1000 packets at 50 packets/second (20ms ptime) = ~20 seconds of audio.
/// This provides backpressure to prevent OOM from slow consumers while
/// still allowing reasonable buffering for transient slowness.
const DEFAULT_TAP_CHANNEL_CAPACITY: usize = 1000;

/// A single media tap registration
struct MediaTap {
    /// Unique identifier for this tap (stored for debug/logging)
    #[allow(dead_code)]
    id: String,
    /// Direction(s) to capture
    direction: TapDirection,
    /// Channel sender for delivering frames to the consumer.
    /// Uses bounded channel with capacity DEFAULT_TAP_CHANNEL_CAPACITY to
    /// provide backpressure and prevent OOM from slow consumers. When full,
    /// the oldest frame concept is approximated by dropping the current frame
    /// and logging a warning.
    tx: mpsc::Sender<AudioFrame>,
}

/// Manages multiple media taps on a single RTP stream
///
/// Thread-safe: all operations are protected by an internal Mutex.
/// The distribute methods use `try_send` which never blocks, ensuring the
/// RTP processing path is not affected by slow consumers. If a consumer's
/// channel is full, the frame is dropped and a warning is logged. If a
/// consumer's channel is closed (dropped receiver), the tap is automatically
/// removed.
pub struct MediaTapManager {
    taps: Mutex<HashMap<String, MediaTap>>,
    next_id: Mutex<u64>,
}

impl MediaTapManager {
    /// Create a new empty tap manager
    pub fn new() -> Self {
        Self {
            taps: Mutex::new(HashMap::new()),
            next_id: Mutex::new(1),
        }
    }

    /// Add a new media tap
    ///
    /// Returns `(tap_id, receiver)` where receiver yields `AudioFrame`s.
    /// The tap is automatically removed when the receiver is dropped.
    /// The channel has a bounded capacity of ~20 seconds of audio at 50pps.
    pub fn add_tap(
        &self,
        direction: TapDirection,
    ) -> (String, mpsc::Receiver<AudioFrame>) {
        let (tx, rx) = mpsc::channel(DEFAULT_TAP_CHANNEL_CAPACITY);

        let id = {
            let mut next = self.next_id.lock();
            let id = format!("tap-{}", *next);
            *next += 1;
            id
        };

        let tap = MediaTap {
            id: id.clone(),
            direction,
            tx,
        };

        self.taps.lock().insert(id.clone(), tap);
        (id, rx)
    }

    /// Remove a media tap by ID
    ///
    /// Returns true if the tap was found and removed.
    pub fn remove_tap(&self, tap_id: &str) -> bool {
        self.taps.lock().remove(tap_id).is_some()
    }

    /// Get the number of active taps
    pub fn tap_count(&self) -> usize {
        self.taps.lock().len()
    }

    /// Check if any taps are active
    pub fn has_taps(&self) -> bool {
        !self.taps.lock().is_empty()
    }

    /// Check if any Rx taps are active (for fast-path skip)
    pub fn has_rx_taps(&self) -> bool {
        self.taps
            .lock()
            .values()
            .any(|t| t.direction.includes_rx())
    }

    /// Check if any Tx taps are active (for fast-path skip)
    pub fn has_tx_taps(&self) -> bool {
        self.taps
            .lock()
            .values()
            .any(|t| t.direction.includes_tx())
    }

    /// Distribute an Rx (received) audio frame to all matching taps.
    ///
    /// Non-blocking: uses `try_send` on bounded channel. If a consumer's
    /// channel is full, the frame is dropped and a warning is logged.
    /// If a consumer's channel is closed (receiver dropped), the tap is
    /// automatically removed.
    pub fn distribute_rx(&self, samples: &[i16], sample_rate: u32, timestamp: u32) {
        let mut taps = self.taps.lock();
        let mut closed_taps: Vec<String> = Vec::new();

        // P2-DTMF-8: Create Arc once, share across all taps
        let shared_samples: std::sync::Arc<[i16]> = samples.into();

        for (id, tap) in taps.iter() {
            if tap.direction.includes_rx() {
                let frame = AudioFrame {
                    samples: shared_samples.clone(),
                    sample_rate,
                    timestamp,
                    direction: TapDirection::Rx,
                };
                match tap.tx.try_send(frame) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        tracing::warn!(
                            tap_id = %id,
                            "media tap rx channel full, dropping frame (slow consumer)"
                        );
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        // Receiver dropped — mark for cleanup
                        closed_taps.push(id.clone());
                    }
                }
            }
        }

        // Remove closed taps
        for id in closed_taps {
            taps.remove(&id);
        }
    }

    /// Distribute a Tx (transmitted) audio frame to all matching taps.
    ///
    /// Non-blocking: uses `try_send` on bounded channel. If a consumer's
    /// channel is full, the frame is dropped and a warning is logged.
    /// If a consumer's channel is closed (receiver dropped), the tap is
    /// automatically removed.
    pub fn distribute_tx(&self, samples: &[i16], sample_rate: u32, timestamp: u32) {
        let mut taps = self.taps.lock();
        let mut closed_taps: Vec<String> = Vec::new();

        // P2-DTMF-8: Create Arc once, share across all taps
        let shared_samples: std::sync::Arc<[i16]> = samples.into();

        for (id, tap) in taps.iter() {
            if tap.direction.includes_tx() {
                let frame = AudioFrame {
                    samples: shared_samples.clone(),
                    sample_rate,
                    timestamp,
                    direction: TapDirection::Tx,
                };
                match tap.tx.try_send(frame) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        tracing::warn!(
                            tap_id = %id,
                            "media tap tx channel full, dropping frame (slow consumer)"
                        );
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        // Receiver dropped — mark for cleanup
                        closed_taps.push(id.clone());
                    }
                }
            }
        }

        // Remove closed taps
        for id in closed_taps {
            taps.remove(&id);
        }
    }

    /// Remove all taps
    pub fn clear(&self) {
        self.taps.lock().clear();
    }

    /// Get list of active tap IDs with their directions
    pub fn active_taps(&self) -> Vec<(String, TapDirection)> {
        self.taps
            .lock()
            .iter()
            .map(|(id, tap)| (id.clone(), tap.direction))
            .collect()
    }
}

impl Default for MediaTapManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_tap_direction_includes() {
        assert!(TapDirection::Rx.includes_rx());
        assert!(!TapDirection::Rx.includes_tx());

        assert!(!TapDirection::Tx.includes_rx());
        assert!(TapDirection::Tx.includes_tx());

        assert!(TapDirection::Both.includes_rx());
        assert!(TapDirection::Both.includes_tx());
    }

    #[test]
    fn test_tap_direction_display() {
        assert_eq!(TapDirection::Rx.to_string(), "rx");
        assert_eq!(TapDirection::Tx.to_string(), "tx");
        assert_eq!(TapDirection::Both.to_string(), "both");
    }

    #[test]
    fn test_add_remove_tap() {
        let manager = MediaTapManager::new();

        assert_eq!(manager.tap_count(), 0);
        assert!(!manager.has_taps());

        let (id1, _rx1) = manager.add_tap(TapDirection::Rx);
        assert_eq!(manager.tap_count(), 1);
        assert!(manager.has_taps());
        assert!(manager.has_rx_taps());
        assert!(!manager.has_tx_taps());

        let (id2, _rx2) = manager.add_tap(TapDirection::Tx);
        assert_eq!(manager.tap_count(), 2);
        assert!(manager.has_tx_taps());

        assert!(manager.remove_tap(&id1));
        assert_eq!(manager.tap_count(), 1);
        assert!(!manager.has_rx_taps());
        assert!(manager.has_tx_taps());

        assert!(manager.remove_tap(&id2));
        assert_eq!(manager.tap_count(), 0);

        // Removing non-existent tap returns false
        assert!(!manager.remove_tap("nonexistent"));
    }

    #[test]
    fn test_distribute_rx() {
        let manager = MediaTapManager::new();

        let (_id1, mut rx1) = manager.add_tap(TapDirection::Rx);
        let (_id2, mut rx2) = manager.add_tap(TapDirection::Both);
        let (_id3, mut rx3) = manager.add_tap(TapDirection::Tx);

        let samples: Vec<i16> = vec![100, 200, 300];
        manager.distribute_rx(&samples, 8000, 1000);

        // Rx tap should receive
        let frame1 = rx1.try_recv().unwrap();
        let expected: Arc<[i16]> = vec![100i16, 200, 300].into();
        assert_eq!(frame1.samples, expected);
        assert_eq!(frame1.sample_rate, 8000);
        assert_eq!(frame1.timestamp, 1000);
        assert_eq!(frame1.direction, TapDirection::Rx);

        // Both tap should receive
        let frame2 = rx2.try_recv().unwrap();
        let expected2: Arc<[i16]> = vec![100i16, 200, 300].into();
        assert_eq!(frame2.samples, expected2);
        assert_eq!(frame2.direction, TapDirection::Rx);

        // Tx-only tap should NOT receive Rx frames
        assert!(rx3.try_recv().is_err());
    }

    #[test]
    fn test_distribute_tx() {
        let manager = MediaTapManager::new();

        let (_id1, mut rx1) = manager.add_tap(TapDirection::Rx);
        let (_id2, mut rx2) = manager.add_tap(TapDirection::Both);
        let (_id3, mut rx3) = manager.add_tap(TapDirection::Tx);

        let samples: Vec<i16> = vec![400, 500, 600];
        manager.distribute_tx(&samples, 8000, 2000);

        // Rx-only tap should NOT receive Tx frames
        assert!(rx1.try_recv().is_err());

        // Both tap should receive
        let frame2 = rx2.try_recv().unwrap();
        let expected_tx: Arc<[i16]> = vec![400i16, 500, 600].into();
        assert_eq!(frame2.samples, expected_tx);
        assert_eq!(frame2.direction, TapDirection::Tx);

        // Tx tap should receive
        let frame3 = rx3.try_recv().unwrap();
        let expected_tx2: Arc<[i16]> = vec![400i16, 500, 600].into();
        assert_eq!(frame3.samples, expected_tx2);
        assert_eq!(frame3.timestamp, 2000);
        assert_eq!(frame3.direction, TapDirection::Tx);
    }

    #[test]
    fn test_auto_cleanup_on_receiver_drop() {
        let manager = MediaTapManager::new();

        let (_id1, rx1) = manager.add_tap(TapDirection::Rx);
        let (_id2, _rx2) = manager.add_tap(TapDirection::Rx);

        assert_eq!(manager.tap_count(), 2);

        // Drop the first receiver
        drop(rx1);

        // Distribute should clean up the closed tap
        manager.distribute_rx(&[1, 2, 3], 8000, 0);
        assert_eq!(manager.tap_count(), 1);
    }

    #[test]
    fn test_multiple_frames() {
        let manager = MediaTapManager::new();
        let (_id, mut rx) = manager.add_tap(TapDirection::Both);

        // Send multiple frames in both directions
        manager.distribute_rx(&[1, 2], 8000, 100);
        manager.distribute_tx(&[3, 4], 8000, 200);
        manager.distribute_rx(&[5, 6], 8000, 300);

        let f1 = rx.try_recv().unwrap();
        assert_eq!(f1.direction, TapDirection::Rx);
        let e1: Arc<[i16]> = vec![1i16, 2].into();
        assert_eq!(f1.samples, e1);

        let f2 = rx.try_recv().unwrap();
        assert_eq!(f2.direction, TapDirection::Tx);
        let e2: Arc<[i16]> = vec![3i16, 4].into();
        assert_eq!(f2.samples, e2);

        let f3 = rx.try_recv().unwrap();
        assert_eq!(f3.direction, TapDirection::Rx);
        let e3: Arc<[i16]> = vec![5i16, 6].into();
        assert_eq!(f3.samples, e3);
    }

    #[test]
    fn test_clear() {
        let manager = MediaTapManager::new();

        let _ = manager.add_tap(TapDirection::Rx);
        let _ = manager.add_tap(TapDirection::Tx);
        let _ = manager.add_tap(TapDirection::Both);

        assert_eq!(manager.tap_count(), 3);

        manager.clear();
        assert_eq!(manager.tap_count(), 0);
        assert!(!manager.has_taps());
    }

    #[test]
    fn test_active_taps() {
        let manager = MediaTapManager::new();

        let (id1, _rx1) = manager.add_tap(TapDirection::Rx);
        let (id2, _rx2) = manager.add_tap(TapDirection::Tx);

        let active = manager.active_taps();
        assert_eq!(active.len(), 2);

        let found_rx = active.iter().any(|(id, dir)| id == &id1 && *dir == TapDirection::Rx);
        let found_tx = active.iter().any(|(id, dir)| id == &id2 && *dir == TapDirection::Tx);
        assert!(found_rx);
        assert!(found_tx);
    }

    #[test]
    fn test_unique_tap_ids() {
        let manager = MediaTapManager::new();

        let (id1, _) = manager.add_tap(TapDirection::Rx);
        let (id2, _) = manager.add_tap(TapDirection::Rx);
        let (id3, _) = manager.add_tap(TapDirection::Rx);

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    // test_audio_frame_clone removed: just testing derive(Clone)

    #[test]
    fn test_channel_full_drops_frame_does_not_block() {
        // Verify that when the bounded channel is full, distribute_rx/tx
        // drops frames instead of blocking (which would stall the RTP path).
        let manager = MediaTapManager::new();
        let (_id, _rx) = manager.add_tap(TapDirection::Rx);

        // Fill the channel to capacity (DEFAULT_TAP_CHANNEL_CAPACITY = 1000)
        let samples: Vec<i16> = vec![42; 160];
        for i in 0..DEFAULT_TAP_CHANNEL_CAPACITY {
            manager.distribute_rx(&samples, 8000, i as u32);
        }

        // This should NOT block -- the frame should be dropped.
        // If this call blocks, the test will hang (and timeout), catching the bug.
        manager.distribute_rx(&samples, 8000, 9999);

        // The manager should still be functional; tap should still exist
        // (channel full != channel closed).
        assert_eq!(manager.tap_count(), 1);
    }

    #[test]
    fn test_channel_full_tx_drops_frame() {
        let manager = MediaTapManager::new();
        let (_id, _rx) = manager.add_tap(TapDirection::Tx);

        let samples: Vec<i16> = vec![42; 160];
        for i in 0..DEFAULT_TAP_CHANNEL_CAPACITY {
            manager.distribute_tx(&samples, 8000, i as u32);
        }

        // Should not block
        manager.distribute_tx(&samples, 8000, 9999);
        assert_eq!(manager.tap_count(), 1);
    }

    #[test]
    fn test_no_taps_distribution_is_noop() {
        let manager = MediaTapManager::new();

        // Should not panic or error with no taps
        manager.distribute_rx(&[1, 2, 3], 8000, 0);
        manager.distribute_tx(&[4, 5, 6], 8000, 0);
    }
}
