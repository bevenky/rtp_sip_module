//! NAT keepalive — periodic STUN binding indications
//!
//! Sends periodic STUN packets to maintain NAT binding entries.
//! Also detects NAT rebinding (reflexive address change) and
//! notifies the caller to trigger re-INVITE / SDP renegotiation.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::stun::client::StunClient;

/// Default keepalive interval range
pub const DEFAULT_KEEPALIVE_MIN_SECS: u64 = 15;
pub const DEFAULT_KEEPALIVE_MAX_SECS: u64 = 25;

/// NAT keepalive task
pub struct NatKeepalive {
    /// Socket to send keepalives on
    socket: Arc<UdpSocket>,
    /// STUN server to send keepalives to
    stun_server: SocketAddr,
    /// Minimum interval between keepalives
    min_interval: Duration,
    /// Maximum interval between keepalives
    max_interval: Duration,
    /// Running flag
    running: Arc<AtomicBool>,
}

impl NatKeepalive {
    pub fn new(
        socket: Arc<UdpSocket>,
        stun_server: SocketAddr,
        min_interval: Duration,
        max_interval: Duration,
    ) -> Self {
        Self {
            socket,
            stun_server,
            min_interval,
            max_interval,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the keepalive loop as a background task.
    ///
    /// If `addr_change_tx` is provided, sends the new reflexive address
    /// when a NAT rebinding is detected.
    pub fn start(
        self: &Arc<Self>,
        addr_change_tx: Option<mpsc::Sender<SocketAddr>>,
    ) -> tokio::task::JoinHandle<()> {
        self.running.store(true, Ordering::SeqCst);
        let this = Arc::clone(self);

        tokio::spawn(async move {
            let mut last_reflexive: Option<SocketAddr> = None;

            while this.running.load(Ordering::SeqCst) {
                // Uniform random interval in [min, max] to avoid synchronized bursts
                let min_secs = this.min_interval.as_secs_f64();
                let max_secs = this.max_interval.as_secs_f64();
                let interval = Duration::from_secs_f64(
                    min_secs + rand::random::<f64>() * (max_secs - min_secs),
                );

                tokio::time::sleep(interval).await;

                if !this.running.load(Ordering::SeqCst) {
                    break;
                }

                // Send STUN Binding Request (not just indication) so we can
                // detect reflexive address changes
                let client = StunClient::new(this.stun_server);
                match client.binding_request_on(&this.socket, this.stun_server).await {
                    Ok(reflexive) => {
                        if let Some(prev) = last_reflexive {
                            if prev != reflexive {
                                tracing::warn!(
                                    old = %prev,
                                    new = %reflexive,
                                    "NAT rebinding detected"
                                );
                                if let Some(ref tx) = addr_change_tx {
                                    let _ = tx.send(reflexive).await;
                                }
                            }
                        }
                        last_reflexive = Some(reflexive);
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "Keepalive STUN request failed");
                        // If binding request fails, fall back to just sending an indication
                        let _ = StunClient::send_keepalive(&this.socket, this.stun_server).await;
                    }
                }
            }

            tracing::debug!("NAT keepalive task stopped");
        })
    }

    /// Stop the keepalive loop
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Whether the keepalive is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}
