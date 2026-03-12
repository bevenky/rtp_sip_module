//! UDP hole punching
//!
//! Sends initial packets to open NAT pinhole entries before media flows.
//! Should be called after SDP exchange but before expecting incoming media.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;

use super::stun::message::StunMessage;
use crate::error::{Result, RtpSipError};

/// Default number of hole-punch packets
pub const DEFAULT_HOLE_PUNCH_COUNT: usize = 3;

/// Default interval between hole-punch packets
pub const DEFAULT_HOLE_PUNCH_INTERVAL: Duration = Duration::from_millis(20);

/// Send hole-punch packets to open a NAT pinhole.
///
/// Uses STUN Binding Requests (which work as a universal NAT traversal
/// mechanism since they have a known format that won't confuse RTP decoders).
///
/// If the remote end is also behind NAT, both sides should call this
/// simultaneously for the best chance of success.
pub async fn punch(
    socket: &UdpSocket,
    target: SocketAddr,
    count: usize,
    interval: Duration,
) -> Result<()> {
    tracing::debug!(target = %target, count, "Sending hole-punch packets");

    for i in 0..count {
        let request = StunMessage::new_binding_request();
        let data = request.marshal();
        socket
            .send_to(&data, target)
            .await
            .map_err(RtpSipError::Io)?;

        if i < count - 1 {
            tokio::time::sleep(interval).await;
        }
    }

    tracing::debug!(target = %target, "Hole-punch complete");
    Ok(())
}
