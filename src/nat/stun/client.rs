//! Async STUN client
//!
//! Drives STUN transactions over a UDP socket, handling retransmits.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;

use super::attributes::StunAttribute;
use super::message::StunMessage;
use super::transaction::StunTransaction;
use crate::error::{Result, RtpSipError};

/// Async STUN binding client
pub struct StunClient {
    server: SocketAddr,
}

impl StunClient {
    pub fn new(server: SocketAddr) -> Self {
        Self { server }
    }

    /// Perform a STUN Binding Request and return the reflexive address.
    /// Uses its own dedicated socket.
    pub async fn binding_request(&self) -> Result<SocketAddr> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| RtpSipError::Io(e))?;
        self.binding_request_on(&socket, self.server).await
    }

    /// Perform a STUN Binding Request on a specific socket to a specific server.
    pub async fn binding_request_on(
        &self,
        socket: &UdpSocket,
        server: SocketAddr,
    ) -> Result<SocketAddr> {
        let request = StunMessage::new_binding_request();
        self.execute_transaction(socket, server, request).await?
            .reflexive_address()
            .ok_or_else(|| {
                RtpSipError::Sip("STUN response missing mapped address".to_string())
            })
    }

    /// Perform a STUN Binding Request with CHANGE-REQUEST flags.
    /// Used for NAT type detection (RFC 3489/5780).
    pub async fn binding_request_with_change(
        &self,
        socket: &UdpSocket,
        server: SocketAddr,
        change_ip: bool,
        change_port: bool,
    ) -> Result<StunMessage> {
        let mut request = StunMessage::new_binding_request();
        request.add_attribute(StunAttribute::ChangeRequest {
            change_ip,
            change_port,
        });
        self.execute_transaction(socket, server, request).await
    }

    /// Execute a STUN transaction with retransmits.
    /// Returns the response or an error on timeout.
    async fn execute_transaction(
        &self,
        socket: &UdpSocket,
        server: SocketAddr,
        request: StunMessage,
    ) -> Result<StunMessage> {
        let now = std::time::Instant::now();
        let mut txn = StunTransaction::new(&request, now);

        // Send initial request
        socket
            .send_to(txn.request_bytes(), server)
            .await
            .map_err(RtpSipError::Io)?;

        let mut recv_buf = [0u8; 1500];

        loop {
            // Calculate how long to wait until next retransmit
            let deadline = match txn.next_deadline() {
                Some(d) => d,
                None => break,
            };

            let now = std::time::Instant::now();
            let timeout = if deadline > now {
                deadline - now
            } else {
                Duration::ZERO
            };

            // Wait for response or timeout
            match tokio::time::timeout(timeout, socket.recv_from(&mut recv_buf)).await {
                Ok(Ok((len, _from))) => {
                    // Try to parse as STUN response
                    if let Ok(response) = StunMessage::unmarshal(&recv_buf[..len]) {
                        if txn.receive_response(response) {
                            break;
                        }
                    }
                    // Not our response — continue waiting
                }
                Ok(Err(e)) => return Err(RtpSipError::Io(e)),
                Err(_) => {
                    // Timeout — poll for retransmit
                    let now = std::time::Instant::now();
                    match txn.poll(now) {
                        super::transaction::PollResult::Retransmit(data) => {
                            socket
                                .send_to(&data, server)
                                .await
                                .map_err(RtpSipError::Io)?;
                        }
                        super::transaction::PollResult::TimedOut => {
                            return Err(RtpSipError::Timeout(
                                "STUN transaction timed out".to_string(),
                            ));
                        }
                        _ => {}
                    }
                }
            }
        }

        txn.response().cloned().ok_or_else(|| {
            RtpSipError::Timeout("STUN transaction did not complete".to_string())
        })
    }

    /// Perform a binding request on a shared RTP socket.
    /// The caller must ensure incoming STUN responses are routed here.
    pub async fn binding_request_shared(
        socket: &Arc<UdpSocket>,
        server: SocketAddr,
    ) -> Result<SocketAddr> {
        let client = StunClient::new(server);
        client.binding_request_on(socket, server).await
    }

    /// Send a STUN Binding Indication (keepalive, no response expected)
    pub async fn send_keepalive(socket: &UdpSocket, server: SocketAddr) -> Result<()> {
        let msg = StunMessage::new_binding_indication();
        let data = msg.marshal();
        socket.send_to(&data, server).await.map_err(RtpSipError::Io)?;
        Ok(())
    }
}
