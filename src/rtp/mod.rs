//! RTP (Real-time Transport Protocol) module
//!
//! This module provides:
//! - RTP packet parsing and building using the rtp crate
//! - G.711 codec (PCMU/PCMA) encoding/decoding using audio-codec-algorithms
//! - Adaptive jitter buffer with packet loss concealment and NACK support
//! - RTP send/receive engine with media timeout, RTCP-mux, codec asymmetry,
//!   ptime negotiation, SSRC collision recovery, and marker-bit restart
//! - RFC 2833/4733 DTMF over RTP (telephone-event)
//! - SRTP encryption/decryption (RFC 3711) with error recovery
//! - RTCP (RFC 3550) with RTCP XR VoIP Metrics (RFC 3611)

mod codec;
pub mod dtmf;
mod engine;
mod jitter;
mod packet;
pub mod plc;
pub mod goertzel;
pub mod vad;
pub mod media_tap;
pub mod rtcp;
pub mod srtp;

pub use codec::{CodecType, G711Codec};
pub use dtmf::{
    DetectedDtmf, DtmfDetector, DtmfEvent, DtmfPacket, DtmfPayload, DtmfSender,
    TELEPHONE_EVENT_PT, TELEPHONE_EVENT_RATE,
};
pub use engine::{RtpEngine, RtpEngineConfig};
pub use jitter::{JitterBuffer, JitterConfig, JitterStats};
pub use packet::{parse_rtp_packet, serialize_rtp_packet, RtpPacket, RtpPacketBuilder};
pub use plc::PacketLossConcealer;
pub use rtcp::VoipMetrics;
pub use srtp::{CryptoAttribute, SrtpCipherSuite, SrtpContext};
