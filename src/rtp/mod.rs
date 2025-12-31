//! RTP (Real-time Transport Protocol) module
//!
//! This module provides:
//! - RTP packet parsing and building using the rtp crate
//! - G.711 codec (PCMU/PCMA) encoding/decoding using audio-codec-algorithms
//! - Adaptive jitter buffer with packet loss concealment
//! - RTP send/receive engine
//! - RFC 2833/4733 DTMF over RTP (telephone-event)

mod codec;
pub mod dtmf;
mod engine;
mod jitter;
mod packet;

pub use codec::{CodecType, G711Codec};
pub use dtmf::{
    DetectedDtmf, DtmfDetector, DtmfEvent, DtmfPacket, DtmfPayload, DtmfSender,
    TELEPHONE_EVENT_PT, TELEPHONE_EVENT_RATE,
};
pub use engine::{RtpEngine, RtpEngineConfig};
pub use jitter::{JitterBuffer, JitterConfig, JitterStats, PacketLossConcealer};
pub use packet::{parse_rtp_packet, serialize_rtp_packet, RtpPacket, RtpPacketBuilder};
