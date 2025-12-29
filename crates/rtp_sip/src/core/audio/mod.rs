//! Audio module - frames, codecs, and resampling
//!
//! This module provides audio processing for pyswitch:
//! - Codec type enumeration (encoding/decoding handled by libfs)
//! - Resampling uses libfs's bundled Speex library
//! - AudioFrame is a simple container for L16 PCM data
//! - BufferPool provides object pooling to reduce allocations in hot path

mod codec;
mod frame;
pub mod pool;
mod resampler;

pub use codec::Codec;
pub use frame::AudioFrame;
pub use pool::{BufferPool, PooledBuffer};
pub use resampler::Resampler;
