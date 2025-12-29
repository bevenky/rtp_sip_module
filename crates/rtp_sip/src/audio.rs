//! Python bindings for audio types

use pyo3::prelude::*;
use crate::core::audio::{AudioFrame, Codec};

/// Audio codec enumeration
#[pyclass(name = "Codec")]
#[derive(Clone)]
pub struct PyCodec {
    inner: Codec,
}

#[pymethods]
impl PyCodec {
    /// G.711 u-law (PCMU)
    #[classattr]
    #[allow(non_snake_case)]
    fn PCMU() -> Self {
        Self { inner: Codec::Pcmu }
    }

    /// G.711 A-law (PCMA)
    #[classattr]
    #[allow(non_snake_case)]
    fn PCMA() -> Self {
        Self { inner: Codec::Pcma }
    }

    /// Linear 16-bit PCM
    #[classattr]
    #[allow(non_snake_case)]
    fn L16() -> Self {
        Self { inner: Codec::L16 }
    }

    /// Get RTP payload type
    #[getter]
    fn payload_type(&self) -> u8 {
        self.inner.payload_type()
    }

    fn __repr__(&self) -> String {
        match self.inner {
            Codec::Pcmu => "Codec.PCMU".to_string(),
            Codec::Pcma => "Codec.PCMA".to_string(),
            Codec::L16 => "Codec.L16".to_string(),
        }
    }
}

impl From<Codec> for PyCodec {
    fn from(c: Codec) -> Self {
        Self { inner: c }
    }
}

impl From<PyCodec> for Codec {
    fn from(c: PyCodec) -> Self {
        c.inner
    }
}

/// Audio frame containing PCM samples
#[pyclass(name = "AudioFrame")]
#[derive(Clone)]
pub struct PyAudioFrame {
    pub(crate) inner: AudioFrame,
}

#[pymethods]
impl PyAudioFrame {
    /// Create a new audio frame from bytes
    ///
    /// # Arguments
    /// * `samples` - L16 PCM bytes (little-endian)
    /// * `sample_rate` - Sample rate in Hz (default: 16000)
    #[new]
    #[pyo3(signature = (samples, sample_rate = 16000))]
    fn new(samples: Vec<u8>, sample_rate: u32) -> Self {
        Self {
            inner: AudioFrame::new(samples, sample_rate),
        }
    }

    /// Raw PCM samples as bytes (L16, little-endian)
    #[getter]
    fn samples(&self) -> &[u8] {
        &self.inner.samples
    }

    /// Sample rate in Hz
    #[getter]
    fn sample_rate(&self) -> u32 {
        self.inner.sample_rate
    }

    /// Number of channels
    #[getter]
    fn channels(&self) -> u8 {
        self.inner.channels
    }

    /// RTP timestamp
    #[getter]
    fn timestamp(&self) -> u64 {
        self.inner.timestamp
    }

    /// Frame duration in milliseconds
    #[getter]
    fn duration_ms(&self) -> u32 {
        self.inner.duration_ms()
    }

    /// Number of samples in the frame
    fn num_samples(&self) -> usize {
        self.inner.num_samples()
    }

    /// Check if frame is empty
    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Create a frame from raw bytes
    #[staticmethod]
    #[pyo3(signature = (data, sample_rate = 16000))]
    fn from_bytes(data: Vec<u8>, sample_rate: u32) -> Self {
        Self {
            inner: AudioFrame::new(data, sample_rate),
        }
    }

    /// Create a 20ms frame of silence at 16kHz
    #[staticmethod]
    fn silence_20ms() -> Self {
        Self {
            inner: AudioFrame::silence_20ms(),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "AudioFrame(samples={} bytes, sample_rate={}, duration={}ms)",
            self.inner.samples.len(),
            self.inner.sample_rate,
            self.inner.duration_ms()
        )
    }

    fn __len__(&self) -> usize {
        self.inner.samples.len()
    }
}

impl From<AudioFrame> for PyAudioFrame {
    fn from(f: AudioFrame) -> Self {
        Self { inner: f }
    }
}

impl From<PyAudioFrame> for AudioFrame {
    fn from(f: PyAudioFrame) -> Self {
        f.inner
    }
}
