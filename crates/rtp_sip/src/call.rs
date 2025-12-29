//! Python bindings for Call types
//!
//! Uses SipSession with media bug for audio capture/injection,
//! which works correctly with mod_sofia's internal RTP management.

use std::sync::Arc;

use pyo3::prelude::*;
use tokio::sync::Mutex;

use crate::core::sip::{SipCallDirection, SipSession};
use crate::audio::PyAudioFrame;
use crate::error::to_py_err;

/// Call direction enumeration
#[pyclass(name = "CallDirection")]
#[derive(Clone)]
pub struct PyCallDirection {
    inner: SipCallDirection,
}

#[pymethods]
impl PyCallDirection {
    /// Inbound call (caller -> us)
    #[classattr]
    #[allow(non_snake_case)]
    fn INBOUND() -> Self {
        Self {
            inner: SipCallDirection::Inbound,
        }
    }

    /// Outbound call (us -> callee)
    #[classattr]
    #[allow(non_snake_case)]
    fn OUTBOUND() -> Self {
        Self {
            inner: SipCallDirection::Outbound,
        }
    }

    fn __repr__(&self) -> String {
        match self.inner {
            SipCallDirection::Inbound => "CallDirection.INBOUND".to_string(),
            SipCallDirection::Outbound => "CallDirection.OUTBOUND".to_string(),
        }
    }

    fn __eq__(&self, other: &PyCallDirection) -> bool {
        self.inner == other.inner
    }
}

/// Active call session
///
/// Represents an active SIP call with audio streaming.
/// Uses media bugs for audio capture/injection, which works
/// correctly with mod_sofia's internal RTP management.
///
/// This class is safe to use across async boundaries - it uses
/// Arc internally for reference counting.
#[pyclass(name = "Call")]
#[derive(Clone)]
pub struct PyCall {
    pub(crate) inner: Arc<Mutex<SipSession>>,
}

impl PyCall {
    pub fn new(session: Arc<Mutex<SipSession>>) -> Self {
        Self { inner: session }
    }
}

#[pymethods]
impl PyCall {
    /// Get call UUID
    #[getter]
    fn uuid(&self) -> PyResult<String> {
        let inner = self.inner.clone();
        // Use blocking lock since this is a sync getter
        let rt = pyo3_async_runtimes::tokio::get_runtime();
        let uuid = rt.block_on(async {
            let session = inner.lock().await;
            session.uuid().to_string()
        });
        Ok(uuid)
    }

    /// Get call direction
    #[getter]
    fn direction(&self) -> PyResult<PyCallDirection> {
        let inner = self.inner.clone();
        let rt = pyo3_async_runtimes::tokio::get_runtime();
        let direction = rt.block_on(async {
            let session = inner.lock().await;
            session.direction()
        });
        Ok(PyCallDirection { inner: direction })
    }

    /// Get caller ID (for inbound calls)
    #[getter]
    fn caller_id(&self) -> PyResult<Option<String>> {
        let inner = self.inner.clone();
        let rt = pyo3_async_runtimes::tokio::get_runtime();
        let caller_id = rt.block_on(async {
            let session = inner.lock().await;
            session.caller_id()
        });
        Ok(caller_id)
    }

    /// Get destination number
    #[getter]
    fn destination(&self) -> PyResult<Option<String>> {
        let inner = self.inner.clone();
        let rt = pyo3_async_runtimes::tokio::get_runtime();
        let dest = rt.block_on(async {
            let session = inner.lock().await;
            session.destination()
        });
        Ok(dest)
    }

    /// Check if call is active
    #[getter]
    fn is_active(&self) -> PyResult<bool> {
        let inner = self.inner.clone();
        let rt = pyo3_async_runtimes::tokio::get_runtime();
        let active = rt.block_on(async {
            let session = inner.lock().await;
            session.is_active()
        });
        Ok(active)
    }

    /// Answer the call (for inbound calls)
    fn answer<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut session = inner.lock().await;
            session.answer().await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Hangup the call
    ///
    /// # Arguments
    /// * `reason` - Hangup reason (optional): "normal_clearing", "user_busy", "no_answer", "call_rejected"
    #[pyo3(signature = (reason = None))]
    fn hangup<'py>(&self, py: Python<'py>, reason: Option<&str>) -> PyResult<Bound<'py, PyAny>> {
        let reason = reason.map(|s| s.to_string());
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut session = inner.lock().await;
            session.hangup(reason.as_deref()).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Receive audio frame from remote
    ///
    /// Returns L16 PCM at 16kHz mono (upsampled from 8kHz).
    /// Returns None on timeout.
    ///
    /// # Arguments
    /// * `timeout_ms` - Timeout in milliseconds (default: 100)
    #[pyo3(signature = (timeout_ms = 100))]
    fn recv_audio<'py>(&self, py: Python<'py>, timeout_ms: u64) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut session = inner.lock().await;
            match session.recv_audio(timeout_ms).await.map_err(to_py_err)? {
                Some(frame) => Ok(Some(PyAudioFrame { inner: frame })),
                None => Ok(None),
            }
        })
    }

    /// Send audio frame to remote
    ///
    /// Frame should be L16 PCM at 16kHz mono.
    fn send_audio<'py>(&self, py: Python<'py>, frame: PyAudioFrame) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let frame_inner = frame.inner;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let session = inner.lock().await;
            session.send_audio(frame_inner).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Send DTMF digits
    ///
    /// # Arguments
    /// * `digits` - DTMF digits to send (0-9, *, #, A-D)
    fn send_dtmf<'py>(&self, py: Python<'py>, digits: &str) -> PyResult<Bound<'py, PyAny>> {
        let digits = digits.to_string();
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let session = inner.lock().await;
            session.send_dtmf(&digits).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Get a channel variable
    fn get_variable(&self, name: &str) -> PyResult<Option<String>> {
        let inner = self.inner.clone();
        let name = name.to_string();
        let rt = pyo3_async_runtimes::tokio::get_runtime();
        let value = rt.block_on(async {
            let session = inner.lock().await;
            session.get_variable(&name)
        });
        Ok(value)
    }

    fn __repr__(&self) -> PyResult<String> {
        let inner = self.inner.clone();
        let rt = pyo3_async_runtimes::tokio::get_runtime();
        let repr = rt.block_on(async {
            let session = inner.lock().await;
            format!(
                "Call(uuid='{}', direction={:?}, active={})",
                session.uuid(),
                session.direction(),
                session.is_active()
            )
        });
        Ok(repr)
    }
}
