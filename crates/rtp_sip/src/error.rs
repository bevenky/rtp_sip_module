//! Error conversion for Python

use pyo3::prelude::*;
use pyo3::exceptions::{PyRuntimeError, PyTimeoutError, PyValueError};
use crate::core::error::Error;

/// Convert pyswitch errors to Python exceptions
pub fn to_py_err(e: Error) -> PyErr {
    match e {
        Error::Timeout => PyTimeoutError::new_err("Operation timed out"),
        Error::Config(msg) => PyValueError::new_err(msg),
        Error::Codec(msg) => PyValueError::new_err(format!("Codec error: {}", msg)),
        Error::SessionClosed => PyRuntimeError::new_err("Session is closed"),
        _ => PyRuntimeError::new_err(e.to_string()),
    }
}
