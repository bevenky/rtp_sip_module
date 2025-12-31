//! Session management module
//!
//! Provides:
//! - Call state machine
//! - Event definitions
//! - Multi-session management

pub mod events;
pub mod manager;
pub mod state;

pub use events::CallEvent;
pub use manager::{CallSession, ManagerHandle, SessionManager};
pub use state::{CallDirection, CallState, CallTiming, StateValidator};
