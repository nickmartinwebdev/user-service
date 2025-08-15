//! Utilities Module
//!
//! Shared utilities for error handling, security, validation, and other
//! cross-cutting concerns used throughout the user service.

pub mod error;
pub mod security;
pub mod validation;

// Re-export commonly used utilities
pub use error::{AppError, AppResult, ErrorResponse};
pub use security::*;
pub use validation::*;