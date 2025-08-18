//! Data Models Module
//!
//! This module contains all data structures used throughout the user service.
//! It includes user entities, request/response types, and validation logic.

pub mod auth;
pub mod email_verification;
pub mod requests;
pub mod user;

// Re-export commonly used types
pub use auth::*;
pub use email_verification::*;
pub use requests::*;
pub use user::*;
