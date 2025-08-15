//! Data Models Module
//!
//! This module contains all data structures used throughout the user service.
//! It includes user entities, request/response types, and validation logic.

pub mod requests;
pub mod user;

// Re-export commonly used types
pub use requests::*;
pub use user::*;
