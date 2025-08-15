//! Database Module
//!
//! Database connection management and utilities for the user service.

pub mod connection;

// Re-export commonly used types
pub use connection::{DatabaseConfig, DatabasePool};