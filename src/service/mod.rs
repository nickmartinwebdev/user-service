//! Service Layer
//!
//! Business logic and data access layer for the user service.

pub mod user;

// Re-export the user service
pub use user::UserService;
