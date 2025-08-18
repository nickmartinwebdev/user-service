//! Service Layer
//!
//! Business logic and data access layer for the user service.

pub mod email_service;
pub mod jwt;
pub mod user;

// Re-export services
pub use email_service::{EmailConfig, EmailService};
pub use jwt::JwtService;
pub use user::UserService;
