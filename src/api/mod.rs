//! API Layer
//!
//! HTTP API endpoints and request handling for the user service.

pub mod handlers;
pub mod routes;

// Re-export commonly used types
pub use handlers::AppState;
pub use routes::create_routes;