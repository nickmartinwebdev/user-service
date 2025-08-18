//! API Layer
//!
//! HTTP API endpoints and request handling for the user service.

pub mod handlers;
pub mod middleware;
pub mod oauth_handlers;
pub mod routes;

// Re-export commonly used types
pub use handlers::AppState;
pub use middleware::{
    auth_middleware, extract_auth_user, extract_optional_auth_user, optional_auth_middleware,
    AuthUser,
};
pub use routes::{
    create_core_routes, create_minimal_routes, create_readonly_routes, create_routes, RouterBuilder,
};
