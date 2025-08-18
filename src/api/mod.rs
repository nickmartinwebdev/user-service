//! API Layer
//!
//! HTTP API endpoints and request handling for the user service.

pub mod handlers;
pub mod middleware;
pub mod oauth_handlers;
pub mod routes;
pub mod security_middleware;
pub mod security_router;
pub mod webauthn_handlers;

// Re-export commonly used types
pub use handlers::AppState;
pub use middleware::{
    auth_middleware, extract_auth_user, extract_optional_auth_user, optional_auth_middleware,
    AuthUser,
};
pub use routes::{
    create_core_routes, create_minimal_routes, create_readonly_routes, create_routes, RouterBuilder,
};
pub use security_middleware::{
    audit_logging_middleware, password_detection_middleware, rate_limiting_middleware,
    security_headers_middleware, SecurityHeaders, SecurityMiddlewareState,
};
pub use security_router::{inject_security_state, with_security_state};
