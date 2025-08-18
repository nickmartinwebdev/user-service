//! Security State Injection
//!
//! Simple utilities for injecting security services into router middleware.

use axum::{extract::Request, middleware::Next, response::Response, Router};
use std::sync::Arc;

use super::{handlers::AppState, security_middleware::SecurityMiddlewareState};
use crate::service::{RateLimitService, SecurityAuditService};

/// Middleware to inject security state into request extensions
pub async fn inject_security_state(
    mut request: Request,
    next: Next,
    security_state: SecurityMiddlewareState,
) -> Response {
    request.extensions_mut().insert(security_state);
    next.run(request).await
}

/// Add security state to any router
pub fn with_security_state(
    router: Router<AppState>,
    rate_limit_service: Arc<RateLimitService>,
    audit_service: Arc<SecurityAuditService>,
) -> Router<AppState> {
    let security_state = SecurityMiddlewareState {
        rate_limit_service,
        audit_service,
    };

    router.layer(axum::middleware::from_fn(
        move |req: Request, next: Next| inject_security_state(req, next, security_state.clone()),
    ))
}
