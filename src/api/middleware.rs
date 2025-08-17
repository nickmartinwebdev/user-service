//! Authentication Middleware
//!
//! Middleware for JWT authentication and authorization in API endpoints.

use crate::models::UserContext;
use crate::service::JwtService;
use crate::utils::error::AppError;
use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, HeaderMap},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

#[cfg(test)]
use axum::http::StatusCode;

/// Extension type for storing authenticated user context in request extensions
#[derive(Debug, Clone)]
pub struct AuthUser(pub UserContext);

/// Authentication middleware that validates JWT tokens and extracts user context
///
/// This middleware:
/// 1. Extracts the Authorization header from the request
/// 2. Validates the Bearer token format
/// 3. Verifies the JWT token using the JWT service
/// 4. Adds the user context to request extensions for use in handlers
///
/// If authentication fails, returns a 401 Unauthorized response.
pub async fn auth_middleware(
    State(jwt_service): State<Arc<JwtService>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Extract Authorization header
    let auth_header = headers
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| AppError::Authentication("Missing Authorization header".into()))?;

    // Check for Bearer token format
    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Authentication(
            "Invalid Authorization header format".into(),
        ));
    }

    // Extract token (remove "Bearer " prefix)
    let token = &auth_header[7..];

    // Validate token and extract user context
    let user_context = jwt_service
        .validate_access_token(token)
        .map_err(|_| AppError::Authentication("Invalid or expired token".into()))?;

    // Add user context to request extensions
    request.extensions_mut().insert(AuthUser(user_context));

    // Continue to the next middleware/handler
    Ok(next.run(request).await)
}

/// Optional authentication middleware that extracts user context if present but doesn't require it
///
/// This middleware:
/// 1. Attempts to extract and validate the Authorization header
/// 2. If valid, adds user context to request extensions
/// 3. If invalid or missing, continues without user context
///
/// This is useful for endpoints that provide different functionality for authenticated users
/// but don't require authentication.
pub async fn optional_auth_middleware(
    State(jwt_service): State<Arc<JwtService>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Response {
    // Try to extract Authorization header
    if let Some(auth_header) = headers
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
    {
        // Check for Bearer token format
        if auth_header.starts_with("Bearer ") {
            let token = &auth_header[7..];

            // Try to validate token and extract user context
            if let Ok(user_context) = jwt_service.validate_access_token(token) {
                request.extensions_mut().insert(AuthUser(user_context));
            }
        }
    }

    // Continue regardless of authentication status
    next.run(request).await
}

/// Helper function to extract authenticated user from request extensions
///
/// This function should be used in handlers that require authentication.
/// The auth_middleware must be applied to the route for this to work.
pub fn extract_auth_user(request: &Request) -> Result<&UserContext, AppError> {
    request
        .extensions()
        .get::<AuthUser>()
        .map(|auth_user| &auth_user.0)
        .ok_or_else(|| {
            AppError::Authentication("User context not found in request extensions".into())
        })
}

/// Helper function to optionally extract authenticated user from request extensions
///
/// This function should be used in handlers that have optional authentication.
/// The optional_auth_middleware should be applied to the route for this to work.
pub fn extract_optional_auth_user(request: &Request) -> Option<&UserContext> {
    request
        .extensions()
        .get::<AuthUser>()
        .map(|auth_user| &auth_user.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::UserContext;
    use axum::{
        body::Body,
        http::{Method, Request},
        middleware::from_fn_with_state,
        routing::get,
        Router,
    };
    use chrono::{Duration, Utc};
    use sqlx::PgPool;
    use std::sync::Arc;
    use tower::util::ServiceExt;
    use uuid::Uuid;

    fn create_test_jwt_service() -> Arc<JwtService> {
        // This would normally use a test database
        let pool = PgPool::connect_lazy("postgresql://test:test@localhost/test")
            .expect("Failed to create test pool");

        Arc::new(JwtService::new(
            pool,
            "test_access_secret_key".to_string(),
            "test_refresh_secret_key".to_string(),
        ))
    }

    async fn test_handler() -> &'static str {
        "OK"
    }

    async fn auth_test_handler(request: Request<Body>) -> Result<&'static str, AppError> {
        let _user_context = extract_auth_user(&request)?;
        Ok("Authenticated OK")
    }

    #[tokio::test]
    async fn test_auth_middleware_missing_header() {
        let jwt_service = create_test_jwt_service();
        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(from_fn_with_state(jwt_service, auth_middleware));

        let request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_middleware_invalid_format() {
        let jwt_service = create_test_jwt_service();
        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(from_fn_with_state(jwt_service, auth_middleware));

        let request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header(AUTHORIZATION, "Invalid token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_optional_auth_middleware_missing_header() {
        let jwt_service = create_test_jwt_service();
        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(from_fn_with_state(jwt_service, optional_auth_middleware));

        let request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_extract_auth_user_missing() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let result = extract_auth_user(&request);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_optional_auth_user_missing() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let result = extract_optional_auth_user(&request);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_auth_user_present() {
        let user_context = UserContext {
            user_id: Uuid::new_v4(),
            token_id: "test_token_id".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
        };

        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        request
            .extensions_mut()
            .insert(AuthUser(user_context.clone()));

        let result = extract_auth_user(&request).unwrap();
        assert_eq!(result.user_id, user_context.user_id);
        assert_eq!(result.token_id, user_context.token_id);
    }

    #[test]
    fn test_extract_optional_auth_user_present() {
        let user_context = UserContext {
            user_id: Uuid::new_v4(),
            token_id: "test_token_id".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
        };

        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        request
            .extensions_mut()
            .insert(AuthUser(user_context.clone()));

        let result = extract_optional_auth_user(&request).unwrap();
        assert_eq!(result.user_id, user_context.user_id);
        assert_eq!(result.token_id, user_context.token_id);
    }
}
