//! Application Authentication Middleware
//!
//! Middleware for authenticating applications and injecting application context.

use axum::{
    extract::{Request, State},
    http::HeaderMap,
    middleware::Next,
    response::Response,
};
use tower_http::cors::CorsLayer;

use crate::{
    api::handlers::AppState,
    models::application::{AppContext, ApplicationCredentials},
    utils::error::{AppError, AppResult},
};

/// Middleware to authenticate applications and inject context
pub async fn application_auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Extract API credentials from headers
    let credentials = extract_api_credentials(&headers)?;

    // Authenticate application
    let application = state
        .application_service
        .authenticate_application(credentials)
        .await?;

    // Create application context
    let app_context = AppContext {
        application_id: application.id,
        application: application.clone(),
    };

    // Check CORS origins
    if let Some(origin) = headers.get("origin") {
        let origin_str = origin
            .to_str()
            .map_err(|_| AppError::BadRequest("Invalid origin header".to_string()))?;

        if !application
            .allowed_origins
            .contains(&origin_str.to_string())
            && !application.allowed_origins.contains(&"*".to_string())
        {
            return Err(AppError::Forbidden(
                "Origin not allowed for this application".to_string(),
            ));
        }
    }

    // Inject application context into request
    request.extensions_mut().insert(app_context);

    Ok(next.run(request).await)
}

/// Extract API credentials from request headers
fn extract_api_credentials(headers: &HeaderMap) -> AppResult<ApplicationCredentials> {
    // Look for credentials in Authorization header (Bearer token format)
    if let Some(auth_header) = headers.get("authorization") {
        let auth_str = auth_header
            .to_str()
            .map_err(|_| AppError::BadRequest("Invalid authorization header".to_string()))?;

        if auth_str.starts_with("Bearer ") {
            let token = &auth_str[7..]; // Remove "Bearer " prefix
            let parts: Vec<&str> = token.split(':').collect();

            if parts.len() == 2 {
                return Ok(ApplicationCredentials {
                    api_key: parts[0].to_string(),
                    api_secret: parts[1].to_string(),
                });
            }
        }
    }

    // Look for credentials in custom headers
    let api_key = headers
        .get("x-api-key")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::BadRequest("Missing X-API-Key header".to_string()))?;

    let api_secret = headers
        .get("x-api-secret")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::BadRequest("Missing X-API-Secret header".to_string()))?;

    Ok(ApplicationCredentials {
        api_key: api_key.to_string(),
        api_secret: api_secret.to_string(),
    })
}

/// Create CORS layer based on application's allowed origins
pub fn create_cors_layer(allowed_origins: Vec<String>) -> CorsLayer {
    use tower_http::cors::{Any, CorsLayer};

    let mut cors = CorsLayer::new()
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT,
            axum::http::HeaderName::from_static("x-api-key"),
            axum::http::HeaderName::from_static("x-api-secret"),
        ]);

    if allowed_origins.contains(&"*".to_string()) {
        cors = cors.allow_origin(Any);
    } else {
        for origin in allowed_origins {
            if let Ok(origin_header) = origin.parse::<axum::http::HeaderValue>() {
                cors = cors.allow_origin(origin_header);
            }
        }
    }

    cors
}

/// Middleware for CORS handling per application
pub async fn application_cors_middleware(
    State(_state): State<AppState>,
    _headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Extract application context if it exists
    if let Some(_app_context) = request.extensions().get::<AppContext>() {
        // Application-specific CORS is handled in the main middleware
        // This is just a placeholder for additional CORS logic if needed
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn test_extract_api_credentials_from_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer ak_test123:secret456"),
        );

        let result = extract_api_credentials(&headers);
        assert!(result.is_ok());

        let credentials = result.unwrap();
        assert_eq!(credentials.api_key, "ak_test123");
        assert_eq!(credentials.api_secret, "secret456");
    }

    #[test]
    fn test_extract_api_credentials_from_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("ak_test123"));
        headers.insert("x-api-secret", HeaderValue::from_static("secret456"));

        let result = extract_api_credentials(&headers);
        assert!(result.is_ok());

        let credentials = result.unwrap();
        assert_eq!(credentials.api_key, "ak_test123");
        assert_eq!(credentials.api_secret, "secret456");
    }

    #[test]
    fn test_extract_api_credentials_missing_headers() {
        let headers = HeaderMap::new();

        let result = extract_api_credentials(&headers);
        assert!(result.is_err());

        if let Err(AppError::BadRequest(msg)) = result {
            assert!(msg.contains("Missing X-API-Key header"));
        } else {
            panic!("Expected BadRequest error");
        }
    }

    #[test]
    fn test_extract_api_credentials_invalid_bearer_format() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer invalid_format"),
        );

        let result = extract_api_credentials(&headers);
        assert!(result.is_err());
    }
}
