//! Security Middleware
//!
//! Provides comprehensive security middleware for authentication endpoints
//! including rate limiting, audit logging, and attack prevention.

use axum::{
    extract::{ConnectInfo, Request},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;

use std::net::SocketAddr;
use std::sync::Arc;

use crate::service::{
    rate_limit_service::{RateLimitError, RateLimitService},
    security_audit_service::{AuditLogEntry, AuthEventType, SecurityAuditService},
};
use crate::utils::error::{AppError, ErrorResponse};

/// Security middleware state containing services
#[derive(Clone)]
pub struct SecurityMiddlewareState {
    pub rate_limit_service: Arc<RateLimitService>,
    pub audit_service: Arc<SecurityAuditService>,
}

/// Security headers that should be applied to all responses
pub struct SecurityHeaders;

impl SecurityHeaders {
    /// Get standard security headers for passwordless authentication
    pub fn get_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();

        headers.insert(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
                .parse()
                .unwrap(),
        );
        headers.insert("X-Frame-Options", "DENY".parse().unwrap());
        headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
        headers.insert(
            "Referrer-Policy",
            "strict-origin-when-cross-origin".parse().unwrap(),
        );
        headers.insert(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=()".parse().unwrap(),
        );
        headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());
        headers.insert(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains".parse().unwrap(),
        );

        headers
    }
}

/// Middleware to add security headers to all responses
pub async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();
    let security_headers = SecurityHeaders::get_headers();

    for (key, value) in security_headers.iter() {
        headers.insert(key, value.clone());
    }

    response
}

/// Rate limiting middleware for authentication endpoints
pub async fn rate_limiting_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Extract security services from request extensions
    let security_state = request
        .extensions()
        .get::<SecurityMiddlewareState>()
        .ok_or_else(|| AppError::Configuration("Security middleware not configured".to_string()))?;

    let ip = addr.ip();
    let path = request.uri().path();
    let method = request.method().clone();

    // Clone the rate limit service before moving request
    let rate_limit_service = security_state.rate_limit_service.clone();

    // Determine endpoint type for rate limiting
    let endpoint = match path {
        p if p.contains("/auth/signup") => "email_signup",
        p if p.contains("/auth/verify-email") => "email_verification",
        p if p.contains("/auth/signin/otp/request") => "email_otp_request",
        p if p.contains("/auth/signin/otp/verify") => "otp_verification",
        p if p.contains("/auth/signin/passkey") => "passkey_attempts",
        p if p.contains("/auth/oauth") => "oauth_attempts",
        _ => "global_ip", // Default to global IP rate limiting
    };

    // Check IP-based rate limiting
    match rate_limit_service.check_ip_rate_limit(ip, endpoint).await {
        Ok(_status) => {
            // Rate limit check passed, continue with request
            let response = next.run(request).await;

            // Record successful rate limit check
            let _ = rate_limit_service
                .record_ip_attempt(ip, endpoint, response.status().is_success())
                .await;

            Ok(response)
        }
        Err(RateLimitError::RateLimitExceeded { retry_after, .. }) => {
            // Log the rate limit violation
            let _ = security_state
                .audit_service
                .log_failure(
                    AuthEventType::from_str(endpoint).unwrap_or(AuthEventType::SigninOtpVerify),
                    "Rate limit exceeded".to_string(),
                    Some(ip),
                    None,
                    None,
                    Some(serde_json::json!({
                        "endpoint": endpoint,
                        "method": method.to_string(),
                        "path": path
                    })),
                )
                .await;

            let error_response = ErrorResponse::new(
                "RATE_LIMIT_EXCEEDED",
                "Too many requests. Please try again later.",
            );

            let mut response =
                (StatusCode::TOO_MANY_REQUESTS, Json(error_response)).into_response();
            response
                .headers_mut()
                .insert("Retry-After", retry_after.to_string().parse().unwrap());

            Ok(response)
        }
        Err(RateLimitError::AccountLocked { locked_until, .. }) => {
            // Log the account lockout
            let _ = security_state
                .audit_service
                .log_failure(
                    AuthEventType::from_str(endpoint).unwrap_or(AuthEventType::SigninOtpVerify),
                    "Account temporarily locked".to_string(),
                    Some(ip),
                    None,
                    None,
                    Some(serde_json::json!({
                        "endpoint": endpoint,
                        "locked_until": locked_until,
                        "reason": "too_many_attempts"
                    })),
                )
                .await;

            let error_response = ErrorResponse::new(
                "ACCOUNT_LOCKED",
                "Account temporarily locked due to too many failed attempts.",
            );

            Ok((StatusCode::TOO_MANY_REQUESTS, Json(error_response)).into_response())
        }
        Err(e) => {
            log::error!("Rate limiting error: {}", e);
            Err(AppError::Internal(
                "Rate limiting service error".to_string(),
            ))
        }
    }
}

/// Middleware to detect and block password-related requests
pub async fn password_detection_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let security_state = request
        .extensions()
        .get::<SecurityMiddlewareState>()
        .ok_or_else(|| AppError::Configuration("Security middleware not configured".to_string()))?;

    let ip = addr.ip();

    // Clone the audit service before moving request
    let audit_service = security_state.audit_service.clone();

    // Check request body for password fields
    let (parts, body) = request.into_parts();
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to read request body: {}", e)))?;

    // Check for password-related fields in JSON body
    if let Ok(body_str) = String::from_utf8(body_bytes.to_vec()) {
        if contains_password_fields(&body_str) {
            // Log critical security alert
            let _ = audit_service
                .log_security_alert(
                    ip,
                    "Password field detected in passwordless authentication system".to_string(),
                    Some(serde_json::json!({
                        "path": parts.uri.path(),
                        "method": parts.method.to_string(),
                        "detected_fields": extract_suspicious_fields(&body_str),
                        "timestamp": Utc::now()
                    })),
                )
                .await;

            let error_response = ErrorResponse::new(
                "INVALID_REQUEST",
                "This system only supports passwordless authentication.",
            );

            return Ok((StatusCode::BAD_REQUEST, Json(error_response)).into_response());
        }
    }

    // Reconstruct request and continue
    let request = Request::from_parts(parts, axum::body::Body::from(body_bytes));
    Ok(next.run(request).await)
}

/// Middleware to log authentication events for audit trail
pub async fn audit_logging_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let security_state = request
        .extensions()
        .get::<SecurityMiddlewareState>()
        .ok_or_else(|| AppError::Configuration("Security middleware not configured".to_string()))?;

    let ip = addr.ip();
    let uri = request.uri().clone();
    let _method = request.method().clone();
    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Clone the audit service before moving request
    let audit_service = security_state.audit_service.clone();

    let response = next.run(request).await;
    // Generate request ID for correlation
    let request_id = uuid::Uuid::new_v4().to_string();

    // Determine event type from path
    let event_type = match uri.path() {
        p if p.contains("/auth/signup") => Some(AuthEventType::SignupEmail),
        p if p.contains("/auth/verify-email") => Some(AuthEventType::EmailVerification),
        p if p.contains("/auth/signin/otp/request") => Some(AuthEventType::SigninOtpRequest),
        p if p.contains("/auth/signin/otp/verify") => Some(AuthEventType::SigninOtpVerify),
        p if p.contains("/auth/signin/passkey") && p.contains("/begin") => {
            Some(AuthEventType::SigninPasskeyBegin)
        }
        p if p.contains("/auth/signin/passkey") && p.contains("/finish") => {
            Some(AuthEventType::SigninPasskeyFinish)
        }
        p if p.contains("/auth/oauth") && p.contains("/init") => {
            Some(AuthEventType::SigninOauthInit)
        }
        p if p.contains("/auth/oauth") && p.contains("/callback") => {
            Some(AuthEventType::SigninOauthCallback)
        }
        p if p.contains("/auth/refresh") => Some(AuthEventType::TokenRefresh),
        _ => None,
    };

    // Log the authentication event if it's relevant
    if let Some(event_type) = event_type {
        let success = response.status().is_success();
        let error_message = if !success {
            Some(format!(
                "HTTP {} - {}",
                response.status().as_u16(),
                response
                    .status()
                    .canonical_reason()
                    .unwrap_or("Unknown error")
            ))
        } else {
            None
        };

        let entry = AuditLogEntry::new(event_type, success)
            .with_ip_address(ip)
            .with_request_id(request_id);

        let entry = if let Some(ua) = user_agent {
            entry.with_user_agent(ua)
        } else {
            entry
        };

        let entry = if let Some(error) = error_message {
            entry.with_error(error)
        } else {
            entry
        };

        // Log asynchronously (don't block response)
        let audit_service_clone = audit_service.clone();
        tokio::spawn(async move {
            if let Err(e) = audit_service_clone.log_auth_event(entry).await {
                log::error!("Failed to log audit event: {}", e);
            }
        });
    }

    Ok(response)
}

/// Check if request body contains password-related fields
fn contains_password_fields(body: &str) -> bool {
    let password_indicators = [
        "password",
        "passwd",
        "pwd",
        "pass",
        "secret",
        "credential",
        "auth_token",
    ];

    let body_lower = body.to_lowercase();

    // Check for JSON field names
    for indicator in &password_indicators {
        if body_lower.contains(&format!("\"{}\"", indicator))
            || body_lower.contains(&format!("'{}'", indicator))
            || body_lower.contains(&format!("{}=", indicator))
            || body_lower.contains(&format!("{}:", indicator))
        {
            return true;
        }
    }

    false
}

/// Extract suspicious field names from request body
fn extract_suspicious_fields(body: &str) -> Vec<String> {
    let password_indicators = [
        "password",
        "passwd",
        "pwd",
        "pass",
        "secret",
        "credential",
        "auth_token",
    ];

    let mut found_fields = Vec::new();
    let body_lower = body.to_lowercase();

    for indicator in &password_indicators {
        if body_lower.contains(indicator) {
            found_fields.push(indicator.to_string());
        }
    }

    found_fields
}

/// Middleware to inject security state into request extensions
pub async fn inject_security_state_middleware(
    mut request: Request,
    next: Next,
    security_state: SecurityMiddlewareState,
) -> Response {
    request.extensions_mut().insert(security_state);
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_field_detection() {
        assert!(contains_password_fields(r#"{"password": "secret123"}"#));
        assert!(contains_password_fields(
            r#"{"email": "test@test.com", "pwd": "secret"}"#
        ));
        assert!(contains_password_fields(r#"password=secret123&email=test"#));
        assert!(!contains_password_fields(
            r#"{"email": "test@test.com", "otp": "123456"}"#
        ));
        assert!(!contains_password_fields(r#"{"passkey_response": {...}}"#));
    }

    #[test]
    fn test_suspicious_field_extraction() {
        let fields =
            extract_suspicious_fields(r#"{"password": "secret", "email": "test@test.com"}"#);
        assert!(fields.contains(&"password".to_string()));
        assert!(!fields.contains(&"email".to_string()));
    }

    #[test]
    fn test_security_headers() {
        let headers = SecurityHeaders::get_headers();
        assert!(headers.contains_key("Content-Security-Policy"));
        assert!(headers.contains_key("X-Frame-Options"));
        assert!(headers.contains_key("X-Content-Type-Options"));
        assert!(headers.contains_key("Referrer-Policy"));
        assert!(headers.contains_key("Permissions-Policy"));
    }
}
