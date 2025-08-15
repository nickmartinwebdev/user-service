//! Error Handling Utilities
//!
//! Comprehensive error types and handling for the user service.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::fmt;
use thiserror::Error;

/// Main application error type that can represent errors from any feature
#[derive(Error, Debug)]
pub enum AppError {
    /// Database-related errors
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Validation errors for user input
    #[error("Validation error: {0}")]
    Validation(String),

    /// Authentication and authorization errors
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// Resource not found errors
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Conflict errors (e.g., duplicate resources)
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Rate limiting errors
    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    /// External service errors
    #[error("External service error: {0}")]
    ExternalService(String),

    /// Generic internal server errors
    #[error("Internal server error: {0}")]
    Internal(String),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Password hashing errors
    #[error("Password hashing error: {0}")]
    HashingError(#[from] bcrypt::BcryptError),
}

/// Standard error response structure for API endpoints
#[derive(Serialize, Debug)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ErrorResponse {
    pub fn new(error: &str, message: &str) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
            details: None,
        }
    }

    pub fn with_details(error: &str, message: &str, details: serde_json::Value) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
            details: Some(details),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match self {
            AppError::Database(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "A database error occurred".to_string(),
            ),
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, "VALIDATION_ERROR", msg),
            AppError::Authentication(msg) => {
                (StatusCode::UNAUTHORIZED, "AUTHENTICATION_ERROR", msg)
            }
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "NOT_FOUND", msg),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "CONFLICT", msg),
            AppError::RateLimit(msg) => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMIT_EXCEEDED", msg),
            AppError::ExternalService(_) => (
                StatusCode::BAD_GATEWAY,
                "EXTERNAL_SERVICE_ERROR",
                "External service unavailable".to_string(),
            ),
            AppError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "An internal server error occurred".to_string(),
            ),
            AppError::Configuration(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "CONFIGURATION_ERROR",
                "Server configuration error".to_string(),
            ),
            AppError::HashingError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "HASHING_ERROR",
                "Password hashing error".to_string(),
            ),
        };

        let error_response = ErrorResponse::new(error_code, &message);
        (status, Json(error_response)).into_response()
    }
}

/// Result type alias for operations that can return AppError
pub type AppResult<T> = Result<T, AppError>;

/// Helper trait for converting other error types to AppError
pub trait IntoAppError<T> {
    fn into_app_error(self, context: &str) -> AppResult<T>;
}

impl<T, E> IntoAppError<T> for Result<T, E>
where
    E: fmt::Display,
{
    fn into_app_error(self, context: &str) -> AppResult<T> {
        self.map_err(|e| AppError::Internal(format!("{}: {}", context, e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_response_creation() {
        let error = ErrorResponse::new("TEST_ERROR", "Test message");
        assert_eq!(error.error, "TEST_ERROR");
        assert_eq!(error.message, "Test message");
        assert!(error.details.is_none());
    }

    #[test]
    fn test_error_response_with_details() {
        let details = serde_json::json!({"field": "email", "value": "invalid"});
        let error =
            ErrorResponse::with_details("VALIDATION_ERROR", "Invalid input", details.clone());
        assert_eq!(error.error, "VALIDATION_ERROR");
        assert_eq!(error.message, "Invalid input");
        assert_eq!(error.details, Some(details));
    }

    #[test]
    fn test_app_error_display() {
        let error = AppError::Validation("Invalid email".to_string());
        assert_eq!(error.to_string(), "Validation error: Invalid email");
    }
}
