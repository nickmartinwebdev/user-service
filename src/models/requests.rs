//! Request and Response Models
//!
//! Data structures for API request and response payloads with validation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::{Validate, ValidationError};

use crate::utils::validation::{email_validator, name_validator, url_validator};

/// Request payload for creating a new user account
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateUserRequest {
    /// User's display name (1-255 characters)
    #[validate(custom(function = "name_validator"))]
    pub name: String,

    /// User's email address (must be unique and valid format)
    #[validate(custom(function = "email_validator"))]
    pub email: String,

    /// User's password (8-128 characters with strength requirements)
    #[validate(length(
        min = 8,
        max = 128,
        message = "Password must be between 8 and 128 characters"
    ))]
    #[validate(custom(function = "validate_password_strength"))]
    pub password: String,

    /// Optional URL to user's profile picture
    #[validate(custom(function = "url_validator"))]
    pub profile_picture_url: Option<String>,
}

/// Request payload for updating user profile information
#[derive(Debug, Deserialize, Validate, Clone)]
pub struct UpdateUserRequest {
    /// Updated user display name (1-255 characters)
    #[validate(custom(function = "name_validator"))]
    pub name: Option<String>,

    /// Updated email address (must be unique if changed)
    #[validate(custom(function = "email_validator"))]
    pub email: Option<String>,

    /// Updated profile picture URL (None means preserve current value)
    #[validate(custom(function = "url_validator"))]
    pub profile_picture_url: Option<String>,
}

/// Request payload for updating only the user's profile picture
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateProfilePictureRequest {
    /// New profile picture URL (or None to remove current picture)
    #[validate(custom(function = "url_validator"))]
    pub profile_picture_url: Option<String>,
}

/// Request payload for password verification
#[derive(Debug, Deserialize, Validate)]
pub struct VerifyPasswordRequest {
    /// Password to verify (cannot be empty)
    #[validate(length(min = 1, message = "Password cannot be empty"))]
    pub password: String,
}

/// Response for user creation
#[derive(Debug, Serialize)]
pub struct CreateUserResponse {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub profile_picture_url: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Response for password verification
#[derive(Debug, Serialize)]
pub struct VerifyPasswordResponse {
    pub valid: bool,
}

/// Response for health check
#[derive(Debug, Serialize)]
pub struct HealthCheckResponse {
    pub status: String,
    pub timestamp: DateTime<Utc>,
    pub version: String,
}

/// Standard success response wrapper
#[derive(Debug, Serialize)]
pub struct SuccessResponse<T> {
    pub success: bool,
    pub data: T,
}

/// Validates password strength according to security requirements
fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    // Check for at least one lowercase letter
    if !password.chars().any(|c| c.is_lowercase()) {
        return Err(ValidationError::new(
            "Password must contain at least one lowercase letter",
        ));
    }

    // Check for at least one uppercase letter
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err(ValidationError::new(
            "Password must contain at least one uppercase letter",
        ));
    }

    // Check for at least one digit
    if !password.chars().any(|c| c.is_numeric()) {
        return Err(ValidationError::new(
            "Password must contain at least one digit",
        ));
    }

    // Check for at least one special character
    if !password.chars().any(|c| !c.is_alphanumeric()) {
        return Err(ValidationError::new(
            "Password must contain at least one special character",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_strength_validation() {
        // Valid password
        assert!(validate_password_strength("SecurePass123!").is_ok());

        // Missing lowercase
        assert!(validate_password_strength("SECUREPASS123!").is_err());

        // Missing uppercase
        assert!(validate_password_strength("securepass123!").is_err());

        // Missing digit
        assert!(validate_password_strength("SecurePass!").is_err());

        // Missing special character
        assert!(validate_password_strength("SecurePass123").is_err());
    }

    #[test]
    fn test_create_user_request_validation() {
        let request = CreateUserRequest {
            name: "John Doe".to_string(),
            email: "john@example.com".to_string(),
            password: "SecurePass123!".to_string(),
            profile_picture_url: Some("https://example.com/avatar.jpg".to_string()),
        };

        assert!(request.validate().is_ok());
    }
}
