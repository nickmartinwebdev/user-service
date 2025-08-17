//! HTTP Request Handlers
//!
//! This module contains Axum handlers for processing HTTP requests and responses.
//! Each handler function corresponds to a specific API endpoint and handles the
//! request validation, business logic delegation, and response formatting.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    Json,
};
use chrono::Utc;
use uuid::Uuid;
use validator::Validate;

use crate::{
    models::requests::*,
    service::{JwtService, UserService},
    utils::error::{AppError, AppResult},
    VERSION,
};

/// Application state shared across all request handlers
///
/// This struct contains shared dependencies that are injected into each
/// handler via Axum's state extraction. It uses Arc for thread-safe sharing
/// across async handlers.
#[derive(Clone)]
pub struct AppState {
    /// User service instance for handling business logic
    pub user_service: Arc<UserService>,
    /// JWT service instance for authentication
    pub jwt_service: Arc<JwtService>,
}

/// Standard success response wrapper for API responses
///
/// This provides a consistent response format across all successful API calls,
/// wrapping the actual data with a success indicator.
#[derive(serde::Serialize)]
pub struct SuccessResponse<T> {
    /// Always true for successful responses
    pub success: bool,
    /// The actual response data
    pub data: T,
}

impl<T> SuccessResponse<T> {
    /// Creates a new success response with the provided data
    pub fn new(data: T) -> Self {
        Self {
            success: true,
            data,
        }
    }
}

/// Handler for creating a new user account
///
/// This endpoint accepts user registration data, validates it, and creates
/// a new user account in the system. Returns the created user information
/// without sensitive data like password hashes.
pub async fn create_user(
    State(state): State<AppState>,
    Json(request): Json<CreateUserRequest>,
) -> AppResult<Json<SuccessResponse<CreateUserResponse>>> {
    // Validate request data using validator crate
    request
        .validate()
        .map_err(|e| AppError::Validation(format!("Invalid user data: {}", e)))?;

    // Delegate to user service for business logic
    let user = state.user_service.create_user(request).await?;

    // Transform internal user model to API response
    let response = CreateUserResponse {
        id: user.id,
        name: user.name,
        email: user.email,
        profile_picture_url: user.profile_picture_url,
        created_at: user.created_at,
    };

    Ok(Json(SuccessResponse::new(response)))
}

/// Handler for retrieving a user by their ID
///
/// This endpoint fetches user information for the specified user ID.
/// Returns user data without sensitive information like password hashes.
pub async fn get_user(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> AppResult<Json<SuccessResponse<crate::models::user::User>>> {
    // Delegate to user service to fetch user data
    let user = state.user_service.get_user_by_id(user_id).await?;
    Ok(Json(SuccessResponse::new(user)))
}

/// Handler for updating an existing user's profile information
///
/// This endpoint allows partial updates to user profile data. Only provided
/// fields will be updated, null/missing fields will be ignored.
pub async fn update_user(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(request): Json<UpdateUserRequest>,
) -> AppResult<Json<SuccessResponse<crate::models::user::User>>> {
    // Validate the update request data
    request
        .validate()
        .map_err(|e| AppError::Validation(format!("Invalid update data: {}", e)))?;

    // Delegate to user service for update logic
    let user = state.user_service.update_user(user_id, request).await?;
    Ok(Json(SuccessResponse::new(user)))
}

/// Handler for updating a user's profile picture
///
/// This endpoint updates the profile picture URL for the specified user.
/// The URL should point to a valid image resource.
pub async fn update_profile_picture(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(request): Json<UpdateProfilePictureRequest>,
) -> AppResult<Json<SuccessResponse<crate::models::user::User>>> {
    // Validate the profile picture request
    request
        .validate()
        .map_err(|e| AppError::Validation(format!("Invalid profile picture data: {}", e)))?;

    // Delegate to user service for profile picture update
    let user = state
        .user_service
        .update_profile_picture(user_id, request)
        .await?;
    Ok(Json(SuccessResponse::new(user)))
}

/// Handler for removing a user's profile picture
///
/// This endpoint removes the profile picture for the specified user,
/// setting the profile_picture_url field to null.
pub async fn remove_profile_picture(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> AppResult<Json<SuccessResponse<crate::models::user::User>>> {
    // Delegate to user service for profile picture removal
    let user = state.user_service.remove_profile_picture(user_id).await?;
    Ok(Json(SuccessResponse::new(user)))
}

/// Handler for verifying a user's password
///
/// This endpoint checks if the provided password matches the user's stored
/// password hash. Used for authentication and password confirmation flows.
pub async fn verify_password(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(request): Json<VerifyPasswordRequest>,
) -> AppResult<Json<SuccessResponse<VerifyPasswordResponse>>> {
    // Validate the password verification request
    request
        .validate()
        .map_err(|e| AppError::Validation(format!("Invalid password data: {}", e)))?;

    // Delegate to user service for password verification
    let is_valid = state
        .user_service
        .verify_password(user_id, &request.password)
        .await?;

    let response = VerifyPasswordResponse { valid: is_valid };
    Ok(Json(SuccessResponse::new(response)))
}

/// Handler for service health check
///
/// This endpoint provides health status information including database
/// connectivity, service version, and current timestamp. Used for monitoring
/// and load balancer health checks.
pub async fn health_check(
    State(state): State<AppState>,
) -> AppResult<Json<SuccessResponse<HealthCheckResponse>>> {
    // Verify database connectivity through user service
    state.user_service.health_check().await?;

    // Build health check response with current status
    let response = HealthCheckResponse {
        status: "healthy".to_string(),
        timestamp: Utc::now(),
        version: VERSION.to_string(),
    };

    Ok(Json(SuccessResponse::new(response)))
}

/// Utility function for converting validation errors to application errors
///
/// This function takes validation errors from the validator crate and converts
/// them into a user-friendly error message format for API responses.
pub fn handle_validation_error(err: validator::ValidationErrors) -> AppError {
    let mut messages = Vec::new();

    // Extract field-level validation errors
    for (field, errors) in err.field_errors() {
        for error in errors {
            let message = error
                .message
                .as_ref()
                .map(|m| m.to_string())
                .unwrap_or_else(|| format!("Invalid value for field '{}'", field));
            messages.push(format!("{}: {}", field, message));
        }
    }

    AppError::Validation(messages.join(", "))
}

/// Handler for refreshing access tokens using a valid refresh token
///
/// This endpoint accepts a refresh token and returns a new access token
/// if the refresh token is valid and hasn't expired.
pub async fn refresh_token(
    State(state): State<AppState>,
    Json(request): Json<RefreshTokenRequest>,
) -> AppResult<Json<SuccessResponse<RefreshTokenResponse>>> {
    // Validate request data
    request
        .validate()
        .map_err(|e| AppError::Validation(format!("Invalid refresh token data: {}", e)))?;

    // Delegate to JWT service for token refresh
    let token_pair = state
        .jwt_service
        .refresh_access_token(&request.refresh_token)
        .await?;

    // Transform token pair to API response
    let response = RefreshTokenResponse {
        access_token: token_pair.access_token,
        token_type: token_pair.token_type,
        expires_in: token_pair.expires_in,
    };

    Ok(Json(SuccessResponse::new(response)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that SuccessResponse wraps data correctly
    #[test]
    fn test_success_response_creation() {
        let data = "test data";
        let response = SuccessResponse::new(data);
        assert!(response.success);
        assert_eq!(response.data, "test data");
    }

    /// Test that SuccessResponse works with different data types
    #[test]
    fn test_success_response_with_different_types() {
        // Test with string
        let string_response = SuccessResponse::new("hello".to_string());
        assert!(string_response.success);
        assert_eq!(string_response.data, "hello");

        // Test with number
        let number_response = SuccessResponse::new(42);
        assert!(number_response.success);
        assert_eq!(number_response.data, 42);

        // Test with boolean
        let bool_response = SuccessResponse::new(true);
        assert!(bool_response.success);
        assert!(bool_response.data);
    }

    /// Test validation error formatting
    #[test]
    fn test_validation_error_handling() {
        // This test verifies the error handling function structure
        // In integration tests, we would test with actual validation errors
        // This test verifies the error handling function structure
        // In integration tests, we would test with actual validation errors
        // TODO: Add proper validation error testing
    }
}
