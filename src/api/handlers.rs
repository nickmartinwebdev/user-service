//! HTTP Request Handlers
//!
//! Axum handlers for processing HTTP requests and responses.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use uuid::Uuid;
use validator::Validate;

use crate::{
    models::requests::*,
    service::UserService,
    utils::error::{AppError, AppResult, ErrorResponse},
    VERSION,
};

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub user_service: Arc<UserService>,
}

/// Standard success response wrapper
#[derive(serde::Serialize)]
pub struct SuccessResponse<T> {
    pub success: bool,
    pub data: T,
}

impl<T> SuccessResponse<T> {
    pub fn new(data: T) -> Self {
        Self {
            success: true,
            data,
        }
    }
}

/// Create a new user
pub async fn create_user(
    State(state): State<AppState>,
    Json(request): Json<CreateUserRequest>,
) -> AppResult<Json<SuccessResponse<CreateUserResponse>>> {
    // Validate request
    request.validate().map_err(|e| {
        AppError::Validation(format!("Invalid user data: {}", e))
    })?;

    // Create user
    let user = state.user_service.create_user(request).await?;

    let response = CreateUserResponse {
        id: user.id,
        name: user.name,
        email: user.email,
        profile_picture_url: user.profile_picture_url,
        created_at: user.created_at,
    };

    Ok(Json(SuccessResponse::new(response)))
}

/// Get user by ID
pub async fn get_user(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> AppResult<Json<SuccessResponse<crate::models::user::User>>> {
    let user = state.user_service.get_user_by_id(user_id).await?;
    Ok(Json(SuccessResponse::new(user)))
}

/// Update user profile
pub async fn update_user(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(request): Json<UpdateUserRequest>,
) -> AppResult<Json<SuccessResponse<crate::models::user::User>>> {
    // Validate request
    request.validate().map_err(|e| {
        AppError::Validation(format!("Invalid update data: {}", e))
    })?;

    let user = state.user_service.update_user(user_id, request).await?;
    Ok(Json(SuccessResponse::new(user)))
}

/// Update user profile picture
pub async fn update_profile_picture(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(request): Json<UpdateProfilePictureRequest>,
) -> AppResult<Json<SuccessResponse<crate::models::user::User>>> {
    // Validate request
    request.validate().map_err(|e| {
        AppError::Validation(format!("Invalid profile picture data: {}", e))
    })?;

    let user = state
        .user_service
        .update_profile_picture(user_id, request)
        .await?;
    Ok(Json(SuccessResponse::new(user)))
}

/// Remove user profile picture
pub async fn remove_profile_picture(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> AppResult<Json<SuccessResponse<crate::models::user::User>>> {
    let user = state.user_service.remove_profile_picture(user_id).await?;
    Ok(Json(SuccessResponse::new(user)))
}

/// Verify user password
pub async fn verify_password(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(request): Json<VerifyPasswordRequest>,
) -> AppResult<Json<SuccessResponse<VerifyPasswordResponse>>> {
    // Validate request
    request.validate().map_err(|e| {
        AppError::Validation(format!("Invalid password data: {}", e))
    })?;

    let is_valid = state
        .user_service
        .verify_password(user_id, &request.password)
        .await?;

    let response = VerifyPasswordResponse { valid: is_valid };
    Ok(Json(SuccessResponse::new(response)))
}

/// Health check endpoint
pub async fn health_check(
    State(state): State<AppState>,
) -> AppResult<Json<SuccessResponse<HealthCheckResponse>>> {
    // Check database connectivity
    state.user_service.health_check().await?;

    let response = HealthCheckResponse {
        status: "healthy".to_string(),
        timestamp: Utc::now(),
        version: VERSION.to_string(),
    };

    Ok(Json(SuccessResponse::new(response)))
}

/// Handle validation errors from request parsing
pub fn handle_validation_error(err: validator::ValidationErrors) -> AppError {
    let mut messages = Vec::new();
    
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::UserService;
    use crate::database::DatabaseConfig;

    fn create_test_app_state() -> AppState {
        // This would need a real database connection in integration tests
        // For unit tests, we'd use a mock service
        todo!("Implement with mock database for unit tests")
    }

    #[test]
    fn test_success_response_creation() {
        let data = "test data";
        let response = SuccessResponse::new(data);
        assert!(response.success);
        assert_eq!(response.data, "test data");
    }

    #[test]
    fn test_validation_error_handling() {
        // Test validation error formatting
        // This would require setting up proper validation errors
        assert!(true); // Placeholder
    }
}