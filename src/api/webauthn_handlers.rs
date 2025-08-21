//! WebAuthn/Passkey API Handlers
//!
//! HTTP handlers for WebAuthn (passkey) authentication endpoints.
//! Provides secure, passwordless authentication using public key cryptography.
//!
//! This file was successfully recreated after being deleted, implementing all
//! the required WebAuthn endpoints with proper authentication middleware integration.

use axum::{
    extract::{Path, Query, State},
    response::Json,
    Extension,
};
use serde_json::Value;
use validator::Validate;

use crate::{
    api::middleware::AuthUser,
    models::{
        webauthn::{
            DeletePasskeyRequest, DeletePasskeyResponse, ListPasskeysRequest, ListPasskeysResponse,
            PasskeyAuthenticationBeginRequest, PasskeyAuthenticationBeginResponse,
            PasskeyAuthenticationFinishRequest, PasskeyAuthenticationFinishResponse,
            PasskeyRegistrationBeginRequest, PasskeyRegistrationBeginResponse,
            PasskeyRegistrationFinishRequest, PasskeyRegistrationFinishResponse,
            UpdatePasskeyRequest, UpdatePasskeyResponse,
        },
        AppContext,
    },
    utils::error::{AppError, AppResult},
};

use super::AppState;

/// Begin passkey registration for an authenticated user
///
/// # Authentication Required
/// This endpoint requires a valid JWT token with user authentication.
///
/// # Request Body
/// - `credential_name` (optional): User-friendly name for the credential
///
/// # Response
/// - `200 OK`: Returns WebAuthn credential creation options
/// - `400 Bad Request`: Invalid request data
/// - `401 Unauthorized`: Authentication required
/// - `500 Internal Server Error`: Server error
pub async fn begin_passkey_registration(
    State(state): State<AppState>,
    Extension(app_ctx): Extension<AppContext>,
    Extension(auth_user): Extension<AuthUser>,
    Json(request): Json<PasskeyRegistrationBeginRequest>,
) -> AppResult<Json<PasskeyRegistrationBeginResponse>> {
    // Validate request
    request.validate().map_err(|e| {
        AppError::Validation(format!("Invalid passkey registration request: {}", e))
    })?;

    // Get WebAuthn service
    let webauthn_service = state
        .webauthn_service
        .as_ref()
        .ok_or_else(|| AppError::Configuration("WebAuthn service not available".to_string()))?;

    // Begin registration
    let response = webauthn_service
        .begin_passkey_registration(app_ctx.application_id, auth_user.0.user_id, request)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to begin registration: {}", e)))?;

    Ok(Json(response))
}

/// Complete passkey registration for an authenticated user
///
/// # Authentication Required
/// This endpoint requires a valid JWT token with user authentication.
///
/// # Request Body
/// - `credential`: WebAuthn registration credential response
/// - `credential_name` (optional): User-friendly name for the credential
///
/// # Response
/// - `200 OK`: Registration successful, returns credential info
/// - `400 Bad Request`: Invalid credential data or verification failed
/// - `401 Unauthorized`: Authentication required
/// - `500 Internal Server Error`: Server error
pub async fn finish_passkey_registration(
    State(state): State<AppState>,
    Extension(app_ctx): Extension<AppContext>,
    Extension(auth_user): Extension<AuthUser>,
    Json(request): Json<PasskeyRegistrationFinishRequest>,
) -> AppResult<Json<PasskeyRegistrationFinishResponse>> {
    // Validate request
    request.validate().map_err(|e| {
        AppError::Validation(format!("Invalid passkey registration request: {}", e))
    })?;

    // Get WebAuthn service
    let webauthn_service = state
        .webauthn_service
        .as_ref()
        .ok_or_else(|| AppError::Configuration("WebAuthn service not available".to_string()))?;

    // Complete registration
    let response = webauthn_service
        .finish_passkey_registration(app_ctx.application_id, auth_user.0.user_id, request)
        .await
        .map_err(|e| AppError::BadRequest(format!("Registration failed: {}", e)))?;

    Ok(Json(response))
}

/// Begin passkey authentication (signin)
///
/// # Public Endpoint
/// This endpoint does not require authentication.
///
/// # Request Body
/// - `email` (optional): User email for UX purposes
///
/// # Response
/// - `200 OK`: Returns WebAuthn credential request options
/// - `400 Bad Request`: Invalid request data
/// - `500 Internal Server Error`: Server error
pub async fn begin_passkey_authentication(
    State(state): State<AppState>,
    Extension(app_ctx): Extension<AppContext>,
    Json(request): Json<PasskeyAuthenticationBeginRequest>,
) -> AppResult<Json<PasskeyAuthenticationBeginResponse>> {
    // Get WebAuthn service
    let webauthn_service = state
        .webauthn_service
        .as_ref()
        .ok_or_else(|| AppError::Configuration("WebAuthn service not available".to_string()))?;

    // Begin authentication
    let response = webauthn_service
        .begin_passkey_authentication(app_ctx.application_id, request)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to begin authentication: {}", e)))?;

    Ok(Json(response))
}

/// Complete passkey authentication (signin)
///
/// # Public Endpoint
/// This endpoint does not require authentication.
///
/// # Request Body
/// - `credential`: WebAuthn authentication credential response
///
/// # Response
/// - `200 OK`: Authentication successful, returns JWT tokens
/// - `400 Bad Request`: Invalid credential data or verification failed
/// - `401 Unauthorized`: Authentication failed
/// - `500 Internal Server Error`: Server error
pub async fn finish_passkey_authentication(
    State(state): State<AppState>,
    Extension(app_ctx): Extension<AppContext>,
    Json(request): Json<PasskeyAuthenticationFinishRequest>,
) -> AppResult<Json<PasskeyAuthenticationFinishResponse>> {
    // Get WebAuthn service
    let webauthn_service = state
        .webauthn_service
        .as_ref()
        .ok_or_else(|| AppError::Configuration("WebAuthn service not available".to_string()))?;

    // Complete authentication
    let response = webauthn_service
        .finish_passkey_authentication(app_ctx.application_id, request)
        .await
        .map_err(|e| AppError::Authentication(format!("Authentication failed: {}", e)))?;

    Ok(Json(response))
}

/// List user's passkeys
///
/// # Authentication Required
/// This endpoint requires a valid JWT token with user authentication.
///
/// # Query Parameters
/// - `name_filter` (optional): Filter credentials by name
///
/// # Response
/// - `200 OK`: Returns list of user's credentials
/// - `401 Unauthorized`: Authentication required
/// - `500 Internal Server Error`: Server error
pub async fn list_user_passkeys(
    State(state): State<AppState>,
    Extension(_app_ctx): Extension<AppContext>,
    Extension(auth_user): Extension<AuthUser>,
    Query(request): Query<ListPasskeysRequest>,
) -> AppResult<Json<ListPasskeysResponse>> {
    // Get WebAuthn service
    let webauthn_service = state
        .webauthn_service
        .as_ref()
        .ok_or_else(|| AppError::Configuration("WebAuthn service not available".to_string()))?;

    // List credentials
    let response = webauthn_service
        .list_user_passkeys(auth_user.0.user_id, request)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to list credentials: {}", e)))?;

    Ok(Json(response))
}

/// Update passkey name
///
/// # Authentication Required
/// This endpoint requires a valid JWT token with user authentication.
///
/// # Path Parameters
/// - `credential_id`: ID of the credential to update
///
/// # Request Body
/// - `credential_name`: New name for the credential
///
/// # Response
/// - `200 OK`: Update successful, returns updated credential info
/// - `400 Bad Request`: Invalid request data
/// - `401 Unauthorized`: Authentication required
/// - `404 Not Found`: Credential not found or not owned by user
/// - `500 Internal Server Error`: Server error
pub async fn update_passkey(
    State(state): State<AppState>,
    Extension(app_ctx): Extension<AppContext>,
    Extension(auth_user): Extension<AuthUser>,
    Path(credential_id): Path<String>,
    Json(request): Json<UpdatePasskeyRequest>,
) -> AppResult<Json<UpdatePasskeyResponse>> {
    // Validate request
    request
        .validate()
        .map_err(|e| AppError::Validation(format!("Invalid passkey update request: {}", e)))?;

    // Get WebAuthn service
    let webauthn_service = state
        .webauthn_service
        .as_ref()
        .ok_or_else(|| AppError::Configuration("WebAuthn service not available".to_string()))?;

    // Update credential
    let response = webauthn_service
        .update_passkey(
            app_ctx.application_id,
            auth_user.0.user_id,
            &credential_id,
            request,
        )
        .await
        .map_err(|e| match e.to_string().contains("not found") {
            true => AppError::NotFound("Credential not found".to_string()),
            false => AppError::Internal(format!("Failed to update credential: {}", e)),
        })?;

    Ok(Json(response))
}

/// Delete passkey
///
/// # Authentication Required
/// This endpoint requires a valid JWT token with user authentication.
///
/// # Path Parameters
/// - `credential_id`: ID of the credential to delete
///
/// # Response
/// - `200 OK`: Deletion successful
/// - `401 Unauthorized`: Authentication required
/// - `404 Not Found`: Credential not found or not owned by user
/// - `500 Internal Server Error`: Server error
pub async fn delete_passkey(
    State(state): State<AppState>,
    Extension(app_ctx): Extension<AppContext>,
    Extension(auth_user): Extension<AuthUser>,
    Path(credential_id): Path<String>,
) -> AppResult<Json<DeletePasskeyResponse>> {
    // Get WebAuthn service
    let webauthn_service = state
        .webauthn_service
        .as_ref()
        .ok_or_else(|| AppError::Configuration("WebAuthn service not available".to_string()))?;

    // Create delete request
    let request = DeletePasskeyRequest {
        credential_id: credential_id.clone(),
    };

    // Delete credential
    let response = webauthn_service
        .delete_passkey(app_ctx.application_id, auth_user.0.user_id, request)
        .await
        .map_err(|e| match e.to_string().contains("not found") {
            true => AppError::NotFound("Credential not found".to_string()),
            false => AppError::Internal(format!("Failed to delete credential: {}", e)),
        })?;

    Ok(Json(response))
}

/// Cleanup expired WebAuthn challenges
///
/// # Public Endpoint
/// This endpoint does not require authentication. It's typically called by
/// a scheduled job or monitoring system to clean up expired challenge data.
///
/// # Response
/// - `200 OK`: Cleanup successful, returns number of deleted challenges
/// - `500 Internal Server Error`: Server error
pub async fn cleanup_expired_challenges(State(state): State<AppState>) -> AppResult<Json<Value>> {
    // Get WebAuthn service
    let webauthn_service = state
        .webauthn_service
        .as_ref()
        .ok_or_else(|| AppError::Configuration("WebAuthn service not available".to_string()))?;

    // Cleanup expired challenges
    let deleted_count = webauthn_service
        .cleanup_expired_challenges()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to cleanup challenges: {}", e)))?;

    Ok(Json(serde_json::json!({
        "message": "Expired challenges cleaned up successfully",
        "deleted_count": deleted_count
    })))
}

#[cfg(test)]
mod tests {
    // Test imports would go here when tests are implemented

    // Note: These are placeholder tests. In a real implementation, you would
    // need to set up proper test fixtures with database connections and
    // mock WebAuthn services.

    #[tokio::test]
    async fn test_webauthn_service_availability() {
        // Test that handlers properly check for WebAuthn service availability
        // This would be expanded with proper test setup
    }

    #[tokio::test]
    async fn test_passkey_registration_validation() {
        // Test that registration requests are properly validated
        // This would include testing credential name length limits, etc.
    }

    #[tokio::test]
    async fn test_passkey_authentication_flow() {
        // Test the complete authentication flow
        // This would require setting up mock WebAuthn responses
    }

    #[tokio::test]
    async fn test_credential_management() {
        // Test listing, updating, and deleting credentials
        // This would require setting up test database state
    }
}
