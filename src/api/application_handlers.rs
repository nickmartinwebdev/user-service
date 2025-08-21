//! Application Management Handlers
//!
//! HTTP handlers for managing multi-tenant applications, including creation,
//! authentication, and administration of tenant configurations.

use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;
use validator::Validate;

use crate::{
    api::handlers::{AppState, SuccessResponse},
    models::application::*,
    utils::error::{AppError, AppResult},
};

/// Create a new application (admin endpoint)
///
/// Creates a new tenant application with generated API credentials and settings.
/// This is typically used by administrators to onboard new clients.
pub async fn create_application(
    State(state): State<AppState>,
    Json(request): Json<CreateApplicationRequest>,
) -> AppResult<Json<SuccessResponse<CreateApplicationResponse>>> {
    // Validate request data
    request
        .validate()
        .map_err(|e| AppError::Validation(format!("Invalid application data: {}", e)))?;

    // Create the application
    let response = state
        .application_service
        .create_application(request)
        .await?;

    Ok(Json(SuccessResponse::new(response)))
}

/// Get application details by ID (admin endpoint)
///
/// Retrieves detailed information about a specific application including
/// its configuration and settings.
pub async fn get_application(
    State(state): State<AppState>,
    Path(app_id): Path<Uuid>,
) -> AppResult<Json<SuccessResponse<Application>>> {
    let application = state.application_service.get_application(app_id).await?;

    Ok(Json(SuccessResponse::new(application)))
}

/// Update application settings (admin endpoint)
///
/// Updates application configuration including allowed origins, settings,
/// and active status.
pub async fn update_application(
    State(state): State<AppState>,
    Path(app_id): Path<Uuid>,
    Json(request): Json<UpdateApplicationRequest>,
) -> AppResult<Json<SuccessResponse<Application>>> {
    // Validate request data
    request
        .validate()
        .map_err(|e| AppError::Validation(format!("Invalid update data: {}", e)))?;

    let application = state
        .application_service
        .update_application(app_id, request)
        .await?;

    Ok(Json(SuccessResponse::new(application)))
}

/// List all applications (admin endpoint)
///
/// Returns a list of all active applications in the system.
/// Used for administration and monitoring purposes.
pub async fn list_applications(
    State(state): State<AppState>,
) -> AppResult<Json<SuccessResponse<Vec<Application>>>> {
    let applications = state.application_service.list_applications().await?;

    Ok(Json(SuccessResponse::new(applications)))
}

/// Get application usage statistics (admin endpoint)
///
/// Returns usage metrics for a specific application including user counts
/// and authentication events.
pub async fn get_application_stats(
    State(state): State<AppState>,
    Path(app_id): Path<Uuid>,
) -> AppResult<Json<SuccessResponse<ApplicationStats>>> {
    let stats = state
        .application_service
        .get_application_stats(app_id)
        .await?;

    Ok(Json(SuccessResponse::new(stats)))
}

/// Rotate API credentials for an application (admin endpoint)
///
/// Generates new API key and secret for an application. The old credentials
/// will be invalidated immediately.
pub async fn rotate_application_credentials(
    State(state): State<AppState>,
    Path(app_id): Path<Uuid>,
) -> AppResult<Json<SuccessResponse<serde_json::Value>>> {
    let (api_key, api_secret) = state.application_service.rotate_credentials(app_id).await?;

    let response = serde_json::json!({
        "api_key": api_key,
        "api_secret": api_secret,
        "message": "Credentials rotated successfully. Update your application configuration immediately."
    });

    Ok(Json(SuccessResponse::new(response)))
}

/// Deactivate an application (admin endpoint)
///
/// Disables an application, preventing all API access. This is used for
/// suspending applications rather than deleting them entirely.
pub async fn deactivate_application(
    State(state): State<AppState>,
    Path(app_id): Path<Uuid>,
) -> AppResult<Json<SuccessResponse<serde_json::Value>>> {
    state
        .application_service
        .deactivate_application(app_id)
        .await?;

    let response = serde_json::json!({
        "message": "Application deactivated successfully"
    });

    Ok(Json(SuccessResponse::new(response)))
}

/// Health check endpoint specifically for application service
///
/// Verifies that the application service and its dependencies are operational.
pub async fn application_health_check(
    State(state): State<AppState>,
) -> AppResult<Json<SuccessResponse<serde_json::Value>>> {
    // Test database connectivity by attempting to list applications
    let _ = state.application_service.list_applications().await?;

    let response = serde_json::json!({
        "status": "healthy",
        "service": "application_service",
        "timestamp": chrono::Utc::now()
    });

    Ok(Json(SuccessResponse::new(response)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_application_validation() {
        // Test validation of CreateApplicationRequest
        let invalid_request = CreateApplicationRequest {
            name: "".to_string(), // Invalid: empty name
            allowed_origins: vec![],
            settings: ApplicationSettings::default(),
        };

        let validation_result = invalid_request.validate();
        assert!(validation_result.is_err());
    }

    #[tokio::test]
    async fn test_update_application_validation() {
        // Test validation of UpdateApplicationRequest
        let invalid_request = UpdateApplicationRequest {
            name: Some("".to_string()), // Invalid: empty name
            allowed_origins: None,
            settings: None,
            active: None,
        };

        let validation_result = invalid_request.validate();
        assert!(validation_result.is_err());
    }
}
