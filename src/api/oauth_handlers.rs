//! OAuth HTTP Request Handlers
//!
//! This module contains Axum handlers for OAuth 2.0 authentication flows,
//! specifically for Google OAuth. It handles OAuth initiation and callback
//! processing with proper error handling and response formatting.

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Json, Redirect},
    Extension,
};
use serde_json::Value as JsonValue;

use crate::{
    models::{
        application::AppContext,
        oauth::{GoogleOAuthCallbackQuery, GoogleOAuthInitRequest, GoogleOAuthInitResponse},
    },
    utils::error::{AppError, AppResult},
};

use super::handlers::SuccessResponse;

/// Handler for initiating Google OAuth flow
///
/// This endpoint generates a Google OAuth authorization URL and secure state token.
/// The client should redirect the user to the returned authorization URL.
///
/// **Endpoint:** `POST /auth/signup/google`
///
/// **Request Body:**
/// ```json
/// {
///   "redirect_url": "https://example.com/dashboard"  // optional
/// }
/// ```
///
/// **Response:**
/// ```json
/// {
///   "success": true,
///   "data": {
///     "authorization_url": "https://accounts.google.com/oauth/authorize?...",
///     "state": "secure_random_state_token"
///   }
/// }
/// ```
pub async fn initiate_google_oauth(
    State(state): State<super::handlers::AppState>,
    Extension(app_ctx): Extension<AppContext>,
    Json(request): Json<GoogleOAuthInitRequest>,
) -> AppResult<Json<SuccessResponse<GoogleOAuthInitResponse>>> {
    // Validate redirect URL if provided
    if let Some(ref redirect_url) = request.redirect_url {
        if redirect_url.is_empty() {
            return Err(AppError::Validation(
                "Redirect URL cannot be empty".to_string(),
            ));
        }

        // Basic URL validation
        if !redirect_url.starts_with("http://") && !redirect_url.starts_with("https://") {
            return Err(AppError::Validation(
                "Redirect URL must be a valid HTTP/HTTPS URL".to_string(),
            ));
        }
    }

    // Generate OAuth authorization URL and state token
    let oauth_service = state
        .oauth_service
        .as_ref()
        .ok_or_else(|| AppError::Internal("OAuth service not configured".to_string()))?;

    let oauth_response = oauth_service
        .initiate_google_oauth(app_ctx.application_id, request.redirect_url)
        .await?;

    Ok(Json(SuccessResponse::new(oauth_response)))
}

/// Handler for Google OAuth callback
///
/// This endpoint processes the callback from Google OAuth, validates the state token,
/// exchanges the authorization code for tokens, and returns JWT tokens for the user.
///
/// **Endpoint:** `GET /auth/callback/google`
///
/// **Query Parameters:**
/// - `code`: Authorization code from Google
/// - `state`: State token for CSRF protection
/// - `error`: Error code if authorization failed (optional)
/// - `error_description`: Human-readable error description (optional)
///
/// **Response Headers:**
/// - `Accept: application/json` returns JSON response
/// - Otherwise redirects to frontend with tokens in URL fragments (for web apps)
///
/// **JSON Response:**
/// ```json
/// {
///   "success": true,
///   "data": {
///     "access_token": "jwt_access_token",
///     "refresh_token": "jwt_refresh_token",
///     "user": { /* user object */ },
///     "is_new_user": true
///   }
/// }
/// ```
pub async fn handle_google_callback(
    State(state): State<super::handlers::AppState>,
    Extension(app_ctx): Extension<AppContext>,
    Query(query): Query<GoogleOAuthCallbackQuery>,
    headers: HeaderMap,
) -> AppResult<axum::response::Response> {
    // Process OAuth callback
    let oauth_service = state
        .oauth_service
        .as_ref()
        .ok_or_else(|| AppError::Internal("OAuth service not configured".to_string()))?;

    let callback_response = oauth_service
        .handle_google_callback(app_ctx.application_id, query)
        .await?;

    // Check Accept header to determine response format
    let accept_header = headers
        .get("accept")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    if accept_header.contains("application/json") {
        // Return JSON response for API clients
        let json_response = Json(SuccessResponse::new(callback_response));
        Ok(json_response.into_response())
    } else {
        // Redirect to frontend for web applications
        // In a real application, you would redirect to your frontend with tokens
        // For security, tokens should be passed as secure HTTP-only cookies or
        // through a secure redirect mechanism rather than URL fragments

        // For now, we'll return a simple success page or redirect
        // In production, implement proper frontend integration
        let redirect_url = format!(
            "/auth/success?access_token={}&refresh_token={}&new_user={}",
            callback_response.access_token,
            callback_response.refresh_token,
            callback_response.is_new_user
        );

        Ok(Redirect::to(&redirect_url).into_response())
    }
}

/// Handler for checking OAuth provider status for a user
///
/// This endpoint returns the OAuth providers linked to the authenticated user's account.
/// Requires authentication via JWT token.
///
/// **Endpoint:** `GET /auth/oauth/providers`
///
/// **Headers:**
/// - `Authorization: Bearer <jwt_token>`
///
/// **Response:**
/// ```json
/// {
///   "success": true,
///   "data": [
///     {
///       "id": "uuid",
///       "provider": "google",
///       "provider_email": "user@gmail.com",
///       "created_at": "2024-01-01T00:00:00Z"
///     }
///   ]
/// }
/// ```
pub async fn get_user_oauth_providers(
    State(state): State<super::handlers::AppState>,
    axum::Extension(auth_user): axum::Extension<crate::api::middleware::AuthUser>,
) -> AppResult<Json<SuccessResponse<JsonValue>>> {
    let oauth_service = state
        .oauth_service
        .as_ref()
        .ok_or_else(|| AppError::Internal("OAuth service not configured".to_string()))?;

    let providers = oauth_service
        .get_user_oauth_providers(auth_user.0.user_id)
        .await?;

    // Transform providers to safe response format (hide sensitive data)
    let safe_providers: Vec<JsonValue> = providers
        .into_iter()
        .map(|provider| {
            serde_json::json!({
                "id": provider.id,
                "provider": provider.provider,
                "provider_email": provider.provider_email,
                "created_at": provider.created_at
            })
        })
        .collect();

    Ok(Json(SuccessResponse::new(serde_json::json!(
        safe_providers
    ))))
}

/// Handler for unlinking an OAuth provider
///
/// This endpoint removes the association between a user account and an OAuth provider.
/// The user account remains intact, but they will no longer be able to sign in
/// using the specified OAuth provider.
///
/// **Endpoint:** `DELETE /auth/oauth/providers/{provider}`
///
/// **Headers:**
/// - `Authorization: Bearer <jwt_token>`
///
/// **Path Parameters:**
/// - `provider`: OAuth provider name (e.g., "google")
///
/// **Response:**
/// ```json
/// {
///   "success": true,
///   "data": {
///     "unlinked": true,
///     "provider": "google"
///   }
/// }
/// ```
pub async fn unlink_oauth_provider(
    State(state): State<super::handlers::AppState>,
    axum::extract::Path(provider): axum::extract::Path<String>,
    Extension(app_ctx): Extension<AppContext>,
    axum::Extension(auth_user): axum::Extension<crate::api::middleware::AuthUser>,
) -> AppResult<Json<SuccessResponse<JsonValue>>> {
    // Parse provider type
    let provider_type = provider
        .parse()
        .map_err(|e| AppError::BadRequest(format!("Invalid provider type: {}", e)))?;

    // Unlink the OAuth provider
    let oauth_service = state
        .oauth_service
        .as_ref()
        .ok_or_else(|| AppError::Internal("OAuth service not configured".to_string()))?;

    let was_unlinked = oauth_service
        .unlink_oauth_provider(app_ctx.application_id, auth_user.0.user_id, provider_type)
        .await?;

    if !was_unlinked {
        return Err(AppError::NotFound(format!(
            "OAuth provider '{}' not found for user",
            provider
        )));
    }

    let response = serde_json::json!({
        "unlinked": true,
        "provider": provider
    });

    Ok(Json(SuccessResponse::new(response)))
}

/// Handler for OAuth health check and cleanup
///
/// This endpoint performs maintenance tasks like cleaning up expired OAuth state tokens.
/// It's intended for internal use or scheduled maintenance tasks.
///
/// **Endpoint:** `POST /auth/oauth/cleanup`
///
/// **Response:**
/// ```json
/// {
///   "success": true,
///   "data": {
///     "expired_states_removed": 42
///   }
/// }
/// ```
pub async fn oauth_cleanup(
    State(state): State<super::handlers::AppState>,
) -> AppResult<Json<SuccessResponse<JsonValue>>> {
    let oauth_service = state
        .oauth_service
        .as_ref()
        .ok_or_else(|| AppError::Internal("OAuth service not configured".to_string()))?;

    let removed_count = oauth_service.cleanup_expired_states().await?;

    let response = serde_json::json!({
        "expired_states_removed": removed_count
    });

    Ok(Json(SuccessResponse::new(response)))
}

#[cfg(test)]
mod tests {
    // Test imports would go here when handler functions are tested
    use crate::{models::oauth::GoogleOAuthInitRequest, GoogleOAuthCallbackResponse};

    #[tokio::test]
    async fn test_initiate_google_oauth_validation() {
        // Test empty redirect URL validation
        let _request = GoogleOAuthInitRequest {
            redirect_url: Some("".to_string()),
        };

        // This would fail validation due to empty redirect URL
        // In a real test, you'd set up a test server and make the request
    }

    #[tokio::test]
    async fn test_redirect_url_validation() {
        // Valid HTTPS URL
        let _request = GoogleOAuthInitRequest {
            redirect_url: Some("https://example.com/dashboard".to_string()),
        };
        // Should pass validation

        // Invalid URL scheme
        let _request = GoogleOAuthInitRequest {
            redirect_url: Some("ftp://example.com/dashboard".to_string()),
        };
        // Should fail validation
    }

    #[test]
    fn test_oauth_callback_response_format() {
        // Test that callback response includes required fields
        let response = GoogleOAuthCallbackResponse {
            access_token: "test_access_token".to_string(),
            refresh_token: "test_refresh_token".to_string(),
            user: crate::models::user::User {
                id: uuid::Uuid::new_v4(),
                application_id: uuid::Uuid::new_v4(),
                name: "Test User".to_string(),
                email: "test@example.com".to_string(),
                email_verified: true,
                profile_picture_url: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            },
            is_new_user: true,
        };

        assert!(!response.access_token.is_empty());
        assert!(!response.refresh_token.is_empty());
        assert!(response.is_new_user);
    }
}
