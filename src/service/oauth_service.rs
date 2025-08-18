//! OAuth Service
//!
//! This module provides OAuth 2.0 authentication services, specifically for Google OAuth.
//! It handles the complete OAuth flow including authorization URL generation, state management,
//! token exchange, and user account creation/linking.

use std::time::Duration;

use chrono::Utc;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl,
    Scope, TokenResponse, TokenUrl,
};
use reqwest::Client as HttpClient;
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    config::GoogleOAuthConfig,
    models::{
        oauth::*,
        user::{User, UserWithPassword},
    },
    service::JwtService,
    utils::error::AppError,
};

/// OAuth service specific errors
#[derive(Error, Debug)]
pub enum OAuthServiceError {
    /// OAuth configuration error
    #[error("OAuth configuration error: {0}")]
    ConfigurationError(String),

    /// OAuth state validation error
    #[error("Invalid OAuth state: {0}")]
    InvalidState(String),

    /// OAuth state has expired
    #[error("OAuth state has expired")]
    StateExpired,

    /// OAuth state not found
    #[error("OAuth state not found")]
    StateNotFound,

    /// OAuth authorization code error
    #[error("Invalid authorization code: {0}")]
    InvalidAuthorizationCode(String),

    /// OAuth token exchange error
    #[error("Token exchange failed: {0}")]
    TokenExchangeError(String),

    /// OAuth provider error
    #[error("OAuth provider error: {0}")]
    ProviderError(String),

    /// User info fetch error
    #[error("Failed to fetch user info: {0}")]
    UserInfoError(String),

    /// Account linking error
    #[error("Account linking error: {0}")]
    AccountLinkingError(String),

    /// Database operation failed
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    /// JWT service error
    #[error("JWT service error: {0}")]
    JwtServiceError(String),

    /// HTTP request error
    #[error("HTTP request error: {0}")]
    HttpError(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// UUID parsing error
    #[error("Invalid UUID: {0}")]
    InvalidUuid(#[from] uuid::Error),

    /// Internal error
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<OAuthServiceError> for AppError {
    fn from(err: OAuthServiceError) -> Self {
        match err {
            OAuthServiceError::ConfigurationError(msg) => AppError::Configuration(msg),
            OAuthServiceError::InvalidState(msg) => {
                AppError::BadRequest(format!("Invalid OAuth state: {}", msg))
            }
            OAuthServiceError::StateExpired => {
                AppError::BadRequest("OAuth state has expired".to_string())
            }
            OAuthServiceError::StateNotFound => {
                AppError::BadRequest("OAuth state not found".to_string())
            }
            OAuthServiceError::InvalidAuthorizationCode(msg) => {
                AppError::BadRequest(format!("Invalid authorization code: {}", msg))
            }
            OAuthServiceError::TokenExchangeError(msg) => {
                AppError::ExternalService(format!("Token exchange failed: {}", msg))
            }
            OAuthServiceError::ProviderError(msg) => {
                AppError::ExternalService(format!("OAuth provider error: {}", msg))
            }
            OAuthServiceError::UserInfoError(msg) => {
                AppError::ExternalService(format!("Failed to fetch user info: {}", msg))
            }
            OAuthServiceError::AccountLinkingError(msg) => {
                AppError::BadRequest(format!("Account linking error: {}", msg))
            }
            OAuthServiceError::DatabaseError(e) => AppError::Database(e),
            OAuthServiceError::JwtServiceError(msg) => {
                AppError::Internal(format!("JWT service error: {}", msg))
            }
            OAuthServiceError::HttpError(msg) => {
                AppError::ExternalService(format!("HTTP request error: {}", msg))
            }
            OAuthServiceError::SerializationError(msg) => {
                AppError::Internal(format!("Serialization error: {}", msg))
            }
            OAuthServiceError::InvalidUuid(e) => {
                AppError::BadRequest(format!("Invalid UUID: {}", e))
            }
            OAuthServiceError::InternalError(msg) => AppError::Internal(msg),
        }
    }
}

/// Result type for OAuth service operations
pub type OAuthServiceResult<T> = Result<T, OAuthServiceError>;

/// OAuth service for handling Google OAuth 2.0 authentication
///
/// This service manages the complete OAuth flow including:
/// - Authorization URL generation with CSRF protection
/// - State token management and validation
/// - Token exchange with Google's OAuth endpoints
/// - User account creation and linking
/// - Integration with existing JWT authentication system
pub struct OAuthService {
    /// Database connection pool
    pool: PgPool,
    /// Google OAuth configuration
    google_config: GoogleOAuthConfig,
    /// OAuth2 client for Google
    google_client: BasicClient,
    /// HTTP client for API requests
    http_client: HttpClient,
    /// JWT service for token generation
    jwt_service: JwtService,
}

impl OAuthService {
    /// Create a new OAuth service instance
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `google_config` - Google OAuth configuration
    /// * `jwt_service` - JWT service for token generation
    ///
    /// # Returns
    /// * `AppResult<Self>` - OAuth service instance or error
    pub fn new(
        pool: PgPool,
        google_config: GoogleOAuthConfig,
        jwt_service: JwtService,
    ) -> OAuthServiceResult<Self> {
        // Create Google OAuth2 client
        let google_client = BasicClient::new(
            ClientId::new(google_config.client_id.clone()),
            Some(ClientSecret::new(google_config.client_secret.clone())),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).map_err(
                |e| {
                    OAuthServiceError::ConfigurationError(format!("Invalid Google auth URL: {}", e))
                },
            )?,
            Some(
                TokenUrl::new("https://www.googleapis.com/oauth2/v4/token".to_string()).map_err(
                    |e| {
                        OAuthServiceError::ConfigurationError(format!(
                            "Invalid Google token URL: {}",
                            e
                        ))
                    },
                )?,
            ),
        )
        .set_redirect_uri(
            RedirectUrl::new(google_config.redirect_uri.clone()).map_err(|e| {
                OAuthServiceError::ConfigurationError(format!("Invalid redirect URI: {}", e))
            })?,
        );

        // Create HTTP client with reasonable timeouts
        let http_client = HttpClient::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| {
                OAuthServiceError::HttpError(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self {
            pool,
            google_config,
            google_client,
            http_client,
            jwt_service,
        })
    }

    /// Initiate Google OAuth flow
    ///
    /// Generates an authorization URL and stores a secure state token for CSRF protection.
    ///
    /// # Arguments
    /// * `redirect_url` - Optional redirect URL after successful authentication
    ///
    /// # Returns
    /// * `AppResult<GoogleOAuthInitResponse>` - Authorization URL and state token
    pub async fn initiate_google_oauth(
        &self,
        redirect_url: Option<String>,
    ) -> OAuthServiceResult<GoogleOAuthInitResponse> {
        // Generate authorization URL with state token
        let (auth_url, csrf_token) = self
            .google_client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .url();

        let state_token = csrf_token.secret().clone();

        // Calculate expiration time
        let expires_at =
            Utc::now() + chrono::Duration::minutes(self.google_config.state_expires_minutes);

        // Store state token in database
        sqlx::query!(
            r#"
            INSERT INTO oauth_states (state_token, expires_at, redirect_url)
            VALUES ($1, $2, $3)
            "#,
            state_token,
            expires_at,
            redirect_url
        )
        .execute(&self.pool)
        .await
        .map_err(OAuthServiceError::DatabaseError)?;

        Ok(GoogleOAuthInitResponse {
            authorization_url: auth_url.to_string(),
            state: state_token,
        })
    }

    /// Handle Google OAuth callback
    ///
    /// Processes the callback from Google OAuth, validates the state token,
    /// exchanges the authorization code for tokens, fetches user info,
    /// and creates or links user accounts.
    ///
    /// # Arguments
    /// * `query` - OAuth callback query parameters
    ///
    /// # Returns
    /// * `OAuthServiceResult<GoogleOAuthCallbackResponse>` - JWT tokens and user info
    pub async fn handle_google_callback(
        &self,
        query: GoogleOAuthCallbackQuery,
    ) -> OAuthServiceResult<GoogleOAuthCallbackResponse> {
        // Validate callback parameters
        let auth_code = query.code.ok_or_else(|| {
            OAuthServiceError::InvalidAuthorizationCode("Missing authorization code".to_string())
        })?;

        let state_token = query
            .state
            .ok_or_else(|| OAuthServiceError::InvalidState("Missing state token".to_string()))?;

        // Check for OAuth errors
        if let Some(error) = query.error {
            let description = query.error_description.unwrap_or_else(|| error.clone());
            return Err(OAuthServiceError::ProviderError(format!(
                "OAuth error: {} - {}",
                error, description
            )));
        }

        // Validate and consume state token
        let _oauth_state = self.validate_and_consume_state(&state_token).await?;

        // Exchange authorization code for access token
        let token_response = self
            .google_client
            .exchange_code(AuthorizationCode::new(auth_code))
            .request_async(&oauth2::reqwest::async_http_client)
            .await
            .map_err(|e| {
                OAuthServiceError::TokenExchangeError(format!(
                    "Failed to exchange OAuth code: {}",
                    e
                ))
            })?;

        // Fetch user information from Google
        let google_user = self
            .fetch_google_user_info(token_response.access_token().secret())
            .await?;

        // Create or link user account
        let (user, is_new_user) = self.create_or_link_user(&google_user).await?;

        // Generate JWT tokens
        let token_pair = self
            .jwt_service
            .generate_token_pair(user.id, None, None)
            .await
            .map_err(|e| {
                OAuthServiceError::JwtServiceError(format!("Failed to generate tokens: {}", e))
            })?;

        Ok(GoogleOAuthCallbackResponse {
            access_token: token_pair.access_token,
            refresh_token: token_pair.refresh_token,
            user,
            is_new_user,
        })
    }

    /// Validate and consume OAuth state token
    ///
    /// Checks if the state token exists, hasn't expired, and removes it from the database
    /// to prevent reuse attacks.
    ///
    /// # Arguments
    /// * `state_token` - State token to validate
    ///
    /// # Returns
    /// * `OAuthServiceResult<OAuthState>` - Valid state record or error
    async fn validate_and_consume_state(
        &self,
        state_token: &str,
    ) -> OAuthServiceResult<OAuthState> {
        // Find and delete state token in a single transaction
        let mut tx = self.pool.begin().await?;

        // Fetch state record
        let state_record = sqlx::query_as!(
            OAuthState,
            r#"
            SELECT id, state_token, expires_at, redirect_url, created_at
            FROM oauth_states
            WHERE state_token = $1
            "#,
            state_token
        )
        .fetch_optional(&mut *tx)
        .await?;

        let state = state_record.ok_or(OAuthServiceError::StateNotFound)?;

        // Check if token has expired
        if state.expires_at < Utc::now() {
            // Delete expired token
            sqlx::query!("DELETE FROM oauth_states WHERE id = $1", state.id)
                .execute(&mut *tx)
                .await?;

            tx.commit().await?;

            return Err(OAuthServiceError::StateExpired);
        }

        // Delete used state token to prevent reuse
        sqlx::query!("DELETE FROM oauth_states WHERE id = $1", state.id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok(state)
    }

    /// Fetch user information from Google's userinfo endpoint
    ///
    /// # Arguments
    /// * `access_token` - Google OAuth access token
    ///
    /// # Returns
    /// * `OAuthServiceResult<GoogleUserInfo>` - Google user information
    async fn fetch_google_user_info(
        &self,
        access_token: &str,
    ) -> OAuthServiceResult<GoogleUserInfo> {
        let response = self
            .http_client
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| {
                OAuthServiceError::UserInfoError(format!("Failed to fetch user info: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(OAuthServiceError::ProviderError(format!(
                "Google API returned error: {}",
                response.status()
            )));
        }

        let user_info: GoogleUserInfo = response.json().await.map_err(|e| {
            OAuthServiceError::UserInfoError(format!("Failed to parse user info: {}", e))
        })?;

        // Validate that email is verified
        if !user_info.verified_email {
            return Err(OAuthServiceError::ProviderError(
                "Google account email is not verified".to_string(),
            ));
        }

        Ok(user_info)
    }

    /// Create new user account or link to existing account
    ///
    /// This method handles both new user registration and linking OAuth accounts
    /// to existing users based on email address matching.
    ///
    /// # Arguments
    /// * `google_user` - Google user information
    ///
    /// # Returns
    /// * `OAuthServiceResult<(User, bool)>` - User and whether it's a new account
    async fn create_or_link_user(
        &self,
        google_user: &GoogleUserInfo,
    ) -> OAuthServiceResult<(User, bool)> {
        let mut tx = self.pool.begin().await?;

        // Check if Google account is already linked
        let existing_provider = sqlx::query_as!(
            OAuthProvider,
            r#"
            SELECT id, user_id, provider, provider_user_id, provider_email,
                   provider_data, created_at, updated_at
            FROM oauth_providers
            WHERE provider = 'google' AND provider_user_id = $1
            "#,
            google_user.id
        )
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(provider) = existing_provider {
            // Existing Google account - fetch user
            let user = sqlx::query_as!(
                UserWithPassword,
                r#"
                SELECT id, name, email, password_hash, email_verified,
                       profile_picture_url, created_at, updated_at
                FROM users
                WHERE id = $1
                "#,
                provider.user_id
            )
            .fetch_one(&mut *tx)
            .await?;

            tx.commit().await?;

            return Ok((user.into(), false));
        }

        // Check if user exists with the same email
        let existing_user = sqlx::query_as!(
            UserWithPassword,
            r#"
            SELECT id, name, email, password_hash, email_verified,
                   profile_picture_url, created_at, updated_at
            FROM users
            WHERE email = $1
            "#,
            google_user.email
        )
        .fetch_optional(&mut *tx)
        .await?;

        let (user, is_new_user) = if let Some(existing_user) = existing_user {
            // Link Google account to existing user
            (existing_user, false)
        } else {
            // Create new user account
            let new_user = sqlx::query_as!(
                UserWithPassword,
                r#"
                INSERT INTO users (name, email, email_verified, profile_picture_url)
                VALUES ($1, $2, $3, $4)
                RETURNING id, name, email, password_hash, email_verified,
                          profile_picture_url, created_at, updated_at
                "#,
                google_user.name,
                google_user.email,
                true, // Google emails are always verified
                google_user.picture
            )
            .fetch_one(&mut *tx)
            .await?;

            (new_user, true)
        };

        // Create OAuth provider record
        let provider_data = serde_json::json!({
            "given_name": google_user.given_name,
            "family_name": google_user.family_name,
            "picture": google_user.picture,
            "locale": google_user.locale
        });

        sqlx::query!(
            r#"
            INSERT INTO oauth_providers (user_id, provider, provider_user_id, provider_email, provider_data)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            user.id,
            "google",
            google_user.id,
            google_user.email,
            provider_data
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok((user.into(), is_new_user))
    }

    /// Clean up expired OAuth state tokens
    ///
    /// This method should be called periodically to remove expired state tokens
    /// from the database to prevent accumulation of stale data.
    ///
    /// # Returns
    /// * `OAuthServiceResult<u64>` - Number of expired tokens removed
    pub async fn cleanup_expired_states(&self) -> OAuthServiceResult<u64> {
        let result = sqlx::query!(
            r#"
            DELETE FROM oauth_states
            WHERE expires_at < NOW()
            "#
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Get OAuth providers for a user
    ///
    /// Returns all OAuth provider accounts linked to the specified user.
    ///
    /// # Arguments
    /// * `user_id` - User ID to fetch providers for
    ///
    /// # Returns
    /// * `OAuthServiceResult<Vec<OAuthProvider>>` - List of linked OAuth providers
    pub async fn get_user_oauth_providers(
        &self,
        user_id: Uuid,
    ) -> OAuthServiceResult<Vec<OAuthProvider>> {
        let providers = sqlx::query_as!(
            OAuthProvider,
            r#"
            SELECT id, user_id, provider, provider_user_id, provider_email,
                   provider_data, created_at, updated_at
            FROM oauth_providers
            WHERE user_id = $1
            ORDER BY created_at ASC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(providers)
    }

    /// Remove OAuth provider link
    ///
    /// Unlinks an OAuth provider from a user account. This does not delete the user
    /// account itself, only removes the OAuth association.
    ///
    /// # Arguments
    /// * `user_id` - User ID
    /// * `provider_type` - OAuth provider type to unlink
    ///
    /// # Returns
    /// * `OAuthServiceResult<bool>` - True if provider was unlinked, false if not found
    pub async fn unlink_oauth_provider(
        &self,
        user_id: Uuid,
        provider_type: OAuthProviderType,
    ) -> OAuthServiceResult<bool> {
        let result = sqlx::query!(
            r#"
            DELETE FROM oauth_providers
            WHERE user_id = $1 AND provider = $2
            "#,
            user_id,
            provider_type.to_string()
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::DatabaseConfig;

    async fn create_test_oauth_service() -> OAuthServiceResult<OAuthService> {
        let config = DatabaseConfig::from_env().unwrap();
        let pool = config.create_pool().await.unwrap();

        let google_config = GoogleOAuthConfig {
            client_id: "test_client_id".to_string(),
            client_secret: "test_client_secret".to_string(),
            redirect_uri: "http://localhost:3000/auth/callback/google".to_string(),
            state_expires_minutes: 10,
        };

        let jwt_service = JwtService::new(
            pool.clone(),
            "test_access_secret".to_string(),
            "test_refresh_secret".to_string(),
        );
        OAuthService::new(pool, google_config, jwt_service)
    }

    #[tokio::test]
    async fn test_oauth_provider_type_conversion() {
        assert_eq!(OAuthProviderType::Google.to_string(), "google");
        assert_eq!(
            "google".parse::<OAuthProviderType>().unwrap(),
            OAuthProviderType::Google
        );
    }

    #[tokio::test]
    async fn test_google_user_info_validation() {
        let verified_user = GoogleUserInfo {
            id: "123".to_string(),
            email: "test@example.com".to_string(),
            verified_email: true,
            name: "Test User".to_string(),
            given_name: Some("Test".to_string()),
            family_name: Some("User".to_string()),
            picture: None,
            locale: Some("en".to_string()),
        };

        assert!(verified_user.verified_email);

        let unverified_user = GoogleUserInfo {
            verified_email: false,
            ..verified_user
        };

        assert!(!unverified_user.verified_email);
    }
}
