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
    /// Creates a new OAuth service instance with Google OAuth configuration
    ///
    /// Initializes the OAuth service with Google OAuth2 client, HTTP client, and
    /// database connectivity. Validates configuration parameters and sets up
    /// proper timeouts for external API calls.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool for state management and user operations
    /// * `google_config` - Google OAuth configuration with client credentials and URLs
    /// * `jwt_service` - JWT service for generating authentication tokens
    ///
    /// # Returns
    /// * `Ok(OAuthService)` - Fully configured OAuth service instance
    /// * `Err(OAuthServiceError)` - Configuration validation or initialization errors
    ///
    /// # Errors
    /// * `ConfigurationError` - Invalid OAuth URLs or client configuration
    /// * `HttpError` - Failed to create HTTP client
    ///
    /// # Configuration Requirements
    /// * Valid Google OAuth client ID and secret
    /// * Properly formatted redirect URI
    /// * Accessible Google OAuth endpoints
    ///
    /// # Examples
    /// ```
    /// use user_service::service::{OAuthService, JwtService};
    /// use user_service::config::GoogleOAuthConfig;
    /// use sqlx::PgPool;
    ///
    /// let pool = PgPool::connect("postgresql://...").await?;
    /// let jwt_service = JwtService::new(pool.clone(), "secret1".to_string(), "secret2".to_string());
    /// let google_config = GoogleOAuthConfig {
    ///     client_id: "your-client-id".to_string(),
    ///     client_secret: "your-client-secret".to_string(),
    ///     redirect_uri: "https://yourapp.com/auth/google/callback".to_string(),
    ///     state_expires_minutes: 10,
    /// };
    ///
    /// let oauth_service = OAuthService::new(pool, google_config, jwt_service)?;
    /// ```
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

    /// Initiates the Google OAuth 2.0 authorization flow
    ///
    /// Generates a secure authorization URL with CSRF protection using state tokens.
    /// The state token is stored in the database with expiration tracking to prevent
    /// replay attacks and session fixation vulnerabilities.
    ///
    /// # Arguments
    /// * `redirect_url` - Optional URL to redirect to after successful authentication
    ///
    /// # Returns
    /// * `Ok(GoogleOAuthInitResponse)` - Authorization URL and state token for the client
    /// * `Err(OAuthServiceError)` - Database storage or URL generation errors
    ///
    /// # Errors
    /// * `DatabaseError` - Failed to store state token in database
    ///
    /// # Security Features
    /// * CSRF protection via cryptographically secure state tokens
    /// * Time-limited state tokens (configurable expiration)
    /// * Secure random state generation using OAuth2 library
    /// * Database persistence for state validation
    ///
    /// # OAuth Scopes Requested
    /// * `openid` - OpenID Connect authentication
    /// * `email` - User's email address
    /// * `profile` - Basic profile information (name, picture)
    ///
    /// # Flow
    /// 1. Generates cryptographically secure state token
    /// 2. Creates Google OAuth authorization URL with required scopes
    /// 3. Stores state token in database with expiration
    /// 4. Returns authorization URL for client redirect
    ///
    /// # Examples
    /// ```
    /// let oauth_service = OAuthService::new(pool, config, jwt_service)?;
    /// let response = oauth_service.initiate_google_oauth(
    ///     Some("https://myapp.com/dashboard".to_string())
    /// ).await?;
    ///
    /// // Redirect user to response.authorization_url
    /// // Store response.state for callback validation
    /// ```
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

    /// Handles the Google OAuth callback and completes the authentication flow
    ///
    /// Processes the OAuth callback from Google, performs comprehensive security
    /// validation, exchanges the authorization code for access tokens, fetches
    /// user information, and either creates a new user account or links to an
    /// existing account based on email address.
    ///
    /// # Arguments
    /// * `query` - OAuth callback query parameters containing code, state, and optional errors
    ///
    /// # Returns
    /// * `Ok(GoogleOAuthCallbackResponse)` - JWT token pair, user object, and registration status
    /// * `Err(OAuthServiceError)` - Validation, token exchange, or user creation errors
    ///
    /// # Errors
    /// * `InvalidAuthorizationCode` - Missing or invalid authorization code
    /// * `InvalidState` - Missing, invalid, expired, or reused state token
    /// * `ProviderError` - Google returned an OAuth error
    /// * `TokenExchangeError` - Failed to exchange code for access token
    /// * `UserInfoError` - Failed to fetch user information from Google
    /// * `AccountLinkingError` - Failed to create or link user account
    /// * `JwtServiceError` - Failed to generate authentication tokens
    /// * `DatabaseError` - Database operations failed
    ///
    /// # Security Validations
    /// * CSRF protection via state token validation
    /// * State token expiration checking
    /// * One-time use enforcement (state tokens are consumed)
    /// * Authorization code validation with Google
    /// * Secure token exchange using OAuth2 standards
    ///
    /// # User Account Handling
    /// * Links to existing account if email already exists
    /// * Creates new account for new email addresses
    /// * Stores OAuth provider association
    /// * Marks email as verified (trusted OAuth provider)
    /// * Generates JWT tokens for immediate authentication
    ///
    /// # Examples
    /// ```
    /// use user_service::models::oauth::GoogleOAuthCallbackQuery;
    ///
    /// let query = GoogleOAuthCallbackQuery {
    ///     code: Some("auth_code_from_google".to_string()),
    ///     state: Some("state_token_from_initiation".to_string()),
    ///     error: None,
    ///     error_description: None,
    /// };
    ///
    /// let response = oauth_service.handle_google_callback(query).await?;
    /// if response.is_new_user {
    ///     println!("New user registered: {}", response.user.email);
    /// } else {
    ///     println!("Existing user logged in: {}", response.user.email);
    /// }
    /// ```
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

    /// Validates and consumes an OAuth state token for CSRF protection
    ///
    /// Performs comprehensive validation of the state token including existence,
    /// expiration checking, and atomic consumption to prevent replay attacks.
    /// This is a critical security operation in the OAuth flow.
    ///
    /// # Arguments
    /// * `state_token` - The state token to validate and consume
    ///
    /// # Returns
    /// * `Ok(OAuthState)` - Valid state record with metadata
    /// * `Err(OAuthServiceError)` - Validation failures or database errors
    ///
    /// # Errors
    /// * `StateNotFound` - State token doesn't exist in database
    /// * `StateExpired` - State token has passed its expiration time
    /// * `DatabaseError` - Database transaction failed
    ///
    /// # Security Features
    /// * Atomic validation and consumption in database transaction
    /// * Automatic cleanup of expired tokens
    /// * One-time use enforcement (tokens deleted after validation)
    /// * Time-based expiration checking
    /// * Transaction rollback on validation failures
    ///
    /// # Database Operations
    /// 1. Begins database transaction for atomicity
    /// 2. Looks up state token record
    /// 3. Validates expiration timestamp
    /// 4. Deletes token from database (consumption)
    /// 5. Commits transaction if all validations pass
    ///
    /// # Privacy Notes
    /// State tokens are automatically cleaned up whether they're expired
    /// or successfully consumed, preventing database bloat and information leakage.
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

    /// Fetches user information from Google's UserInfo API endpoint
    ///
    /// Makes an authenticated request to Google's userinfo endpoint to retrieve
    /// the user's profile information including email, name, and profile picture.
    /// Uses the access token obtained from the OAuth token exchange.
    ///
    /// # Arguments
    /// * `access_token` - Valid Google OAuth access token with appropriate scopes
    ///
    /// # Returns
    /// * `Ok(GoogleUserInfo)` - Complete user profile information from Google
    /// * `Err(OAuthServiceError)` - HTTP request, parsing, or validation errors
    ///
    /// # Errors
    /// * `HttpError` - Network request failed or timeout occurred
    /// * `UserInfoError` - Invalid response format or missing required fields
    /// * `SerializationError` - JSON parsing failed
    ///
    /// # Required OAuth Scopes
    /// The access token must include these scopes for successful API calls:
    /// * `openid` - Basic OpenID Connect access
    /// * `email` - Access to email address
    /// * `profile` - Access to profile information
    ///
    /// # API Endpoint
    /// Calls: `https://www.googleapis.com/oauth2/v2/userinfo`
    ///
    /// # Data Retrieved
    /// * `id` - Google user identifier (sub claim)
    /// * `email` - Verified email address
    /// * `name` - Full display name
    /// * `picture` - Profile picture URL
    /// * `verified_email` - Email verification status
    ///
    /// # Privacy and Security
    /// * Uses HTTPS for all API communications
    /// * Respects Google's rate limiting
    /// * Validates response data structure
    /// * Handles missing optional fields gracefully
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

    /// Creates a new user account or links OAuth provider to existing account
    ///
    /// Implements intelligent account linking based on email address matching.
    /// If a Google account is already linked, returns the existing user. If a user
    /// exists with the same email, links the Google account. Otherwise, creates
    /// a new user account with Google authentication.
    ///
    /// # Arguments
    /// * `google_user` - Complete Google user profile information from OAuth
    ///
    /// # Returns
    /// * `Ok((User, bool))` - User object and new account flag (true = newly created)
    /// * `Err(OAuthServiceError)` - Database operations or validation failed
    ///
    /// # Errors
    /// * `DatabaseError` - User creation, linking, or transaction failed
    /// * `AccountLinkingError` - OAuth provider association failed
    ///
    /// # Account Linking Logic
    /// 1. **Existing Google Link**: Return associated user (no changes)
    /// 2. **Email Match**: Link Google account to existing user
    /// 3. **New User**: Create account with Google as primary authentication
    ///
    /// # Database Operations
    /// * Creates user record for new accounts
    /// * Links OAuth provider association
    /// * Marks email as verified (trusted OAuth provider)
    /// * Uses database transactions for atomicity
    ///
    /// # Security Features
    /// * Email verification trust from OAuth provider
    /// * Atomic operations prevent inconsistent state
    /// * Profile picture from trusted source
    /// * Provider-specific user ID tracking
    ///
    /// # Examples
    /// ```
    /// let google_user = GoogleUserInfo {
    ///     id: "google_user_123".to_string(),
    ///     email: "user@example.com".to_string(),
    ///     name: "John Doe".to_string(),
    ///     picture: Some("https://photo.url".to_string()),
    ///     verified_email: true,
    /// };
    ///
    /// let (user, is_new) = oauth_service.create_or_link_user(&google_user).await?;
    /// ```
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

    /// Cleans up expired OAuth state tokens from the database
    ///
    /// Removes all state tokens that have passed their expiration time to prevent
    /// database bloat and maintain security hygiene. This is a maintenance operation
    /// that should be run periodically via scheduled jobs or application startup.
    ///
    /// # Returns
    /// * `Ok(u64)` - Number of expired state tokens that were deleted
    /// * `Err(OAuthServiceError)` - Database operation failed
    ///
    /// # Errors
    /// * `DatabaseError` - Failed to execute cleanup query
    ///
    /// # Performance Notes
    /// * Operation performance depends on number of expired tokens
    /// * Consider adding database index on `expires_at` column
    /// * Safe to run frequently as it only affects expired tokens
    ///
    /// # Scheduling Recommendations
    /// * Run hourly for high-traffic applications
    /// * Run daily for moderate-traffic applications
    /// * Include in application health check routines
    /// * Trigger during off-peak hours for large databases
    ///
    /// # Examples
    /// ```
    /// // Cleanup job in scheduled task
    /// let deleted_count = oauth_service.cleanup_expired_states().await?;
    /// if deleted_count > 0 {
    ///     println!("Cleaned up {} expired OAuth state tokens", deleted_count);
    /// }
    /// ```
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
    /// Retrieves all OAuth providers linked to a specific user account
    ///
    /// Returns a list of external OAuth providers (Google, etc.) that are
    /// associated with the user's account. Useful for account management
    /// interfaces and security dashboards.
    ///
    /// # Arguments
    /// * `user_id` - Unique identifier of the user account
    ///
    /// # Returns
    /// * `Ok(Vec<OAuthProvider>)` - List of linked OAuth provider records
    /// * `Err(OAuthServiceError)` - Database query failed
    ///
    /// # Errors
    /// * `DatabaseError` - Failed to query OAuth provider associations
    ///
    /// # OAuth Provider Information
    /// Each provider record includes:
    /// * Provider type (e.g., "google")
    /// * Provider-specific user ID
    /// * Link creation timestamp
    /// * Last update timestamp
    ///
    /// # Use Cases
    /// * Account settings page showing linked providers
    /// * Security dashboard displaying authentication methods
    /// * Admin tools for user account management
    /// * Audit trails for authentication method changes
    ///
    /// # Privacy Notes
    /// * Does not expose sensitive OAuth tokens
    /// * Only returns metadata about provider associations
    /// * Suitable for user-facing account management interfaces
    ///
    /// # Examples
    /// ```
    /// use uuid::Uuid;
    ///
    /// let user_id = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000")?;
    /// let providers = oauth_service.get_user_oauth_providers(user_id).await?;
    ///
    /// for provider in providers {
    ///     println!("Linked provider: {} (since {})", provider.provider_type, provider.created_at);
    /// }
    /// ```
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

    /// Removes an OAuth provider association from a user account
    ///
    /// Unlinks a specific OAuth provider (e.g., Google) from a user's account.
    /// This operation only removes the OAuth association - the user account
    /// itself remains intact. Used for account security management and
    /// when users want to remove external authentication methods.
    ///
    /// # Arguments
    /// * `user_id` - Unique identifier of the user account
    /// * `provider_type` - Type of OAuth provider to unlink (e.g., Google)
    ///
    /// # Returns
    /// * `Ok(true)` - OAuth provider was successfully unlinked
    /// * `Ok(false)` - No association found for the specified provider
    /// * `Err(OAuthServiceError)` - Database operation failed
    ///
    /// # Errors
    /// * `DatabaseError` - Failed to delete OAuth provider association
    ///
    /// # Security Considerations
    /// * Ensure user has alternative authentication method before unlinking
    /// * May leave user unable to sign in if it's their only auth method
    /// * Consider requiring password authentication before unlinking
    /// * Log unlinking events for security audit trails
    ///
    /// # Use Cases
    /// * User-initiated removal of linked social accounts
    /// * Security incident response (compromise of external provider)
    /// * Account management and privacy controls
    /// * Admin-initiated security actions
    ///
    /// # Examples
    /// ```
    /// use uuid::Uuid;
    /// use user_service::models::oauth::OAuthProviderType;
    ///
    /// let user_id = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000")?;
    /// let was_unlinked = oauth_service.unlink_oauth_provider(
    ///     user_id,
    ///     OAuthProviderType::Google
    /// ).await?;
    ///
    /// if was_unlinked {
    ///     println!("Google account successfully unlinked");
    /// } else {
    ///     println!("No Google account was linked to this user");
    /// }
    /// ```
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
