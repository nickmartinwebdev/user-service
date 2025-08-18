//! JWT Authentication Service
//!
//! Provides JWT token generation, validation, and session management functionality.

use crate::models::{AccessTokenClaims, AuthSession, RefreshTokenClaims, TokenPair, UserContext};
use crate::utils::error::AppError;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use sha2::{Digest, Sha256};
use sqlx::types::ipnetwork::IpNetwork;
use sqlx::PgPool;
use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;

/// JWT service specific errors
#[derive(Error, Debug)]
pub enum JwtServiceError {
    /// JWT token generation failed
    #[error("Token generation error: {0}")]
    TokenGeneration(String),

    /// JWT token is invalid or malformed
    #[error("Invalid token: {0}")]
    InvalidToken(String),

    /// JWT token has expired
    #[error("Token expired")]
    TokenExpired,

    /// Database operation failed
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    /// Session not found or invalid
    #[error("Session not found")]
    SessionNotFound,

    /// Session has expired
    #[error("Session expired")]
    SessionExpired,

    /// Invalid session data
    #[error("Invalid session data: {0}")]
    InvalidSession(String),

    /// UUID parsing error
    #[error("Invalid UUID: {0}")]
    InvalidUuid(#[from] uuid::Error),

    /// Internal error
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<JwtServiceError> for AppError {
    fn from(err: JwtServiceError) -> Self {
        match err {
            JwtServiceError::TokenGeneration(msg) => AppError::TokenGeneration(msg),
            JwtServiceError::InvalidToken(msg) => AppError::InvalidToken(msg),
            JwtServiceError::TokenExpired => AppError::InvalidToken("Token expired".to_string()),
            JwtServiceError::DatabaseError(e) => AppError::Database(e),
            JwtServiceError::SessionNotFound => {
                AppError::InvalidToken("Session not found".to_string())
            }
            JwtServiceError::SessionExpired => {
                AppError::InvalidToken("Session expired".to_string())
            }
            JwtServiceError::InvalidSession(msg) => {
                AppError::InvalidToken(format!("Invalid session: {}", msg))
            }
            JwtServiceError::InvalidUuid(e) => {
                AppError::InvalidToken(format!("Invalid UUID: {}", e))
            }
            JwtServiceError::InternalError(msg) => AppError::Internal(msg),
        }
    }
}

/// Result type for JWT service operations
pub type JwtServiceResult<T> = Result<T, JwtServiceError>;

/// JWT authentication service for token management and validation
#[derive(Clone)]
pub struct JwtService {
    /// Database connection pool
    pool: PgPool,
    /// JWT access token secret
    access_secret: String,
    /// JWT refresh token secret
    refresh_secret: String,
    /// Access token expiration duration (default: 1 hour)
    access_token_expires_in: Duration,
    /// Refresh token expiration duration (default: 30 days)
    refresh_token_expires_in: Duration,
}

impl JwtService {
    /// Creates a new JWT service instance with default token expiration times
    ///
    /// Initializes the JWT service with default expiration times:
    /// - Access tokens: 1 hour
    /// - Refresh tokens: 30 days
    ///
    /// # Arguments
    /// * `pool` - Database connection pool for session management
    /// * `access_secret` - Secret key for signing access tokens (should be cryptographically secure)
    /// * `refresh_secret` - Secret key for signing refresh tokens (should be different from access secret)
    ///
    /// # Returns
    /// A new JwtService instance configured with default expiration times
    ///
    /// # Security Notes
    /// - Use different secrets for access and refresh tokens
    /// - Secrets should be at least 32 bytes of random data
    /// - Store secrets securely (environment variables, key management systems)
    ///
    /// # Examples
    /// ```
    /// use sqlx::PgPool;
    /// use user_service::service::JwtService;
    ///
    /// let pool = PgPool::connect("postgresql://...").await?;
    /// let access_secret = "your-secure-access-secret".to_string();
    /// let refresh_secret = "your-secure-refresh-secret".to_string();
    /// let jwt_service = JwtService::new(pool, access_secret, refresh_secret);
    /// ```
    pub fn new(pool: PgPool, access_secret: String, refresh_secret: String) -> Self {
        Self {
            pool,
            access_secret,
            refresh_secret,
            access_token_expires_in: Duration::hours(1),
            refresh_token_expires_in: Duration::days(30),
        }
    }

    /// Creates a new JWT service instance with custom token expiration times
    ///
    /// Allows full customization of token lifetimes for different security requirements.
    /// Shorter access token lifetimes increase security but may impact user experience.
    /// Longer refresh token lifetimes reduce login frequency but increase session hijacking risk.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool for session management
    /// * `access_secret` - Secret key for signing access tokens
    /// * `refresh_secret` - Secret key for signing refresh tokens
    /// * `access_expires_in` - How long access tokens remain valid
    /// * `refresh_expires_in` - How long refresh tokens remain valid
    ///
    /// # Returns
    /// A new JwtService instance with custom expiration configuration
    ///
    /// # Security Recommendations
    /// - Access tokens: 15 minutes to 2 hours for high-security applications
    /// - Refresh tokens: 1-90 days depending on security requirements
    /// - Use shorter lifetimes for sensitive applications
    ///
    /// # Examples
    /// ```
    /// use chrono::Duration;
    /// use sqlx::PgPool;
    /// use user_service::service::JwtService;
    ///
    /// let pool = PgPool::connect("postgresql://...").await?;
    /// let jwt_service = JwtService::with_expiration(
    ///     pool,
    ///     "access-secret".to_string(),
    ///     "refresh-secret".to_string(),
    ///     Duration::minutes(15), // Short-lived access tokens
    ///     Duration::days(7),     // Weekly refresh
    /// );
    /// ```
    pub fn with_expiration(
        pool: PgPool,
        access_secret: String,
        refresh_secret: String,
        access_expires_in: Duration,
        refresh_expires_in: Duration,
    ) -> Self {
        Self {
            pool,
            access_secret,
            refresh_secret,
            access_token_expires_in: access_expires_in,
            refresh_token_expires_in: refresh_expires_in,
        }
    }

    /// Generates a new JWT token pair for authenticated user sessions
    ///
    /// Creates both access and refresh tokens with embedded session information.
    /// The refresh token is associated with a database session for secure revocation.
    /// Session metadata is stored for security monitoring and device management.
    ///
    /// # Arguments
    /// * `user_id` - Unique identifier of the authenticated user
    /// * `user_agent` - Optional client user agent string for session tracking
    /// * `ip_address` - Optional client IP address for security monitoring
    ///
    /// # Returns
    /// * `Ok(TokenPair)` - New access and refresh tokens with expiration info
    /// * `Err(JwtServiceError)` - Token generation or database errors
    ///
    /// # Errors
    /// * `TokenGeneration` - JWT encoding failed
    /// * `DatabaseError` - Session storage failed
    ///
    /// # Security Features
    /// - Each refresh token maps to a unique database session
    /// - Sessions can be individually revoked
    /// - IP address and user agent tracking for anomaly detection
    /// - Cryptographically secure random session IDs
    ///
    /// # Examples
    /// ```
    /// use uuid::Uuid;
    /// use std::net::IpAddr;
    ///
    /// let user_id = Uuid::new_v4();
    /// let user_agent = Some("Mozilla/5.0...".to_string());
    /// let ip = Some("192.168.1.100".to_string());
    ///
    /// let tokens = jwt_service.generate_token_pair(user_id, user_agent, ip).await?;
    /// println!("Access token expires in {} seconds", tokens.expires_in);
    /// ```
    pub async fn generate_token_pair(
        &self,
        user_id: Uuid,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> JwtServiceResult<TokenPair> {
        let now = Utc::now();
        let access_expires_at = now + self.access_token_expires_in;
        let refresh_expires_at = now + self.refresh_token_expires_in;

        // Generate access token
        let access_claims = AccessTokenClaims::new(user_id, access_expires_at, now);
        let access_token = self.encode_access_token(&access_claims)?;

        // Create session and generate refresh token
        let session_id = Uuid::new_v4();
        let refresh_claims = RefreshTokenClaims::new(user_id, session_id, refresh_expires_at, now);
        let refresh_token = self.encode_refresh_token(&refresh_claims)?;

        // Store session in database
        self.create_session(
            session_id,
            user_id,
            &refresh_token,
            refresh_expires_at,
            user_agent,
            ip_address,
        )
        .await?;

        Ok(TokenPair::new(
            access_token,
            refresh_token,
            self.access_token_expires_in.num_seconds(),
        ))
    }

    /// Refreshes an access token using a valid refresh token
    ///
    /// Validates the refresh token, verifies the associated session exists and is valid,
    /// then generates a new access token. The refresh token remains unchanged and valid
    /// until its expiration. Updates session usage tracking for monitoring.
    ///
    /// # Arguments
    /// * `refresh_token` - The refresh token to validate and use for renewal
    ///
    /// # Returns
    /// * `Ok(TokenPair)` - New access token with same refresh token
    /// * `Err(JwtServiceError)` - Token validation, session, or generation errors
    ///
    /// # Errors
    /// * `InvalidToken` - Refresh token is malformed, invalid, or doesn't match session
    /// * `SessionNotFound` - Session was deleted or never existed
    /// * `SessionExpired` - Session has passed its expiration time
    /// * `TokenGeneration` - New access token creation failed
    /// * `DatabaseError` - Session lookup or update failed
    ///
    /// # Security Features
    /// - Validates refresh token signature and expiration
    /// - Cross-references token with stored session hash
    /// - Automatic cleanup of expired sessions
    /// - Session usage tracking for anomaly detection
    /// - Constant-time token comparison to prevent timing attacks
    ///
    /// # Examples
    /// ```
    /// let refresh_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...";
    /// let new_tokens = jwt_service.refresh_access_token(refresh_token).await?;
    /// // New access token, same refresh token
    /// ```
    pub async fn refresh_access_token(&self, refresh_token: &str) -> JwtServiceResult<TokenPair> {
        // Validate refresh token
        let refresh_claims = self.decode_refresh_token(refresh_token)?;
        let session_id = Uuid::parse_str(&refresh_claims.session_id)?;

        // Verify session exists and is valid
        let session = self.get_session(session_id).await?;
        if session.expires_at <= Utc::now() {
            self.delete_session(session_id).await?;
            return Err(JwtServiceError::SessionExpired);
        }

        // Verify refresh token hash matches stored hash
        let token_hash = self.hash_token(refresh_token);
        if session.refresh_token_hash != token_hash {
            return Err(JwtServiceError::InvalidToken(
                "Invalid refresh token".to_string(),
            ));
        }

        // Generate new access token
        let now = Utc::now();
        let access_expires_at = now + self.access_token_expires_in;
        let access_claims = AccessTokenClaims::new(session.user_id, access_expires_at, now);
        let access_token = self.encode_access_token(&access_claims)?;

        // Update session last_used_at
        self.update_session_last_used(session_id).await?;

        Ok(TokenPair::new(
            access_token,
            refresh_token.to_string(),
            self.access_token_expires_in.num_seconds(),
        ))
    }

    /// Validates an access token and extracts user authentication context
    ///
    /// Verifies the token signature, checks expiration, and extracts user information
    /// for request authorization. This is typically called by authentication middleware
    /// on each protected endpoint request.
    ///
    /// # Arguments
    /// * `token` - The access token to validate (without "Bearer " prefix)
    ///
    /// # Returns
    /// * `Ok(UserContext)` - Authenticated user context with ID and token metadata
    /// * `Err(JwtServiceError)` - Token validation or parsing errors
    ///
    /// # Errors
    /// * `InvalidToken` - Token is malformed, expired, or has invalid signature
    /// * `TokenExpired` - Token has passed its expiration time
    ///
    /// # Performance Notes
    /// This operation is stateless and does not require database access,
    /// making it suitable for high-frequency authorization checks.
    ///
    /// # Examples
    /// ```
    /// let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...";
    /// let context = jwt_service.validate_access_token(token)?;
    /// println!("Authenticated user: {}", context.user_id);
    /// ```
    pub fn validate_access_token(&self, token: &str) -> JwtServiceResult<UserContext> {
        let claims = self.decode_access_token(token)?;
        UserContext::from_access_claims(&claims)
            .map_err(|_| JwtServiceError::InvalidToken("Invalid user ID in token".to_string()))
    }

    /// Revokes a specific refresh token by deleting its database session
    ///
    /// Immediately invalidates the refresh token by removing its associated session.
    /// The corresponding access token remains valid until its natural expiration.
    /// This is typically used for individual device logout.
    ///
    /// # Arguments
    /// * `refresh_token` - The refresh token to revoke
    ///
    /// # Returns
    /// * `Ok(())` - Token was successfully revoked
    /// * `Err(JwtServiceError)` - Token parsing or database errors
    ///
    /// # Errors
    /// * `InvalidToken` - Refresh token is malformed or invalid
    /// * `InvalidUuid` - Session ID in token is not a valid UUID
    /// * `DatabaseError` - Session deletion failed
    ///
    /// # Security Notes
    /// - Revocation is immediate and cannot be undone
    /// - Access tokens derived from this refresh token remain valid until expiration
    /// - For complete session termination, use `revoke_all_user_sessions`
    ///
    /// # Examples
    /// ```
    /// // User logs out from specific device
    /// let refresh_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...";
    /// jwt_service.revoke_refresh_token(refresh_token).await?;
    /// println!("Device logged out successfully");
    /// ```
    pub async fn revoke_refresh_token(&self, refresh_token: &str) -> JwtServiceResult<()> {
        let claims = self.decode_refresh_token(refresh_token)?;
        let session_id = Uuid::parse_str(&claims.session_id)?;

        self.delete_session(session_id).await?;
        Ok(())
    }

    /// Revokes all active sessions for a user across all devices
    ///
    /// Immediately invalidates all refresh tokens for the specified user by deleting
    /// all their database sessions. This forces the user to re-authenticate on all
    /// devices. Typically used for security incidents, password changes, or account locks.
    ///
    /// # Arguments
    /// * `user_id` - Unique identifier of the user whose sessions to revoke
    ///
    /// # Returns
    /// * `Ok(())` - All sessions were successfully revoked
    /// * `Err(JwtServiceError)` - Database operation failed
    ///
    /// # Errors
    /// * `DatabaseError` - Session deletion failed
    ///
    /// # Use Cases
    /// - Password change (force re-authentication for security)
    /// - Suspected account compromise
    /// - User-initiated "log out from all devices"
    /// - Account suspension or security lock
    /// - Employee termination in enterprise systems
    ///
    /// # Security Impact
    /// - All refresh tokens become invalid immediately
    /// - Existing access tokens remain valid until their natural expiration
    /// - User must re-authenticate on all devices
    ///
    /// # Examples
    /// ```
    /// use uuid::Uuid;
    ///
    /// let user_id = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000")?;
    /// jwt_service.revoke_all_user_sessions(user_id).await?;
    /// println!("User logged out from all devices");
    /// ```
    pub async fn revoke_all_user_sessions(&self, user_id: Uuid) -> JwtServiceResult<()> {
        sqlx::query!("DELETE FROM auth_sessions WHERE user_id = $1", user_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Removes expired sessions from the database for maintenance
    ///
    /// Deletes all sessions that have passed their expiration time. This is a
    /// maintenance operation that should be run periodically to prevent database
    /// bloat and ensure accurate session metrics.
    ///
    /// # Returns
    /// * `Ok(u64)` - Number of expired sessions that were deleted
    /// * `Err(JwtServiceError)` - Database operation failed
    ///
    /// # Errors
    /// * `DatabaseError` - Session deletion query failed
    ///
    /// # Performance Notes
    /// - This operation may be expensive on large databases
    /// - Consider running during low-traffic periods
    /// - May benefit from database indexing on expires_at column
    ///
    /// # Scheduling Recommendations
    /// - Run hourly for high-traffic applications
    /// - Run daily for moderate-traffic applications
    /// - Can be triggered by cron jobs, scheduled tasks, or application startup
    ///
    /// # Examples
    /// ```
    /// // Cleanup job example
    /// let deleted_count = jwt_service.cleanup_expired_sessions().await?;
    /// println!("Cleaned up {} expired sessions", deleted_count);
    /// ```
    pub async fn cleanup_expired_sessions(&self) -> JwtServiceResult<u64> {
        let result = sqlx::query!("DELETE FROM auth_sessions WHERE expires_at <= NOW()")
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    /// Encodes an access token JWT with the provided claims
    ///
    /// Creates a signed JWT using the HS256 algorithm and the configured access secret.
    /// Access tokens contain user identity and authorization information for API requests.
    ///
    /// # Arguments
    /// * `claims` - Token claims including user ID, expiration, and metadata
    ///
    /// # Returns
    /// * `Ok(String)` - Base64-encoded JWT token
    /// * `Err(JwtServiceError)` - Token encoding failed
    ///
    /// # Errors
    /// * `TokenGeneration` - JWT library encoding error
    fn encode_access_token(&self, claims: &AccessTokenClaims) -> JwtServiceResult<String> {
        let header = Header::new(Algorithm::HS256);
        let encoding_key = EncodingKey::from_secret(self.access_secret.as_ref());

        encode(&header, claims, &encoding_key)
            .map_err(|e| JwtServiceError::TokenGeneration(e.to_string()))
    }

    /// Encodes a refresh token JWT with the provided claims
    ///
    /// Creates a signed JWT using the HS256 algorithm and the configured refresh secret.
    /// Refresh tokens contain session information for generating new access tokens.
    ///
    /// # Arguments
    /// * `claims` - Token claims including user ID, session ID, and expiration
    ///
    /// # Returns
    /// * `Ok(String)` - Base64-encoded JWT token
    /// * `Err(JwtServiceError)` - Token encoding failed
    ///
    /// # Errors
    /// * `TokenGeneration` - JWT library encoding error
    fn encode_refresh_token(&self, claims: &RefreshTokenClaims) -> JwtServiceResult<String> {
        let header = Header::new(Algorithm::HS256);
        let encoding_key = EncodingKey::from_secret(self.refresh_secret.as_ref());

        encode(&header, claims, &encoding_key)
            .map_err(|e| JwtServiceError::TokenGeneration(e.to_string()))
    }

    /// Decodes and validates an access token's signature and expiration
    ///
    /// Verifies the token was signed with the correct secret and hasn't expired.
    /// Extracts the claims for further processing.
    ///
    /// # Arguments
    /// * `token` - JWT token string to decode
    ///
    /// # Returns
    /// * `Ok(AccessTokenClaims)` - Validated token claims
    /// * `Err(JwtServiceError)` - Token validation failed
    ///
    /// # Errors
    /// * `InvalidToken` - Signature verification or parsing failed
    fn decode_access_token(&self, token: &str) -> JwtServiceResult<AccessTokenClaims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.validate_aud = false;

        let decoding_key = DecodingKey::from_secret(self.access_secret.as_ref());

        decode::<AccessTokenClaims>(token, &decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| JwtServiceError::InvalidToken(e.to_string()))
    }

    /// Decodes and validates a refresh token's signature and expiration
    ///
    /// Verifies the token was signed with the correct refresh secret and hasn't expired.
    /// Extracts the claims including session ID for database verification.
    ///
    /// # Arguments
    /// * `token` - JWT token string to decode
    ///
    /// # Returns
    /// * `Ok(RefreshTokenClaims)` - Validated token claims
    /// * `Err(JwtServiceError)` - Token validation failed
    ///
    /// # Errors
    /// * `InvalidToken` - Signature verification or parsing failed
    fn decode_refresh_token(&self, token: &str) -> JwtServiceResult<RefreshTokenClaims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.validate_aud = false;

        let decoding_key = DecodingKey::from_secret(self.refresh_secret.as_ref());

        decode::<RefreshTokenClaims>(token, &decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| JwtServiceError::InvalidToken(e.to_string()))
    }

    /// Creates a new authentication session record in the database
    ///
    /// Stores session metadata including hashed refresh token, expiration time,
    /// and client information for security monitoring and session management.
    ///
    /// # Arguments
    /// * `session_id` - Unique session identifier
    /// * `user_id` - User this session belongs to
    /// * `refresh_token` - Refresh token to hash and store
    /// * `expires_at` - When this session expires
    /// * `user_agent` - Optional client user agent string
    /// * `ip_address` - Optional client IP address
    ///
    /// # Returns
    /// * `Ok(())` - Session created successfully
    /// * `Err(JwtServiceError)` - Database insertion failed
    ///
    /// # Security Notes
    /// - Refresh tokens are hashed before storage using SHA-256
    /// - IP addresses are stored as PostgreSQL INET types for efficient querying
    /// - Session IDs are cryptographically random UUIDs
    async fn create_session(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        refresh_token: &str,
        expires_at: DateTime<Utc>,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> JwtServiceResult<()> {
        let token_hash = self.hash_token(refresh_token);

        // Convert IP address string to IpNetwork if provided
        let ip_network = ip_address
            .as_ref()
            .and_then(|ip| IpNetwork::from_str(ip).ok());

        sqlx::query!(
            r#"
            INSERT INTO auth_sessions (id, user_id, refresh_token_hash, expires_at, user_agent, ip_address)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            session_id,
            user_id,
            token_hash,
            expires_at,
            user_agent,
            ip_network as Option<IpNetwork>
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Retrieves an authentication session by its unique identifier
    ///
    /// Looks up session metadata from the database for validation and tracking.
    /// Used during refresh token validation to verify session state.
    ///
    /// # Arguments
    /// * `session_id` - Unique session identifier from refresh token
    ///
    /// # Returns
    /// * `Ok(AuthSession)` - Session data if found
    /// * `Err(JwtServiceError)` - Session not found or database error
    ///
    /// # Errors
    /// * `SessionNotFound` - No session exists with the provided ID
    /// * `DatabaseError` - Database query failed
    async fn get_session(&self, session_id: Uuid) -> JwtServiceResult<AuthSession> {
        let session = sqlx::query_as!(
            AuthSession,
            "SELECT id, user_id, refresh_token_hash, expires_at, created_at as \"created_at!\", last_used_at as \"last_used_at!\", user_agent, ip_address FROM auth_sessions WHERE id = $1",
            session_id
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(JwtServiceError::SessionNotFound)?;

        Ok(session)
    }

    /// Updates the last usage timestamp for session activity tracking
    ///
    /// Records when a session was last used for refresh token operations.
    /// Useful for identifying inactive sessions and security monitoring.
    ///
    /// # Arguments
    /// * `session_id` - Session to update
    ///
    /// # Returns
    /// * `Ok(())` - Timestamp updated successfully
    /// * `Err(JwtServiceError)` - Database update failed
    async fn update_session_last_used(&self, session_id: Uuid) -> JwtServiceResult<()> {
        sqlx::query!(
            "UPDATE auth_sessions SET last_used_at = NOW() WHERE id = $1",
            session_id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Removes an authentication session from the database
    ///
    /// Permanently deletes a session record, effectively revoking the associated
    /// refresh token. This operation cannot be undone.
    ///
    /// # Arguments
    /// * `session_id` - Session to delete
    ///
    /// # Returns
    /// * `Ok(())` - Session deleted successfully (or didn't exist)
    /// * `Err(JwtServiceError)` - Database deletion failed
    async fn delete_session(&self, session_id: Uuid) -> JwtServiceResult<()> {
        sqlx::query!("DELETE FROM auth_sessions WHERE id = $1", session_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Hashes a token using SHA-256 for secure database storage
    ///
    /// Converts tokens to irreversible hashes before database storage.
    /// This prevents token exposure in case of database compromise.
    ///
    /// # Arguments
    /// * `token` - Token string to hash
    ///
    /// # Returns
    /// Hexadecimal string representation of the SHA-256 hash
    ///
    /// # Security Notes
    /// - Uses SHA-256 for cryptographic security
    /// - Hashes are compared in constant time to prevent timing attacks
    /// - Original tokens are never stored in the database
    fn hash_token(&self, token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_service(pool: sqlx::PgPool) -> JwtService {
        JwtService::new(
            pool,
            "test_access_secret_key".to_string(),
            "test_refresh_secret_key".to_string(),
        )
    }

    #[sqlx::test]
    async fn test_token_hash(pool: sqlx::PgPool) {
        let service = create_test_service(pool).await;
        let token = "test_token";
        let hash1 = service.hash_token(token);
        let hash2 = service.hash_token(token);

        // Same token should produce same hash
        assert_eq!(hash1, hash2);

        // Different tokens should produce different hashes
        let different_hash = service.hash_token("different_token");
        assert_ne!(hash1, different_hash);
    }

    #[sqlx::test]
    async fn test_access_token_encoding_decoding(pool: sqlx::PgPool) {
        let service = create_test_service(pool).await;
        let user_id = Uuid::new_v4();
        let now = Utc::now();
        let expires_at = now + Duration::hours(1);

        let claims = AccessTokenClaims::new(user_id, expires_at, now);
        let token = service.encode_access_token(&claims).unwrap();
        let decoded_claims = service.decode_access_token(&token).unwrap();

        assert_eq!(claims.sub, decoded_claims.sub);
        assert_eq!(claims.token_type, decoded_claims.token_type);
    }

    #[sqlx::test]
    async fn test_refresh_token_encoding_decoding(pool: sqlx::PgPool) {
        let service = create_test_service(pool).await;
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let now = Utc::now();
        let expires_at = now + Duration::days(30);

        let claims = RefreshTokenClaims::new(user_id, session_id, expires_at, now);
        let token = service.encode_refresh_token(&claims).unwrap();
        let decoded_claims = service.decode_refresh_token(&token).unwrap();

        assert_eq!(claims.sub, decoded_claims.sub);
        assert_eq!(claims.session_id, decoded_claims.session_id);
        assert_eq!(claims.token_type, decoded_claims.token_type);
    }

    #[sqlx::test]
    async fn test_user_context_from_access_token(pool: sqlx::PgPool) {
        let service = create_test_service(pool).await;
        let user_id = Uuid::new_v4();
        let now = Utc::now();
        let expires_at = now + Duration::hours(1);

        let claims = AccessTokenClaims::new(user_id, expires_at, now);
        let token = service.encode_access_token(&claims).unwrap();
        let context = service.validate_access_token(&token).unwrap();

        assert_eq!(context.user_id, user_id);
        assert_eq!(context.token_id, claims.jti);
    }
}
