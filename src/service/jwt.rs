//! JWT Authentication Service
//!
//! Provides JWT token generation, validation, and session management functionality.

use crate::models::{AccessTokenClaims, AuthSession, RefreshTokenClaims, TokenPair, UserContext};
use crate::utils::error::{ServiceError, ServiceResult};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use sha2::{Digest, Sha256};
use sqlx::types::ipnetwork::IpNetwork;
use sqlx::PgPool;
use std::str::FromStr;
use uuid::Uuid;

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
    /// Create a new JWT service instance
    pub fn new(pool: PgPool, access_secret: String, refresh_secret: String) -> Self {
        Self {
            pool,
            access_secret,
            refresh_secret,
            access_token_expires_in: Duration::hours(1),
            refresh_token_expires_in: Duration::days(30),
        }
    }

    /// Create a new JWT service with custom token expiration times
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

    /// Generate a new access and refresh token pair for a user
    pub async fn generate_token_pair(
        &self,
        user_id: Uuid,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> ServiceResult<TokenPair> {
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

    /// Refresh an access token using a valid refresh token
    pub async fn refresh_access_token(&self, refresh_token: &str) -> ServiceResult<TokenPair> {
        // Validate refresh token
        let refresh_claims = self.decode_refresh_token(refresh_token)?;
        let session_id = Uuid::parse_str(&refresh_claims.session_id)
            .map_err(|_| ServiceError::InvalidToken("Invalid session ID in token".into()))?;

        // Verify session exists and is valid
        let session = self.get_session(session_id).await?;
        if session.expires_at <= Utc::now() {
            self.delete_session(session_id).await?;
            return Err(ServiceError::InvalidToken("Refresh token expired".into()));
        }

        // Verify refresh token hash matches stored hash
        let token_hash = self.hash_token(refresh_token);
        if session.refresh_token_hash != token_hash {
            return Err(ServiceError::InvalidToken("Invalid refresh token".into()));
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

    /// Validate an access token and extract user context
    pub fn validate_access_token(&self, token: &str) -> ServiceResult<UserContext> {
        let claims = self.decode_access_token(token)?;
        UserContext::from_access_claims(&claims)
            .map_err(|_| ServiceError::InvalidToken("Invalid user ID in token".into()))
    }

    /// Revoke a refresh token by deleting its session
    pub async fn revoke_refresh_token(&self, refresh_token: &str) -> ServiceResult<()> {
        let claims = self.decode_refresh_token(refresh_token)?;
        let session_id = Uuid::parse_str(&claims.session_id)
            .map_err(|_| ServiceError::InvalidToken("Invalid session ID in token".into()))?;

        self.delete_session(session_id).await?;
        Ok(())
    }

    /// Revoke all sessions for a user (logout from all devices)
    pub async fn revoke_all_user_sessions(&self, user_id: Uuid) -> ServiceResult<()> {
        sqlx::query!("DELETE FROM auth_sessions WHERE user_id = $1", user_id)
            .execute(&self.pool)
            .await
            .map_err(ServiceError::Database)?;

        Ok(())
    }

    /// Clean up expired sessions from the database
    pub async fn cleanup_expired_sessions(&self) -> ServiceResult<u64> {
        let result = sqlx::query!("DELETE FROM auth_sessions WHERE expires_at <= NOW()")
            .execute(&self.pool)
            .await
            .map_err(ServiceError::Database)?;

        Ok(result.rows_affected())
    }

    /// Encode an access token with the given claims
    fn encode_access_token(&self, claims: &AccessTokenClaims) -> ServiceResult<String> {
        let header = Header::new(Algorithm::HS256);
        let encoding_key = EncodingKey::from_secret(self.access_secret.as_ref());

        encode(&header, claims, &encoding_key)
            .map_err(|e| ServiceError::TokenGeneration(e.to_string()))
    }

    /// Encode a refresh token with the given claims
    fn encode_refresh_token(&self, claims: &RefreshTokenClaims) -> ServiceResult<String> {
        let header = Header::new(Algorithm::HS256);
        let encoding_key = EncodingKey::from_secret(self.refresh_secret.as_ref());

        encode(&header, claims, &encoding_key)
            .map_err(|e| ServiceError::TokenGeneration(e.to_string()))
    }

    /// Decode and validate an access token
    fn decode_access_token(&self, token: &str) -> ServiceResult<AccessTokenClaims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.validate_aud = false;

        let decoding_key = DecodingKey::from_secret(self.access_secret.as_ref());

        decode::<AccessTokenClaims>(token, &decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| ServiceError::InvalidToken(e.to_string()))
    }

    /// Decode and validate a refresh token
    fn decode_refresh_token(&self, token: &str) -> ServiceResult<RefreshTokenClaims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.validate_aud = false;

        let decoding_key = DecodingKey::from_secret(self.refresh_secret.as_ref());

        decode::<RefreshTokenClaims>(token, &decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| ServiceError::InvalidToken(e.to_string()))
    }

    /// Create a new authentication session in the database
    async fn create_session(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        refresh_token: &str,
        expires_at: DateTime<Utc>,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> ServiceResult<()> {
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
        .await
        .map_err(ServiceError::Database)?;

        Ok(())
    }

    /// Get an authentication session by ID
    async fn get_session(&self, session_id: Uuid) -> ServiceResult<AuthSession> {
        let session = sqlx::query_as!(
            AuthSession,
            "SELECT id, user_id, refresh_token_hash, expires_at, created_at as \"created_at!\", last_used_at as \"last_used_at!\", user_agent, ip_address FROM auth_sessions WHERE id = $1",
            session_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(ServiceError::Database)?
        .ok_or_else(|| ServiceError::InvalidToken("Session not found".into()))?;

        Ok(session)
    }

    /// Update the last_used_at timestamp for a session
    async fn update_session_last_used(&self, session_id: Uuid) -> ServiceResult<()> {
        sqlx::query!(
            "UPDATE auth_sessions SET last_used_at = NOW() WHERE id = $1",
            session_id
        )
        .execute(&self.pool)
        .await
        .map_err(ServiceError::Database)?;

        Ok(())
    }

    /// Delete an authentication session
    async fn delete_session(&self, session_id: Uuid) -> ServiceResult<()> {
        sqlx::query!("DELETE FROM auth_sessions WHERE id = $1", session_id)
            .execute(&self.pool)
            .await
            .map_err(ServiceError::Database)?;

        Ok(())
    }

    /// Hash a token using SHA-256 for secure storage
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
