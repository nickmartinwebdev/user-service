//! Authentication Models
//!
//! Data structures for JWT authentication and session management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::ipnetwork::IpNetwork;
use uuid::Uuid;

/// Authentication session representation for database operations
///
/// This struct represents an active authentication session with refresh token management.
/// Sessions track user login state and enable secure token refresh flows.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthSession {
    /// Unique identifier for the session
    pub id: Uuid,

    /// Reference to the user who owns this session
    pub user_id: Uuid,

    /// Hashed refresh token (SHA-256 hash for security)
    pub refresh_token_hash: String,

    /// Timestamp when the session expires
    pub expires_at: DateTime<Utc>,

    /// Timestamp when the session was created
    pub created_at: DateTime<Utc>,

    /// Timestamp when the session was last used
    pub last_used_at: DateTime<Utc>,

    /// Optional client user agent string
    pub user_agent: Option<String>,

    /// Optional client IP address
    pub ip_address: Option<IpNetwork>,
}

/// JWT token pair containing access and refresh tokens
///
/// This structure is returned when a user successfully authenticates
/// or refreshes their tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    /// Short-lived access token for API authentication
    pub access_token: String,

    /// Long-lived refresh token for obtaining new access tokens
    pub refresh_token: String,

    /// Token type (always "Bearer" for JWT)
    pub token_type: String,

    /// Access token expiration time in seconds
    pub expires_in: i64,
}

impl TokenPair {
    /// Create a new token pair
    pub fn new(access_token: String, refresh_token: String, expires_in: i64) -> Self {
        Self {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in,
        }
    }
}

/// JWT claims structure for access tokens
///
/// Contains standard JWT claims plus custom claims for user identification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Subject - user ID
    pub sub: String,

    /// Expiration time (Unix timestamp)
    pub exp: i64,

    /// Issued at (Unix timestamp)
    pub iat: i64,

    /// JWT ID - unique token identifier
    pub jti: String,

    /// Token type (always "access" for access tokens)
    #[serde(rename = "type")]
    pub token_type: String,
}

impl AccessTokenClaims {
    /// Create new access token claims
    pub fn new(user_id: Uuid, expires_at: DateTime<Utc>, issued_at: DateTime<Utc>) -> Self {
        Self {
            sub: user_id.to_string(),
            exp: expires_at.timestamp(),
            iat: issued_at.timestamp(),
            jti: Uuid::new_v4().to_string(),
            token_type: "access".to_string(),
        }
    }
}

/// JWT claims structure for refresh tokens
///
/// Contains standard JWT claims plus custom claims for session management.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    /// Subject - user ID
    pub sub: String,

    /// Expiration time (Unix timestamp)
    pub exp: i64,

    /// Issued at (Unix timestamp)
    pub iat: i64,

    /// JWT ID - unique token identifier
    pub jti: String,

    /// Token type (always "refresh" for refresh tokens)
    #[serde(rename = "type")]
    pub token_type: String,

    /// Session ID this refresh token belongs to
    pub session_id: String,
}

impl RefreshTokenClaims {
    /// Create new refresh token claims
    pub fn new(
        user_id: Uuid,
        session_id: Uuid,
        expires_at: DateTime<Utc>,
        issued_at: DateTime<Utc>,
    ) -> Self {
        Self {
            sub: user_id.to_string(),
            exp: expires_at.timestamp(),
            iat: issued_at.timestamp(),
            jti: Uuid::new_v4().to_string(),
            token_type: "refresh".to_string(),
            session_id: session_id.to_string(),
        }
    }
}

/// User context extracted from JWT tokens
///
/// This structure contains user information extracted from validated JWT tokens
/// and is used throughout the application for authorization decisions.
#[derive(Debug, Clone)]
pub struct UserContext {
    /// User ID extracted from token subject
    pub user_id: Uuid,

    /// Token ID for tracking and revocation
    pub token_id: String,

    /// Token expiration time
    pub expires_at: DateTime<Utc>,
}

impl UserContext {
    /// Create user context from access token claims
    pub fn from_access_claims(claims: &AccessTokenClaims) -> Result<Self, uuid::Error> {
        Ok(Self {
            user_id: Uuid::parse_str(&claims.sub)?,
            token_id: claims.jti.clone(),
            expires_at: DateTime::from_timestamp(claims.exp, 0).unwrap_or_else(|| Utc::now()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_pair_creation() {
        let token_pair = TokenPair::new(
            "access_token".to_string(),
            "refresh_token".to_string(),
            3600,
        );

        assert_eq!(token_pair.access_token, "access_token");
        assert_eq!(token_pair.refresh_token, "refresh_token");
        assert_eq!(token_pair.token_type, "Bearer");
        assert_eq!(token_pair.expires_in, 3600);
    }

    #[test]
    fn test_access_token_claims_creation() {
        let user_id = Uuid::new_v4();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::hours(1);

        let claims = AccessTokenClaims::new(user_id, expires_at, now);

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.exp, expires_at.timestamp());
        assert_eq!(claims.iat, now.timestamp());
        assert_eq!(claims.token_type, "access");
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn test_refresh_token_claims_creation() {
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::days(30);

        let claims = RefreshTokenClaims::new(user_id, session_id, expires_at, now);

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.session_id, session_id.to_string());
        assert_eq!(claims.exp, expires_at.timestamp());
        assert_eq!(claims.iat, now.timestamp());
        assert_eq!(claims.token_type, "refresh");
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn test_user_context_from_access_claims() {
        let user_id = Uuid::new_v4();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::hours(1);

        let claims = AccessTokenClaims::new(user_id, expires_at, now);
        let context = UserContext::from_access_claims(&claims).unwrap();

        assert_eq!(context.user_id, user_id);
        assert_eq!(context.token_id, claims.jti);
        assert_eq!(context.expires_at.timestamp(), expires_at.timestamp());
    }
}
