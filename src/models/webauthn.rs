//! WebAuthn Models and Types
//!
//! This module contains all data structures related to WebAuthn/Passkey authentication,
//! including credential management, challenge handling, and request/response types.

use base64::prelude::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;
use webauthn_rs_proto::{PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions};

/// User credential record stored in the database
#[derive(Debug, Clone, Serialize)]
pub struct UserCredential {
    /// Unique credential record identifier
    pub id: Uuid,
    /// Reference to the user account
    pub user_id: Uuid,
    /// WebAuthn credential ID (base64url encoded for API responses)
    pub credential_id: String,
    /// User-friendly name for the credential
    pub credential_name: Option<String>,
    /// Additional authenticator-specific data
    pub authenticator_data: Option<serde_json::Value>,
    /// Credential registration timestamp
    pub created_at: DateTime<Utc>,
    /// Last authentication timestamp
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Raw user credential data as stored in the database
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserCredentialRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub credential_name: Option<String>,
    pub authenticator_data: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl From<UserCredentialRow> for UserCredential {
    fn from(row: UserCredentialRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            credential_id: base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(&row.credential_id),
            credential_name: row.credential_name,
            authenticator_data: row.authenticator_data,
            created_at: row.created_at,
            last_used_at: row.last_used_at,
        }
    }
}

/// WebAuthn challenge record stored in the database
#[derive(Debug, sqlx::FromRow)]
pub struct WebAuthnChallenge {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub challenge: Vec<u8>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub user_handle: Option<Vec<u8>>,
}

/// Type of WebAuthn challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeType {
    Registration,
    Authentication,
}

impl From<ChallengeType> for String {
    fn from(challenge_type: ChallengeType) -> Self {
        match challenge_type {
            ChallengeType::Registration => "registration".to_string(),
            ChallengeType::Authentication => "authentication".to_string(),
        }
    }
}

/// Request to begin passkey registration
#[derive(Debug, Deserialize, Validate)]
pub struct PasskeyRegistrationBeginRequest {
    /// Optional user-friendly name for the credential
    #[validate(length(min = 1, max = 255))]
    pub credential_name: Option<String>,
}

/// Response for passkey registration begin
#[derive(Debug, Serialize)]
pub struct PasskeyRegistrationBeginResponse {
    /// WebAuthn credential creation options
    #[serde(flatten)]
    pub options: PublicKeyCredentialCreationOptions,
}

/// Request to finish passkey registration
#[derive(Debug, Deserialize, Validate)]
pub struct PasskeyRegistrationFinishRequest {
    /// WebAuthn registration credential response
    pub credential: serde_json::Value,
    /// Optional user-friendly name for the credential
    #[validate(length(min = 1, max = 255))]
    pub credential_name: Option<String>,
}

/// Response for passkey registration finish
#[derive(Debug, Serialize)]
pub struct PasskeyRegistrationFinishResponse {
    /// Success message
    pub message: String,
    /// Created credential information
    pub credential: UserCredential,
}

/// Request to begin passkey authentication (no user context)
#[derive(Debug, Deserialize)]
pub struct PasskeyAuthenticationBeginRequest {
    /// Optional email for user identification (for UX)
    pub email: Option<String>,
}

/// Response for passkey authentication begin
#[derive(Debug, Serialize)]
pub struct PasskeyAuthenticationBeginResponse {
    /// WebAuthn credential request options
    #[serde(flatten)]
    pub options: PublicKeyCredentialRequestOptions,
}

/// Request to finish passkey authentication
#[derive(Debug, Deserialize, Validate)]
pub struct PasskeyAuthenticationFinishRequest {
    /// WebAuthn authentication credential response
    pub credential: serde_json::Value,
}

/// Response for passkey authentication finish
#[derive(Debug, Serialize)]
pub struct PasskeyAuthenticationFinishResponse {
    /// JWT access token
    pub access_token: String,
    /// JWT refresh token
    pub refresh_token: String,
    /// Token type (always "Bearer")
    pub token_type: String,
    /// Access token expiration time in seconds
    pub expires_in: i64,
    /// Authenticated user information
    pub user: crate::models::user::User,
}

/// Request to list user's passkeys
#[derive(Debug, Deserialize)]
pub struct ListPasskeysRequest {
    /// Optional filter by credential name
    pub name_filter: Option<String>,
}

/// Response for listing user's passkeys
#[derive(Debug, Serialize)]
pub struct ListPasskeysResponse {
    /// List of user credentials
    pub credentials: Vec<UserCredential>,
    /// Total number of credentials
    pub total: usize,
}

/// Request to delete a passkey
#[derive(Debug, Deserialize)]
pub struct DeletePasskeyRequest {
    /// Credential ID to delete
    pub credential_id: String,
}

/// Response for deleting a passkey
#[derive(Debug, Serialize)]
pub struct DeletePasskeyResponse {
    /// Success message
    pub message: String,
    /// Deleted credential ID
    pub credential_id: String,
}

/// Request to update passkey name
#[derive(Debug, Deserialize, Validate)]
pub struct UpdatePasskeyRequest {
    /// New credential name
    #[validate(length(min = 1, max = 255))]
    pub credential_name: String,
}

/// Response for updating passkey name
#[derive(Debug, Serialize)]
pub struct UpdatePasskeyResponse {
    /// Success message
    pub message: String,
    /// Updated credential information
    pub credential: UserCredential,
}

/// WebAuthn configuration for the service
#[derive(Debug, Clone)]
pub struct WebAuthnConfig {
    /// Relying party ID (domain name)
    pub rp_id: String,
    /// Relying party name (human-readable service name)
    pub rp_name: String,
    /// Relying party origin (protocol + domain + port)
    pub rp_origin: String,
    /// Challenge timeout in seconds (default: 60 seconds)
    pub challenge_timeout_seconds: u32,
    /// Whether to require user verification (default: false)
    pub require_user_verification: bool,
    /// Allowed algorithms for credential creation
    pub allowed_algorithms: Vec<i32>,
}

impl WebAuthnConfig {
    /// Create WebAuthn configuration from environment variables
    pub fn from_env() -> Result<Self, std::env::VarError> {
        let rp_id = std::env::var("WEBAUTHN_RP_ID")?;
        let rp_name =
            std::env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| "User Service".to_string());
        let rp_origin = std::env::var("WEBAUTHN_RP_ORIGIN")?;

        let challenge_timeout_seconds = std::env::var("WEBAUTHN_CHALLENGE_TIMEOUT_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60);

        let require_user_verification = std::env::var("WEBAUTHN_REQUIRE_USER_VERIFICATION")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(false);

        // Default to ES256 (-7) and RS256 (-257)
        let allowed_algorithms = std::env::var("WEBAUTHN_ALLOWED_ALGORITHMS")
            .ok()
            .and_then(|s| {
                s.split(',')
                    .map(|alg| alg.trim().parse::<i32>())
                    .collect::<Result<Vec<_>, _>>()
                    .ok()
            })
            .unwrap_or_else(|| vec![-7, -257]);

        Ok(Self {
            rp_id,
            rp_name,
            rp_origin,
            challenge_timeout_seconds,
            require_user_verification,
            allowed_algorithms,
        })
    }

    /// Create a default configuration for development
    pub fn default_dev() -> Self {
        Self {
            rp_id: "localhost".to_string(),
            rp_name: "User Service Dev".to_string(),
            rp_origin: "http://localhost:3000".to_string(),
            challenge_timeout_seconds: 60,
            require_user_verification: false,
            allowed_algorithms: vec![-7, -257], // ES256, RS256
        }
    }
}

/// WebAuthn credential creation data for internal use
#[derive(Debug, Clone)]
pub struct CredentialCreationData {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub user_handle: Vec<u8>,
    pub credential_name: Option<String>,
    pub authenticator_data: Option<serde_json::Value>,
}

/// WebAuthn authentication verification data for internal use
#[derive(Debug, Clone)]
pub struct AuthenticationVerificationData {
    pub credential_id: Vec<u8>,
    pub user_id: Uuid,
    pub new_sign_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_type_conversion() {
        assert_eq!(String::from(ChallengeType::Registration), "registration");
        assert_eq!(
            String::from(ChallengeType::Authentication),
            "authentication"
        );
    }

    #[test]
    fn test_webauthn_config_default_dev() {
        let config = WebAuthnConfig::default_dev();
        assert_eq!(config.rp_id, "localhost");
        assert_eq!(config.rp_name, "User Service Dev");
        assert_eq!(config.rp_origin, "http://localhost:3000");
        assert_eq!(config.challenge_timeout_seconds, 60);
        assert!(!config.require_user_verification);
        assert_eq!(config.allowed_algorithms, vec![-7, -257]);
    }

    #[test]
    fn test_user_credential_from_row() {
        let row = UserCredentialRow {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            credential_id: vec![1, 2, 3, 4],
            public_key: vec![5, 6, 7, 8],
            sign_count: 42,
            credential_name: Some("Test Credential".to_string()),
            authenticator_data: Some(serde_json::json!({"test": "data"})),
            created_at: Utc::now(),
            last_used_at: None,
        };

        let credential = UserCredential::from(row.clone());
        assert_eq!(credential.id, row.id);
        assert_eq!(credential.user_id, row.user_id);
        assert_eq!(credential.credential_name, row.credential_name);
        assert_eq!(credential.authenticator_data, row.authenticator_data);
        assert_eq!(credential.created_at, row.created_at);
        assert_eq!(credential.last_used_at, row.last_used_at);

        // Check base64url encoding
        let expected_id = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(&row.credential_id);
        assert_eq!(credential.credential_id, expected_id);
    }
}
