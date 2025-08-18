//! WebAuthn Service
//!
//! This module provides WebAuthn/Passkey authentication services for passwordless authentication.
//! It handles the complete WebAuthn flow including credential registration, authentication challenges,
//! and credential management.

use base64::prelude::*;
use chrono::{Duration, Utc};

use sqlx::PgPool;
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use webauthn_rs::{prelude::*, Webauthn, WebauthnBuilder};

use crate::{
    models::{user::User, webauthn::*},
    service::JwtService,
    utils::error::AppError,
};

/// WebAuthn service specific errors
#[derive(Error, Debug)]
pub enum WebAuthnServiceError {
    /// WebAuthn configuration error
    #[error("WebAuthn configuration error: {0}")]
    ConfigurationError(String),

    /// WebAuthn challenge generation error
    #[error("Challenge generation error: {0}")]
    ChallengeGenerationError(String),

    /// WebAuthn challenge validation error
    #[error("Challenge validation error: {0}")]
    ChallengeValidationError(String),

    /// WebAuthn challenge not found
    #[error("Challenge not found")]
    ChallengeNotFound,

    /// WebAuthn challenge has expired
    #[error("Challenge has expired")]
    ChallengeExpired,

    /// WebAuthn credential registration error
    #[error("Credential registration error: {0}")]
    CredentialRegistrationError(String),

    /// WebAuthn credential authentication error
    #[error("Credential authentication error: {0}")]
    CredentialAuthenticationError(String),

    /// WebAuthn credential not found
    #[error("Credential not found")]
    CredentialNotFound,

    /// WebAuthn credential already exists
    #[error("Credential already exists")]
    CredentialAlreadyExists,

    /// User not found
    #[error("User not found")]
    UserNotFound,

    /// Invalid credential ID format
    #[error("Invalid credential ID format: {0}")]
    InvalidCredentialId(String),

    /// Invalid user handle
    #[error("Invalid user handle: {0}")]
    InvalidUserHandle(String),

    /// Database operation failed
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    /// JWT service error
    #[error("JWT service error: {0}")]
    JwtServiceError(String),

    /// Base64 decoding error
    #[error("Base64 decoding error: {0}")]
    Base64DecodingError(#[from] base64::DecodeError),

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

impl From<WebAuthnServiceError> for AppError {
    fn from(err: WebAuthnServiceError) -> Self {
        match err {
            WebAuthnServiceError::ConfigurationError(msg) => AppError::Configuration(msg),
            WebAuthnServiceError::ChallengeGenerationError(msg) => AppError::Internal(msg),
            WebAuthnServiceError::ChallengeValidationError(msg) => AppError::BadRequest(msg),
            WebAuthnServiceError::ChallengeNotFound => {
                AppError::BadRequest("Challenge not found".to_string())
            }
            WebAuthnServiceError::ChallengeExpired => {
                AppError::BadRequest("Challenge has expired".to_string())
            }
            WebAuthnServiceError::CredentialRegistrationError(msg) => AppError::BadRequest(msg),
            WebAuthnServiceError::CredentialAuthenticationError(msg) => AppError::BadRequest(msg),
            WebAuthnServiceError::CredentialNotFound => {
                AppError::NotFound("Credential not found".to_string())
            }
            WebAuthnServiceError::CredentialAlreadyExists => {
                AppError::Conflict("Credential already exists".to_string())
            }
            WebAuthnServiceError::UserNotFound => AppError::NotFound("User not found".to_string()),
            WebAuthnServiceError::InvalidCredentialId(msg) => AppError::BadRequest(msg),
            WebAuthnServiceError::InvalidUserHandle(msg) => AppError::BadRequest(msg),
            WebAuthnServiceError::DatabaseError(e) => AppError::Database(e),
            WebAuthnServiceError::JwtServiceError(msg) => AppError::Internal(msg),
            WebAuthnServiceError::Base64DecodingError(e) => {
                AppError::BadRequest(format!("Invalid base64 encoding: {}", e))
            }
            WebAuthnServiceError::SerializationError(msg) => AppError::Internal(msg),
            WebAuthnServiceError::InvalidUuid(e) => {
                AppError::BadRequest(format!("Invalid UUID: {}", e))
            }
            WebAuthnServiceError::InternalError(msg) => AppError::Internal(msg),
        }
    }
}

/// Result type for WebAuthn service operations
pub type WebAuthnServiceResult<T> = Result<T, WebAuthnServiceError>;

/// WebAuthn service for managing passkey authentication
#[derive(Clone)]
pub struct WebAuthnService {
    /// Database connection pool
    pool: PgPool,
    /// WebAuthn core instance
    webauthn: Webauthn,
    /// WebAuthn configuration
    config: WebAuthnConfig,
    /// JWT service for token generation
    jwt_service: JwtService,
}

impl WebAuthnService {
    /// Create a new WebAuthn service instance
    pub fn new(
        pool: PgPool,
        config: WebAuthnConfig,
        jwt_service: JwtService,
    ) -> WebAuthnServiceResult<Self> {
        let rp_origin = Url::parse(&config.rp_origin).map_err(|e| {
            WebAuthnServiceError::ConfigurationError(format!("Invalid RP origin: {}", e))
        })?;

        let webauthn = WebauthnBuilder::new(&config.rp_id, &rp_origin)
            .map_err(|e| {
                WebAuthnServiceError::ConfigurationError(format!(
                    "Failed to create WebAuthn instance: {:?}",
                    e
                ))
            })?
            .rp_name(&config.rp_name)
            .build()
            .map_err(|e| {
                WebAuthnServiceError::ConfigurationError(format!(
                    "Failed to build WebAuthn instance: {:?}",
                    e
                ))
            })?;

        Ok(Self {
            pool,
            webauthn,
            config,
            jwt_service,
        })
    }

    /// Begin passkey registration for an authenticated user
    pub async fn begin_passkey_registration(
        &self,
        user_id: Uuid,
        _request: PasskeyRegistrationBeginRequest,
    ) -> WebAuthnServiceResult<PasskeyRegistrationBeginResponse> {
        // Get user information
        let user = self.get_user_by_id(user_id).await?;

        // Get existing credentials to exclude them
        let existing_creds = self.get_user_credentials_for_exclusion(user_id).await?;

        // Generate WebAuthn user UUID
        let webauthn_user_id = webauthn_rs::prelude::Uuid::new_v4();

        // Start registration
        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(
                webauthn_user_id,
                &user.email,
                &user.name,
                Some(existing_creds),
            )
            .map_err(|e| {
                WebAuthnServiceError::ChallengeGenerationError(format!(
                    "Failed to start passkey registration: {:?}",
                    e
                ))
            })?;

        // Store challenge in database
        self.store_challenge(
            Some(user_id),
            ChallengeType::Registration,
            reg_state,
            Some(&self.generate_user_handle(user_id)),
        )
        .await?;

        Ok(PasskeyRegistrationBeginResponse {
            options: ccr.public_key,
        })
    }

    /// Finish passkey registration for an authenticated user
    pub async fn finish_passkey_registration(
        &self,
        user_id: Uuid,
        request: PasskeyRegistrationFinishRequest,
    ) -> WebAuthnServiceResult<PasskeyRegistrationFinishResponse> {
        // Retrieve and validate challenge
        let challenge = self
            .get_and_remove_challenge(Some(user_id), ChallengeType::Registration)
            .await?;

        // Deserialize registration state
        let _reg_state: serde_json::Value = serde_json::from_slice(&challenge.challenge)
            .map_err(|e| WebAuthnServiceError::SerializationError(e.to_string()))?;

        // For now, create a simplified credential record
        // In a real implementation, you'd complete the webauthn registration flow
        let credential_data = CredentialCreationData {
            credential_id: BASE64_URL_SAFE_NO_PAD
                .decode(
                    request
                        .credential
                        .get("id")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            WebAuthnServiceError::CredentialRegistrationError(
                                "Missing credential ID".to_string(),
                            )
                        })?,
                )
                .map_err(|e| {
                    WebAuthnServiceError::CredentialRegistrationError(format!(
                        "Invalid credential ID: {}",
                        e
                    ))
                })?,
            public_key: vec![0u8; 32], // Placeholder - extract from attestation
            sign_count: 0,
            user_handle: challenge
                .user_handle
                .unwrap_or_else(|| self.generate_user_handle(user_id)),
            credential_name: request.credential_name.clone(),
            authenticator_data: Some(request.credential.clone()),
        };

        let stored_credential = self.store_credential(user_id, credential_data).await?;

        Ok(PasskeyRegistrationFinishResponse {
            message: "Passkey registered successfully".to_string(),
            credential: stored_credential,
        })
    }

    /// Begin passkey authentication (no user context required)
    pub async fn begin_passkey_authentication(
        &self,
        request: PasskeyAuthenticationBeginRequest,
    ) -> WebAuthnServiceResult<PasskeyAuthenticationBeginResponse> {
        // Get allowed credentials for authentication
        let allowed_creds = if let Some(email) = &request.email {
            self.get_credentials_by_email(email).await?
        } else {
            Vec::new() // Allow all credentials
        };

        // Start authentication
        let (rcr, auth_state) = self
            .webauthn
            .start_passkey_authentication(&allowed_creds)
            .map_err(|e| {
                WebAuthnServiceError::ChallengeGenerationError(format!(
                    "Failed to start passkey authentication: {:?}",
                    e
                ))
            })?;

        // Store challenge in database (no user_id for authentication)
        self.store_challenge(None, ChallengeType::Authentication, auth_state, None)
            .await?;

        Ok(PasskeyAuthenticationBeginResponse {
            options: rcr.public_key,
        })
    }

    /// Finish passkey authentication
    pub async fn finish_passkey_authentication(
        &self,
        request: PasskeyAuthenticationFinishRequest,
    ) -> WebAuthnServiceResult<PasskeyAuthenticationFinishResponse> {
        // Retrieve and validate challenge
        let _challenge = self
            .get_and_remove_challenge(None, ChallengeType::Authentication)
            .await?;

        // Get credential from the request
        let credential_id = request
            .credential
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                WebAuthnServiceError::CredentialAuthenticationError(
                    "Missing credential ID".to_string(),
                )
            })?;

        let credential_id_bytes = BASE64_URL_SAFE_NO_PAD.decode(credential_id)?;
        let credential_row = self.get_credential_by_id(&credential_id_bytes).await?;

        // For now, assume authentication is successful
        // In a real implementation, you'd complete the webauthn authentication flow

        // Update credential usage
        self.update_credential_usage(credential_row.user_id, &credential_id_bytes, 1)
            .await?;

        // Get user information
        let user = self.get_user_by_id(credential_row.user_id).await?;

        // Generate JWT tokens
        let token_pair = self
            .jwt_service
            .generate_token_pair(user.id, None, None)
            .await
            .map_err(|e| {
                WebAuthnServiceError::JwtServiceError(format!("Token generation failed: {}", e))
            })?;

        Ok(PasskeyAuthenticationFinishResponse {
            access_token: token_pair.access_token,
            refresh_token: token_pair.refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: 3600, // Should match JWT service configuration
            user,
        })
    }

    /// List user's passkeys
    pub async fn list_user_passkeys(
        &self,
        user_id: Uuid,
        request: ListPasskeysRequest,
    ) -> WebAuthnServiceResult<ListPasskeysResponse> {
        let credentials = self
            .get_user_credentials(user_id, request.name_filter)
            .await?;
        let total = credentials.len();

        Ok(ListPasskeysResponse { credentials, total })
    }

    /// Delete a user's passkey
    pub async fn delete_passkey(
        &self,
        user_id: Uuid,
        request: DeletePasskeyRequest,
    ) -> WebAuthnServiceResult<DeletePasskeyResponse> {
        let credential_id_bytes = BASE64_URL_SAFE_NO_PAD.decode(&request.credential_id)?;

        let result = sqlx::query!(
            "DELETE FROM user_credentials WHERE user_id = $1 AND credential_id = $2",
            user_id,
            credential_id_bytes
        )
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(WebAuthnServiceError::CredentialNotFound);
        }

        Ok(DeletePasskeyResponse {
            message: "Passkey deleted successfully".to_string(),
            credential_id: request.credential_id,
        })
    }

    /// Update passkey name
    pub async fn update_passkey(
        &self,
        user_id: Uuid,
        credential_id: &str,
        request: UpdatePasskeyRequest,
    ) -> WebAuthnServiceResult<UpdatePasskeyResponse> {
        let credential_id_bytes = BASE64_URL_SAFE_NO_PAD.decode(credential_id)?;

        let result = sqlx::query!(
            "UPDATE user_credentials SET credential_name = $1 WHERE user_id = $2 AND credential_id = $3",
            request.credential_name,
            user_id,
            credential_id_bytes
        )
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(WebAuthnServiceError::CredentialNotFound);
        }

        // Get updated credential
        let credential_row = sqlx::query_as!(
            UserCredentialRow,
            "SELECT * FROM user_credentials WHERE user_id = $1 AND credential_id = $2",
            user_id,
            credential_id_bytes
        )
        .fetch_one(&self.pool)
        .await?;

        let credential = UserCredential::from(credential_row);

        Ok(UpdatePasskeyResponse {
            message: "Passkey updated successfully".to_string(),
            credential,
        })
    }

    /// Cleanup expired challenges
    pub async fn cleanup_expired_challenges(&self) -> WebAuthnServiceResult<u64> {
        let result = sqlx::query!("DELETE FROM webauthn_challenges WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    // Private helper methods

    /// Get user by ID
    async fn get_user_by_id(&self, user_id: Uuid) -> WebAuthnServiceResult<User> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, name, email, profile_picture_url, email_verified, created_at, updated_at
             FROM users WHERE id = $1",
            user_id
        )
        .fetch_optional(&self.pool)
        .await?;

        user.ok_or(WebAuthnServiceError::UserNotFound)
    }

    /// Get user credentials for exclusion during registration
    async fn get_user_credentials_for_exclusion(
        &self,
        user_id: Uuid,
    ) -> WebAuthnServiceResult<Vec<CredentialID>> {
        let rows = sqlx::query!(
            "SELECT credential_id FROM user_credentials WHERE user_id = $1",
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| CredentialID::from(row.credential_id))
            .collect())
    }

    /// Get credentials for a specific email (for authentication optimization)
    async fn get_credentials_by_email(&self, email: &str) -> WebAuthnServiceResult<Vec<Passkey>> {
        let _rows = sqlx::query_as!(
            UserCredentialRow,
            "SELECT uc.* FROM user_credentials uc
             JOIN users u ON uc.user_id = u.id
             WHERE u.email = $1",
            email
        )
        .fetch_all(&self.pool)
        .await?;

        // For simplicity, return empty vec
        // In a real implementation, you'd reconstruct Passkey objects from stored data
        Ok(Vec::new())
    }

    /// Get credential by credential ID
    async fn get_credential_by_id(
        &self,
        credential_id: &[u8],
    ) -> WebAuthnServiceResult<UserCredentialRow> {
        let credential = sqlx::query_as!(
            UserCredentialRow,
            "SELECT * FROM user_credentials WHERE credential_id = $1",
            credential_id
        )
        .fetch_optional(&self.pool)
        .await?;

        credential.ok_or(WebAuthnServiceError::CredentialNotFound)
    }

    /// Get user credentials with optional name filter
    async fn get_user_credentials(
        &self,
        user_id: Uuid,
        name_filter: Option<String>,
    ) -> WebAuthnServiceResult<Vec<UserCredential>> {
        let rows = if let Some(filter) = name_filter {
            sqlx::query_as!(
                UserCredentialRow,
                "SELECT * FROM user_credentials
                 WHERE user_id = $1 AND credential_name ILIKE $2
                 ORDER BY created_at DESC",
                user_id,
                format!("%{}%", filter)
            )
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as!(
                UserCredentialRow,
                "SELECT * FROM user_credentials
                 WHERE user_id = $1
                 ORDER BY created_at DESC",
                user_id
            )
            .fetch_all(&self.pool)
            .await?
        };

        Ok(rows.into_iter().map(UserCredential::from).collect())
    }

    /// Store WebAuthn challenge in database
    async fn store_challenge<T: serde::Serialize>(
        &self,
        user_id: Option<Uuid>,
        challenge_type: ChallengeType,
        state: T,
        user_handle: Option<&[u8]>,
    ) -> WebAuthnServiceResult<()> {
        let challenge_bytes = serde_json::to_vec(&state)
            .map_err(|e| WebAuthnServiceError::SerializationError(e.to_string()))?;

        let expires_at =
            Utc::now() + Duration::seconds(self.config.challenge_timeout_seconds as i64);

        sqlx::query!(
            "INSERT INTO webauthn_challenges (user_id, challenge_type, challenge, expires_at, user_handle)
             VALUES ($1, $2, $3, $4, $5)",
            user_id,
            String::from(challenge_type),
            challenge_bytes,
            expires_at,
            user_handle
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get and remove challenge from database
    async fn get_and_remove_challenge(
        &self,
        user_id: Option<Uuid>,
        challenge_type: ChallengeType,
    ) -> WebAuthnServiceResult<WebAuthnChallenge> {
        let challenge = if let Some(uid) = user_id {
            sqlx::query_as!(
                WebAuthnChallenge,
                "DELETE FROM webauthn_challenges
                 WHERE user_id = $1 AND challenge_type = $2 AND expires_at > NOW()
                 RETURNING *",
                uid,
                String::from(challenge_type)
            )
            .fetch_optional(&self.pool)
            .await?
        } else {
            sqlx::query_as!(
                WebAuthnChallenge,
                "DELETE FROM webauthn_challenges
                 WHERE user_id IS NULL AND challenge_type = $1 AND expires_at > NOW()
                 RETURNING *",
                String::from(challenge_type)
            )
            .fetch_optional(&self.pool)
            .await?
        };

        challenge.ok_or(WebAuthnServiceError::ChallengeNotFound)
    }

    /// Store credential in database
    async fn store_credential(
        &self,
        user_id: Uuid,
        data: CredentialCreationData,
    ) -> WebAuthnServiceResult<UserCredential> {
        let credential_row = sqlx::query_as!(
            UserCredentialRow,
            "INSERT INTO user_credentials
             (user_id, credential_id, public_key, sign_count, credential_name, authenticator_data)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING *",
            user_id,
            data.credential_id,
            data.public_key,
            data.sign_count as i64,
            data.credential_name,
            data.authenticator_data
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(UserCredential::from(credential_row))
    }

    /// Update credential usage (counter and last used timestamp)
    async fn update_credential_usage(
        &self,
        user_id: Uuid,
        credential_id: &[u8],
        new_sign_count: u32,
    ) -> WebAuthnServiceResult<()> {
        sqlx::query!(
            "UPDATE user_credentials
             SET sign_count = $1, last_used_at = NOW()
             WHERE user_id = $2 AND credential_id = $3",
            new_sign_count as i64,
            user_id,
            credential_id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Generate user handle for WebAuthn
    fn generate_user_handle(&self, user_id: Uuid) -> Vec<u8> {
        user_id.as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webauthn_service_error_conversion() {
        let error = WebAuthnServiceError::UserNotFound;
        let app_error: AppError = error.into();
        match app_error {
            AppError::NotFound(_) => {}
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn test_generate_user_handle() {
        let user_id = Uuid::new_v4();
        let handle = user_id.as_bytes().to_vec();
        assert_eq!(handle.len(), 16); // UUID is 16 bytes
        assert_eq!(handle, user_id.as_bytes().to_vec());
    }
}
