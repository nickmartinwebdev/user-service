//! Email Verification Model
//!
//! Data structures and types for managing email verification codes in passwordless authentication.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Email verification record for passwordless authentication
///
/// This struct represents an email verification code that is sent to users
/// during the passwordless signup process. Each code has an expiration time
/// and tracks verification attempts for security.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailVerification {
    /// Unique identifier for the verification record
    pub id: Uuid,

    /// Reference to the user account
    pub user_id: Uuid,

    /// 6-digit numeric verification code
    pub verification_code: String,

    /// Expiration timestamp for the verification code
    pub expires_at: DateTime<Utc>,

    /// When the verification code was generated
    pub created_at: DateTime<Utc>,

    /// Number of verification attempts made
    pub attempts: i32,

    /// When the code was successfully verified (if applicable)
    pub verified_at: Option<DateTime<Utc>>,
}

/// Internal struct for database queries with nullable verified_at field
#[derive(Debug, sqlx::FromRow)]
pub(crate) struct EmailVerificationRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub verification_code: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: Option<DateTime<Utc>>,
    pub attempts: Option<i32>,
    pub verified_at: Option<DateTime<Utc>>,
}

impl From<EmailVerificationRow> for EmailVerification {
    fn from(row: EmailVerificationRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            verification_code: row.verification_code,
            expires_at: row.expires_at,
            created_at: row.created_at.unwrap_or_else(|| Utc::now()),
            attempts: row.attempts.unwrap_or(0),
            verified_at: row.verified_at,
        }
    }
}

impl EmailVerification {
    /// Check if the verification code has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the verification code has been verified
    pub fn is_verified(&self) -> bool {
        self.verified_at.is_some()
    }

    /// Check if the maximum number of attempts has been exceeded
    pub fn has_exceeded_max_attempts(&self, max_attempts: i32) -> bool {
        self.attempts >= max_attempts
    }

    /// Check if this verification code can be used
    pub fn is_usable(&self, max_attempts: i32) -> bool {
        !self.is_expired() && !self.is_verified() && !self.has_exceeded_max_attempts(max_attempts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn create_test_verification() -> EmailVerification {
        EmailVerification {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            verification_code: "123456".to_string(),
            expires_at: Utc::now() + Duration::minutes(10),
            created_at: Utc::now(),
            attempts: 0,
            verified_at: None,
        }
    }

    #[test]
    fn test_is_expired() {
        let mut verification = create_test_verification();

        // Not expired
        assert!(!verification.is_expired());

        // Expired
        verification.expires_at = Utc::now() - Duration::minutes(1);
        assert!(verification.is_expired());
    }

    #[test]
    fn test_is_verified() {
        let mut verification = create_test_verification();

        // Not verified
        assert!(!verification.is_verified());

        // Verified
        verification.verified_at = Some(Utc::now());
        assert!(verification.is_verified());
    }

    #[test]
    fn test_has_exceeded_max_attempts() {
        let mut verification = create_test_verification();
        let max_attempts = 3;

        // Within limits
        verification.attempts = 2;
        assert!(!verification.has_exceeded_max_attempts(max_attempts));

        // Exceeded limits
        verification.attempts = 3;
        assert!(verification.has_exceeded_max_attempts(max_attempts));
    }

    #[test]
    fn test_is_usable() {
        let verification = create_test_verification();
        let max_attempts = 3;

        // Fresh verification should be usable
        assert!(verification.is_usable(max_attempts));

        // Expired verification should not be usable
        let mut expired_verification = verification.clone();
        expired_verification.expires_at = Utc::now() - Duration::minutes(1);
        assert!(!expired_verification.is_usable(max_attempts));

        // Verified verification should not be usable
        let mut verified_verification = verification.clone();
        verified_verification.verified_at = Some(Utc::now());
        assert!(!verified_verification.is_usable(max_attempts));

        // Verification with too many attempts should not be usable
        let mut max_attempts_verification = verification.clone();
        max_attempts_verification.attempts = 3;
        assert!(!max_attempts_verification.is_usable(max_attempts));
    }
}
