//! Login OTP Models
//!
//! Data structures for OTP-based sign-in for existing verified users.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;
use std::net::IpAddr;
use uuid::Uuid;

/// Database row representation of a login OTP record
#[derive(Debug, Clone, FromRow)]
pub struct LoginOtpRow {
    /// Unique identifier for the OTP record
    pub id: Uuid,
    /// Reference to the user account
    pub user_id: Uuid,
    /// 6-digit numeric OTP code
    pub otp_code: String,
    /// When the OTP expires (typically 5 minutes from creation)
    pub expires_at: DateTime<Utc>,
    /// When the OTP was created
    pub created_at: DateTime<Utc>,
    /// Number of verification attempts made
    pub attempts: i32,
    /// When the OTP was successfully used (None if not used)
    pub used_at: Option<DateTime<Utc>>,
    /// IP address from which the OTP was requested
    pub ip_address: Option<sqlx::types::ipnetwork::IpNetwork>,
    /// User agent string from the OTP request
    pub user_agent: Option<String>,
}

/// Business logic representation of a login OTP
#[derive(Debug, Clone, Serialize)]
pub struct LoginOtp {
    /// Unique identifier for the OTP record
    pub id: Uuid,
    /// Reference to the user account
    pub user_id: Uuid,
    /// 6-digit numeric OTP code
    pub otp_code: String,
    /// When the OTP expires
    pub expires_at: DateTime<Utc>,
    /// When the OTP was created
    pub created_at: DateTime<Utc>,
    /// Number of verification attempts made
    pub attempts: i32,
    /// When the OTP was successfully used
    pub used_at: Option<DateTime<Utc>>,
    /// IP address from which the OTP was requested
    pub ip_address: Option<IpAddr>,
    /// User agent string from the OTP request
    pub user_agent: Option<String>,
}

impl From<LoginOtpRow> for LoginOtp {
    fn from(row: LoginOtpRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            otp_code: row.otp_code,
            expires_at: row.expires_at,
            created_at: row.created_at,
            attempts: row.attempts,
            used_at: row.used_at,
            ip_address: row.ip_address.map(|ip| match ip {
                sqlx::types::ipnetwork::IpNetwork::V4(net) => IpAddr::V4(net.ip()),
                sqlx::types::ipnetwork::IpNetwork::V6(net) => IpAddr::V6(net.ip()),
            }),
            user_agent: row.user_agent,
        }
    }
}

impl LoginOtp {
    /// Check if the OTP has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the OTP has been used
    pub fn is_used(&self) -> bool {
        self.used_at.is_some()
    }

    /// Check if the OTP has exceeded maximum attempts
    pub fn has_exceeded_max_attempts(&self) -> bool {
        self.attempts >= 3
    }

    /// Check if the OTP is valid for verification
    pub fn is_valid_for_verification(&self) -> bool {
        !self.is_expired() && !self.is_used() && !self.has_exceeded_max_attempts()
    }

    /// Get remaining time until expiration in seconds
    pub fn remaining_seconds(&self) -> i64 {
        let now = Utc::now();
        if now >= self.expires_at {
            0
        } else {
            (self.expires_at - now).num_seconds()
        }
    }
}

/// Request data for creating a new login OTP
#[derive(Debug, Clone)]
pub struct CreateLoginOtpRequest {
    /// User ID for whom to create the OTP
    pub user_id: Uuid,
    /// IP address from which the request originated
    pub ip_address: Option<IpAddr>,
    /// User agent string from the request
    pub user_agent: Option<String>,
}

/// OTP verification result
#[derive(Debug, Clone)]
pub enum OtpVerificationResult {
    /// OTP verification was successful
    Success,
    /// OTP is invalid or not found
    InvalidCode,
    /// OTP has expired
    Expired,
    /// OTP has already been used
    AlreadyUsed,
    /// Too many verification attempts
    TooManyAttempts,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn create_test_otp(expires_in_minutes: i64) -> LoginOtp {
        LoginOtp {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            otp_code: "123456".to_string(),
            expires_at: Utc::now() + Duration::minutes(expires_in_minutes),
            created_at: Utc::now(),
            attempts: 0,
            used_at: None,
            ip_address: Some("127.0.0.1".parse().unwrap()),
            user_agent: Some("test-agent".to_string()),
        }
    }

    #[test]
    fn test_otp_is_expired() {
        let expired_otp = create_test_otp(-1); // Expired 1 minute ago
        let valid_otp = create_test_otp(5); // Expires in 5 minutes

        assert!(expired_otp.is_expired());
        assert!(!valid_otp.is_expired());
    }

    #[test]
    fn test_otp_is_used() {
        let mut otp = create_test_otp(5);
        assert!(!otp.is_used());

        otp.used_at = Some(Utc::now());
        assert!(otp.is_used());
    }

    #[test]
    fn test_otp_max_attempts() {
        let mut otp = create_test_otp(5);
        assert!(!otp.has_exceeded_max_attempts());

        otp.attempts = 3;
        assert!(otp.has_exceeded_max_attempts());

        otp.attempts = 2;
        assert!(!otp.has_exceeded_max_attempts());
    }

    #[test]
    fn test_otp_validity() {
        let valid_otp = create_test_otp(5);
        assert!(valid_otp.is_valid_for_verification());

        // Expired OTP
        let expired_otp = create_test_otp(-1);
        assert!(!expired_otp.is_valid_for_verification());

        // Used OTP
        let mut used_otp = create_test_otp(5);
        used_otp.used_at = Some(Utc::now());
        assert!(!used_otp.is_valid_for_verification());

        // Too many attempts
        let mut max_attempts_otp = create_test_otp(5);
        max_attempts_otp.attempts = 3;
        assert!(!max_attempts_otp.is_valid_for_verification());
    }

    #[test]
    fn test_remaining_seconds() {
        let otp = create_test_otp(5);
        let remaining = otp.remaining_seconds();

        // Should be approximately 300 seconds (5 minutes), allow some variance
        assert!(remaining > 290 && remaining <= 300);

        let expired_otp = create_test_otp(-1);
        assert_eq!(expired_otp.remaining_seconds(), 0);
    }
}
