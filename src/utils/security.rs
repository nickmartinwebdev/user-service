//! Security Utilities
//!
//! Cryptographic functions, password hashing, and security-related utilities.

use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{DateTime, Utc};
use rand::{distributions::Alphanumeric, Rng};
use uuid::Uuid;

/// Default bcrypt cost for password hashing
pub const DEFAULT_BCRYPT_COST: u32 = DEFAULT_COST;

/// Generate a cryptographically secure random string
pub fn generate_secure_token(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// Generate a secure numeric OTP code
pub fn generate_otp_code() -> String {
    rand::thread_rng().gen_range(100000..=999999).to_string()
}

/// Generate a secure alphanumeric verification code
pub fn generate_verification_code() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..6)
        .map(|_| {
            let idx = rand::thread_rng().gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Hash a password using bcrypt
pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash_password_with_cost(password, DEFAULT_BCRYPT_COST)
}

/// Hash a password with custom bcrypt cost
pub fn hash_password_with_cost(password: &str, cost: u32) -> Result<String, bcrypt::BcryptError> {
    hash(password, cost)
}

/// Verify a password against its hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}

/// Generate a secure session token
pub fn generate_session_token() -> String {
    format!("{}_{}", Uuid::new_v4(), generate_secure_token(32))
}

/// Generate a secure state token for OAuth flows
pub fn generate_state_token() -> String {
    generate_secure_token(32)
}

/// Create a secure hash of sensitive data for storage
pub fn hash_sensitive_data(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Timing-safe string comparison to prevent timing attacks
pub fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (byte_a, byte_b) in a.bytes().zip(b.bytes()) {
        result |= byte_a ^ byte_b;
    }
    result == 0
}

/// Generate a secure user handle for WebAuthn
pub fn generate_user_handle() -> Vec<u8> {
    Uuid::new_v4().as_bytes().to_vec()
}

/// Create an expiration timestamp
pub fn create_expiration(duration_minutes: i64) -> DateTime<Utc> {
    Utc::now() + chrono::Duration::minutes(duration_minutes)
}

/// Check if a timestamp has expired
pub fn is_expired(expiry: DateTime<Utc>) -> bool {
    Utc::now() > expiry
}

/// Generate a secure challenge for WebAuthn
pub fn generate_webauthn_challenge() -> Vec<u8> {
    (0..32).map(|_| rand::random::<u8>()).collect()
}

/// Security headers for HTTP responses
pub struct SecurityHeaders;

impl SecurityHeaders {
    /// Get standard security headers as a vector of tuples
    pub fn standard() -> Vec<(&'static str, &'static str)> {
        vec![
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("X-XSS-Protection", "1; mode=block"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            (
                "Permissions-Policy",
                "geolocation=(), microphone=(), camera=()",
            ),
            (
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            ),
        ]
    }

    /// Get CSP header for authentication endpoints
    pub fn auth_csp() -> (&'static str, &'static str) {
        (
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'",
        )
    }
}

/// Rate limiting utilities
pub struct RateLimit {
    pub max_attempts: u32,
    pub window_minutes: u32,
}

impl RateLimit {
    pub fn new(max_attempts: u32, window_minutes: u32) -> Self {
        Self {
            max_attempts,
            window_minutes,
        }
    }

    /// Get the window start time for current time
    pub fn window_start(&self) -> DateTime<Utc> {
        let now = Utc::now();
        let minutes_since_epoch = now.timestamp() / 60;
        let window_start_minutes =
            (minutes_since_epoch / self.window_minutes as i64) * self.window_minutes as i64;
        DateTime::from_timestamp(window_start_minutes * 60, 0).unwrap_or(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secure_token() {
        let token1 = generate_secure_token(32);
        let token2 = generate_secure_token(32);

        assert_eq!(token1.len(), 32);
        assert_eq!(token2.len(), 32);
        assert_ne!(token1, token2); // Should be different
    }

    #[test]
    fn test_generate_otp_code() {
        let otp = generate_otp_code();
        assert_eq!(otp.len(), 6);
        assert!(otp.chars().all(|c| c.is_ascii_digit()));

        let otp_num: u32 = otp.parse().unwrap();
        assert!((100000..=999999).contains(&otp_num));
    }

    #[test]
    fn test_password_hashing() {
        let password = "test_password_123";
        let hash = hash_password(password).unwrap();

        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("hello", "hello"));
        assert!(!constant_time_compare("hello", "world"));
        assert!(!constant_time_compare("hello", "hello_world"));
    }

    #[test]
    fn test_generate_session_token() {
        let token = generate_session_token();
        assert!(token.contains('_'));
        assert!(token.len() > 32);
    }

    #[test]
    fn test_hash_sensitive_data() {
        let data = "sensitive_data";
        let hash1 = hash_sensitive_data(data);
        let hash2 = hash_sensitive_data(data);

        assert_eq!(hash1, hash2); // Same input should produce same hash
        assert_eq!(hash1.len(), 64); // SHA256 produces 64-character hex string
    }

    #[test]
    fn test_security_headers() {
        let headers = SecurityHeaders::standard();
        assert!(!headers.is_empty());

        let (name, value) = SecurityHeaders::auth_csp();
        assert_eq!(name, "Content-Security-Policy");
        assert!(value.contains("default-src 'self'"));
    }
}
