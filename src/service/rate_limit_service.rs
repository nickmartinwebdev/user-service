//! Rate Limiting Service
//!
//! Provides comprehensive rate limiting functionality for authentication endpoints
//! to prevent abuse and brute force attacks on passwordless authentication flows.

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use sqlx::PgPool;

use std::net::IpAddr;
use thiserror::Error;
use uuid::Uuid;

/// Rate limiting specific errors
#[derive(Error, Debug)]
pub enum RateLimitError {
    #[error("Database error in rate limiting: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Rate limit exceeded for {identifier} on {endpoint}: {attempts} attempts in window")]
    RateLimitExceeded {
        identifier: String,
        endpoint: String,
        attempts: u32,
        retry_after: u64,
    },

    #[error("Account temporarily locked for {identifier}: {reason}")]
    AccountLocked {
        identifier: String,
        reason: String,
        locked_until: DateTime<Utc>,
    },

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Invalid rate limit parameters: {0}")]
    InvalidParameters(String),
}

/// Result type for rate limiting operations
pub type RateLimitResult<T> = Result<T, RateLimitError>;

/// Rate limit configuration for a specific endpoint
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RateLimit {
    pub max_attempts: u32,
    pub window_minutes: u32,
    pub lockout_minutes: Option<u32>,
}

impl RateLimit {
    pub fn new(max_attempts: u32, window_minutes: u32) -> Self {
        Self {
            max_attempts,
            window_minutes,
            lockout_minutes: None,
        }
    }

    pub fn with_lockout(max_attempts: u32, window_minutes: u32, lockout_minutes: u32) -> Self {
        Self {
            max_attempts,
            window_minutes,
            lockout_minutes: Some(lockout_minutes),
        }
    }
}

/// Complete rate limiting configuration for passwordless authentication
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RateLimitConfig {
    pub email_signup: RateLimit,
    pub email_verification: RateLimit,
    pub email_otp_request: RateLimit,
    pub otp_verification: RateLimit,
    pub passkey_attempts: RateLimit,
    pub oauth_attempts: RateLimit,
    pub global_ip: RateLimit,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            email_signup: RateLimit::with_lockout(5, 60, 60),
            email_verification: RateLimit::with_lockout(5, 15, 30),
            email_otp_request: RateLimit::with_lockout(3, 60, 120),
            otp_verification: RateLimit::with_lockout(5, 15, 30),
            passkey_attempts: RateLimit::new(10, 60),
            oauth_attempts: RateLimit::new(10, 60),
            global_ip: RateLimit::with_lockout(50, 60, 60),
        }
    }
}

impl RateLimitConfig {
    /// Get rate limit configuration for a specific endpoint
    pub fn get_limit(&self, endpoint: &str) -> Option<&RateLimit> {
        match endpoint {
            "email_signup" => Some(&self.email_signup),
            "email_verification" => Some(&self.email_verification),
            "email_otp_request" => Some(&self.email_otp_request),
            "otp_verification" => Some(&self.otp_verification),
            "passkey_attempts" => Some(&self.passkey_attempts),
            "oauth_attempts" => Some(&self.oauth_attempts),
            "global_ip" => Some(&self.global_ip),
            _ => None,
        }
    }

    /// Create configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // Allow override from environment variables
        if let Ok(val) = std::env::var("RATE_LIMIT_EMAIL_SIGNUP_MAX") {
            if let Ok(max) = val.parse::<u32>() {
                config.email_signup.max_attempts = max;
            }
        }

        if let Ok(val) = std::env::var("RATE_LIMIT_EMAIL_SIGNUP_WINDOW") {
            if let Ok(window) = val.parse::<u32>() {
                config.email_signup.window_minutes = window;
            }
        }

        // Similar for other endpoints...
        config
    }
}

/// Rate limiting status for an identifier
#[derive(Debug, Clone, Serialize)]
pub struct RateLimitStatus {
    pub identifier: String,
    pub endpoint: String,
    pub attempts: u32,
    pub max_attempts: u32,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub blocked_until: Option<DateTime<Utc>>,
    pub retry_after_seconds: Option<u64>,
}

impl RateLimitStatus {
    pub fn is_blocked(&self) -> bool {
        self.blocked_until
            .map(|until| Utc::now() < until)
            .unwrap_or(false)
    }

    pub fn is_limit_exceeded(&self) -> bool {
        self.attempts >= self.max_attempts
    }
}

/// Database record for rate limiting
#[derive(Debug, sqlx::FromRow)]
struct RateLimitRecord {
    id: Uuid,
    identifier: String,
    endpoint: String,
    attempt_count: i32,
    window_start: DateTime<Utc>,
    blocked_until: Option<DateTime<Utc>>,
    created_at: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
}

/// Rate limiting service implementation
pub struct RateLimitService {
    pool: PgPool,
    config: RateLimitConfig,
}

impl RateLimitService {
    /// Creates a new rate limiting service with custom configuration
    ///
    /// Initializes the rate limiting service with a database connection pool
    /// and custom rate limiting rules for different endpoints.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool for storing rate limit data
    /// * `config` - Rate limiting configuration with endpoint-specific rules
    ///
    /// # Returns
    /// A new RateLimitService instance ready for rate limiting operations
    ///
    /// # Examples
    /// ```
    /// use user_service::service::{RateLimitService, RateLimitConfig};
    /// use sqlx::PgPool;
    ///
    /// let pool = PgPool::connect("postgresql://...").await?;
    /// let config = RateLimitConfig::default();
    /// let rate_limiter = RateLimitService::new(pool, config);
    /// ```
    pub fn new(pool: PgPool, config: RateLimitConfig) -> Self {
        Self { pool, config }
    }

    /// Create with default configuration
    pub fn with_default_config(pool: PgPool) -> Self {
        Self::new(pool, RateLimitConfig::default())
    }

    /// Check if a request should be rate limited
    pub async fn check_rate_limit(
        &self,
        identifier: &str,
        endpoint: &str,
    ) -> RateLimitResult<RateLimitStatus> {
        let rate_limit = self.config.get_limit(endpoint).ok_or_else(|| {
            RateLimitError::Configuration(format!("Unknown endpoint: {}", endpoint))
        })?;

        let now = Utc::now();
        let window_start = now - Duration::minutes(rate_limit.window_minutes as i64);

        // Check if identifier is currently blocked
        if let Some(record) = self.get_current_rate_limit(identifier, endpoint).await? {
            if let Some(blocked_until) = record.blocked_until {
                if now < blocked_until {
                    let _retry_after = (blocked_until - now).num_seconds() as u64;
                    return Err(RateLimitError::AccountLocked {
                        identifier: identifier.to_string(),
                        reason: "Too many failed attempts".to_string(),
                        locked_until: blocked_until,
                    });
                }
            }

            // Check if we're still in the same window
            if record.window_start > window_start {
                let status = RateLimitStatus {
                    identifier: identifier.to_string(),
                    endpoint: endpoint.to_string(),
                    attempts: record.attempt_count as u32,
                    max_attempts: rate_limit.max_attempts,
                    window_start: record.window_start,
                    window_end: record.window_start
                        + Duration::minutes(rate_limit.window_minutes as i64),
                    blocked_until: record.blocked_until,
                    retry_after_seconds: record
                        .blocked_until
                        .map(|until| std::cmp::max(0, (until - now).num_seconds()) as u64),
                };

                if status.is_limit_exceeded() {
                    let retry_after = status
                        .retry_after_seconds
                        .unwrap_or(rate_limit.window_minutes as u64 * 60);
                    return Err(RateLimitError::RateLimitExceeded {
                        identifier: identifier.to_string(),
                        endpoint: endpoint.to_string(),
                        attempts: status.attempts,
                        retry_after,
                    });
                }

                return Ok(status);
            }
        }

        // No current rate limit or window expired, create new window
        Ok(RateLimitStatus {
            identifier: identifier.to_string(),
            endpoint: endpoint.to_string(),
            attempts: 0,
            max_attempts: rate_limit.max_attempts,
            window_start: now,
            window_end: now + Duration::minutes(rate_limit.window_minutes as i64),
            blocked_until: None,
            retry_after_seconds: None,
        })
    }

    /// Record a rate limit attempt (increment counter)
    pub async fn record_attempt(
        &self,
        identifier: &str,
        endpoint: &str,
        success: bool,
    ) -> RateLimitResult<RateLimitStatus> {
        let rate_limit = self.config.get_limit(endpoint).ok_or_else(|| {
            RateLimitError::Configuration(format!("Unknown endpoint: {}", endpoint))
        })?;

        let now = Utc::now();
        let window_start = now - Duration::minutes(rate_limit.window_minutes as i64);

        // If successful, we might want to reset or reduce the counter
        if success {
            // For successful attempts, we could implement a more lenient policy
            // For now, we still count successful attempts to prevent abuse
        }

        let mut tx = self.pool.begin().await?;

        // Get or create current rate limit record
        let existing = sqlx::query_as!(
            RateLimitRecord,
            r#"
            SELECT id, identifier, endpoint, attempt_count, window_start, blocked_until, created_at, updated_at
            FROM auth_rate_limits
            WHERE identifier = $1 AND endpoint = $2 AND window_start > $3
            ORDER BY window_start DESC
            LIMIT 1
            "#,
            identifier,
            endpoint,
            window_start
        )
        .fetch_optional(&mut *tx)
        .await?;

        let (new_attempts, new_window_start, blocked_until) = if let Some(record) = existing {
            let new_attempts = record.attempt_count + 1;
            let blocked_until = if new_attempts >= rate_limit.max_attempts as i32 {
                rate_limit
                    .lockout_minutes
                    .map(|lockout| now + Duration::minutes(lockout as i64))
            } else {
                record.blocked_until
            };

            // Update existing record
            sqlx::query!(
                r#"
                UPDATE auth_rate_limits
                SET attempt_count = $1, blocked_until = $2, updated_at = NOW()
                WHERE id = $3
                "#,
                new_attempts,
                blocked_until,
                record.id
            )
            .execute(&mut *tx)
            .await?;

            (new_attempts, record.window_start, blocked_until)
        } else {
            // Create new record
            let new_window_start = now;
            let blocked_until = if 1 >= rate_limit.max_attempts as i32 {
                rate_limit
                    .lockout_minutes
                    .map(|lockout| now + Duration::minutes(lockout as i64))
            } else {
                None
            };

            sqlx::query!(
                r#"
                INSERT INTO auth_rate_limits (identifier, endpoint, attempt_count, window_start, blocked_until)
                VALUES ($1, $2, $3, $4, $5)
                "#,
                identifier,
                endpoint,
                1,
                new_window_start,
                blocked_until
            )
            .execute(&mut *tx)
            .await?;

            (1, new_window_start, blocked_until)
        };

        tx.commit().await?;

        let status = RateLimitStatus {
            identifier: identifier.to_string(),
            endpoint: endpoint.to_string(),
            attempts: new_attempts as u32,
            max_attempts: rate_limit.max_attempts,
            window_start: new_window_start,
            window_end: new_window_start + Duration::minutes(rate_limit.window_minutes as i64),
            blocked_until,
            retry_after_seconds: blocked_until
                .map(|until| std::cmp::max(0, (until - now).num_seconds()) as u64),
        };

        // Check if rate limit exceeded after recording
        if status.is_limit_exceeded() && status.is_blocked() {
            let retry_after = status
                .retry_after_seconds
                .unwrap_or(rate_limit.window_minutes as u64 * 60);
            return Err(RateLimitError::RateLimitExceeded {
                identifier: identifier.to_string(),
                endpoint: endpoint.to_string(),
                attempts: status.attempts,
                retry_after,
            });
        }

        Ok(status)
    }

    /// Check rate limit for an IP address
    pub async fn check_ip_rate_limit(
        &self,
        ip: IpAddr,
        endpoint: &str,
    ) -> RateLimitResult<RateLimitStatus> {
        self.check_rate_limit(&ip.to_string(), endpoint).await
    }

    /// Record attempt for an IP address
    pub async fn record_ip_attempt(
        &self,
        ip: IpAddr,
        endpoint: &str,
        success: bool,
    ) -> RateLimitResult<RateLimitStatus> {
        self.record_attempt(&ip.to_string(), endpoint, success)
            .await
    }

    /// Check rate limit for an email address
    pub async fn check_email_rate_limit(
        &self,
        email: &str,
        endpoint: &str,
    ) -> RateLimitResult<RateLimitStatus> {
        self.check_rate_limit(email, endpoint).await
    }

    /// Record attempt for an email address
    pub async fn record_email_attempt(
        &self,
        email: &str,
        endpoint: &str,
        success: bool,
    ) -> RateLimitResult<RateLimitStatus> {
        self.record_attempt(email, endpoint, success).await
    }

    /// Reset rate limit for an identifier (admin function)
    pub async fn reset_rate_limit(&self, identifier: &str, endpoint: &str) -> RateLimitResult<()> {
        sqlx::query!(
            r#"
            DELETE FROM auth_rate_limits
            WHERE identifier = $1 AND endpoint = $2
            "#,
            identifier,
            endpoint
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Removes expired rate limiting records from the database
    ///
    /// Cleans up rate limiting records that are no longer relevant due to
    /// expired time windows and lockout periods. This is a maintenance
    /// operation that should be run periodically to prevent database bloat.
    ///
    /// # Returns
    /// * `Ok(u64)` - Number of expired records that were deleted
    /// * `Err(RateLimitError)` - Database operation failed
    ///
    /// # Cleanup Criteria
    /// Records are considered expired if:
    /// * Time window has passed and no lockout is active
    /// * Lockout period has expired
    /// * Record is older than maximum retention period
    ///
    /// # Performance Notes
    /// * Safe to run frequently as it only affects expired records
    /// * Performance depends on number of expired records
    /// * Consider indexing on time-based columns
    ///
    /// # Scheduling Recommendations
    /// * Run hourly for high-traffic applications
    /// * Run daily for moderate-traffic applications
    /// * Include in application maintenance routines
    ///
    /// # Examples
    /// ```
    /// // Cleanup job in scheduled task
    /// let deleted_count = rate_limiter.cleanup_expired_records().await?;
    /// println!("Cleaned up {} expired rate limit records", deleted_count);
    /// ```
    pub async fn cleanup_expired_records(&self) -> RateLimitResult<u64> {
        let cutoff = Utc::now() - Duration::hours(24); // Keep records for 24 hours

        let result = sqlx::query!(
            r#"
            DELETE FROM auth_rate_limits
            WHERE window_start < $1 AND (blocked_until IS NULL OR blocked_until < NOW())
            "#,
            cutoff
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Get current rate limit status for debugging
    pub async fn get_rate_limit_status(
        &self,
        identifier: &str,
        endpoint: &str,
    ) -> RateLimitResult<Option<RateLimitStatus>> {
        if let Some(record) = self.get_current_rate_limit(identifier, endpoint).await? {
            let rate_limit = self.config.get_limit(endpoint).ok_or_else(|| {
                RateLimitError::Configuration(format!("Unknown endpoint: {}", endpoint))
            })?;

            let now = Utc::now();
            let status = RateLimitStatus {
                identifier: identifier.to_string(),
                endpoint: endpoint.to_string(),
                attempts: record.attempt_count as u32,
                max_attempts: rate_limit.max_attempts,
                window_start: record.window_start,
                window_end: record.window_start
                    + Duration::minutes(rate_limit.window_minutes as i64),
                blocked_until: record.blocked_until,
                retry_after_seconds: record
                    .blocked_until
                    .map(|until| std::cmp::max(0, (until - now).num_seconds()) as u64),
            };

            Ok(Some(status))
        } else {
            Ok(None)
        }
    }

    /// Internal helper to get current rate limit record
    async fn get_current_rate_limit(
        &self,
        identifier: &str,
        endpoint: &str,
    ) -> RateLimitResult<Option<RateLimitRecord>> {
        let window_start = Utc::now() - Duration::hours(24); // Look for records from last 24 hours

        let record = sqlx::query_as!(
            RateLimitRecord,
            r#"
            SELECT id, identifier, endpoint, attempt_count, window_start, blocked_until, created_at, updated_at
            FROM auth_rate_limits
            WHERE identifier = $1 AND endpoint = $2 AND window_start > $3
            ORDER BY window_start DESC
            LIMIT 1
            "#,
            identifier,
            endpoint,
            window_start
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    async fn setup_test_db() -> PgPool {
        // This would be implemented with a test database setup
        todo!("Test database setup")
    }

    #[tokio::test]
    async fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert_eq!(config.email_signup.max_attempts, 5);
        assert_eq!(config.email_signup.window_minutes, 60);
        assert_eq!(config.email_signup.lockout_minutes, Some(60));
    }

    #[tokio::test]
    async fn test_rate_limit_status_blocked() {
        let status = RateLimitStatus {
            identifier: "test@example.com".to_string(),
            endpoint: "email_signup".to_string(),
            attempts: 5,
            max_attempts: 5,
            window_start: Utc::now(),
            window_end: Utc::now() + Duration::minutes(60),
            blocked_until: Some(Utc::now() + Duration::minutes(30)),
            retry_after_seconds: Some(1800),
        };

        assert!(status.is_blocked());
        assert!(status.is_limit_exceeded());
    }

    #[tokio::test]
    async fn test_rate_limit_within_limits() {
        let status = RateLimitStatus {
            identifier: "test@example.com".to_string(),
            endpoint: "email_signup".to_string(),
            attempts: 2,
            max_attempts: 5,
            window_start: Utc::now(),
            window_end: Utc::now() + Duration::minutes(60),
            blocked_until: None,
            retry_after_seconds: None,
        };

        assert!(!status.is_blocked());
        assert!(!status.is_limit_exceeded());
    }
}
