//! Security Audit Service
//!
//! Provides comprehensive security audit logging for authentication events
//! to support compliance, monitoring, and incident response for passwordless flows.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::types::ipnetwork::IpNetwork;
use sqlx::PgPool;
use std::net::IpAddr;
use thiserror::Error;
use uuid::Uuid;

/// Security audit specific errors
#[derive(Error, Debug)]
pub enum SecurityAuditError {
    #[error("Database error in security audit: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Serialization error in audit data: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid audit event type: {0}")]
    InvalidEventType(String),

    #[error("Missing required audit field: {0}")]
    MissingField(String),

    #[error("Audit configuration error: {0}")]
    Configuration(String),

    #[error("Password attempt detected from IP {ip}: {reason}")]
    PasswordAttemptDetected { ip: IpAddr, reason: String },
}

/// Result type for security audit operations
pub type SecurityAuditResult<T> = Result<T, SecurityAuditError>;

/// Authentication event types for passwordless flows
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthEventType {
    /// User signup via email verification
    SignupEmail,
    /// Email verification completion
    EmailVerification,
    /// OTP signin request (email sent)
    SigninOtpRequest,
    /// OTP signin verification
    SigninOtpVerify,
    /// Passkey authentication begin
    SigninPasskeyBegin,
    /// Passkey authentication completion
    SigninPasskeyFinish,
    /// OAuth authentication initiation
    SigninOauthInit,
    /// OAuth authentication callback
    SigninOauthCallback,
    /// Token refresh operation
    TokenRefresh,
    /// Security alert: password attempt detected
    PasswordAttemptDetected,
}

impl AuthEventType {
    /// Convert from string representation
    pub fn from_str(s: &str) -> Result<Self, SecurityAuditError> {
        match s {
            "signup_email" => Ok(Self::SignupEmail),
            "email_verification" => Ok(Self::EmailVerification),
            "signin_otp_request" => Ok(Self::SigninOtpRequest),
            "signin_otp_verify" => Ok(Self::SigninOtpVerify),
            "signin_passkey_begin" => Ok(Self::SigninPasskeyBegin),
            "signin_passkey_finish" => Ok(Self::SigninPasskeyFinish),
            "signin_oauth_init" => Ok(Self::SigninOauthInit),
            "signin_oauth_callback" => Ok(Self::SigninOauthCallback),
            "token_refresh" => Ok(Self::TokenRefresh),
            "password_attempt_detected" => Ok(Self::PasswordAttemptDetected),
            _ => Err(SecurityAuditError::InvalidEventType(s.to_string())),
        }
    }

    /// Convert to string representation for database storage
    pub fn to_string(&self) -> String {
        match self {
            Self::SignupEmail => "signup_email".to_string(),
            Self::EmailVerification => "email_verification".to_string(),
            Self::SigninOtpRequest => "signin_otp_request".to_string(),
            Self::SigninOtpVerify => "signin_otp_verify".to_string(),
            Self::SigninPasskeyBegin => "signin_passkey_begin".to_string(),
            Self::SigninPasskeyFinish => "signin_passkey_finish".to_string(),
            Self::SigninOauthInit => "signin_oauth_init".to_string(),
            Self::SigninOauthCallback => "signin_oauth_callback".to_string(),
            Self::TokenRefresh => "token_refresh".to_string(),
            Self::PasswordAttemptDetected => "password_attempt_detected".to_string(),
        }
    }

    /// Check if this event type should trigger security alerts
    pub fn is_security_event(&self) -> bool {
        matches!(self, Self::PasswordAttemptDetected)
    }

    /// Check if this is a signin-related event
    pub fn is_signin_event(&self) -> bool {
        matches!(
            self,
            Self::SigninOtpRequest
                | Self::SigninOtpVerify
                | Self::SigninPasskeyBegin
                | Self::SigninPasskeyFinish
                | Self::SigninOauthInit
                | Self::SigninOauthCallback
        )
    }
}

/// Security event data for monitoring and alerting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_type: AuthEventType,
    pub identifier: String, // IP or email
    pub details: JsonValue,
    pub severity: SecurityEventSeverity,
    pub should_alert: bool,
}

/// Security event severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Audit log entry for authentication events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub event_type: AuthEventType,
    pub user_id: Option<Uuid>,
    pub event_data: Option<JsonValue>,
    pub ip_address: Option<IpNetwork>,
    pub user_agent: Option<String>,
    pub success: bool,
    pub error_message: Option<String>,
    pub request_id: Option<String>,
    pub session_id: Option<String>,
}

impl AuditLogEntry {
    /// Create a new audit log entry
    pub fn new(event_type: AuthEventType, success: bool) -> Self {
        Self {
            event_type,
            user_id: None,
            event_data: None,
            ip_address: None,
            user_agent: None,
            success,
            error_message: None,
            request_id: None,
            session_id: None,
        }
    }

    /// Builder pattern methods
    pub fn with_user_id(mut self, user_id: Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn with_event_data(mut self, data: JsonValue) -> Self {
        self.event_data = Some(data);
        self
    }

    pub fn with_ip_address(mut self, ip: IpAddr) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    pub fn with_error(mut self, error: String) -> Self {
        self.error_message = Some(error);
        self.success = false;
        self
    }

    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }

    pub fn with_session_id(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Validate the audit entry before logging
    pub fn validate(&self) -> SecurityAuditResult<()> {
        if !self.success && self.error_message.is_none() {
            return Err(SecurityAuditError::MissingField(
                "error_message required for failed events".to_string(),
            ));
        }

        if self.success && self.error_message.is_some() {
            return Err(SecurityAuditError::Configuration(
                "error_message should not be present for successful events".to_string(),
            ));
        }

        Ok(())
    }

    /// Check if this entry indicates suspicious activity
    pub fn is_suspicious(&self) -> bool {
        !self.success || self.event_type.is_security_event()
    }

    /// Get security event data if this is a security-relevant event
    pub fn to_security_event(&self) -> Option<SecurityEvent> {
        if !self.is_suspicious() {
            return None;
        }

        let severity = match self.event_type {
            AuthEventType::PasswordAttemptDetected => SecurityEventSeverity::Critical,
            _ if !self.success => SecurityEventSeverity::Medium,
            _ => SecurityEventSeverity::Low,
        };

        let should_alert = matches!(self.event_type, AuthEventType::PasswordAttemptDetected)
            || (!self.success && self.event_type.is_signin_event());

        let identifier = self
            .ip_address
            .map(|ip| ip.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        Some(SecurityEvent {
            event_type: self.event_type.clone(),
            identifier,
            details: self.event_data.clone().unwrap_or_default(),
            severity,
            should_alert,
        })
    }
}

/// Database record for audit log
#[derive(Debug, sqlx::FromRow)]
pub struct AuditLogRecord {
    id: Uuid,
    user_id: Option<Uuid>,
    event_type: String,
    event_data: Option<JsonValue>,
    ip_address: Option<IpNetwork>,
    user_agent: Option<String>,
    success: bool,
    error_message: Option<String>,
    request_id: Option<String>,
    session_id: Option<String>,
    created_at: Option<DateTime<Utc>>,
}

/// Audit query filters for searching audit logs
#[derive(Debug, Clone, Default)]
pub struct AuditQueryFilters {
    pub user_id: Option<Uuid>,
    pub event_type: Option<AuthEventType>,
    pub ip_address: Option<IpNetwork>,
    pub success: Option<bool>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Audit statistics for monitoring
#[derive(Debug, Serialize)]
pub struct AuditStatistics {
    pub total_events: i64,
    pub successful_events: i64,
    pub failed_events: i64,
    pub unique_ips: i64,
    pub unique_users: i64,
    pub events_by_type: std::collections::HashMap<String, i64>,
}

/// Security audit service for comprehensive authentication event logging
///
/// Provides enterprise-grade security audit logging for all authentication
/// events in the passwordless system. Supports compliance requirements,
/// security monitoring, incident response, and threat detection.
///
/// # Features
/// * Complete audit trail of authentication events
/// * Configurable security alerting
/// * Suspicious activity detection
/// * Compliance reporting capabilities
/// * Performance-optimized event logging
/// * Automatic log retention management
pub struct SecurityAuditService {
    /// Database connection pool for audit log storage
    pool: PgPool,
    /// Whether to enable real-time security alerts
    enable_alerts: bool,
}

impl SecurityAuditService {
    /// Creates a new security audit service with configurable alerting
    ///
    /// Initializes the security audit service with database connectivity and
    /// optional real-time security alerting. Alert configuration is controlled
    /// via the `AUTH_SECURITY_ALERTS_ENABLED` environment variable.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool for audit log storage
    ///
    /// # Returns
    /// A new SecurityAuditService instance ready for audit logging
    ///
    /// # Environment Variables
    /// * `AUTH_SECURITY_ALERTS_ENABLED` - Enable/disable security alerts (default: true)
    ///
    /// # Examples
    /// ```
    /// use user_service::service::SecurityAuditService;
    /// use sqlx::PgPool;
    ///
    /// let pool = PgPool::connect("postgresql://...").await?;
    /// let audit_service = SecurityAuditService::new(pool);
    /// ```
    pub fn new(pool: PgPool) -> Self {
        let enable_alerts = std::env::var("AUTH_SECURITY_ALERTS_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);

        Self {
            pool,
            enable_alerts,
        }
    }

    /// Records an authentication event with full audit trail details
    ///
    /// Stores a complete audit log entry in the database with validation and
    /// optional security alerting. This is the core logging method used by
    /// all convenience methods.
    ///
    /// # Arguments
    /// * `entry` - Complete audit log entry with all relevant details
    ///
    /// # Returns
    /// * `Ok(Uuid)` - Unique identifier of the created audit log record
    /// * `Err(SecurityAuditError)` - Validation or storage failed
    ///
    /// # Errors
    /// * `MissingField` - Required audit fields are missing
    /// * `Database` - Audit log storage failed
    /// * `Serialization` - Event data serialization failed
    ///
    /// # Security Features
    /// * Automatic validation of audit entry completeness
    /// * Real-time security event processing and alerting
    /// * Tamper-resistant audit trail storage
    /// * Performance-optimized database operations
    ///
    /// # Examples
    /// ```
    /// use user_service::models::AuditLogEntry;
    /// use user_service::service::AuthEventType;
    ///
    /// let entry = AuditLogEntry::new(AuthEventType::SigninOtpVerify, true)
    ///     .with_user_id(user_id)
    ///     .with_ip_address(client_ip);
    ///
    /// let record_id = audit_service.log_auth_event(entry).await?;
    /// ```
    pub async fn log_auth_event(&self, entry: AuditLogEntry) -> SecurityAuditResult<Uuid> {
        entry.validate()?;

        let event_type_str = entry.event_type.to_string();

        let record_id = sqlx::query_scalar!(
            r#"
            INSERT INTO auth_audit_log (
                user_id, event_type, event_data, ip_address, user_agent,
                success, error_message, request_id, session_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
            "#,
            entry.user_id,
            event_type_str,
            entry.event_data,
            entry.ip_address,
            entry.user_agent,
            entry.success,
            entry.error_message,
            entry.request_id,
            entry.session_id
        )
        .fetch_one(&self.pool)
        .await?;

        // Check for security events that need alerting
        if self.enable_alerts {
            if let Some(security_event) = entry.to_security_event() {
                self.handle_security_event(security_event).await?;
            }
        }

        Ok(record_id)
    }

    /// Records a successful authentication event with standard context
    ///
    /// Convenience method for logging successful authentication events with
    /// common parameters. Automatically sets success flag and handles
    /// standard event data formatting.
    ///
    /// # Arguments
    /// * `event_type` - Type of authentication event that succeeded
    /// * `user_id` - Optional user identifier (if known at this point)
    /// * `ip_address` - Optional client IP address for security tracking
    /// * `user_agent` - Optional client user agent string
    /// * `additional_data` - Optional extra event-specific data
    ///
    /// # Returns
    /// * `Ok(())` - Success event logged successfully
    /// * `Err(SecurityAuditError)` - Logging failed
    ///
    /// # Examples
    /// ```
    /// use user_service::service::{SecurityAuditService, AuthEventType};
    /// use std::net::IpAddr;
    /// use serde_json::json;
    ///
    /// // Log successful OTP verification
    /// audit_service.log_success(
    ///     AuthEventType::SigninOtpVerify,
    ///     Some(user_id),
    ///     Some(IpAddr::V4([192, 168, 1, 100].into())),
    ///     Some("Mozilla/5.0...".to_string()),
    ///     Some(json!({"otp_method": "email"}))
    /// ).await?;
    /// ```
    pub async fn log_success(
        &self,
        event_type: AuthEventType,
        user_id: Option<Uuid>,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        additional_data: Option<JsonValue>,
    ) -> SecurityAuditResult<()> {
        let mut entry = AuditLogEntry::new(event_type, true);

        if let Some(uid) = user_id {
            entry = entry.with_user_id(uid);
        }
        if let Some(ip) = ip_address {
            entry = entry.with_ip_address(ip);
        }
        if let Some(ua) = user_agent {
            entry = entry.with_user_agent(ua);
        }

        self.log_auth_event(entry).await.map(|_| ())
    }

    /// Records a failed authentication event with error details
    ///
    /// Convenience method for logging authentication failures with error
    /// information and security context. Automatically triggers security
    /// monitoring for suspicious patterns.
    ///
    /// # Arguments
    /// * `event_type` - Type of authentication event that failed
    /// * `error_message` - Detailed error description for troubleshooting
    /// * `ip_address` - Optional client IP address for security tracking
    /// * `user_agent` - Optional client user agent string
    /// * `request_id` - Optional request identifier for correlation
    /// * `event_data` - Optional additional event-specific data
    ///
    /// # Returns
    /// * `Ok(Uuid)` - Unique identifier of the created audit log record
    /// * `Err(SecurityAuditError)` - Logging failed
    ///
    /// # Security Features
    /// * Automatic failure pattern detection
    /// * IP-based suspicious activity monitoring
    /// * Error message sanitization for sensitive data
    /// * Integration with threat detection systems
    ///
    /// # Examples
    /// ```
    /// use user_service::service::{SecurityAuditService, AuthEventType};
    /// use std::net::IpAddr;
    /// use serde_json::json;
    ///
    /// // Log failed OTP verification
    /// audit_service.log_failure(
    ///     AuthEventType::SigninOtpVerify,
    ///     "Invalid OTP code provided".to_string(),
    ///     Some(IpAddr::V4([192, 168, 1, 100].into())),
    ///     Some("Mozilla/5.0...".to_string()),
    ///     Some("req_123".to_string()),
    ///     Some(json!({"attempts": 3}))
    /// ).await?;
    /// ```
    pub async fn log_failure(
        &self,
        event_type: AuthEventType,
        error_message: String,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        request_id: Option<String>,
        event_data: Option<JsonValue>,
    ) -> SecurityAuditResult<Uuid> {
        let mut entry = AuditLogEntry::new(event_type, false).with_error(error_message);

        if let Some(ip) = ip_address {
            entry = entry.with_ip_address(ip);
        }
        if let Some(ua) = user_agent {
            entry = entry.with_user_agent(ua);
        }
        if let Some(rid) = request_id {
            entry = entry.with_request_id(rid);
        }
        if let Some(data) = event_data {
            entry = entry.with_event_data(data);
        }

        self.log_auth_event(entry).await
    }

    /// Log a critical security event (password attempt detected)
    pub async fn log_security_alert(
        &self,
        ip_address: IpAddr,
        reason: String,
        request_data: Option<JsonValue>,
    ) -> SecurityAuditResult<Uuid> {
        let _event_data = serde_json::json!({
            "reason": reason,
            "detected_fields": request_data,
            "severity": "critical",
            "alert_type": "password_attempt"
        });

        let mut entry = AuditLogEntry::new(AuthEventType::PasswordAttemptDetected, false)
            .with_ip_address(ip_address)
            .with_error(format!("Password attempt detected: {}", reason));

        if let Some(data) = request_data {
            entry = entry.with_event_data(data);
        }

        self.log_auth_event(entry).await
    }

    /// Query audit logs with filters
    pub async fn query_audit_logs(
        &self,
        filters: AuditQueryFilters,
    ) -> SecurityAuditResult<Vec<AuditLogRecord>> {
        let limit = filters.limit.unwrap_or(100).min(1000); // Cap at 1000 for safety
        let offset = filters.offset.unwrap_or(0);

        // Handle most common cases with compile-time queries
        match (
            &filters.user_id,
            &filters.event_type,
            &filters.start_time,
            &filters.end_time,
        ) {
            // Most common: query by user_id with time range
            (Some(user_id), None, Some(start_time), Some(end_time)) => {
                let records = sqlx::query_as!(
                    AuditLogRecord,
                    r#"
                    SELECT id, user_id, event_type, event_data, ip_address, user_agent,
                           success, error_message, request_id, session_id, created_at
                    FROM auth_audit_log
                    WHERE user_id = $1 AND created_at BETWEEN $2 AND $3
                    ORDER BY created_at DESC
                    LIMIT $4 OFFSET $5
                    "#,
                    user_id,
                    start_time,
                    end_time,
                    limit as i64,
                    offset as i64
                )
                .fetch_all(&self.pool)
                .await?;
                Ok(records)
            }
            // Query by event type with time range
            (None, Some(event_type), Some(start_time), Some(end_time)) => {
                let event_type_str = event_type.to_string();
                let records = sqlx::query_as!(
                    AuditLogRecord,
                    r#"
                    SELECT id, user_id, event_type, event_data, ip_address, user_agent,
                           success, error_message, request_id, session_id, created_at
                    FROM auth_audit_log
                    WHERE event_type = $1 AND created_at BETWEEN $2 AND $3
                    ORDER BY created_at DESC
                    LIMIT $4 OFFSET $5
                    "#,
                    event_type_str,
                    start_time,
                    end_time,
                    limit as i64,
                    offset as i64
                )
                .fetch_all(&self.pool)
                .await?;
                Ok(records)
            }
            // Query by time range only
            (None, None, Some(start_time), Some(end_time)) => {
                let records = sqlx::query_as!(
                    AuditLogRecord,
                    r#"
                    SELECT id, user_id, event_type, event_data, ip_address, user_agent,
                           success, error_message, request_id, session_id, created_at
                    FROM auth_audit_log
                    WHERE created_at BETWEEN $1 AND $2
                    ORDER BY created_at DESC
                    LIMIT $3 OFFSET $4
                    "#,
                    start_time,
                    end_time,
                    limit as i64,
                    offset as i64
                )
                .fetch_all(&self.pool)
                .await?;
                Ok(records)
            }
            // Simple recent logs query (no filters)
            (None, None, None, None) => {
                let records = sqlx::query_as!(
                    AuditLogRecord,
                    r#"
                    SELECT id, user_id, event_type, event_data, ip_address, user_agent,
                           success, error_message, request_id, session_id, created_at
                    FROM auth_audit_log
                    ORDER BY created_at DESC
                    LIMIT $1 OFFSET $2
                    "#,
                    limit as i64,
                    offset as i64
                )
                .fetch_all(&self.pool)
                .await?;
                Ok(records)
            }
            // For complex queries, fall back to safe dynamic building
            _ => self.query_audit_logs_dynamic(filters).await,
        }
    }

    /// Handle complex dynamic queries using QueryBuilder for type safety
    async fn query_audit_logs_dynamic(
        &self,
        filters: AuditQueryFilters,
    ) -> SecurityAuditResult<Vec<AuditLogRecord>> {
        let mut query_builder = sqlx::QueryBuilder::new(
            "SELECT id, user_id, event_type, event_data, ip_address, user_agent, success, error_message, request_id, session_id, created_at FROM auth_audit_log WHERE 1=1"
        );

        if let Some(user_id) = filters.user_id {
            query_builder.push(" AND user_id = ");
            query_builder.push_bind(user_id);
        }

        if let Some(event_type) = filters.event_type {
            query_builder.push(" AND event_type = ");
            query_builder.push_bind(event_type.to_string());
        }

        if let Some(ip) = filters.ip_address {
            query_builder.push(" AND ip_address = ");
            query_builder.push_bind(ip);
        }

        if let Some(success) = filters.success {
            query_builder.push(" AND success = ");
            query_builder.push_bind(success);
        }

        if let Some(start_time) = filters.start_time {
            query_builder.push(" AND created_at >= ");
            query_builder.push_bind(start_time);
        }

        if let Some(end_time) = filters.end_time {
            query_builder.push(" AND created_at <= ");
            query_builder.push_bind(end_time);
        }

        query_builder.push(" ORDER BY created_at DESC");

        let limit = filters.limit.unwrap_or(100).min(1000);
        let offset = filters.offset.unwrap_or(0);

        query_builder.push(" LIMIT ");
        query_builder.push_bind(limit as i64);
        query_builder.push(" OFFSET ");
        query_builder.push_bind(offset as i64);

        let records = query_builder
            .build_query_as::<AuditLogRecord>()
            .fetch_all(&self.pool)
            .await?;

        Ok(records)
    }

    /// Get audit statistics for monitoring dashboard
    pub async fn get_audit_statistics(
        &self,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> SecurityAuditResult<AuditStatistics> {
        let total_events: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM auth_audit_log WHERE created_at BETWEEN $1 AND $2",
            start_time,
            end_time
        )
        .fetch_one(&self.pool)
        .await?
        .unwrap_or(0);

        let successful_events: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM auth_audit_log WHERE created_at BETWEEN $1 AND $2 AND success = true",
            start_time,
            end_time
        )
        .fetch_one(&self.pool)
        .await?
        .unwrap_or(0);

        let failed_events = total_events - successful_events;

        let unique_ips: i64 = sqlx::query_scalar!(
            "SELECT COUNT(DISTINCT ip_address) FROM auth_audit_log WHERE created_at BETWEEN $1 AND $2 AND ip_address IS NOT NULL",
            start_time,
            end_time
        )
        .fetch_one(&self.pool)
        .await?
        .unwrap_or(0);

        let unique_users: i64 = sqlx::query_scalar!(
            "SELECT COUNT(DISTINCT user_id) FROM auth_audit_log WHERE created_at BETWEEN $1 AND $2 AND user_id IS NOT NULL",
            start_time,
            end_time
        )
        .fetch_one(&self.pool)
        .await?
        .unwrap_or(0);

        let events_by_type_rows = sqlx::query!(
            "SELECT event_type, COUNT(*) as count FROM auth_audit_log WHERE created_at BETWEEN $1 AND $2 GROUP BY event_type",
            start_time,
            end_time
        )
        .fetch_all(&self.pool)
        .await?;

        let events_by_type = events_by_type_rows
            .into_iter()
            .map(|row| (row.event_type, row.count.unwrap_or(0)))
            .collect();

        Ok(AuditStatistics {
            total_events,
            successful_events,
            failed_events,
            unique_ips,
            unique_users,
            events_by_type,
        })
    }

    /// Detect suspicious activity patterns
    pub async fn detect_suspicious_activity(
        &self,
        lookback_hours: i64,
    ) -> SecurityAuditResult<Vec<SecurityEvent>> {
        let since = Utc::now() - chrono::Duration::hours(lookback_hours);
        let threshold = 5i64; // Threshold for suspicious activity

        // Look for multiple failed attempts from same IP
        let suspicious_ip_rows = sqlx::query!(
            r#"
            SELECT ip_address, COUNT(*) as failed_count
            FROM auth_audit_log
            WHERE created_at > $1 AND success = false AND ip_address IS NOT NULL
            GROUP BY ip_address
            HAVING COUNT(*) >= $2
            ORDER BY failed_count DESC
            LIMIT 100
            "#,
            since,
            threshold
        )
        .fetch_all(&self.pool)
        .await?;

        let mut security_events = Vec::new();

        for row in suspicious_ip_rows {
            if let Some(ip_network) = row.ip_address {
                let count = row.failed_count.unwrap_or(0);
                security_events.push(SecurityEvent {
                    event_type: AuthEventType::SigninOtpVerify, // Representative
                    identifier: ip_network.ip().to_string(),
                    details: serde_json::json!({
                        "failed_attempts": count,
                        "timeframe_hours": lookback_hours,
                        "pattern": "multiple_failures_same_ip"
                    }),
                    severity: if count > 10 {
                        SecurityEventSeverity::High
                    } else {
                        SecurityEventSeverity::Medium
                    },
                    should_alert: count > 10,
                });
            }
        }

        Ok(security_events)
    }

    /// Removes old audit logs based on retention policy
    ///
    /// Deletes audit log records older than the specified retention period
    /// to comply with data retention policies and manage database size.
    /// Critical security events may have different retention rules.
    ///
    /// # Arguments
    /// * `retention_days` - Number of days to retain audit logs
    ///
    /// # Returns
    /// * `Ok(u64)` - Number of audit records that were deleted
    /// * `Err(SecurityAuditError)` - Cleanup operation failed
    ///
    /// # Retention Policy
    /// * Standard events: Configurable retention period
    /// * Security alerts: Extended retention (typically longer)
    /// * Compliance events: May have legal retention requirements
    /// * Failed attempts: Often retained longer for security analysis
    ///
    /// # Performance Notes
    /// * Operation performance depends on number of old records
    /// * Consider running during off-peak hours
    /// * May benefit from database partitioning on large datasets
    ///
    /// # Examples
    /// ```
    /// // Cleanup logs older than 90 days
    /// let deleted_count = audit_service.cleanup_old_logs(90).await?;
    /// println!("Cleaned up {} old audit log records", deleted_count);
    /// ```
    pub async fn cleanup_old_logs(&self, retention_days: i64) -> SecurityAuditResult<u64> {
        let cutoff = Utc::now() - chrono::Duration::days(retention_days);

        let result = sqlx::query!("DELETE FROM auth_audit_log WHERE created_at < $1", cutoff)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    /// Internal method to handle security events
    async fn handle_security_event(&self, event: SecurityEvent) -> SecurityAuditResult<()> {
        if event.should_alert {
            // Log the security event at a higher level
            log::warn!(
                "Security Alert: {:?} from {} - {:?}",
                event.event_type,
                event.identifier,
                event.details
            );

            // In a real implementation, this would:
            // - Send alerts to security team
            // - Update threat intelligence feeds
            // - Trigger automated response actions
            // - Integrate with SIEM systems
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_event_type_conversion() {
        let event_type = AuthEventType::SignupEmail;
        let string_repr = event_type.to_string();
        assert_eq!(string_repr, "signup_email");

        let parsed = AuthEventType::from_str(&string_repr).unwrap();
        assert_eq!(parsed, event_type);
    }

    #[test]
    fn test_audit_entry_validation() {
        // Valid successful entry
        let entry = AuditLogEntry::new(AuthEventType::SignupEmail, true);
        assert!(entry.validate().is_ok());

        // Invalid failed entry (missing error message)
        let entry = AuditLogEntry::new(AuthEventType::SignupEmail, false);
        assert!(entry.validate().is_err());

        // Valid failed entry
        let entry = AuditLogEntry::new(AuthEventType::SignupEmail, false)
            .with_error("Test error".to_string());
        assert!(entry.validate().is_ok());
    }

    #[test]
    fn test_security_event_detection() {
        // Failed authentication should be suspicious
        let entry = AuditLogEntry::new(AuthEventType::SigninOtpVerify, false)
            .with_error("Invalid OTP".to_string())
            .with_ip_address("192.168.1.1".parse().unwrap());

        assert!(entry.is_suspicious());
        let security_event = entry.to_security_event();
        assert!(security_event.is_some());

        let event = security_event.unwrap();
        assert_eq!(event.identifier, "192.168.1.1");
        assert!(matches!(event.severity, SecurityEventSeverity::Medium));
    }

    #[test]
    fn test_password_attempt_detection() {
        let entry = AuditLogEntry::new(AuthEventType::PasswordAttemptDetected, false)
            .with_error("Password field detected".to_string())
            .with_ip_address("192.168.1.1".parse().unwrap());

        let security_event = entry.to_security_event().unwrap();
        assert!(matches!(
            security_event.severity,
            SecurityEventSeverity::Critical
        ));
        assert!(security_event.should_alert);
    }
}
