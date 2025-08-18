//! Security Configuration
//!
//! Centralized configuration for all security-related settings including
//! rate limiting, audit logging, and authentication security measures.

use std::collections::HashMap;
use std::env;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::service::rate_limit_service::{RateLimit, RateLimitConfig};

/// Security configuration errors
#[derive(Error, Debug)]
pub enum SecurityConfigError {
    #[error("Missing required environment variable: {0}")]
    MissingEnvVar(String),

    #[error("Invalid configuration value for {key}: {value} - {reason}")]
    InvalidValue {
        key: String,
        value: String,
        reason: String,
    },

    #[error("Configuration validation error: {0}")]
    ValidationError(String),
}

/// Complete security configuration for the user service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Rate limiting configuration
    pub rate_limiting: RateLimitingConfig,

    /// Audit logging configuration
    pub audit_logging: AuditLoggingConfig,

    /// Authentication security configuration
    pub auth_security: AuthSecurityConfig,

    /// Monitoring and alerting configuration
    pub monitoring: MonitoringConfig,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    /// Whether rate limiting is enabled
    pub enabled: bool,

    /// Storage backend for rate limiting (database or redis)
    pub store: RateLimitStore,

    /// Rate limits for specific endpoints
    pub limits: RateLimitConfig,

    /// Global IP rate limiting
    pub global_ip_limit: RateLimit,

    /// Progressive backoff settings
    pub progressive_backoff: ProgressiveBackoffConfig,
}

/// Rate limiting storage backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RateLimitStore {
    Database,
    Redis { url: String },
    Memory, // For testing only
}

/// Progressive backoff configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressiveBackoffConfig {
    /// Enable progressive backoff
    pub enabled: bool,

    /// Multiplier for each subsequent failure
    pub multiplier: f64,

    /// Maximum backoff time in minutes
    pub max_backoff_minutes: u32,

    /// Reset backoff after successful authentication
    pub reset_on_success: bool,
}

/// Audit logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLoggingConfig {
    /// Whether audit logging is enabled
    pub enabled: bool,

    /// Log retention period in days
    pub retention_days: u32,

    /// Enable async logging (recommended for performance)
    pub async_logging: bool,

    /// Log failed authentication attempts
    pub log_failures: bool,

    /// Log successful authentication attempts
    pub log_successes: bool,

    /// Include IP address in logs
    pub include_ip: bool,

    /// Include user agent in logs
    pub include_user_agent: bool,

    /// Sensitive data filtering
    pub data_filtering: DataFilteringConfig,
}

/// Data filtering configuration for audit logs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFilteringConfig {
    /// Fields to exclude from logging
    pub excluded_fields: Vec<String>,

    /// Maximum length for logged values
    pub max_value_length: usize,

    /// Mask sensitive data
    pub mask_sensitive: bool,
}

/// Authentication security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSecurityConfig {
    /// Require HTTPS for all authentication endpoints
    pub require_https: bool,

    /// Enable CSRF protection
    pub csrf_protection: bool,

    /// Secure cookie settings
    pub secure_cookies: bool,

    /// Reject any password-related fields
    pub reject_password_fields: bool,

    /// Enable security headers
    pub security_headers: SecurityHeadersConfig,

    /// Session security settings
    pub session_security: SessionSecurityConfig,
}

/// Security headers configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeadersConfig {
    /// Enable Content Security Policy
    pub csp_enabled: bool,

    /// CSP directive
    pub csp_directive: String,

    /// Enable X-Frame-Options
    pub frame_options: bool,

    /// Enable X-Content-Type-Options
    pub content_type_options: bool,

    /// Enable Referrer-Policy
    pub referrer_policy: bool,

    /// Enable Permissions-Policy
    pub permissions_policy: bool,

    /// Enable HSTS
    pub hsts_enabled: bool,

    /// HSTS max age in seconds
    pub hsts_max_age: u32,
}

/// Session security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSecurityConfig {
    /// Session timeout in minutes
    pub timeout_minutes: u32,

    /// Maximum concurrent sessions per user
    pub max_concurrent_sessions: u32,

    /// Enable session fixation protection
    pub fixation_protection: bool,

    /// Regenerate session ID on authentication
    pub regenerate_on_auth: bool,
}

/// Monitoring and alerting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Enable security event monitoring
    pub enabled: bool,

    /// Alert on suspicious activity
    pub enable_alerts: bool,

    /// Threshold for suspicious activity detection
    pub suspicious_activity_threshold: u32,

    /// Alert on password attempts
    pub alert_on_password_attempts: bool,

    /// Monitoring endpoints
    pub endpoints: Vec<String>,

    /// Alert destinations
    pub alert_destinations: AlertDestinations,
}

/// Alert destination configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertDestinations {
    /// Email alerts
    pub email: Option<EmailAlertConfig>,

    /// Webhook alerts
    pub webhook: Option<WebhookAlertConfig>,

    /// Slack alerts
    pub slack: Option<SlackAlertConfig>,
}

/// Email alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAlertConfig {
    pub enabled: bool,
    pub recipients: Vec<String>,
    pub smtp_config: SmtpConfig,
}

/// SMTP configuration for email alerts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub use_tls: bool,
}

/// Webhook alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookAlertConfig {
    pub enabled: bool,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub timeout_seconds: u32,
}

/// Slack alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackAlertConfig {
    pub enabled: bool,
    pub webhook_url: String,
    pub channel: String,
    pub username: String,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            rate_limiting: RateLimitingConfig::default(),
            audit_logging: AuditLoggingConfig::default(),
            auth_security: AuthSecurityConfig::default(),
            monitoring: MonitoringConfig::default(),
        }
    }
}

impl Default for RateLimitingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            store: RateLimitStore::Database,
            limits: RateLimitConfig::default(),
            global_ip_limit: RateLimit::with_lockout(50, 60, 60),
            progressive_backoff: ProgressiveBackoffConfig::default(),
        }
    }
}

impl Default for ProgressiveBackoffConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            multiplier: 2.0,
            max_backoff_minutes: 60,
            reset_on_success: true,
        }
    }
}

impl Default for AuditLoggingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 90,
            async_logging: true,
            log_failures: true,
            log_successes: true,
            include_ip: true,
            include_user_agent: true,
            data_filtering: DataFilteringConfig::default(),
        }
    }
}

impl Default for DataFilteringConfig {
    fn default() -> Self {
        Self {
            excluded_fields: vec![
                "password".to_string(),
                "secret".to_string(),
                "token".to_string(),
                "key".to_string(),
            ],
            max_value_length: 1000,
            mask_sensitive: true,
        }
    }
}

impl Default for AuthSecurityConfig {
    fn default() -> Self {
        Self {
            require_https: true,
            csrf_protection: true,
            secure_cookies: true,
            reject_password_fields: true,
            security_headers: SecurityHeadersConfig::default(),
            session_security: SessionSecurityConfig::default(),
        }
    }
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            csp_enabled: true,
            csp_directive: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'".to_string(),
            frame_options: true,
            content_type_options: true,
            referrer_policy: true,
            permissions_policy: true,
            hsts_enabled: true,
            hsts_max_age: 31536000, // 1 year
        }
    }
}

impl Default for SessionSecurityConfig {
    fn default() -> Self {
        Self {
            timeout_minutes: 60,
            max_concurrent_sessions: 5,
            fixation_protection: true,
            regenerate_on_auth: true,
        }
    }
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            enable_alerts: true,
            suspicious_activity_threshold: 10,
            alert_on_password_attempts: true,
            endpoints: vec![
                "/auth/signup".to_string(),
                "/auth/signin".to_string(),
                "/auth/verify".to_string(),
            ],
            alert_destinations: AlertDestinations::default(),
        }
    }
}

impl Default for AlertDestinations {
    fn default() -> Self {
        Self {
            email: None,
            webhook: None,
            slack: None,
        }
    }
}

impl SecurityConfig {
    /// Load security configuration from environment variables
    pub fn from_env() -> Result<Self, SecurityConfigError> {
        let mut config = Self::default();

        // Rate limiting configuration
        config.rate_limiting.enabled = env_bool("AUTH_RATE_LIMIT_ENABLED", true);

        if let Ok(store) = env::var("AUTH_RATE_LIMIT_STORE") {
            config.rate_limiting.store = match store.as_str() {
                "database" => RateLimitStore::Database,
                "redis" => {
                    let redis_url = env::var("REDIS_URL")
                        .map_err(|_| SecurityConfigError::MissingEnvVar("REDIS_URL".to_string()))?;
                    RateLimitStore::Redis { url: redis_url }
                }
                "memory" => RateLimitStore::Memory,
                _ => {
                    return Err(SecurityConfigError::InvalidValue {
                        key: "AUTH_RATE_LIMIT_STORE".to_string(),
                        value: store,
                        reason: "Must be 'database', 'redis', or 'memory'".to_string(),
                    })
                }
            };
        }

        // Audit logging configuration
        config.audit_logging.enabled = env_bool("AUTH_AUDIT_LOGGING", true);
        config.audit_logging.retention_days = env_u32("AUTH_AUDIT_RETENTION_DAYS", 90);
        config.audit_logging.async_logging = env_bool("AUTH_AUDIT_ASYNC", true);

        // Authentication security configuration
        config.auth_security.require_https = env_bool("AUTH_REQUIRE_HTTPS", true);
        config.auth_security.csrf_protection = env_bool("AUTH_CSRF_PROTECTION", true);
        config.auth_security.secure_cookies = env_bool("AUTH_SECURE_COOKIES", true);
        config.auth_security.reject_password_fields = env_bool("AUTH_REJECT_PASSWORD_FIELDS", true);

        // Monitoring configuration
        config.monitoring.enabled = env_bool("AUTH_SECURITY_ALERTS_ENABLED", true);
        config.monitoring.suspicious_activity_threshold =
            env_u32("AUTH_SUSPICIOUS_ACTIVITY_THRESHOLD", 10);
        config.monitoring.alert_on_password_attempts =
            env_bool("AUTH_ALERT_ON_PASSWORD_ATTEMPTS", true);

        // Validate configuration
        config.validate()?;

        Ok(config)
    }

    /// Validate the security configuration
    pub fn validate(&self) -> Result<(), SecurityConfigError> {
        // Validate rate limiting configuration
        if self.rate_limiting.enabled {
            if self.rate_limiting.limits.email_signup.max_attempts == 0 {
                return Err(SecurityConfigError::ValidationError(
                    "Rate limit max_attempts must be greater than 0".to_string(),
                ));
            }

            if self.rate_limiting.progressive_backoff.enabled {
                if self.rate_limiting.progressive_backoff.multiplier <= 1.0 {
                    return Err(SecurityConfigError::ValidationError(
                        "Progressive backoff multiplier must be greater than 1.0".to_string(),
                    ));
                }
            }
        }

        // Validate audit logging configuration
        if self.audit_logging.enabled {
            if self.audit_logging.retention_days == 0 {
                return Err(SecurityConfigError::ValidationError(
                    "Audit log retention days must be greater than 0".to_string(),
                ));
            }
        }

        // Validate session security configuration
        if self.auth_security.session_security.timeout_minutes == 0 {
            return Err(SecurityConfigError::ValidationError(
                "Session timeout must be greater than 0".to_string(),
            ));
        }

        if self.auth_security.session_security.max_concurrent_sessions == 0 {
            return Err(SecurityConfigError::ValidationError(
                "Max concurrent sessions must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }

    /// Get rate limiting configuration
    pub fn get_rate_limit_config(&self) -> &RateLimitConfig {
        &self.rate_limiting.limits
    }

    /// Check if rate limiting is enabled
    pub fn is_rate_limiting_enabled(&self) -> bool {
        self.rate_limiting.enabled
    }

    /// Check if audit logging is enabled
    pub fn is_audit_logging_enabled(&self) -> bool {
        self.audit_logging.enabled
    }

    /// Check if security alerts are enabled
    pub fn are_security_alerts_enabled(&self) -> bool {
        self.monitoring.enabled && self.monitoring.enable_alerts
    }

    /// Get security headers configuration
    pub fn get_security_headers_config(&self) -> &SecurityHeadersConfig {
        &self.auth_security.security_headers
    }
}

// Helper functions for environment variable parsing
fn env_bool(key: &str, default: bool) -> bool {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u32(key: &str, default: u32) -> u32 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_security_config() {
        let config = SecurityConfig::default();
        assert!(config.rate_limiting.enabled);
        assert!(config.audit_logging.enabled);
        assert!(config.auth_security.require_https);
        assert!(config.monitoring.enabled);
    }

    #[test]
    fn test_security_config_validation() {
        let config = SecurityConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_rate_limit_config() {
        let mut config = SecurityConfig::default();
        config.rate_limiting.limits.email_signup.max_attempts = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_progressive_backoff() {
        let mut config = SecurityConfig::default();
        config.rate_limiting.progressive_backoff.multiplier = 0.5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_env_bool_parsing() {
        assert_eq!(env_bool("NONEXISTENT_VAR", true), true);
        assert_eq!(env_bool("NONEXISTENT_VAR", false), false);
    }

    #[test]
    fn test_env_u32_parsing() {
        assert_eq!(env_u32("NONEXISTENT_VAR", 42), 42);
    }
}
