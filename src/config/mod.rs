//! Configuration Module
//!
//! Centralized configuration management for the user service, including
//! security, database, authentication, and service-specific settings.

pub mod security;

// Re-export configuration types for convenient access
pub use security::{
    AlertDestinations, AuditLoggingConfig, AuthSecurityConfig, DataFilteringConfig,
    EmailAlertConfig, MonitoringConfig, ProgressiveBackoffConfig, RateLimitingConfig,
    SecurityConfig, SecurityConfigError, SecurityHeadersConfig, SessionSecurityConfig,
    SlackAlertConfig, SmtpConfig, WebhookAlertConfig,
};

/// Environment variable helpers
pub mod env {
    use std::env;

    /// Get environment variable as string with default
    pub fn get_string(key: &str, default: &str) -> String {
        env::var(key).unwrap_or_else(|_| default.to_string())
    }

    /// Get environment variable as boolean with default
    pub fn get_bool(key: &str, default: bool) -> bool {
        env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// Get environment variable as u32 with default
    pub fn get_u32(key: &str, default: u32) -> u32 {
        env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// Get environment variable as u16 with default
    pub fn get_u16(key: &str, default: u16) -> u16 {
        env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// Get environment variable as f64 with default
    pub fn get_f64(key: &str, default: f64) -> f64 {
        env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// Get environment variable as u64 with default
    pub fn get_u64(key: &str, default: u64) -> u64 {
        env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// Get environment variable as usize with default
    pub fn get_usize(key: &str, default: usize) -> usize {
        env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// Get environment variable as i64 with default
    pub fn get_i64(key: &str, default: i64) -> i64 {
        env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// Check if environment variable is set
    pub fn is_set(key: &str) -> bool {
        env::var(key).is_ok()
    }

    /// Get required environment variable or panic
    pub fn get_required(key: &str) -> String {
        env::var(key).unwrap_or_else(|_| panic!("Required environment variable {} is not set", key))
    }
}

/// Application configuration combining all service configurations
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Security configuration
    pub security: SecurityConfig,

    /// Server configuration
    pub server: ServerConfig,

    /// Database configuration
    pub database: DatabaseConfig,

    /// JWT configuration
    pub jwt: JwtConfig,

    /// Email configuration
    pub email: Option<EmailConfig>,

    /// OAuth configuration
    pub oauth: Option<OAuthConfig>,

    /// WebAuthn configuration
    pub webauthn: Option<WebAuthnConfig>,
}

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub log_level: String,
    pub cors_origins: Vec<String>,
    pub request_timeout_seconds: u64,
    pub max_request_size: usize,
}

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub max_lifetime_seconds: u64,
}

/// JWT configuration
#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub access_secret: String,
    pub refresh_secret: String,
    pub access_token_expires_hours: i64,
    pub refresh_token_expires_days: i64,
    pub issuer: String,
    pub audience: String,
}

/// Email service configuration
#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_use_tls: bool,
    pub from_name: String,
    pub from_email: String,
    pub template_dir: String,
}

/// OAuth configuration
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub google_redirect_uri: Option<String>,
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    pub github_redirect_uri: Option<String>,
    pub state_expires_minutes: i64,
}

/// Google OAuth specific configuration
#[derive(Debug, Clone)]
pub struct GoogleOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub state_expires_minutes: i64,
}

/// WebAuthn configuration
#[derive(Debug, Clone)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
    pub require_resident_key: bool,
    pub user_verification: String,
    pub authenticator_attachment: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: env::get_string("SERVER_HOST", "0.0.0.0"),
            port: env::get_u16("SERVER_PORT", 3000),
            log_level: env::get_string("LOG_LEVEL", "info"),
            cors_origins: env::get_string("CORS_ORIGINS", "*")
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            request_timeout_seconds: env::get_u64("REQUEST_TIMEOUT_SECONDS", 30),
            max_request_size: env::get_usize("MAX_REQUEST_SIZE", 1024 * 1024), // 1MB
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: env::get_required("DATABASE_URL"),
            max_connections: env::get_u32("DB_MAX_CONNECTIONS", 10),
            min_connections: env::get_u32("DB_MIN_CONNECTIONS", 1),
            connect_timeout_seconds: env::get_u64("DB_CONNECT_TIMEOUT", 10),
            idle_timeout_seconds: env::get_u64("DB_IDLE_TIMEOUT", 600),
            max_lifetime_seconds: env::get_u64("DB_MAX_LIFETIME", 3600),
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            access_secret: env::get_required("JWT_ACCESS_SECRET"),
            refresh_secret: env::get_required("JWT_REFRESH_SECRET"),
            access_token_expires_hours: env::get_i64("JWT_ACCESS_EXPIRES_HOURS", 1),
            refresh_token_expires_days: env::get_i64("JWT_REFRESH_EXPIRES_DAYS", 30),
            issuer: env::get_string("JWT_ISSUER", "user-service"),
            audience: env::get_string("JWT_AUDIENCE", "user-service-api"),
        }
    }
}

impl EmailConfig {
    pub fn from_env() -> Option<Self> {
        if !env::is_set("SMTP_HOST") {
            return None;
        }

        Some(Self {
            smtp_host: env::get_required("SMTP_HOST"),
            smtp_port: env::get_u16("SMTP_PORT", 587),
            smtp_username: env::get_required("SMTP_USERNAME"),
            smtp_password: env::get_required("SMTP_PASSWORD"),
            smtp_use_tls: env::get_bool("SMTP_USE_TLS", true),
            from_name: env::get_string("SMTP_FROM_NAME", "User Service"),
            from_email: env::get_required("SMTP_FROM_EMAIL"),
            template_dir: env::get_string("EMAIL_TEMPLATE_DIR", "templates/email"),
        })
    }
}

impl OAuthConfig {
    pub fn from_env() -> Option<Self> {
        let google_enabled = env::is_set("GOOGLE_CLIENT_ID");
        let github_enabled = env::is_set("GITHUB_CLIENT_ID");

        if !google_enabled && !github_enabled {
            return None;
        }

        Some(Self {
            google_client_id: if google_enabled {
                Some(env::get_required("GOOGLE_CLIENT_ID"))
            } else {
                None
            },
            google_client_secret: if google_enabled {
                Some(env::get_required("GOOGLE_CLIENT_SECRET"))
            } else {
                None
            },
            google_redirect_uri: if google_enabled {
                Some(env::get_required("GOOGLE_REDIRECT_URI"))
            } else {
                None
            },
            github_client_id: if github_enabled {
                Some(env::get_required("GITHUB_CLIENT_ID"))
            } else {
                None
            },
            github_client_secret: if github_enabled {
                Some(env::get_required("GITHUB_CLIENT_SECRET"))
            } else {
                None
            },
            github_redirect_uri: if github_enabled {
                Some(env::get_required("GITHUB_REDIRECT_URI"))
            } else {
                None
            },
            state_expires_minutes: env::get_i64("OAUTH_STATE_EXPIRES_MINUTES", 10),
        })
    }
}

impl GoogleOAuthConfig {
    pub fn from_env() -> Option<Self> {
        if !env::is_set("GOOGLE_CLIENT_ID") {
            return None;
        }

        Some(Self {
            client_id: env::get_required("GOOGLE_CLIENT_ID"),
            client_secret: env::get_required("GOOGLE_CLIENT_SECRET"),
            redirect_uri: env::get_required("GOOGLE_REDIRECT_URI"),
            state_expires_minutes: env::get_i64("OAUTH_STATE_EXPIRES_MINUTES", 10),
        })
    }
}

impl WebAuthnConfig {
    pub fn from_env() -> Option<Self> {
        if !env::is_set("WEBAUTHN_RP_ID") {
            return None;
        }

        Some(Self {
            rp_id: env::get_required("WEBAUTHN_RP_ID"),
            rp_name: env::get_string("WEBAUTHN_RP_NAME", "User Service"),
            rp_origin: env::get_required("WEBAUTHN_RP_ORIGIN"),
            require_resident_key: env::get_bool("WEBAUTHN_REQUIRE_RESIDENT_KEY", false),
            user_verification: env::get_string("WEBAUTHN_USER_VERIFICATION", "preferred"),
            authenticator_attachment: if env::is_set("WEBAUTHN_AUTHENTICATOR_ATTACHMENT") {
                Some(env::get_string("WEBAUTHN_AUTHENTICATOR_ATTACHMENT", ""))
            } else {
                None
            },
        })
    }
}

impl AppConfig {
    /// Load complete application configuration from environment
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            security: SecurityConfig::from_env()?,
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            jwt: JwtConfig::default(),
            email: EmailConfig::from_env(),
            oauth: OAuthConfig::from_env(),
            webauthn: WebAuthnConfig::from_env(),
        })
    }

    /// Validate the complete configuration
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.security.validate()?;

        // Validate server configuration
        if self.server.port == 0 {
            return Err("Server port must be greater than 0".into());
        }

        // Validate database configuration
        if self.database.max_connections == 0 {
            return Err("Database max_connections must be greater than 0".into());
        }

        if self.database.min_connections > self.database.max_connections {
            return Err("Database min_connections cannot be greater than max_connections".into());
        }

        // Validate JWT configuration
        if self.jwt.access_secret.is_empty() {
            return Err("JWT access secret cannot be empty".into());
        }

        if self.jwt.refresh_secret.is_empty() {
            return Err("JWT refresh secret cannot be empty".into());
        }

        if self.jwt.access_secret == self.jwt.refresh_secret {
            return Err("JWT access and refresh secrets must be different".into());
        }

        Ok(())
    }
}

// Additional helper functions for environment variable parsing
mod env_helpers {
    use std::env;

    pub fn get_i64(key: &str, default: i64) -> i64 {
        env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    pub fn get_u64(key: &str, default: u64) -> u64 {
        env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    pub fn get_usize(key: &str, default: usize) -> usize {
        env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }
}

// Re-export helper functions
pub use env_helpers::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert_eq!(config.port, 3000);
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.log_level, "info");
    }

    #[test]
    fn test_env_helpers() {
        assert_eq!(env::get_bool("NONEXISTENT_BOOL", true), true);
        assert_eq!(env::get_bool("NONEXISTENT_BOOL", false), false);
        assert_eq!(env::get_u32("NONEXISTENT_U32", 42), 42);
        assert_eq!(env::get_string("NONEXISTENT_STRING", "default"), "default");
    }
}
