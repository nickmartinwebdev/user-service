//! Application Models
//!
//! Data structures for multi-tenant application management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use super::webauthn::WebAuthnConfig;
use crate::utils::validation::name_validator;

/// Application/tenant configuration for multi-tenant service
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Application {
    pub id: Uuid,
    pub name: String,
    pub api_key: String,
    #[serde(skip_serializing)]
    pub api_secret_hash: String,
    pub allowed_origins: Vec<String>,
    #[sqlx(try_from = "sqlx::types::Json<ApplicationSettings>")]
    pub settings: ApplicationSettings,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Application-specific configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationSettings {
    #[serde(default)]
    pub email_config: Option<EmailConfig>,
    #[serde(default)]
    pub oauth_config: Option<OAuthConfig>,
    #[serde(default)]
    pub jwt_settings: JwtSettings,
    #[serde(default)]
    pub rate_limits: RateLimitConfig,
    #[serde(default)]
    pub webauthn_config: Option<WebAuthnConfig>,
    #[serde(default)]
    pub ui_settings: UiSettings,
}

/// Email configuration per application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub from_name: String,
    pub from_email: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub templates: EmailTemplates,
}

/// Email template settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailTemplates {
    pub verification_subject: String,
    pub verification_template: String,
    pub otp_subject: String,
    pub otp_template: String,
    pub welcome_subject: String,
    pub welcome_template: String,
}

/// OAuth configuration per application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub google: Option<GoogleOAuthConfig>,
    // Future: facebook, github, etc.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

/// JWT settings per application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtSettings {
    pub access_token_expires_hours: i64,
    pub refresh_token_expires_days: i64,
    pub issuer: String,
    pub audience: String,
}

impl Default for JwtSettings {
    fn default() -> Self {
        Self {
            access_token_expires_hours: 1,
            refresh_token_expires_days: 30,
            issuer: "user-service".to_string(),
            audience: "user-service-clients".to_string(),
        }
    }
}

/// Rate limiting configuration per application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub email_verification_per_hour: u32,
    pub otp_requests_per_hour: u32,
    pub password_attempts_per_hour: u32,
    pub account_creation_per_hour: u32,
    pub oauth_attempts_per_hour: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            email_verification_per_hour: 5,
            otp_requests_per_hour: 3,
            password_attempts_per_hour: 10,
            account_creation_per_hour: 5,
            oauth_attempts_per_hour: 10,
        }
    }
}

/// UI/branding settings per application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiSettings {
    pub app_name: String,
    pub logo_url: Option<String>,
    pub primary_color: String,
    pub login_url: String,
    pub signup_url: String,
    pub support_email: String,
}

impl Default for UiSettings {
    fn default() -> Self {
        Self {
            app_name: "My App".to_string(),
            logo_url: None,
            primary_color: "#007bff".to_string(),
            login_url: "/login".to_string(),
            signup_url: "/signup".to_string(),
            support_email: "support@example.com".to_string(),
        }
    }
}

impl Default for ApplicationSettings {
    fn default() -> Self {
        Self {
            email_config: None,
            oauth_config: None,
            jwt_settings: JwtSettings::default(),
            rate_limits: RateLimitConfig::default(),
            webauthn_config: None,
            ui_settings: UiSettings::default(),
        }
    }
}

/// Request to create a new application
#[derive(Debug, Deserialize, Validate)]
pub struct CreateApplicationRequest {
    #[validate(custom(function = "name_validator"))]
    pub name: String,

    #[validate(length(min = 1, message = "At least one allowed origin is required"))]
    pub allowed_origins: Vec<String>,

    #[serde(default)]
    pub settings: ApplicationSettings,
}

/// Response for application creation (includes API secret)
#[derive(Debug, Serialize)]
pub struct CreateApplicationResponse {
    pub id: Uuid,
    pub name: String,
    pub api_key: String,
    pub api_secret: String, // Only returned once during creation
    pub allowed_origins: Vec<String>,
    pub settings: ApplicationSettings,
    pub created_at: DateTime<Utc>,
}

/// Request to update an application
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateApplicationRequest {
    #[validate(custom(function = "name_validator"))]
    pub name: Option<String>,

    pub allowed_origins: Option<Vec<String>>,
    pub settings: Option<ApplicationSettings>,
    pub active: Option<bool>,
}

/// Application context for request processing
#[derive(Debug, Clone)]
pub struct AppContext {
    pub application_id: Uuid,
    pub application: Application,
}

/// Application authentication credentials
#[derive(Debug, Deserialize, Validate)]
pub struct ApplicationCredentials {
    #[validate(length(min = 1, message = "API key cannot be empty"))]
    pub api_key: String,

    #[validate(length(min = 1, message = "API secret cannot be empty"))]
    pub api_secret: String,
}

/// Application statistics for monitoring
#[derive(Debug, Serialize)]
pub struct ApplicationStats {
    pub total_users: i64,
    pub active_users_24h: i64,
    pub auth_events_24h: i64,
    pub failed_auth_events_24h: i64,
}

// Implement sqlx conversion for ApplicationSettings
impl From<sqlx::types::Json<ApplicationSettings>> for ApplicationSettings {
    fn from(json: sqlx::types::Json<ApplicationSettings>) -> Self {
        json.0
    }
}
