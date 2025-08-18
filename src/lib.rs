//! User Service Library
//!
//! A comprehensive user management service providing secure CRUD operations,
//! authentication, and profile management. Designed for microservices architecture
//! with a focus on security, performance, and maintainability.
//!
//! # Features
//!
//! - **Secure User Management**: Complete CRUD operations with input validation
//! - **Password Security**: bcrypt hashing with configurable cost factors
//! - **Type Safety**: Compile-time query verification with SQLx
//! - **HTTP API**: RESTful endpoints with comprehensive error handling
//! - **Flexible Router**: Configurable endpoints via RouterBuilder pattern
//! - **Database Integration**: PostgreSQL with connection pooling
//! - **Security First**: Protection against common vulnerabilities
//!
//! # Quick Start
//!
//! ## As a Service Library
//!
//! ```rust,no_run
//! use user_service::{UserService, CreateUserRequest};
//! use sqlx::PgPool;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let pool = PgPool::connect("postgres://localhost/db").await?;
//!     let user_service = UserService::new(pool);
//!
//!     let request = CreateUserRequest {
//!         name: "Alice Smith".to_string(),
//!         email: "alice@example.com".to_string(),
//!         password: "SecurePass123!".to_string(),
//!         profile_picture_url: None,
//!     };
//!
//!     let user = user_service.create_user(request).await?;
//!     println!("Created user: {} ({})", user.name, user.email);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## As a Web Server Library
//!
//! ```rust,no_run
//! use user_service::{
//!     api::{AppState, RouterBuilder},
//!     service::UserService,
//!     database::DatabaseConfig,
//! };
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Setup database and service
//!     let config = DatabaseConfig::from_env()?;
//!     let pool = config.create_pool().await?;
//!     let user_service = UserService::new(pool);
//!
//!     // Create application state
//!     let app_state = AppState {
//!         user_service: Arc::new(user_service),
//!     };
//!
//!     // Build custom router - only enable needed endpoints
//!     let app = RouterBuilder::with_core_routes()
//!         .build()
//!         .with_state(app_state);
//!
//!     // Start server
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
//!     axum::serve(listener, app).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Router Builder Examples
//!
//! Create different service configurations:
//!
//! ```rust,no_run
//! use user_service::api::RouterBuilder;
//!
//! // Full service with all endpoints
//! let full_router = RouterBuilder::with_all_routes().build();
//!
//! // Authentication service
//! let auth_router = RouterBuilder::new()
//!     .health_check(true)
//!     .get_user(true)
//!     .verify_password(true)
//!     .build();
//!
//! // User directory (read-only)
//! let directory_router = RouterBuilder::with_readonly_routes().build();
//!
//! // Registration service
//! let registration_router = RouterBuilder::new()
//!     .health_check(true)
//!     .create_user(true)
//!     .build();
//! ```
//!
//! # Architecture
//!
//! The library is organized into several layers:
//!
//! - **API Layer**: HTTP handlers and configurable route definitions
//! - **Service Layer**: Business logic and data validation
//! - **Models**: Data structures and type definitions
//! - **Database**: Connection management and queries
//! - **Utils**: Shared utilities for security, validation, and error handling
//!
//! # Security
//!
//! - bcrypt password hashing with configurable cost
//! - SQL injection prevention through prepared statements
//! - Input validation and sanitization
//! - Security headers and CORS configuration
//! - Configurable endpoint exposure for attack surface reduction

/// HTTP API layer with handlers and configurable routing
pub mod api;

/// Database connection management and configuration
pub mod database;

/// Data models and request/response structures
pub mod models;

/// Business logic and user management services
pub mod service;

/// Shared utilities for security, validation, and error handling
pub mod utils;

// Re-export commonly used types for convenient access
pub use api::{create_routes, AppState, RouterBuilder};
pub use models::{
    auth::{TokenPair, UserContext},
    requests::{
        CreateUserRequest, OtpSigninEmailRequest, OtpSigninVerifyRequest,
        PasswordlessSignupRequest, RefreshTokenRequest, UpdateProfilePictureRequest,
        UpdateUserRequest, VerifyEmailRequest, VerifyPasswordRequest,
    },
    user::User,
    EmailVerification, LoginOtp,
};
pub use service::{EmailConfig, EmailService, JwtService, UserService};
pub use utils::error::{AppError, AppResult, ErrorResponse};

// Re-export database utilities for configuration
pub use database::{DatabaseConfig, DatabasePool};

// Re-export JWT configuration
pub use config::JwtConfig;

/// Library version from Cargo.toml
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default configuration constants for the service
pub mod config {
    /// Default HTTP server port for development
    pub const DEFAULT_PORT: u16 = 3000;

    /// Default server bind address (all interfaces)
    pub const DEFAULT_HOST: &str = "0.0.0.0";

    /// Default logging level for the application
    pub const DEFAULT_LOG_LEVEL: &str = "info";

    /// Default bcrypt cost factor for password hashing
    /// Higher values are more secure but slower
    pub const DEFAULT_BCRYPT_COST: u32 = 12;

    /// Default access token expiration time in hours
    pub const DEFAULT_ACCESS_TOKEN_EXPIRES_HOURS: i64 = 1;

    /// Default refresh token expiration time in days
    pub const DEFAULT_REFRESH_TOKEN_EXPIRES_DAYS: i64 = 30;

    /// JWT configuration for authentication
    #[derive(Debug, Clone)]
    pub struct JwtConfig {
        /// Secret key for signing access tokens
        pub access_secret: String,
        /// Secret key for signing refresh tokens
        pub refresh_secret: String,
        /// Access token expiration time in hours
        pub access_token_expires_hours: i64,
        /// Refresh token expiration time in days
        pub refresh_token_expires_days: i64,
    }

    impl JwtConfig {
        /// Create JWT configuration from environment variables
        pub fn from_env() -> Result<Self, std::env::VarError> {
            let access_secret = std::env::var("JWT_ACCESS_SECRET")?;
            let refresh_secret = std::env::var("JWT_REFRESH_SECRET")?;

            let access_token_expires_hours = std::env::var("JWT_ACCESS_EXPIRES_HOURS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_ACCESS_TOKEN_EXPIRES_HOURS);

            let refresh_token_expires_days = std::env::var("JWT_REFRESH_EXPIRES_DAYS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_REFRESH_TOKEN_EXPIRES_DAYS);

            Ok(Self {
                access_secret,
                refresh_secret,
                access_token_expires_hours,
                refresh_token_expires_days,
            })
        }
    }
}
