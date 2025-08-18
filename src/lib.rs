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
//!     service::{UserService, JwtService},
//!     database::DatabaseConfig,
//! };
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Setup database and services
//!     let config = DatabaseConfig::from_env()?;
//!     let pool = config.create_pool().await?;
//!     let user_service = UserService::new(pool.clone());
//!     let jwt_service = JwtService::new(
//!         pool,
//!         "access_secret".to_string(),
//!         "refresh_secret".to_string(),
//!     );
//!
//!     // Create application state
//!     let app_state = AppState {
//!         user_service: Arc::new(user_service),
//!         jwt_service: Arc::new(jwt_service),
//!         oauth_service: None,
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

/// Configuration management for all service settings
pub mod config;

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
    oauth::{
        GoogleOAuthCallbackQuery, GoogleOAuthCallbackResponse, GoogleOAuthInitRequest,
        GoogleOAuthInitResponse, GoogleUserInfo, OAuthProvider, OAuthProviderType, OAuthState,
    },
    requests::{
        CreateUserRequest, OtpSigninEmailRequest, OtpSigninVerifyRequest,
        PasswordlessSignupRequest, RefreshTokenRequest, UpdateProfilePictureRequest,
        UpdateUserRequest, VerifyEmailRequest, VerifyPasswordRequest,
    },
    user::User,
    webauthn::{
        DeletePasskeyRequest, DeletePasskeyResponse, ListPasskeysRequest, ListPasskeysResponse,
        PasskeyAuthenticationBeginRequest, PasskeyAuthenticationBeginResponse,
        PasskeyAuthenticationFinishRequest, PasskeyAuthenticationFinishResponse,
        PasskeyRegistrationBeginRequest, PasskeyRegistrationBeginResponse,
        PasskeyRegistrationFinishRequest, PasskeyRegistrationFinishResponse, UpdatePasskeyRequest,
        UpdatePasskeyResponse, UserCredential, WebAuthnConfig,
    },
    EmailVerification, LoginOtp,
};
pub use service::{
    EmailService, JwtService, OAuthService, RateLimitService, SecurityAuditService, UserService,
    WebAuthnService,
};
pub use utils::error::{AppError, AppResult, ErrorResponse};

// Re-export database utilities for configuration
pub use database::{DatabaseConfig, DatabasePool};

// Re-export configuration system
pub use config::{
    env, AppConfig, EmailConfig, GoogleOAuthConfig, JwtConfig, OAuthConfig, SecurityConfig,
    ServerConfig,
};

/// Library version from Cargo.toml
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
