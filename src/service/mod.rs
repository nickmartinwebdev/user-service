//! Service Layer
//!
//! Business logic and data access layer for the user service, providing
//! comprehensive authentication and user management capabilities.
//!
//! This module contains the core business logic services that power the
//! passwordless authentication system. Each service is designed to be
//! composable, testable, and maintainable while providing enterprise-grade
//! security features.
//!
//! # Architecture
//!
//! The service layer follows a modular architecture where each service has
//! specific responsibilities and clear interfaces:
//!
//! ```text
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │   API Layer     │    │  Rate Limiting  │    │ Security Audit  │
//! │   (handlers)    │───▶│    Service      │───▶│    Service      │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//!          │                       │                       │
//!          ▼                       ▼                       ▼
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │  User Service   │    │  Email Service  │    │  JWT Service    │
//! │  (core CRUD)    │───▶│ (notifications) │    │ (auth tokens)   │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//!          │                       │                       │
//!          ▼                       ▼                       ▼
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │ WebAuthn Service│    │ OAuth Service   │    │    Database     │
//! │  (passkeys)     │    │ (social auth)   │    │     Layer       │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//! ```
//!
//! # Services Overview
//!
//! ## Core Services
//!
//! - **[`UserService`]**: Core user management operations including CRUD,
//!   password verification, and profile management
//! - **[`JwtService`]**: JWT token generation, validation, and session management
//! - **[`EmailService`]**: Email notifications for verification and passwordless flows
//!
//! ## Authentication Services
//!
//! - **[`WebAuthnService`]**: FIDO2/WebAuthn passkey authentication
//! - **[`OAuthService`]**: OAuth 2.0 social authentication (Google, etc.)
//!
//! ## Security Services
//!
//! - **[`RateLimitService`]**: Rate limiting and abuse prevention
//! - **[`SecurityAuditService`]**: Comprehensive audit logging and monitoring
//!
//! # Authentication Flows
//!
//! ## Passwordless Email Flow
//!
//! ```text
//! User → Email Signup → Email Verification → Account Created
//!   ↓
//! User → OTP Request → Email Sent → OTP Verification → JWT Tokens
//! ```
//!
//! ## Passkey Flow
//!
//! ```text
//! User → Registration Begin → Create Passkey → Registration Finish
//!   ↓
//! User → Auth Begin → Use Passkey → Auth Finish → JWT Tokens
//! ```
//!
//! ## OAuth Flow
//!
//! ```text
//! User → OAuth Init → Provider Auth → OAuth Callback → Account Link → JWT Tokens
//! ```
//!
//! # Security Features
//!
//! All services implement enterprise-grade security features:
//!
//! - **Rate Limiting**: Prevents brute force and abuse attacks
//! - **Audit Logging**: Complete audit trail for compliance and monitoring
//! - **Input Validation**: Comprehensive validation using the `validator` crate
//! - **Error Handling**: Consistent error types and secure error messages
//! - **Session Management**: Secure JWT token handling with refresh capabilities
//! - **CSRF Protection**: State tokens for OAuth and challenge-response for WebAuthn
//!
//! # Usage Examples
//!
//! ## Basic User Operations
//!
//! ```rust
//! use user_service::service::UserService;
//! use user_service::models::requests::CreateUserRequest;
//!
//! // Create user service
//! let user_service = UserService::new(db_pool);
//!
//! // Create new user
//! let request = CreateUserRequest {
//!     name: "John Doe".to_string(),
//!     email: "john@example.com".to_string(),
//!     password: "secure_password".to_string(),
//!     profile_picture_url: None,
//! };
//! let user = user_service.create_user(request).await?;
//! ```
//!
//! ## Passwordless Authentication
//!
//! ```rust
//! use user_service::service::{UserService, EmailService, JwtService};
//! use user_service::models::requests::PasswordlessSignupRequest;
//!
//! // Setup services
//! let email_service = Arc::new(EmailService::new(email_config)?);
//! let jwt_service = Arc::new(JwtService::new(db_pool.clone(), access_secret, refresh_secret));
//! let user_service = UserService::with_email_service(db_pool, email_service, jwt_service);
//!
//! // Passwordless signup
//! let request = PasswordlessSignupRequest {
//!     name: "Jane Smith".to_string(),
//!     email: "jane@example.com".to_string(),
//! };
//! let response = user_service.passwordless_signup(request).await?;
//! ```
//!
//! ## Rate Limiting
//!
//! ```rust
//! use user_service::service::{RateLimitService, RateLimitConfig};
//!
//! let rate_limiter = RateLimitService::new(db_pool, RateLimitConfig::default());
//!
//! // Check rate limit before processing
//! rate_limiter.check_email_rate_limit("user@example.com", "otp_verification").await?;
//! // Process request...
//! rate_limiter.record_email_attempt("user@example.com", "otp_verification", true).await?;
//! ```
//!
//! # Error Handling
//!
//! All services use strongly-typed error enums that implement the `Error` trait
//! and convert to the common `AppError` type for API responses:
//!
//! ```rust
//! use user_service::service::{UserService, UserServiceError};
//! use user_service::utils::error::AppError;
//!
//! match user_service.get_user_by_email("test@example.com").await {
//!     Ok(user) => println!("Found user: {}", user.name),
//!     Err(UserServiceError::UserNotFound) => println!("User not found"),
//!     Err(e) => {
//!         let app_error: AppError = e.into();
//!         println!("Error: {}", app_error);
//!     }
//! }
//! ```
//!
//! # Testing
//!
//! Services include comprehensive test suites with database integration:
//!
//! ```rust
//! #[sqlx::test]
//! async fn test_user_creation(pool: sqlx::PgPool) {
//!     let user_service = UserService::new(pool);
//!     let request = CreateUserRequest { /* ... */ };
//!     let user = user_service.create_user(request).await.unwrap();
//!     assert_eq!(user.email, "test@example.com");
//! }
//! ```
//!
//! # Configuration
//!
//! Services are configured through environment variables and configuration structs:
//!
//! ```rust
//! use user_service::service::{EmailService, EmailConfig};
//!
//! // Load from environment
//! let email_config = EmailConfig::from_env()?;
//! let email_service = EmailService::new(email_config)?;
//! ```
//!
//! # Performance Considerations
//!
//! - **Connection Pooling**: All services use sqlx connection pools for efficiency
//! - **Async Operations**: Full async/await support for non-blocking I/O
//! - **Caching**: JWT validation is stateless for high performance
//! - **Rate Limiting**: Protects against abuse while maintaining performance
//! - **Batch Operations**: Audit logging and cleanup operations are optimized
//!
//! # Compliance and Monitoring
//!
//! The service layer supports enterprise compliance requirements:
//!
//! - **GDPR**: User data management and deletion capabilities
//! - **SOX**: Complete audit trails for financial service compliance
//! - **HIPAA**: Secure handling of sensitive authentication data
//! - **PCI DSS**: Secure token handling and data protection
//!
//! For more information on specific services, see their individual documentation.

pub mod email_service;
pub mod jwt;
pub mod oauth_service;
pub mod rate_limit_service;
pub mod security_audit_service;
pub mod user;
pub mod webauthn_service;

// Re-export services
pub use email_service::{EmailConfig, EmailService};
pub use jwt::JwtService;
pub use oauth_service::OAuthService;
pub use rate_limit_service::{RateLimitConfig, RateLimitService, RateLimitStatus};
pub use security_audit_service::{AuditLogEntry, AuthEventType, SecurityAuditService};
pub use user::UserService;
pub use webauthn_service::WebAuthnService;
