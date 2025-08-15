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
//! - **Database Integration**: PostgreSQL with connection pooling
//! - **Security First**: Protection against common vulnerabilities
//!
//! # Quick Start
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
//! # Architecture
//!
//! The library is organized into several layers:
//!
//! - **API Layer**: HTTP handlers and route definitions
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
//! - Rate limiting support structures

pub mod api;
pub mod database;
pub mod models;
pub mod service;
pub mod utils;

// Re-export commonly used types for convenience
pub use api::{create_routes, AppState};
pub use models::{
    requests::{CreateUserRequest, UpdateProfilePictureRequest, UpdateUserRequest, VerifyPasswordRequest},
    user::User,
};
pub use service::UserService;
pub use utils::error::{AppError, AppResult, ErrorResponse};

// Re-export database utilities
pub use database::{DatabaseConfig, DatabasePool};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default server configuration
pub mod config {
    /// Default server port
    pub const DEFAULT_PORT: u16 = 3000;
    
    /// Default server host
    pub const DEFAULT_HOST: &str = "0.0.0.0";
    
    /// Default log level
    pub const DEFAULT_LOG_LEVEL: &str = "info";
    
    /// Default bcrypt cost
    pub const DEFAULT_BCRYPT_COST: u32 = 12;
}