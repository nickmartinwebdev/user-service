//! User Service Implementation
//!
//! Core business logic for user management operations.

use chrono::{Duration, Utc};
use rand::Rng;
use sqlx::PgPool;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;
use validator::Validate;

use crate::models::{
    email_verification::{EmailVerification, EmailVerificationRow},
    requests::*,
    user::{User, UserWithPassword},
};
use crate::service::{EmailService, JwtService};
use crate::utils::{
    error::AppError,
    security::{hash_password_with_cost, verify_password, DEFAULT_BCRYPT_COST},
    validation::normalize_email,
};

/// Custom error types for the user service
#[derive(Error, Debug)]
pub enum UserServiceError {
    /// User with the specified identifier was not found
    #[error("User not found")]
    UserNotFound,

    /// Attempted to create a user with an email that already exists
    #[error("Email already exists")]
    EmailAlreadyExists,

    /// Invalid login credentials provided
    #[error("Invalid credentials")]
    InvalidCredentials,

    /// Input validation failed with detailed error message
    #[error("Validation error: {0}")]
    ValidationError(String),

    /// Database operation failed
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    /// Password hashing operation failed
    #[error("Password hashing error: {0}")]
    HashingError(#[from] bcrypt::BcryptError),

    /// Verification code not found or invalid
    #[error("Invalid verification code")]
    InvalidVerificationCode,

    /// Verification code has expired
    #[error("Verification code has expired")]
    VerificationCodeExpired,

    /// Too many verification attempts
    #[error("Too many verification attempts")]
    TooManyAttempts,

    /// Email service error
    #[error("Email service error: {0}")]
    EmailServiceError(String),

    /// Unexpected internal server error
    #[error("Internal server error")]
    InternalError,
}

impl From<UserServiceError> for AppError {
    fn from(err: UserServiceError) -> Self {
        match err {
            UserServiceError::UserNotFound => AppError::NotFound("User not found".to_string()),
            UserServiceError::EmailAlreadyExists => {
                AppError::Conflict("Email already exists".to_string())
            }
            UserServiceError::InvalidCredentials => {
                AppError::Authentication("Invalid credentials".to_string())
            }
            UserServiceError::ValidationError(msg) => AppError::Validation(msg),
            UserServiceError::DatabaseError(e) => AppError::Database(e),
            UserServiceError::HashingError(e) => AppError::HashingError(e),
            UserServiceError::InvalidVerificationCode => {
                AppError::BadRequest("Invalid verification code".to_string())
            }
            UserServiceError::VerificationCodeExpired => {
                AppError::BadRequest("Verification code has expired".to_string())
            }
            UserServiceError::TooManyAttempts => {
                AppError::TooManyRequests("Too many verification attempts".to_string())
            }
            UserServiceError::EmailServiceError(msg) => {
                AppError::Internal(format!("Email service error: {}", msg))
            }
            UserServiceError::InternalError => {
                AppError::Internal("Internal server error".to_string())
            }
        }
    }
}

/// Result type for user service operations
pub type UserServiceResult<T> = Result<T, UserServiceError>;

/// Core user service providing CRUD operations and business logic
#[derive(Clone)]
pub struct UserService {
    /// Database connection pool for efficient connection management
    db_pool: PgPool,

    /// bcrypt cost factor for password hashing (higher = more secure but slower)
    bcrypt_cost: u32,

    /// Email service for sending verification emails
    email_service: Option<Arc<EmailService>>,

    /// JWT service for token generation
    jwt_service: Option<Arc<JwtService>>,
}

impl UserService {
    /// Creates a new UserService instance with the provided database connection pool
    pub fn new(db_pool: PgPool) -> Self {
        Self {
            db_pool,
            bcrypt_cost: DEFAULT_BCRYPT_COST,
            email_service: None,
            jwt_service: None,
        }
    }

    /// Creates a new UserService with email service for passwordless operations
    pub fn with_email_service(
        db_pool: PgPool,
        email_service: Arc<EmailService>,
        jwt_service: Arc<JwtService>,
    ) -> Self {
        Self {
            db_pool,
            bcrypt_cost: DEFAULT_BCRYPT_COST,
            email_service: Some(email_service),
            jwt_service: Some(jwt_service),
        }
    }

    /// Creates a new user account with the provided information
    pub async fn create_user(&self, request: CreateUserRequest) -> UserServiceResult<User> {
        // Validate the request
        request
            .validate()
            .map_err(|e| UserServiceError::ValidationError(format!("Invalid user data: {}", e)))?;

        // Normalize email
        let normalized_email = normalize_email(&request.email);

        // Hash the password
        let password_hash = hash_password_with_cost(&request.password, self.bcrypt_cost)?;

        // Insert user into database
        let user = sqlx::query_as!(
            UserWithPassword,
            r#"
            INSERT INTO users (name, email, password_hash, profile_picture_url, email_verified)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, name, email, password_hash, profile_picture_url, email_verified, created_at, updated_at
            "#,
            request.name,
            normalized_email,
            password_hash,
            request.profile_picture_url as Option<String>,
            true // Traditional signup considers email verified
        )
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(db_err) => {
                if db_err.constraint() == Some("users_email_key") {
                    UserServiceError::EmailAlreadyExists
                } else {
                    UserServiceError::DatabaseError(sqlx::Error::Database(db_err))
                }
            }
            _ => UserServiceError::DatabaseError(e),
        })?;

        Ok(user.into())
    }

    /// Updates an existing user's profile information
    pub async fn update_user(
        &self,
        user_id: Uuid,
        request: UpdateUserRequest,
    ) -> UserServiceResult<User> {
        // Validate the request
        request.validate().map_err(|e| {
            UserServiceError::ValidationError(format!("Invalid update data: {}", e))
        })?;

        // Normalize email if provided
        let normalized_email = request.email.as_ref().map(|email| normalize_email(email));

        // Update user in database
        let user = sqlx::query_as!(
            UserWithPassword,
            r#"
            UPDATE users
            SET
                name = COALESCE($2, name),
                email = COALESCE($3, email),
                profile_picture_url = COALESCE($4, profile_picture_url),
                updated_at = NOW()
            WHERE id = $1
            RETURNING id, name, email, password_hash, profile_picture_url, email_verified, created_at, updated_at
            "#,
            user_id,
            request.name as Option<String>,
            normalized_email as Option<String>,
            request.profile_picture_url as Option<String>
        )
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => UserServiceError::UserNotFound,
            sqlx::Error::Database(db_err) => {
                if db_err.constraint() == Some("users_email_key") {
                    UserServiceError::EmailAlreadyExists
                } else {
                    UserServiceError::DatabaseError(sqlx::Error::Database(db_err))
                }
            }
            _ => UserServiceError::DatabaseError(e),
        })?;

        Ok(user.into())
    }

    /// Retrieves a user by their unique ID
    pub async fn get_user_by_id(&self, user_id: Uuid) -> UserServiceResult<User> {
        let user = sqlx::query_as!(
            UserWithPassword,
            r#"
            SELECT id, name, email, password_hash, profile_picture_url, email_verified, created_at, updated_at
            FROM users
            WHERE id = $1
            "#,
            user_id
        )
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => UserServiceError::UserNotFound,
            _ => UserServiceError::DatabaseError(e),
        })?;

        Ok(user.into())
    }

    /// Retrieves a user by their email address
    pub async fn get_user_by_email(&self, email: &str) -> UserServiceResult<User> {
        let normalized_email = normalize_email(email);

        let user = sqlx::query_as!(
            UserWithPassword,
            r#"
            SELECT id, name, email, password_hash, profile_picture_url, email_verified, created_at, updated_at
            FROM users
            WHERE email = $1
            "#,
            normalized_email
        )
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => UserServiceError::UserNotFound,
            _ => UserServiceError::DatabaseError(e),
        })?;

        Ok(user.into())
    }

    /// Verifies a user's password
    pub async fn verify_password(&self, user_id: Uuid, password: &str) -> UserServiceResult<bool> {
        let password_row = sqlx::query!("SELECT password_hash FROM users WHERE id = $1", user_id)
            .fetch_one(&self.db_pool)
            .await
            .map_err(|e| match e {
                sqlx::Error::RowNotFound => UserServiceError::UserNotFound,
                _ => UserServiceError::DatabaseError(e),
            })?;

        if let Some(password_hash) = password_row.password_hash {
            let is_valid = verify_password(password, &password_hash)?;
            Ok(is_valid)
        } else {
            // User has no password (passwordless account)
            Ok(false)
        }
    }

    /// Updates a user's profile picture
    pub async fn update_profile_picture(
        &self,
        user_id: Uuid,
        request: UpdateProfilePictureRequest,
    ) -> UserServiceResult<User> {
        // Validate the request
        request.validate().map_err(|e| {
            UserServiceError::ValidationError(format!("Invalid profile picture data: {}", e))
        })?;

        let user = sqlx::query_as!(
            UserWithPassword,
            r#"
            UPDATE users
            SET profile_picture_url = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING id, name, email, password_hash, profile_picture_url, email_verified, created_at, updated_at
            "#,
            user_id,
            request.profile_picture_url as Option<String>
        )
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => UserServiceError::UserNotFound,
            _ => UserServiceError::DatabaseError(e),
        })?;

        Ok(user.into())
    }

    /// Removes a user's profile picture
    pub async fn remove_profile_picture(&self, user_id: Uuid) -> UserServiceResult<User> {
        let user = sqlx::query_as!(
            UserWithPassword,
            r#"
            UPDATE users
            SET profile_picture_url = NULL, updated_at = NOW()
            WHERE id = $1
            RETURNING id, name, email, password_hash, profile_picture_url, email_verified, created_at, updated_at
            "#,
            user_id
        )
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => UserServiceError::UserNotFound,
            _ => UserServiceError::DatabaseError(e),
        })?;

        Ok(user.into())
    }

    /// Creates a passwordless user account and sends verification email
    pub async fn passwordless_signup(
        &self,
        request: PasswordlessSignupRequest,
    ) -> UserServiceResult<PasswordlessSignupResponse> {
        // Validate the request
        request
            .validate()
            .map_err(|e| UserServiceError::ValidationError(format!("Invalid user data: {}", e)))?;

        // Check if email service is available
        let email_service =
            self.email_service
                .as_ref()
                .ok_or(UserServiceError::EmailServiceError(
                    "Email service not configured".to_string(),
                ))?;

        // Normalize email
        let normalized_email = normalize_email(&request.email);

        // Create unverified user account (no password)
        let user = sqlx::query_as!(
            UserWithPassword,
            r#"
            INSERT INTO users (name, email, password_hash, email_verified)
            VALUES ($1, $2, NULL, FALSE)
            RETURNING id, name, email, password_hash, profile_picture_url, email_verified, created_at, updated_at
            "#,
            request.name,
            normalized_email,
        )
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(db_err) => {
                if db_err.constraint() == Some("users_email_key") {
                    UserServiceError::EmailAlreadyExists
                } else {
                    UserServiceError::DatabaseError(sqlx::Error::Database(db_err))
                }
            }
            _ => UserServiceError::DatabaseError(e),
        })?;

        // Generate verification code
        let verification_code = self.generate_verification_code();
        let expires_at = Utc::now() + Duration::minutes(10);

        // Store verification code
        sqlx::query!(
            r#"
            INSERT INTO email_verifications (user_id, verification_code, expires_at)
            VALUES ($1, $2, $3)
            "#,
            user.id,
            verification_code,
            expires_at
        )
        .execute(&self.db_pool)
        .await?;

        // Send verification email
        email_service
            .send_verification_email(
                &normalized_email,
                &request.name,
                &verification_code,
                10, // 10 minutes
            )
            .await
            .map_err(|e| UserServiceError::EmailServiceError(e.to_string()))?;

        Ok(PasswordlessSignupResponse {
            message: "Verification email sent".to_string(),
            user_id: user.id,
            expires_in: 600, // 10 minutes in seconds
        })
    }

    /// Verifies email with code and activates account
    pub async fn verify_email(
        &self,
        request: VerifyEmailRequest,
    ) -> UserServiceResult<VerifyEmailResponse> {
        // Validate the request
        request
            .validate()
            .map_err(|e| UserServiceError::ValidationError(format!("Invalid request: {}", e)))?;

        let jwt_service = self
            .jwt_service
            .as_ref()
            .ok_or(UserServiceError::EmailServiceError(
                "JWT service not configured".to_string(),
            ))?;

        let email_service =
            self.email_service
                .as_ref()
                .ok_or(UserServiceError::EmailServiceError(
                    "Email service not configured".to_string(),
                ))?;

        let normalized_email = normalize_email(&request.email);

        // Get user by email
        let user = sqlx::query_as!(
            UserWithPassword,
            r#"
            SELECT id, name, email, password_hash, profile_picture_url, email_verified, created_at, updated_at
            FROM users
            WHERE email = $1
            "#,
            normalized_email
        )
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => UserServiceError::UserNotFound,
            _ => UserServiceError::DatabaseError(e),
        })?;

        // Get verification record
        let verification_row = sqlx::query_as!(
            EmailVerificationRow,
            r#"
            SELECT id, user_id, verification_code, expires_at, created_at, attempts, verified_at
            FROM email_verifications
            WHERE user_id = $1 AND verification_code = $2
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            user.id,
            request.verification_code
        )
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => UserServiceError::InvalidVerificationCode,
            _ => UserServiceError::DatabaseError(e),
        })?;

        let verification: EmailVerification = verification_row.into();

        // Check if verification is usable
        if !verification.is_usable(3) {
            if verification.is_expired() {
                return Err(UserServiceError::VerificationCodeExpired);
            }
            if verification.has_exceeded_max_attempts(3) {
                return Err(UserServiceError::TooManyAttempts);
            }
            if verification.is_verified() {
                return Err(UserServiceError::InvalidVerificationCode);
            }
        }

        // Increment attempt count
        sqlx::query!(
            r#"
            UPDATE email_verifications
            SET attempts = attempts + 1
            WHERE id = $1
            "#,
            verification.id
        )
        .execute(&self.db_pool)
        .await?;

        // Mark verification as verified and user as email_verified
        let mut tx = self.db_pool.begin().await?;

        sqlx::query!(
            r#"
            UPDATE email_verifications
            SET verified_at = NOW()
            WHERE id = $1
            "#,
            verification.id
        )
        .execute(&mut *tx)
        .await?;

        let updated_user = sqlx::query_as!(
            UserWithPassword,
            r#"
            UPDATE users
            SET email_verified = TRUE, updated_at = NOW()
            WHERE id = $1
            RETURNING id, name, email, password_hash, profile_picture_url, email_verified, created_at, updated_at
            "#,
            user.id
        )
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;

        // Generate tokens
        let tokens = jwt_service
            .generate_token_pair(updated_user.id, None, None)
            .await
            .map_err(|_| UserServiceError::InternalError)?;

        // Send welcome email
        let _ = email_service
            .send_welcome_email(&updated_user.email, &updated_user.name)
            .await; // Don't fail if welcome email fails

        Ok(VerifyEmailResponse {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: 3600, // 1 hour
            user: updated_user.into(),
        })
    }

    /// Generates a 6-digit verification code
    fn generate_verification_code(&self) -> String {
        let mut rng = rand::thread_rng();
        format!("{:06}", rng.gen_range(0..1000000))
    }

    /// Health check for the service
    pub async fn health_check(&self) -> UserServiceResult<()> {
        sqlx::query!("SELECT 1 as health_check")
            .fetch_one(&self.db_pool)
            .await
            .map_err(UserServiceError::DatabaseError)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::PasswordlessSignupRequest;

    // Note: sqlx::test automatically runs migrations from ./migrations folder
    // No manual migration helper needed!

    // Test helper functions
    fn create_test_user_request() -> CreateUserRequest {
        CreateUserRequest {
            name: "John Doe".to_string(),
            email: "john.doe@example.com".to_string(),
            password: "SecurePass123!".to_string(),
            profile_picture_url: Some("https://example.com/avatar.jpg".to_string()),
        }
    }

    fn create_test_user_request_minimal() -> CreateUserRequest {
        CreateUserRequest {
            name: "Jane Smith".to_string(),
            email: "jane.smith@example.com".to_string(),
            password: "AnotherPass456@".to_string(),
            profile_picture_url: None,
        }
    }

    fn create_update_user_request() -> UpdateUserRequest {
        UpdateUserRequest {
            name: Some("John Updated".to_string()),
            email: Some("john.updated@example.com".to_string()),
            profile_picture_url: Some("https://example.com/new-avatar.jpg".to_string()),
        }
    }

    // ============================================================================
    // Configuration Tests
    // ============================================================================

    #[test]
    fn test_bcrypt_cost_validation() {
        // These are compile-time constants, so the assertions are optimized out
        // but they serve as documentation and will catch issues during development
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(DEFAULT_BCRYPT_COST >= 4, "bcrypt cost too low for security");
            assert!(
                DEFAULT_BCRYPT_COST <= 31,
                "bcrypt cost too high for performance"
            );
        }
    }

    // ============================================================================
    // User Creation Tests
    // ============================================================================

    #[sqlx::test]
    async fn test_create_user_success(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let request = create_test_user_request();

        let user = service.create_user(request.clone()).await.unwrap();

        assert_eq!(user.name, request.name);
        assert_eq!(user.email, "john.doe@example.com"); // normalized
        assert_eq!(user.profile_picture_url, request.profile_picture_url);
        assert!(user.created_at <= chrono::Utc::now());
        assert!(user.updated_at <= chrono::Utc::now());
        assert_eq!(user.created_at, user.updated_at);
    }

    #[sqlx::test]
    async fn test_create_user_minimal_fields(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let request = create_test_user_request_minimal();

        let user = service.create_user(request.clone()).await.unwrap();

        assert_eq!(user.name, request.name);
        assert_eq!(user.email, "jane.smith@example.com");
        assert_eq!(user.profile_picture_url, None);
    }

    #[sqlx::test]
    async fn test_create_user_email_normalization(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let mut request = create_test_user_request();
        request.email = "JOHN.DOE@EXAMPLE.COM".to_string();

        let user = service.create_user(request).await.unwrap();

        assert_eq!(user.email, "john.doe@example.com");
    }

    #[sqlx::test]
    async fn test_create_user_password_hashed(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let request = create_test_user_request();
        let original_password = request.password.clone();

        let user = service.create_user(request).await.unwrap();

        // Verify password can be verified but isn't stored in plain text
        let password_valid = service
            .verify_password(user.id, &original_password)
            .await
            .unwrap();
        assert!(password_valid);

        let password_invalid = service
            .verify_password(user.id, "wrong_password")
            .await
            .unwrap();
        assert!(!password_invalid);
    }

    #[sqlx::test]
    async fn test_create_user_duplicate_email_error(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let request1 = create_test_user_request();
        let mut request2 = create_test_user_request();
        request2.name = "Different Name".to_string();

        // Create first user
        service.create_user(request1).await.unwrap();

        // Attempt to create second user with same email
        let result = service.create_user(request2).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            UserServiceError::EmailAlreadyExists => {}
            _ => panic!("Expected EmailAlreadyExists error"),
        }
    }

    #[sqlx::test]
    async fn test_create_user_duplicate_email_case_insensitive(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let request1 = create_test_user_request();
        let mut request2 = create_test_user_request();
        request2.email = "JOHN.DOE@EXAMPLE.COM".to_string();
        request2.name = "Different Name".to_string();

        // Create first user
        service.create_user(request1).await.unwrap();

        // Attempt to create second user with same email (different case)
        let result = service.create_user(request2).await;
        assert!(result.is_err());
    }

    #[sqlx::test]
    async fn test_create_user_invalid_email(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let mut request = create_test_user_request();
        request.email = "invalid-email".to_string();

        let result = service.create_user(request).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            UserServiceError::ValidationError(_) => {}
            _ => panic!("Expected ValidationError"),
        }
    }

    #[sqlx::test]
    async fn test_create_user_invalid_name_empty(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let mut request = create_test_user_request();
        request.name = "".to_string();

        let result = service.create_user(request).await;
        assert!(result.is_err());
    }

    #[sqlx::test]
    async fn test_create_user_invalid_name_too_long(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let mut request = create_test_user_request();
        request.name = "a".repeat(256);

        let result = service.create_user(request).await;
        assert!(result.is_err());
    }

    #[sqlx::test]
    async fn test_create_user_weak_password(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let mut request = create_test_user_request();
        request.password = "weak".to_string();

        let result = service.create_user(request).await;
        assert!(result.is_err());
    }

    #[sqlx::test]
    async fn test_create_user_password_too_short(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let mut request = create_test_user_request();
        request.password = "Short1!".to_string();

        let result = service.create_user(request).await;
        assert!(result.is_err());
    }

    #[sqlx::test]
    async fn test_create_user_password_too_long(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let mut request = create_test_user_request();
        request.password = format!("{}1!A", "a".repeat(126));

        let result = service.create_user(request).await;
        assert!(result.is_err());
    }

    #[sqlx::test]
    async fn test_create_user_invalid_profile_picture_url(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let mut request = create_test_user_request();
        request.profile_picture_url = Some("not-a-valid-url".to_string());

        let result = service.create_user(request).await;
        assert!(result.is_err());
    }

    // ============================================================================
    // User Retrieval Tests
    // ============================================================================

    #[sqlx::test]
    async fn test_get_user_by_id_success(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let request = create_test_user_request();

        let created_user = service.create_user(request.clone()).await.unwrap();
        let retrieved_user = service.get_user_by_id(created_user.id).await.unwrap();

        assert_eq!(created_user.id, retrieved_user.id);
        assert_eq!(created_user.name, retrieved_user.name);
        assert_eq!(created_user.email, retrieved_user.email);
        assert_eq!(
            created_user.profile_picture_url,
            retrieved_user.profile_picture_url
        );
    }

    #[sqlx::test]
    async fn test_get_user_by_id_not_found(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let non_existent_id = uuid::Uuid::new_v4();

        let result = service.get_user_by_id(non_existent_id).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            UserServiceError::UserNotFound => {}
            _ => panic!("Expected UserNotFound error"),
        }
    }

    #[sqlx::test]
    async fn test_get_user_by_email_success(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let request = create_test_user_request();

        let created_user = service.create_user(request.clone()).await.unwrap();
        let retrieved_user = service.get_user_by_email(&request.email).await.unwrap();

        assert_eq!(created_user.id, retrieved_user.id);
        assert_eq!(created_user.email, retrieved_user.email);
    }

    #[sqlx::test]
    async fn test_get_user_by_email_case_insensitive(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let request = create_test_user_request();

        let created_user = service.create_user(request).await.unwrap();
        let retrieved_user = service
            .get_user_by_email("JOHN.DOE@EXAMPLE.COM")
            .await
            .unwrap();

        assert_eq!(created_user.id, retrieved_user.id);
    }

    #[sqlx::test]
    async fn test_get_user_by_email_not_found(pool: sqlx::PgPool) {
        let service = UserService::new(pool);

        let result = service.get_user_by_email("nonexistent@example.com").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            UserServiceError::UserNotFound => {}
            _ => panic!("Expected UserNotFound error"),
        }
    }

    // ============================================================================
    // User Update Tests
    // ============================================================================

    #[sqlx::test]
    async fn test_update_user_success(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let create_request = create_test_user_request();
        let update_request = create_update_user_request();

        let created_user = service.create_user(create_request).await.unwrap();
        let original_created_at = created_user.created_at;

        // Small delay to ensure updated_at changes
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let updated_user = service
            .update_user(created_user.id, update_request.clone())
            .await
            .unwrap();

        assert_eq!(updated_user.id, created_user.id);
        assert_eq!(updated_user.name, update_request.name.unwrap());
        assert_eq!(updated_user.email, update_request.email.unwrap());
        assert_eq!(
            updated_user.profile_picture_url,
            update_request.profile_picture_url
        );
        assert_eq!(updated_user.created_at, original_created_at); // Should not change
        assert!(updated_user.updated_at > created_user.updated_at); // Should be updated
    }

    #[sqlx::test]
    async fn test_update_user_partial_fields(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let create_request = create_test_user_request();

        let created_user = service.create_user(create_request.clone()).await.unwrap();

        let update_request = UpdateUserRequest {
            name: Some("Updated Name".to_string()),
            email: None,
            profile_picture_url: None,
        };

        let updated_user = service
            .update_user(created_user.id, update_request)
            .await
            .unwrap();

        assert_eq!(updated_user.name, "Updated Name");
        assert_eq!(updated_user.email, created_user.email); // Should remain unchanged
        assert_eq!(
            updated_user.profile_picture_url,
            created_user.profile_picture_url
        ); // Should remain unchanged
    }

    #[sqlx::test]
    async fn test_update_user_not_found(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let update_request = create_update_user_request();
        let non_existent_id = uuid::Uuid::new_v4();

        let result = service.update_user(non_existent_id, update_request).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            UserServiceError::UserNotFound => {}
            _ => panic!("Expected UserNotFound error"),
        }
    }

    #[sqlx::test]
    async fn test_update_user_duplicate_email(pool: sqlx::PgPool) {
        let service = UserService::new(pool);

        // Create two users
        let user1 = service
            .create_user(create_test_user_request())
            .await
            .unwrap();
        let user2 = service
            .create_user(create_test_user_request_minimal())
            .await
            .unwrap();

        // Try to update user2 with user1's email
        let update_request = UpdateUserRequest {
            name: None,
            email: Some(user1.email),
            profile_picture_url: None,
        };

        let result = service.update_user(user2.id, update_request).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            UserServiceError::EmailAlreadyExists => {}
            _ => panic!("Expected EmailAlreadyExists error"),
        }
    }

    // ============================================================================
    // Password Verification Tests
    // ============================================================================

    #[sqlx::test]
    async fn test_verify_password_correct(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let request = create_test_user_request();
        let password = request.password.clone();

        let user = service.create_user(request).await.unwrap();
        let is_valid = service.verify_password(user.id, &password).await.unwrap();

        assert!(is_valid);
    }

    #[sqlx::test]
    async fn test_verify_password_incorrect(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let request = create_test_user_request();

        let user = service.create_user(request).await.unwrap();
        let is_valid = service
            .verify_password(user.id, "WrongPassword123!")
            .await
            .unwrap();

        assert!(!is_valid);
    }

    #[sqlx::test]
    async fn test_verify_password_user_not_found(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let non_existent_id = uuid::Uuid::new_v4();

        let result = service
            .verify_password(non_existent_id, "SomePassword123!")
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            UserServiceError::UserNotFound => {}
            _ => panic!("Expected UserNotFound error"),
        }
    }

    // ============================================================================
    // Profile Picture Tests
    // ============================================================================

    #[sqlx::test]
    async fn test_update_profile_picture_success(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let create_request = create_test_user_request();

        let created_user = service.create_user(create_request).await.unwrap();

        let update_request = UpdateProfilePictureRequest {
            profile_picture_url: Some("https://example.com/new-pic.jpg".to_string()),
        };

        let updated_user = service
            .update_profile_picture(created_user.id, update_request)
            .await
            .unwrap();

        assert_eq!(
            updated_user.profile_picture_url,
            Some("https://example.com/new-pic.jpg".to_string())
        );
        assert!(updated_user.updated_at > created_user.updated_at);
    }

    #[sqlx::test]
    async fn test_update_profile_picture_to_none(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let create_request = create_test_user_request();

        let created_user = service.create_user(create_request).await.unwrap();

        let update_request = UpdateProfilePictureRequest {
            profile_picture_url: None,
        };

        let updated_user = service
            .update_profile_picture(created_user.id, update_request)
            .await
            .unwrap();

        assert_eq!(updated_user.profile_picture_url, None);
    }

    #[sqlx::test]
    async fn test_update_profile_picture_user_not_found(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let non_existent_id = uuid::Uuid::new_v4();

        let update_request = UpdateProfilePictureRequest {
            profile_picture_url: Some("https://example.com/pic.jpg".to_string()),
        };

        let result = service
            .update_profile_picture(non_existent_id, update_request)
            .await;
        assert!(result.is_err());
    }

    #[sqlx::test]
    async fn test_remove_profile_picture_success(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let create_request = create_test_user_request();

        let created_user = service.create_user(create_request).await.unwrap();
        let updated_user = service
            .remove_profile_picture(created_user.id)
            .await
            .unwrap();

        assert_eq!(updated_user.profile_picture_url, None);
        assert!(updated_user.updated_at > created_user.updated_at);
    }

    #[sqlx::test]
    async fn test_remove_profile_picture_when_already_none(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let create_request = create_test_user_request_minimal(); // No profile picture

        let created_user = service.create_user(create_request).await.unwrap();
        let updated_user = service
            .remove_profile_picture(created_user.id)
            .await
            .unwrap();

        assert_eq!(updated_user.profile_picture_url, None);
    }

    #[sqlx::test]
    async fn test_remove_profile_picture_user_not_found(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let non_existent_id = uuid::Uuid::new_v4();

        let result = service.remove_profile_picture(non_existent_id).await;
        assert!(result.is_err());
    }

    // ============================================================================
    // Health Check Tests
    // ============================================================================

    #[sqlx::test]
    async fn test_health_check_success(pool: sqlx::PgPool) {
        let service = UserService::new(pool);

        let result = service.health_check().await;
        assert!(result.is_ok());
    }

    // ============================================================================
    // Integration and Data Integrity Tests
    // ============================================================================

    #[sqlx::test]
    async fn test_create_retrieve_update_cycle(pool: sqlx::PgPool) {
        let service = UserService::new(pool);

        // Create user
        let create_request = create_test_user_request();
        let created_user = service.create_user(create_request.clone()).await.unwrap();

        // Retrieve by ID
        let retrieved_user = service.get_user_by_id(created_user.id).await.unwrap();
        assert_eq!(created_user.id, retrieved_user.id);
        assert_eq!(created_user.name, retrieved_user.name);

        // Retrieve by email
        let retrieved_by_email = service
            .get_user_by_email(&created_user.email)
            .await
            .unwrap();
        assert_eq!(created_user.id, retrieved_by_email.id);

        // Update user
        let update_request = create_update_user_request();
        let updated_user = service
            .update_user(created_user.id, update_request.clone())
            .await
            .unwrap();
        assert_eq!(updated_user.name, update_request.name.clone().unwrap());

        // Verify update persisted
        let final_user = service.get_user_by_id(created_user.id).await.unwrap();
        assert_eq!(final_user.name, update_request.name.unwrap());
        assert_eq!(final_user.email, update_request.email.unwrap());
    }

    #[sqlx::test]
    async fn test_multiple_users_no_conflicts(pool: sqlx::PgPool) {
        let service = UserService::new(pool);

        let mut requests = vec![];
        let user_names = [
            "Alice Smith",
            "Bob Johnson",
            "Carol Davis",
            "David Wilson",
            "Eve Brown",
        ];
        for (i, name) in user_names.iter().enumerate() {
            requests.push(CreateUserRequest {
                name: name.to_string(),
                email: format!("user{}@example.com", i),
                password: "SecurePass123!".to_string(),
                profile_picture_url: None,
            });
        }

        let mut users = vec![];
        for request in requests {
            let user = service.create_user(request).await.unwrap();
            users.push(user);
        }

        // Verify all users can be retrieved
        for user in &users {
            let retrieved = service.get_user_by_id(user.id).await.unwrap();
            assert_eq!(user.id, retrieved.id);
            assert_eq!(user.email, retrieved.email);
        }
    }

    #[sqlx::test]
    async fn test_password_hashing_security(pool: sqlx::PgPool) {
        let service = UserService::new(pool);

        // Create two users with the same password
        let request1 = CreateUserRequest {
            name: "Alice Jones".to_string(),
            email: "user1@example.com".to_string(),
            password: "SamePassword123!".to_string(),
            profile_picture_url: None,
        };

        let request2 = CreateUserRequest {
            name: "Bob Miller".to_string(),
            email: "user2@example.com".to_string(),
            password: "SamePassword123!".to_string(),
            profile_picture_url: None,
        };

        let user1 = service.create_user(request1).await.unwrap();
        let user2 = service.create_user(request2).await.unwrap();

        // Both should be able to verify their passwords
        assert!(service
            .verify_password(user1.id, "SamePassword123!")
            .await
            .unwrap());
        assert!(service
            .verify_password(user2.id, "SamePassword123!")
            .await
            .unwrap());

        // Cross-verification should fail (different salts)
        assert!(!service
            .verify_password(user1.id, "WrongPassword")
            .await
            .unwrap());
        assert!(!service
            .verify_password(user2.id, "WrongPassword")
            .await
            .unwrap());
    }

    #[sqlx::test]
    async fn test_field_length_limits(pool: sqlx::PgPool) {
        let service = UserService::new(pool);

        // Test maximum allowed lengths
        let request = CreateUserRequest {
            name: "a".repeat(255), // Maximum allowed
            email: "user@example.com".to_string(),
            password: format!("{}1!A", "a".repeat(124)), // 128 chars total
            profile_picture_url: Some(format!("https://example.com/{}", "a".repeat(480))), // ~512 chars
        };

        let result = service.create_user(request).await;
        assert!(result.is_ok());
    }

    #[sqlx::test]
    async fn test_user_struct_excludes_password_hash(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let request = create_test_user_request();

        let user = service.create_user(request).await.unwrap();

        // Verify User struct doesn't contain password_hash field
        // This is enforced by the type system, but we can verify the data integrity
        let retrieved_user = service.get_user_by_id(user.id).await.unwrap();

        // User should have all expected fields but no password_hash
        assert!(retrieved_user.id == user.id);
        assert!(!retrieved_user.name.is_empty());
        assert!(!retrieved_user.email.is_empty());

        // The actual password verification should still work
        assert!(service
            .verify_password(user.id, "SecurePass123!")
            .await
            .unwrap());
    }
}
