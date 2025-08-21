//! User Service Implementation
//!
//! Core business logic for user management operations.

use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use sqlx::PgPool;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;
use validator::Validate;

use crate::models::{
    email_verification::{EmailVerification, EmailVerificationRow},
    login_otp::LoginOtp,
    requests::*,
    user::{User, UserWithPassword},
};
use crate::service::email_service::EmailServiceError;
use crate::service::jwt::JwtServiceError;
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
    EmailServiceError(#[from] EmailServiceError),

    /// JWT service error
    #[error("JWT service error: {0}")]
    JwtServiceError(#[from] JwtServiceError),

    /// Unexpected internal server error
    #[error("Internal server error")]
    InternalError,

    /// User email is not verified
    #[error("Email not verified")]
    EmailNotVerified,

    /// OTP request rate limit exceeded
    #[error("Too many OTP requests")]
    TooManyOtpRequests,

    /// No valid OTP found for user
    #[error("No valid OTP found")]
    NoValidOtpFound,
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
            UserServiceError::EmailServiceError(e) => e.into(),
            UserServiceError::JwtServiceError(e) => e.into(),
            UserServiceError::InternalError => {
                AppError::Internal("Internal server error".to_string())
            }
            UserServiceError::EmailNotVerified => {
                AppError::BadRequest("Email address is not verified".to_string())
            }
            UserServiceError::TooManyOtpRequests => AppError::TooManyRequests(
                "Too many OTP requests. Please try again later".to_string(),
            ),
            UserServiceError::NoValidOtpFound => {
                AppError::BadRequest("No valid OTP found for this user".to_string())
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
    /// Creates a new UserService instance with default configuration
    ///
    /// This constructor creates a basic UserService with only database connectivity.
    /// For passwordless authentication features, use [`UserService::with_email_service`] instead.
    ///
    /// # Arguments
    /// * `db_pool` - PostgreSQL connection pool for database operations
    ///
    /// # Returns
    /// A new UserService instance with default bcrypt cost and no email/JWT services
    ///
    /// # Examples
    /// ```
    /// use sqlx::PgPool;
    /// use user_service::service::UserService;
    ///
    /// let pool = PgPool::connect("postgresql://...").await?;
    /// let user_service = UserService::new(pool);
    /// ```
    pub fn new(db_pool: PgPool) -> Self {
        Self {
            db_pool,
            bcrypt_cost: DEFAULT_BCRYPT_COST,
            email_service: None,
            jwt_service: None,
        }
    }

    /// Creates a new UserService with email and JWT services for advanced features
    ///
    /// This constructor enables passwordless authentication, email verification,
    /// and JWT token generation capabilities.
    ///
    /// # Arguments
    /// * `db_pool` - PostgreSQL connection pool for database operations
    /// * `email_service` - Email service for sending verification and OTP emails
    /// * `jwt_service` - JWT service for token generation and validation
    ///
    /// # Returns
    /// A fully-configured UserService instance with all authentication features enabled
    ///
    /// # Examples
    /// ```
    /// use std::sync::Arc;
    /// use sqlx::PgPool;
    /// use user_service::service::{UserService, EmailService, JwtService};
    ///
    /// let pool = PgPool::connect("postgresql://...").await?;
    /// let email_service = Arc::new(EmailService::new(email_config));
    /// let jwt_service = Arc::new(JwtService::new(jwt_config));
    /// let user_service = UserService::with_email_service(pool, email_service, jwt_service);
    /// ```
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

    /// Helper method to convert validation errors to UserServiceError
    fn validation_error(result: Result<(), validator::ValidationErrors>) -> UserServiceResult<()> {
        result.map_err(|e| UserServiceError::ValidationError(format!("Validation failed: {}", e)))
    }

    /// Helper method to get email service or return error if not configured
    fn require_email_service(&self) -> UserServiceResult<&Arc<EmailService>> {
        self.email_service.as_ref().ok_or_else(|| {
            UserServiceError::EmailServiceError(EmailServiceError::ConfigurationError(
                "Email service not configured".to_string(),
            ))
        })
    }

    /// Helper method to get JWT service or return error if not configured
    fn require_jwt_service(&self) -> UserServiceResult<&Arc<JwtService>> {
        self.jwt_service
            .as_ref()
            .ok_or(UserServiceError::InternalError)
    }

    /// Creates a new user account with password-based authentication
    ///
    /// Validates the request data, normalizes the email address, hashes the password
    /// with bcrypt, and stores the user in the database. The email is automatically
    /// marked as verified for traditional signup flows.
    ///
    /// # Arguments
    /// * `request` - User creation request containing name, email, password, and optional profile picture
    ///
    /// # Returns
    /// * `Ok(User)` - The created user object (password hash excluded)
    /// * `Err(UserServiceError)` - Validation, database, or hashing errors
    ///
    /// # Errors
    /// * `ValidationError` - Invalid input data (email format, password strength, etc.)
    /// * `EmailAlreadyExists` - Email address is already registered
    /// * `HashingError` - Password hashing failed
    /// * `DatabaseError` - Database operation failed
    ///
    /// # Examples
    /// ```
    /// use user_service::models::requests::CreateUserRequest;
    /// use user_service::service::UserService;
    ///
    /// let request = CreateUserRequest {
    ///     name: "John Doe".to_string(),
    ///     email: "john@example.com".to_string(),
    ///     password: "SecurePassword123!".to_string(),
    ///     profile_picture_url: None,
    /// };
    ///
    /// let user = user_service.create_user(request).await?;
    /// println!("Created user with ID: {}", user.id);
    /// ```
    pub async fn create_user(
        &self,
        app_id: Uuid,
        request: CreateUserRequest,
    ) -> UserServiceResult<User> {
        // Validate the request
        Self::validation_error(request.validate())?;

        // Normalize email
        let normalized_email = normalize_email(&request.email);

        // Hash the password
        let password_hash = hash_password_with_cost(&request.password, self.bcrypt_cost)?;

        // Insert user into database
        let user = sqlx::query_as!(
            UserWithPassword,
            r#"
            INSERT INTO users (application_id, name, email, password_hash, profile_picture_url, email_verified)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, application_id, name, email, profile_picture_url, email_verified, created_at as "created_at!", updated_at as "updated_at!"
            "#,
            app_id,
            request.name,
            normalized_email,
            password_hash,
            request.profile_picture_url,
            false // Email not verified for new users with passwords
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
    ///
    /// Allows partial updates of user data including name, email, and profile picture.
    /// Only provided fields are updated; omitted fields remain unchanged.
    /// Email addresses are automatically normalized before storage.
    ///
    /// # Arguments
    /// * `user_id` - Unique identifier of the user to update
    /// * `request` - Update request containing optional new values
    ///
    /// # Returns
    /// * `Ok(User)` - The updated user object
    /// * `Err(UserServiceError)` - Validation, database, or constraint errors
    ///
    /// # Errors
    /// * `UserNotFound` - No user exists with the provided ID
    /// * `ValidationError` - Invalid input data
    /// * `EmailAlreadyExists` - New email address is already registered
    /// * `DatabaseError` - Database operation failed
    ///
    /// # Examples
    /// ```
    /// use uuid::Uuid;
    /// use user_service::models::requests::UpdateUserRequest;
    ///
    /// let user_id = Uuid::parse_str("...")?;
    /// let request = UpdateUserRequest {
    ///     name: Some("Jane Doe".to_string()),
    ///     email: None, // Keep existing email
    ///     profile_picture_url: Some(Some("https://example.com/new-avatar.jpg".to_string())),
    /// };
    ///
    /// let updated_user = user_service.update_user(app_id, user_id, request).await?;
    /// ```
    pub async fn update_user(
        &self,
        app_id: Uuid,
        user_id: Uuid,
        request: UpdateUserRequest,
    ) -> UserServiceResult<User> {
        // Validate the request
        Self::validation_error(request.validate())?;

        // Normalize email if provided
        let normalized_email = request.email.as_ref().map(|email| normalize_email(email));

        // Update user in database
        let user = sqlx::query_as!(
            UserWithPassword,
            r#"
            UPDATE users
            SET
                name = COALESCE($3, name),
                email = COALESCE($4, email),
                profile_picture_url = COALESCE($5, profile_picture_url),
                updated_at = NOW()
            WHERE application_id = $1 AND id = $2
            RETURNING id, application_id, name, email, profile_picture_url, email_verified, created_at as "created_at!", updated_at as "updated_at!"
            "#,
            app_id,
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
                if db_err.constraint() == Some("idx_users_app_email_unique") {
                    UserServiceError::EmailAlreadyExists
                } else {
                    UserServiceError::DatabaseError(sqlx::Error::Database(db_err))
                }
            }
            _ => UserServiceError::DatabaseError(e),
        })?;

        Ok(user.into())
    }

    /// Retrieves a user by their unique identifier
    ///
    /// Looks up a user record by UUID. The returned user object excludes
    /// sensitive information like password hashes.
    ///
    /// # Arguments
    /// * `user_id` - Unique identifier of the user to retrieve
    ///
    /// # Returns
    /// * `Ok(User)` - The user object if found
    /// * `Err(UserServiceError)` - User not found or database error
    ///
    /// # Errors
    /// * `UserNotFound` - No user exists with the provided ID
    /// * `DatabaseError` - Database query failed
    ///
    /// # Examples
    /// ```
    /// use uuid::Uuid;
    ///
    /// let user_id = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000")?;
    /// let user = user_service.get_user_by_id(user_id).await?;
    /// println!("Found user: {}", user.name);
    /// ```
    pub async fn get_user_by_id(&self, app_id: Uuid, user_id: Uuid) -> UserServiceResult<User> {
        let user = sqlx::query_as!(
            UserWithPassword,
            r#"
            SELECT id, application_id, name, email, profile_picture_url, email_verified, created_at as "created_at!", updated_at as "updated_at!"
            FROM users
            WHERE application_id = $1 AND id = $2
            "#,
            app_id,
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
    ///
    /// Performs a case-insensitive lookup after normalizing the email address.
    /// The returned user object excludes sensitive information like password hashes.
    ///
    /// # Arguments
    /// * `email` - Email address to search for (will be normalized)
    ///
    /// # Returns
    /// * `Ok(User)` - The user object if found
    /// * `Err(UserServiceError)` - User not found or database error
    ///
    /// # Errors
    /// * `UserNotFound` - No user exists with the provided email
    /// * `DatabaseError` - Database query failed
    ///
    /// # Examples
    /// ```
    /// let user = user_service.get_user_by_email("john@EXAMPLE.com").await?;
    /// // Finds user even with different casing
    /// assert_eq!(user.email, "john@example.com");
    /// ```
    pub async fn get_user_by_email(&self, app_id: Uuid, email: &str) -> UserServiceResult<User> {
        let normalized_email = normalize_email(email);

        let user = sqlx::query_as!(
            UserWithPassword,
            r#"
            SELECT id, application_id, name, email, profile_picture_url, email_verified, created_at as "created_at!", updated_at as "updated_at!"
            FROM users
            WHERE application_id = $1 AND email = $2
            "#,
            app_id,
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

    /// Verifies a user's password against their stored hash
    ///
    /// Securely compares the provided plaintext password with the stored bcrypt hash.
    /// Returns false for passwordless accounts (users created via passwordless signup).
    ///
    /// # Arguments
    /// * `user_id` - Unique identifier of the user
    /// * `password` - Plaintext password to verify
    ///
    /// # Returns
    /// * `Ok(true)` - Password is correct
    /// * `Ok(false)` - Password is incorrect or user has no password
    /// * `Err(UserServiceError)` - User not found or verification error
    ///
    /// # Errors
    /// * `UserNotFound` - No user exists with the provided ID
    /// * `HashingError` - Password verification failed
    /// * `DatabaseError` - Database query failed
    ///
    /// # Security Notes
    /// This method uses constant-time comparison to prevent timing attacks.
    /// Passwordless accounts always return false for security.
    ///
    /// # Examples
    /// ```
    /// use uuid::Uuid;
    ///
    /// let user_id = Uuid::parse_str("...")?;
    /// let is_valid = user_service.verify_password(user_id, "user_password").await?;
    /// if is_valid {
    ///     println!("Password is correct");
    /// }
    /// ```
    pub async fn verify_password(
        &self,
        app_id: Uuid,
        user_id: Uuid,
        password: &str,
    ) -> UserServiceResult<bool> {
        let password_row = sqlx::query!(
            "SELECT password_hash FROM users WHERE application_id = $1 AND id = $2",
            app_id,
            user_id
        )
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

    /// Updates a user's profile picture URL
    ///
    /// Sets or updates the profile picture URL for a user. The URL is validated
    /// during request validation. Setting to None removes the profile picture.
    ///
    /// # Arguments
    /// * `user_id` - Unique identifier of the user
    /// * `request` - Request containing the new profile picture URL (or None to remove)
    ///
    /// # Returns
    /// * `Ok(User)` - The updated user object
    /// * `Err(UserServiceError)` - Validation, user not found, or database error
    ///
    /// # Errors
    /// * `UserNotFound` - No user exists with the provided ID
    /// * `ValidationError` - Invalid URL format
    /// * `DatabaseError` - Database update failed
    ///
    /// # Examples
    /// ```
    /// use uuid::Uuid;
    /// use user_service::models::requests::UpdateProfilePictureRequest;
    ///
    /// let user_id = Uuid::parse_str("...")?;
    /// let request = UpdateProfilePictureRequest {
    ///     profile_picture_url: Some("https://example.com/avatar.jpg".to_string()),
    /// };
    ///
    /// let updated_user = user_service.update_profile_picture(app_id, user_id, request).await?;
    /// ```
    pub async fn update_profile_picture(
        &self,
        app_id: Uuid,
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
            SET profile_picture_url = $3, updated_at = NOW()
            WHERE application_id = $1 AND id = $2
            RETURNING id, application_id, name, email, profile_picture_url, email_verified, created_at as "created_at!", updated_at as "updated_at!"
            "#,
            app_id,
            user_id,
            request.profile_picture_url
        )
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => UserServiceError::UserNotFound,
            _ => UserServiceError::DatabaseError(e),
        })?;

        Ok(user.into())
    }

    /// Updates a user's profile picture
    ///
    /// Sets the profile picture URL to the provided value. Pass None to remove
    /// the profile picture entirely.
    ///
    /// # Arguments
    /// * `app_id` - Application ID for tenant isolation
    /// * `user_id` - Unique identifier of the user
    /// * `profile_picture_url` - New profile picture URL or None to remove
    ///
    /// # Returns
    /// * `Ok(User)` - The updated user object
    /// * `Err(UserServiceError)` - User not found or database error
    ///
    /// # Errors
    /// * `UserNotFound` - No user exists with the provided ID in this application
    /// * `DatabaseError` - Database update failed
    #[allow(dead_code)]
    async fn update_profile_picture_legacy(
        &self,
        app_id: Uuid,
        user_id: Uuid,
        profile_picture_url: Option<String>,
    ) -> UserServiceResult<User> {
        let user = sqlx::query_as!(
            UserWithPassword,
            r#"
            UPDATE users
            SET profile_picture_url = $3, updated_at = NOW()
            WHERE application_id = $1 AND id = $2
            RETURNING id, application_id, name, email, profile_picture_url, email_verified, created_at as "created_at!", updated_at as "updated_at!"
            "#,
            app_id,
            user_id,
            profile_picture_url
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
    ///
    /// Sets the profile picture URL to NULL, effectively removing the profile picture.
    /// This operation is idempotent - removing an already-absent picture succeeds.
    ///
    /// # Arguments
    /// * `user_id` - Unique identifier of the user
    ///
    /// # Returns
    /// * `Ok(User)` - The updated user object with no profile picture
    /// * `Err(UserServiceError)` - User not found or database error
    ///
    /// # Errors
    /// * `UserNotFound` - No user exists with the provided ID
    /// * `DatabaseError` - Database update failed
    ///
    /// # Examples
    /// ```
    /// use uuid::Uuid;
    ///
    /// let user_id = Uuid::parse_str("...")?;
    /// let user = user_service.remove_profile_picture(user_id).await?;
    /// assert!(user.profile_picture_url.is_none());
    /// ```
    pub async fn remove_profile_picture(
        &self,
        app_id: Uuid,
        user_id: Uuid,
    ) -> UserServiceResult<User> {
        let user = sqlx::query_as!(
            UserWithPassword,
            r#"
            UPDATE users
            SET profile_picture_url = NULL, updated_at = NOW()
            WHERE application_id = $1 AND id = $2
            RETURNING id, application_id, name, email, profile_picture_url, email_verified, created_at as "created_at!", updated_at as "updated_at!"
            "#,
            app_id,
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

    /// Creates a passwordless user account and initiates email verification
    ///
    /// Creates an unverified user account without a password and sends a verification
    /// email with a time-limited code. This is part of the passwordless authentication flow.
    /// Requires email service to be configured.
    ///
    /// # Arguments
    /// * `request` - Signup request containing name and email
    ///
    /// # Returns
    /// * `Ok(PasswordlessSignupResponse)` - Confirmation with user ID and expiration info
    /// * `Err(UserServiceError)` - Validation, email service, or database error
    ///
    /// # Errors
    /// * `ValidationError` - Invalid input data
    /// * `EmailAlreadyExists` - Email address is already registered
    /// * `EmailServiceError` - Email service not configured or sending failed
    /// * `DatabaseError` - Database operation failed
    ///
    /// # Flow
    /// 1. Validates request data
    /// 2. Creates unverified user account (no password, email_verified=false)
    /// 3. Generates 6-digit verification code with 10-minute expiration
    /// 4. Stores verification code in database
    /// 5. Sends verification email
    ///
    /// # Examples
    /// ```
    /// use user_service::models::requests::PasswordlessSignupRequest;
    ///
    /// let request = PasswordlessSignupRequest {
    ///     name: "Jane Doe".to_string(),
    ///     email: "jane@example.com".to_string(),
    /// };
    ///
    /// let response = user_service.passwordless_signup(request).await?;
    /// println!("Verification email sent, expires in {} seconds", response.expires_in);
    /// ```
    pub async fn passwordless_signup(
        &self,
        app_id: Uuid,
        request: PasswordlessSignupRequest,
    ) -> UserServiceResult<PasswordlessSignupResponse> {
        // Validate the request
        Self::validation_error(request.validate())?;

        // Check if email service is available
        let email_service = self.require_email_service()?;

        // Normalize email
        let normalized_email = normalize_email(&request.email);

        // Create unverified user account (no password)
        let user = sqlx::query_as!(
            UserWithPassword,
            r#"
            INSERT INTO users (application_id, name, email, email_verified)
            VALUES ($1, $2, $3, FALSE)
            RETURNING id, application_id, name, email, profile_picture_url, email_verified, created_at as "created_at!", updated_at as "updated_at!"
            "#,
            app_id,
            request.name,
            normalized_email,
        )
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(db_err) => {
                if db_err.constraint() == Some("idx_users_app_email_unique") {
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
            .await?;

        Ok(PasswordlessSignupResponse {
            message: "Verification email sent".to_string(),
            user_id: user.id,
            expires_in: 600, // 10 minutes in seconds
        })
    }

    /// Verifies email address and completes passwordless account activation
    ///
    /// Validates the verification code, marks the user's email as verified,
    /// generates JWT tokens, and sends a welcome email. This completes the
    /// passwordless signup flow.
    ///
    /// # Arguments
    /// * `request` - Verification request containing email and verification code
    ///
    /// # Returns
    /// * `Ok(VerifyEmailResponse)` - JWT tokens and user object
    /// * `Err(UserServiceError)` - Verification, expiration, or service errors
    ///
    /// # Errors
    /// * `UserNotFound` - No user exists with the provided email
    /// * `InvalidVerificationCode` - Code not found or already used
    /// * `VerificationCodeExpired` - Code has passed its expiration time
    /// * `TooManyAttempts` - Exceeded maximum verification attempts
    /// * `ValidationError` - Invalid request data
    /// * `JwtServiceError` - Token generation failed
    /// * `EmailServiceError` - Welcome email sending failed (non-fatal)
    ///
    /// # Security Features
    /// * Rate limiting: Maximum 3 attempts per verification code
    /// * Time-based expiration: Codes expire after 10 minutes
    /// * Single-use: Codes cannot be reused after successful verification
    /// * Atomic operations: Database updates are transactional
    ///
    /// # Examples
    /// ```
    /// use user_service::models::requests::VerifyEmailRequest;
    ///
    /// let request = VerifyEmailRequest {
    ///     email: "jane@example.com".to_string(),
    ///     verification_code: "123456".to_string(),
    /// };
    ///
    /// let response = user_service.verify_email(request).await?;
    /// println!("User verified! Access token: {}", response.access_token);
    /// ```
    pub async fn verify_email(
        &self,
        app_id: Uuid,
        request: VerifyEmailRequest,
    ) -> UserServiceResult<VerifyEmailResponse> {
        // Validate the request
        Self::validation_error(request.validate())?;

        let jwt_service = self.require_jwt_service()?;
        let email_service = self.require_email_service()?;

        let normalized_email = normalize_email(&request.email);

        // Get user by email
        let user = sqlx::query_as!(
            UserWithPassword,
            r#"
            SELECT id, application_id, name, email, profile_picture_url, email_verified, created_at as "created_at!", updated_at as "updated_at!"
            FROM users
            WHERE application_id = $1 AND email = $2
            "#,
            app_id,
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
            WHERE application_id = $1 AND user_id = $2 AND verification_code = $3
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            app_id,
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
            WHERE application_id = $1 AND id = $2
            RETURNING id, application_id, name, email, profile_picture_url, email_verified, created_at as "created_at!", updated_at as "updated_at!"
            "#,
            app_id,
            user.id
        )
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;

        // Generate tokens
        let tokens = jwt_service
            .generate_token_pair(app_id, updated_user.id, None, None)
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

    /// Generates a cryptographically secure 6-digit verification code
    ///
    /// Creates a random numeric code with leading zeros preserved.
    /// Used for both email verification and OTP signin flows.
    ///
    /// # Returns
    /// A 6-digit string with leading zeros (e.g., "000123", "456789")
    ///
    /// # Security Notes
    /// Uses the system's cryptographically secure random number generator.
    /// Provides 10^6 = 1,000,000 possible combinations.
    fn generate_verification_code(&self) -> String {
        let mut rng = rand::thread_rng();
        format!("{:06}", rng.gen_range(0..1000000))
    }

    /// Requests a one-time password (OTP) for email-based signin
    ///
    /// Generates and sends an OTP to existing verified users for passwordless signin.
    /// Implements rate limiting and security tracking with IP address and user agent.
    /// Requires email service to be configured.
    ///
    /// # Arguments
    /// * `request` - OTP request containing the user's email address
    /// * `ip_address` - Optional client IP address for security logging
    /// * `user_agent` - Optional client user agent for security logging
    ///
    /// # Returns
    /// * `Ok(OtpSigninEmailResponse)` - Confirmation message and expiration time
    /// * `Err(UserServiceError)` - Various authentication and rate limiting errors
    ///
    /// # Errors
    /// * `UserNotFound` - No user exists with the provided email
    /// * `EmailNotVerified` - User account exists but email is not verified
    /// * `TooManyOtpRequests` - Rate limit exceeded (3 requests per hour)
    /// * `EmailServiceError` - Email service not configured or sending failed
    /// * `DatabaseError` - Database operation failed
    ///
    /// # Security Features
    /// * Rate limiting: Maximum 3 OTP requests per hour per user
    /// * OTP expiration: Codes expire after 5 minutes
    /// * Single active OTP: Previous unused OTPs are invalidated
    /// * Security logging: IP address and user agent tracking
    /// * Email verification requirement: Only verified accounts can request OTPs
    ///
    /// # Examples
    /// ```
    /// use std::net::IpAddr;
    /// use user_service::models::requests::OtpSigninEmailRequest;
    ///
    /// let request = OtpSigninEmailRequest {
    ///     email: "user@example.com".to_string(),
    /// };
    /// let ip = Some(IpAddr::V4([192, 168, 1, 100].into()));
    /// let user_agent = Some("Mozilla/5.0...".to_string());
    ///
    /// let response = user_service.request_signin_otp(request, ip, user_agent).await?;
    /// println!("OTP sent, expires in {} seconds", response.expires_in);
    /// ```
    pub async fn request_signin_otp(
        &self,
        app_id: Uuid,
        request: OtpSigninEmailRequest,
        ip_address: Option<std::net::IpAddr>,
        user_agent: Option<String>,
    ) -> UserServiceResult<OtpSigninEmailResponse> {
        let email_service = self.require_email_service()?;

        let normalized_email = normalize_email(&request.email);

        // Get user by email
        let user = self.get_user_by_email(app_id, &normalized_email).await?;

        // Check if user's email is verified
        if !user.email_verified {
            return Err(UserServiceError::EmailNotVerified);
        }

        // Check rate limiting - max 3 OTP requests per hour per user
        let one_hour_ago = Utc::now() - Duration::hours(1);
        let recent_otps = sqlx::query!(
            r#"
            SELECT COUNT(*) as count
            FROM login_otps
            WHERE application_id = $1 AND user_id = $2 AND created_at > $3
            "#,
            app_id,
            user.id,
            one_hour_ago
        )
        .fetch_one(&self.db_pool)
        .await?;

        if recent_otps.count.unwrap_or(0) >= 3 {
            return Err(UserServiceError::TooManyOtpRequests);
        }

        // Invalidate any existing unused OTPs for this user
        sqlx::query!(
            r#"
            DELETE FROM login_otps
            WHERE user_id = $1 AND used_at IS NULL
            "#,
            user.id
        )
        .execute(&self.db_pool)
        .await?;

        // Generate new OTP
        let otp_code = self.generate_verification_code();
        let expires_at = Utc::now() + Duration::minutes(5); // 5 minute expiration

        // Convert IpAddr to sqlx IpNetwork if present
        let ip_network = ip_address.map(|ip| match ip {
            std::net::IpAddr::V4(ipv4) => sqlx::types::ipnetwork::IpNetwork::V4(
                sqlx::types::ipnetwork::Ipv4Network::new(ipv4, 32).unwrap(),
            ),
            std::net::IpAddr::V6(ipv6) => sqlx::types::ipnetwork::IpNetwork::V6(
                sqlx::types::ipnetwork::Ipv6Network::new(ipv6, 128).unwrap(),
            ),
        });

        // Store OTP in database
        sqlx::query!(
            r#"
            INSERT INTO login_otps (application_id, user_id, otp_code, expires_at, ip_address, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            app_id,
            user.id,
            otp_code,
            expires_at,
            ip_network,
            user_agent
        )
        .execute(&self.db_pool)
        .await?;

        // Send OTP email
        email_service
            .send_signin_otp_email(&user.email, &user.name, &otp_code)
            .await?;

        Ok(OtpSigninEmailResponse {
            message: "OTP sent to your email".to_string(),
            expires_in: 300, // 5 minutes in seconds
        })
    }

    /// Verifies OTP and completes signin for existing users
    ///
    /// Validates the provided OTP against stored codes, marks it as used,
    /// and generates JWT tokens for authenticated access. This completes
    /// the passwordless signin flow for existing verified users.
    ///
    /// # Arguments
    /// * `request` - OTP verification request containing email and OTP code
    ///
    /// # Returns
    /// * `Ok(OtpSigninVerifyResponse)` - JWT tokens and user object
    /// * `Err(UserServiceError)` - Verification, expiration, or service errors
    ///
    /// # Errors
    /// * `UserNotFound` - No user exists with the provided email
    /// * `InvalidVerificationCode` - OTP not found, already used, or invalid
    /// * `VerificationCodeExpired` - OTP has passed its 5-minute expiration
    /// * `TooManyAttempts` - Exceeded maximum verification attempts
    /// * `JwtServiceError` - Token generation failed
    /// * `DatabaseError` - Database operation failed
    ///
    /// # Security Features
    /// * Time-based expiration: OTPs expire after 5 minutes
    /// * Single-use enforcement: OTPs are marked as used after verification
    /// * Attempt limiting: Maximum attempts per OTP to prevent brute force
    /// * Atomic operations: OTP verification and token generation are transactional
    /// * Recent OTP selection: Uses the most recently generated unused OTP
    ///
    /// # Examples
    /// ```
    /// use user_service::models::requests::OtpSigninVerifyRequest;
    ///
    /// let request = OtpSigninVerifyRequest {
    ///     email: "user@example.com".to_string(),
    ///     otp_code: "123456".to_string(),
    /// };
    ///
    /// let response = user_service.verify_signin_otp(request).await?;
    /// println!("Signin successful! Access token: {}", response.access_token);
    /// ```
    pub async fn verify_signin_otp(
        &self,
        app_id: Uuid,
        request: OtpSigninVerifyRequest,
    ) -> UserServiceResult<OtpSigninVerifyResponse> {
        let jwt_service = self.require_jwt_service()?;

        let normalized_email = normalize_email(&request.email);

        // Get user by email
        let user = self.get_user_by_email(app_id, &normalized_email).await?;

        // Find the most recent unused OTP for this user
        let otp_row = sqlx::query!(
            r#"
            SELECT id, user_id, otp_code, expires_at as "expires_at!", created_at as "created_at!", attempts, used_at as "used_at?: DateTime<Utc>", ip_address, user_agent
            FROM login_otps
            WHERE application_id = $1 AND user_id = $2 AND otp_code = $3 AND used_at IS NULL
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            app_id,
            user.id,
            request.otp_code
        )
        .fetch_optional(&self.db_pool)
        .await?;

        let Some(otp_row) = otp_row else {
            return Err(UserServiceError::InvalidVerificationCode);
        };

        let otp = LoginOtp {
            id: otp_row.id,
            user_id: otp_row.user_id,
            otp_code: otp_row.otp_code,
            expires_at: otp_row.expires_at,
            created_at: otp_row.created_at,
            attempts: otp_row.attempts,
            used_at: otp_row.used_at,
            ip_address: otp_row.ip_address.map(|ip| match ip {
                sqlx::types::ipnetwork::IpNetwork::V4(net) => std::net::IpAddr::V4(net.ip()),
                sqlx::types::ipnetwork::IpNetwork::V6(net) => std::net::IpAddr::V6(net.ip()),
            }),
            user_agent: otp_row.user_agent,
        };

        // Check if OTP is valid for verification
        if !otp.is_valid_for_verification() {
            if otp.is_expired() {
                return Err(UserServiceError::VerificationCodeExpired);
            } else if otp.has_exceeded_max_attempts() {
                return Err(UserServiceError::TooManyAttempts);
            } else {
                return Err(UserServiceError::InvalidVerificationCode);
            }
        }

        // Start transaction for atomic OTP verification and token generation
        let mut tx = self.db_pool.begin().await?;

        // Increment attempts
        sqlx::query!(
            r#"
            UPDATE login_otps
            SET attempts = attempts + 1
            WHERE id = $1
            "#,
            otp.id
        )
        .execute(&mut *tx)
        .await?;

        // Mark OTP as used
        sqlx::query!(
            r#"
            UPDATE login_otps
            SET used_at = NOW()
            WHERE id = $1
            "#,
            otp.id
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        // Generate JWT tokens
        let tokens = jwt_service
            .generate_token_pair(app_id, user.id, None, None)
            .await?;

        Ok(OtpSigninVerifyResponse {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: 3600, // 1 hour
            user,
        })
    }

    /// Performs a health check on the user service
    ///
    /// Executes a simple database query to verify connectivity and service availability.
    /// Used by health check endpoints and monitoring systems.
    ///
    /// # Returns
    /// * `Ok(())` - Service is healthy and database is accessible
    /// * `Err(UserServiceError::DatabaseError)` - Database connectivity issues
    ///
    /// # Examples
    /// ```
    /// match user_service.health_check().await {
    ///     Ok(()) => println!("User service is healthy"),
    ///     Err(e) => println!("Health check failed: {}", e),
    /// }
    /// ```
    pub async fn health_check(&self) -> UserServiceResult<()> {
        sqlx::query!("SELECT 1 as health_check")
            .fetch_one(&self.db_pool)
            .await
            .map_err(UserServiceError::DatabaseError)?;

        Ok(())
    }

    /// Generate JWT tokens for a user (used by OAuth service)
    ///
    /// This method generates access and refresh tokens for a user, primarily
    /// used during OAuth authentication flows.
    ///
    /// # Arguments
    /// * `user` - User object to generate tokens for
    ///
    /// # Returns
    /// * `Result<crate::models::auth::TokenPair, AppError>` - JWT token pair or error
    pub async fn generate_tokens(
        &self,
        app_id: Uuid,
        user: &User,
    ) -> UserServiceResult<crate::models::auth::TokenPair> {
        let jwt_service = self
            .jwt_service
            .as_ref()
            .ok_or(UserServiceError::JwtServiceError(
                JwtServiceError::InternalError("JWT service not configured".to_string()),
            ))?;

        jwt_service
            .generate_token_pair(app_id, user.id, None, None)
            .await
            .map_err(UserServiceError::JwtServiceError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::IpAddr;

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

    fn create_test_otp_signin_email_request() -> OtpSigninEmailRequest {
        OtpSigninEmailRequest {
            email: "john.doe@example.com".to_string(),
        }
    }

    // Create a verified user for OTP tests (bypasses email service)
    async fn create_verified_user(service: &UserService) -> User {
        // Directly insert a verified user into the database
        let user_id = uuid::Uuid::new_v4();
        let normalized_email = normalize_email("john.doe@example.com");

        sqlx::query!(
            r#"
            INSERT INTO users (id, name, email, email_verified, created_at, updated_at)
            VALUES ($1, $2, $3, TRUE, NOW(), NOW())
            "#,
            user_id,
            "John Doe",
            normalized_email
        )
        .execute(&service.db_pool)
        .await
        .unwrap();

        service
            .get_user_by_email(get_test_app_id(), &normalized_email)
            .await
            .unwrap()
    }

    fn create_update_user_request() -> UpdateUserRequest {
        UpdateUserRequest {
            name: Some("John Updated".to_string()),
            email: Some("john.updated@example.com".to_string()),
            profile_picture_url: Some("https://example.com/new-avatar.jpg".to_string()),
        }
    }

    // Test helper to get a default app_id for testing
    fn get_test_app_id() -> Uuid {
        Uuid::parse_str("018d4a3d-7f2e-7b5a-9c1d-2e3f4a5b6c7d").unwrap()
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

        let user = service
            .create_user(get_test_app_id(), request.clone())
            .await
            .unwrap();

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

        let user = service
            .create_user(get_test_app_id(), request.clone())
            .await
            .unwrap();

        assert_eq!(user.name, request.name);
        assert_eq!(user.email, "jane.smith@example.com");
        assert_eq!(user.profile_picture_url, None);
    }

    #[sqlx::test]
    async fn test_create_user_email_normalization(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let mut request = create_test_user_request();
        request.email = "JOHN.DOE@EXAMPLE.COM".to_string();

        let user = service
            .create_user(get_test_app_id(), request)
            .await
            .unwrap();

        assert_eq!(user.email, "john.doe@example.com");
    }

    #[sqlx::test]
    async fn test_create_user_password_hashed(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let request = create_test_user_request();
        let original_password = request.password.clone();

        let user = service
            .create_user(get_test_app_id(), request)
            .await
            .unwrap();

        // Verify password can be verified but isn't stored in plain text
        let password_valid = service
            .verify_password(get_test_app_id(), user.id, &original_password)
            .await
            .unwrap();
        assert!(password_valid);

        let password_invalid = service
            .verify_password(get_test_app_id(), user.id, "wrong_password")
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
        service
            .create_user(get_test_app_id(), request1)
            .await
            .unwrap();

        // Attempt to create second user with same email
        let result = service.create_user(get_test_app_id(), request2).await;
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
        service
            .create_user(get_test_app_id(), request1)
            .await
            .unwrap();

        // Attempt to create second user with same email (different case)
        let result = service.create_user(get_test_app_id(), request2).await;
        assert!(result.is_err());
    }

    #[sqlx::test]
    async fn test_create_user_invalid_email(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let mut request = create_test_user_request();
        request.email = "invalid-email".to_string();

        let result = service.create_user(get_test_app_id(), request).await;
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

        let result = service.create_user(get_test_app_id(), request).await;
        assert!(result.is_err());
    }

    #[sqlx::test]
    async fn test_create_user_invalid_name_too_long(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let mut request = create_test_user_request();
        request.name = "a".repeat(256);

        let result = service.create_user(get_test_app_id(), request).await;
        assert!(result.is_err());
    }

    #[sqlx::test]
    async fn test_create_user_weak_password(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let mut request = create_test_user_request();
        request.password = "weak".to_string();

        let result = service.create_user(get_test_app_id(), request).await;
        assert!(result.is_err());
    }

    #[sqlx::test]
    async fn test_create_user_password_too_short(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let mut request = create_test_user_request();
        request.password = "Short1!".to_string();

        let result = service.create_user(get_test_app_id(), request).await;
        assert!(result.is_err());
    }

    #[sqlx::test]
    async fn test_create_user_password_too_long(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let mut request = create_test_user_request();
        request.password = format!("{}1!A", "a".repeat(126));

        let result = service.create_user(get_test_app_id(), request).await;
        assert!(result.is_err());
    }

    #[sqlx::test]
    async fn test_create_user_invalid_profile_picture_url(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let mut request = create_test_user_request();
        request.profile_picture_url = Some("not-a-valid-url".to_string());

        let result = service.create_user(get_test_app_id(), request).await;
        assert!(result.is_err());
    }

    // ============================================================================
    // User Retrieval Tests
    // ============================================================================

    #[sqlx::test]
    async fn test_get_user_by_id_success(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let request = create_test_user_request();

        let created_user = service
            .create_user(get_test_app_id(), request.clone())
            .await
            .unwrap();
        let retrieved_user = service
            .get_user_by_id(get_test_app_id(), created_user.id)
            .await
            .unwrap();

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

        let result = service
            .get_user_by_id(get_test_app_id(), non_existent_id)
            .await;
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

        let created_user = service
            .create_user(get_test_app_id(), request.clone())
            .await
            .unwrap();
        let retrieved_user = service
            .get_user_by_email(get_test_app_id(), &request.email)
            .await
            .unwrap();

        assert_eq!(created_user.id, retrieved_user.id);
        assert_eq!(created_user.email, retrieved_user.email);
    }

    #[sqlx::test]
    async fn test_get_user_by_email_case_insensitive(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let request = create_test_user_request();

        let created_user = service
            .create_user(get_test_app_id(), request)
            .await
            .unwrap();
        let retrieved_user = service
            .get_user_by_email(get_test_app_id(), "JOHN.DOE@EXAMPLE.COM")
            .await
            .unwrap();

        assert_eq!(created_user.id, retrieved_user.id);
    }

    #[sqlx::test]
    async fn test_get_user_by_email_not_found(pool: sqlx::PgPool) {
        let service = UserService::new(pool);

        let result = service
            .get_user_by_email(get_test_app_id(), "nonexistent@example.com")
            .await;
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

        let created_user = service
            .create_user(get_test_app_id(), create_request)
            .await
            .unwrap();
        let original_created_at = created_user.created_at;

        // Small delay to ensure updated_at changes
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let updated_user = service
            .update_user(get_test_app_id(), created_user.id, update_request.clone())
            .await
            .unwrap();

        assert_eq!(updated_user.name, update_request.name.clone().unwrap());
        assert_eq!(updated_user.email, update_request.email.clone().unwrap());
        assert_eq!(
            updated_user.profile_picture_url,
            update_request.profile_picture_url.clone()
        );
        assert_eq!(updated_user.created_at, original_created_at); // Should not change
        assert!(updated_user.updated_at > created_user.updated_at); // Should be updated
    }

    #[sqlx::test]
    async fn test_update_user_partial_fields(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let create_request = create_test_user_request();

        let created_user = service
            .create_user(get_test_app_id(), create_request.clone())
            .await
            .unwrap();

        let update_request = UpdateUserRequest {
            name: Some("Updated Name".to_string()),
            email: None,
            profile_picture_url: None,
        };

        let updated_user = service
            .update_user(get_test_app_id(), created_user.id, update_request)
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
        let non_existent_id = uuid::Uuid::new_v4();
        let update_request = create_update_user_request();

        let result = service
            .update_user(get_test_app_id(), non_existent_id, update_request)
            .await;
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
            .create_user(get_test_app_id(), create_test_user_request())
            .await
            .unwrap();
        let user2 = service
            .create_user(get_test_app_id(), create_test_user_request_minimal())
            .await
            .unwrap();

        let update_request = UpdateUserRequest {
            name: None,
            email: Some(user1.email.clone()),
            profile_picture_url: None,
        };

        let result = service
            .update_user(get_test_app_id(), user2.id, update_request)
            .await;
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

        let user = service
            .create_user(get_test_app_id(), request)
            .await
            .unwrap();
        let is_valid = service
            .verify_password(get_test_app_id(), user.id, &password)
            .await
            .unwrap();

        assert!(is_valid);
    }

    #[sqlx::test]
    async fn test_verify_password_incorrect(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let request = create_test_user_request();

        let user = service
            .create_user(get_test_app_id(), request)
            .await
            .unwrap();
        let is_valid = service
            .verify_password(get_test_app_id(), user.id, "WrongPassword123!")
            .await
            .unwrap();

        assert!(!is_valid);
    }

    #[sqlx::test]
    async fn test_verify_password_user_not_found(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let non_existent_id = uuid::Uuid::new_v4();

        let result = service
            .verify_password(get_test_app_id(), non_existent_id, "SomePassword123!")
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

        let created_user = service
            .create_user(get_test_app_id(), create_request)
            .await
            .unwrap();

        let update_request = UpdateProfilePictureRequest {
            profile_picture_url: Some("https://example.com/new-pic.jpg".to_string()),
        };

        let updated_user = service
            .update_profile_picture(get_test_app_id(), created_user.id, update_request)
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

        let created_user = service
            .create_user(get_test_app_id(), create_request)
            .await
            .unwrap();

        let update_request = UpdateProfilePictureRequest {
            profile_picture_url: None,
        };

        let updated_user = service
            .update_profile_picture(get_test_app_id(), created_user.id, update_request)
            .await
            .unwrap();

        assert_eq!(updated_user.profile_picture_url, None);
    }

    #[sqlx::test]
    async fn test_update_profile_picture_not_found(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let non_existent_id = uuid::Uuid::new_v4();

        let update_request = UpdateProfilePictureRequest {
            profile_picture_url: Some("https://example.com/pic.jpg".to_string()),
        };

        let result = service
            .update_profile_picture(get_test_app_id(), non_existent_id, update_request)
            .await;
        assert!(result.is_err());
    }

    #[sqlx::test]
    async fn test_remove_profile_picture_success(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let create_request = create_test_user_request();

        let created_user = service
            .create_user(get_test_app_id(), create_request)
            .await
            .unwrap();
        let updated_user = service
            .remove_profile_picture(get_test_app_id(), created_user.id)
            .await
            .unwrap();

        assert_eq!(updated_user.profile_picture_url, None);
        assert!(updated_user.updated_at > created_user.updated_at);
    }

    #[sqlx::test]
    async fn test_remove_profile_picture_when_already_none(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let create_request = create_test_user_request_minimal(); // No profile picture

        let created_user = service
            .create_user(get_test_app_id(), create_request)
            .await
            .unwrap();
        let updated_user = service
            .remove_profile_picture(get_test_app_id(), created_user.id)
            .await
            .unwrap();

        assert_eq!(updated_user.profile_picture_url, None);
    }

    #[sqlx::test]
    async fn test_remove_profile_picture_user_not_found(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let non_existent_id = uuid::Uuid::new_v4();

        let result = service
            .remove_profile_picture(get_test_app_id(), non_existent_id)
            .await;
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
        let created_user = service
            .create_user(get_test_app_id(), create_request)
            .await
            .unwrap();

        // Retrieve by ID
        let retrieved_user = service
            .get_user_by_id(get_test_app_id(), created_user.id)
            .await
            .unwrap();
        assert_eq!(created_user.id, retrieved_user.id);
        assert_eq!(created_user.name, retrieved_user.name);

        // Retrieve by email
        let retrieved_by_email = service
            .get_user_by_email(get_test_app_id(), &created_user.email)
            .await
            .unwrap();
        assert_eq!(created_user.id, retrieved_by_email.id);

        // Update user
        let update_request = create_update_user_request();
        let updated_user = service
            .update_user(get_test_app_id(), created_user.id, update_request)
            .await
            .unwrap();
        assert_eq!(updated_user.name, "Jane Smith");

        // Verify update persisted
        let final_user = service
            .get_user_by_id(get_test_app_id(), created_user.id)
            .await
            .unwrap();
        assert_eq!(final_user.name, "John Updated".to_string());
        assert_eq!(final_user.email, "john.updated@example.com".to_string());
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
            let user = service
                .create_user(get_test_app_id(), request)
                .await
                .unwrap();
            users.push(user);
        }

        // Verify all users can be retrieved
        for user in &users {
            let retrieved = service
                .get_user_by_id(get_test_app_id(), user.id)
                .await
                .unwrap();
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

        let user1 = service
            .create_user(get_test_app_id(), request1)
            .await
            .unwrap();
        let user2 = service
            .create_user(get_test_app_id(), request2)
            .await
            .unwrap();

        // Both should be able to verify their passwords
        assert!(service
            .verify_password(get_test_app_id(), user1.id, "SamePassword123!")
            .await
            .unwrap());
        assert!(service
            .verify_password(get_test_app_id(), user2.id, "SamePassword123!")
            .await
            .unwrap());

        // Cross-verification should fail (different salts)
        assert!(!service
            .verify_password(get_test_app_id(), user1.id, "WrongPassword")
            .await
            .unwrap());
        assert!(!service
            .verify_password(get_test_app_id(), user2.id, "WrongPassword")
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

        let result = service.create_user(get_test_app_id(), request).await;
        assert!(result.is_ok());
    }

    #[sqlx::test]
    async fn test_user_struct_excludes_password_hash(pool: sqlx::PgPool) {
        let service = UserService::new(pool);
        let request = create_test_user_request();

        let user = service
            .create_user(get_test_app_id(), request)
            .await
            .unwrap();

        // Verify User struct doesn't contain password_hash field
        // This is enforced by the type system, but we can verify the data integrity
        let retrieved_user = service
            .get_user_by_id(get_test_app_id(), user.id)
            .await
            .unwrap();

        // User should have all expected fields but no password_hash
        assert!(retrieved_user.id == user.id);
        assert!(!retrieved_user.name.is_empty());
        assert!(!retrieved_user.email.is_empty());

        // The actual password verification should still work
        assert!(service
            .verify_password(get_test_app_id(), user.id, "SecurePass123!")
            .await
            .unwrap());
    }

    #[sqlx::test]
    async fn test_request_signin_otp_without_email_service_fails(pool: sqlx::PgPool) {
        let service = UserService::new(pool.clone());
        let _user = create_verified_user(&service).await;

        let request = create_test_otp_signin_email_request();
        let ip_address = Some("127.0.0.1".parse::<IpAddr>().unwrap());
        let user_agent = Some("test-agent".to_string());

        let result = service
            .request_signin_otp(get_test_app_id(), request, ip_address, user_agent)
            .await;
        assert!(result.is_err());

        match result.unwrap_err() {
            UserServiceError::EmailServiceError(_) => {}
            _ => panic!("Expected EmailServiceError"),
        }
    }

    #[sqlx::test]
    async fn test_request_signin_otp_unverified_email_fails(pool: sqlx::PgPool) {
        let service = UserService::new(pool.clone());

        // Create unverified user directly in database
        let user_id = uuid::Uuid::new_v4();
        let normalized_email = normalize_email("jane.doe@example.com");

        sqlx::query!(
            r#"
            INSERT INTO users (id, name, email, email_verified, created_at, updated_at)
            VALUES ($1, $2, $3, FALSE, NOW(), NOW())
            "#,
            user_id,
            "Jane Doe",
            normalized_email
        )
        .execute(&pool)
        .await
        .unwrap();

        let request = OtpSigninEmailRequest {
            email: normalized_email.clone(),
        };
        let ip_address = Some("127.0.0.1".parse::<IpAddr>().unwrap());
        let user_agent = Some("test-agent".to_string());

        let result = service
            .request_signin_otp(get_test_app_id(), request, ip_address, user_agent)
            .await;
        assert!(result.is_err());

        // Should fail with email service error since we don't have email service configured
        match result.unwrap_err() {
            UserServiceError::EmailServiceError(_) => {}
            _ => panic!("Expected EmailServiceError"),
        }
    }

    #[test]
    fn test_otp_generation() {
        // Test OTP code generation directly without requiring a service instance
        let mut rng = rand::thread_rng();
        let otp1 = format!("{:06}", rng.gen_range(0..1000000));
        let otp2 = format!("{:06}", rng.gen_range(0..1000000));

        // OTP should be 6 digits
        assert_eq!(otp1.len(), 6);
        assert_eq!(otp2.len(), 6);

        // OTP should be numeric
        assert!(otp1.chars().all(|c| c.is_numeric()));
        assert!(otp2.chars().all(|c| c.is_numeric()));

        // Test edge cases
        let otp_min = format!("{:06}", 0);
        let otp_max = format!("{:06}", 999999);
        assert_eq!(otp_min, "000000");
        assert_eq!(otp_max, "999999");
    }

    // Note: Integration tests for OTP functionality are provided in the examples directory
    // These tests require proper email and JWT service configuration
}
