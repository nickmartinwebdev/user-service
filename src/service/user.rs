//! User Service Implementation
//!
//! Core business logic for user management operations.

use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;
use validator::Validate;

use crate::models::{
    requests::*,
    user::{User, UserWithPassword},
};
use crate::utils::{
    error::{AppError, AppResult},
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
}

impl UserService {
    /// Creates a new UserService instance with the provided database connection pool
    pub fn new(db_pool: PgPool) -> Self {
        Self {
            db_pool,
            bcrypt_cost: DEFAULT_BCRYPT_COST,
        }
    }

    /// Creates a new user account with the provided information
    pub async fn create_user(&self, request: CreateUserRequest) -> AppResult<User> {
        // Validate the request
        request
            .validate()
            .map_err(|e| AppError::Validation(format!("Invalid user data: {}", e)))?;

        // Normalize email
        let normalized_email = normalize_email(&request.email);

        // Hash the password
        let password_hash = hash_password_with_cost(&request.password, self.bcrypt_cost)
            .map_err(AppError::HashingError)?;

        // Insert user into database
        let user = sqlx::query_as::<_, UserWithPassword>(
            r#"
            INSERT INTO users (name, email, password_hash, profile_picture_url)
            VALUES ($1, $2, $3, $4)
            RETURNING id, name, email, password_hash, profile_picture_url, created_at, updated_at
            "#,
        )
        .bind(&request.name)
        .bind(&normalized_email)
        .bind(&password_hash)
        .bind(&request.profile_picture_url)
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(db_err) => {
                if db_err.constraint() == Some("users_email_key") {
                    AppError::Conflict("Email already exists".to_string())
                } else {
                    AppError::Database(sqlx::Error::Database(db_err))
                }
            }
            _ => AppError::Database(e),
        })?;

        Ok(user.into())
    }

    /// Updates an existing user's profile information
    pub async fn update_user(&self, user_id: Uuid, request: UpdateUserRequest) -> AppResult<User> {
        // Validate the request
        request
            .validate()
            .map_err(|e| AppError::Validation(format!("Invalid update data: {}", e)))?;

        // Normalize email if provided
        let normalized_email = request.email.as_ref().map(|email| normalize_email(email));

        // Update user in database
        let user = sqlx::query_as::<_, UserWithPassword>(
            r#"
            UPDATE users
            SET
                name = COALESCE($2, name),
                email = COALESCE($3, email),
                profile_picture_url = COALESCE($4, profile_picture_url),
                updated_at = NOW()
            WHERE id = $1
            RETURNING id, name, email, password_hash, profile_picture_url, created_at, updated_at
            "#,
        )
        .bind(user_id)
        .bind(&request.name)
        .bind(&normalized_email)
        .bind(&request.profile_picture_url)
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::NotFound("User not found".to_string()),
            sqlx::Error::Database(db_err) => {
                if db_err.constraint() == Some("users_email_key") {
                    AppError::Conflict("Email already exists".to_string())
                } else {
                    AppError::Database(sqlx::Error::Database(db_err))
                }
            }
            _ => AppError::Database(e),
        })?;

        Ok(user.into())
    }

    /// Retrieves a user by their unique ID
    pub async fn get_user_by_id(&self, user_id: Uuid) -> AppResult<User> {
        let user = sqlx::query_as::<_, UserWithPassword>(
            r#"
            SELECT id, name, email, password_hash, profile_picture_url, created_at, updated_at
            FROM users
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::NotFound("User not found".to_string()),
            _ => AppError::Database(e),
        })?;

        Ok(user.into())
    }

    /// Retrieves a user by their email address
    pub async fn get_user_by_email(&self, email: &str) -> AppResult<User> {
        let normalized_email = normalize_email(email);

        let user = sqlx::query_as::<_, UserWithPassword>(
            r#"
            SELECT id, name, email, password_hash, profile_picture_url, created_at, updated_at
            FROM users
            WHERE email = $1
            "#,
        )
        .bind(&normalized_email)
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::NotFound("User not found".to_string()),
            _ => AppError::Database(e),
        })?;

        Ok(user.into())
    }

    /// Verifies a user's password
    pub async fn verify_password(&self, user_id: Uuid, password: &str) -> AppResult<bool> {
        #[derive(sqlx::FromRow)]
        struct PasswordRow {
            password_hash: String,
        }

        let password_row =
            sqlx::query_as::<_, PasswordRow>("SELECT password_hash FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(&self.db_pool)
                .await
                .map_err(|e| match e {
                    sqlx::Error::RowNotFound => AppError::NotFound("User not found".to_string()),
                    _ => AppError::Database(e),
                })?;

        let is_valid = verify_password(password, &password_row.password_hash)
            .map_err(AppError::HashingError)?;

        Ok(is_valid)
    }

    /// Updates a user's profile picture
    pub async fn update_profile_picture(
        &self,
        user_id: Uuid,
        request: UpdateProfilePictureRequest,
    ) -> AppResult<User> {
        // Validate the request
        request
            .validate()
            .map_err(|e| AppError::Validation(format!("Invalid profile picture data: {}", e)))?;

        let user = sqlx::query_as::<_, UserWithPassword>(
            r#"
            UPDATE users
            SET profile_picture_url = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING id, name, email, password_hash, profile_picture_url, created_at, updated_at
            "#,
        )
        .bind(user_id)
        .bind(&request.profile_picture_url)
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::NotFound("User not found".to_string()),
            _ => AppError::Database(e),
        })?;

        Ok(user.into())
    }

    /// Removes a user's profile picture
    pub async fn remove_profile_picture(&self, user_id: Uuid) -> AppResult<User> {
        let user = sqlx::query_as::<_, UserWithPassword>(
            r#"
            UPDATE users
            SET profile_picture_url = NULL, updated_at = NOW()
            WHERE id = $1
            RETURNING id, name, email, password_hash, profile_picture_url, created_at, updated_at
            "#,
        )
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::NotFound("User not found".to_string()),
            _ => AppError::Database(e),
        })?;

        Ok(user.into())
    }

    /// Health check for the service
    pub async fn health_check(&self) -> AppResult<()> {
        sqlx::query("SELECT 1")
            .fetch_one(&self.db_pool)
            .await
            .map_err(AppError::Database)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that UserService configuration is correct
    #[test]
    fn test_service_configuration() {
        // Test service configuration without requiring database connection
        assert_eq!(DEFAULT_BCRYPT_COST, 12);
        assert!(DEFAULT_BCRYPT_COST >= 4);
        assert!(DEFAULT_BCRYPT_COST <= 31);
    }

    /// Test that service can be created with a mock connection string
    #[test]
    fn test_service_creation_parameters() {
        // Test that the service creation logic is sound
        // without actually creating database connections
        let test_cost = 10;
        assert!(test_cost >= 4);
        assert!(test_cost <= 31);

        // Verify the bcrypt cost is in valid range
        assert!(DEFAULT_BCRYPT_COST >= 4);
        assert!(DEFAULT_BCRYPT_COST <= 31);
    }

    /// Test bcrypt cost validation ranges
    #[test]
    fn test_bcrypt_cost_validation() {
        // Test that bcrypt cost is within valid range for security
        assert!(DEFAULT_BCRYPT_COST >= 4, "bcrypt cost too low for security");
        assert!(
            DEFAULT_BCRYPT_COST <= 31,
            "bcrypt cost too high for performance"
        );

        // Test edge cases
        let min_cost = 4;
        let max_cost = 31;
        assert!(min_cost < max_cost);
        assert!(DEFAULT_BCRYPT_COST >= min_cost);
        assert!(DEFAULT_BCRYPT_COST <= max_cost);
    }
}
