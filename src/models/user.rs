//! User Model
//!
//! Core user data structures and type definitions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User representation for external API responses
///
/// This struct represents a user profile without sensitive information like password hashes.
/// All datetime fields use UTC timezone for consistency across different deployments.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    /// Unique identifier for the user
    pub id: Uuid,

    /// User's display name
    pub name: String,

    /// User's email address (unique, normalized)
    pub email: String,

    /// Whether the user's email address has been verified
    pub email_verified: bool,

    /// Optional URL to user's profile picture
    pub profile_picture_url: Option<String>,

    /// Timestamp when the user account was created
    pub created_at: DateTime<Utc>,

    /// Timestamp when the user profile was last modified
    pub updated_at: DateTime<Utc>,
}

/// Internal user representation including password hash
///
/// This struct is used internally for database operations that require access to the
/// password hash. It's never exposed in API responses for security reasons.
#[derive(Debug, sqlx::FromRow)]
pub(crate) struct UserWithPassword {
    /// Unique identifier for the user
    pub id: Uuid,

    /// User's display name
    pub name: String,

    /// User's email address
    pub email: String,

    /// bcrypt hashed password (optional for passwordless users)
    pub password_hash: Option<String>,

    /// Whether the user's email address has been verified
    pub email_verified: bool,

    /// Optional URL to user's profile picture
    pub profile_picture_url: Option<String>,

    /// Timestamp when the user account was created
    pub created_at: DateTime<Utc>,

    /// Timestamp when the user profile was last modified
    pub updated_at: DateTime<Utc>,
}

impl From<UserWithPassword> for User {
    /// Convert internal user representation to public user struct
    ///
    /// This conversion strips the password hash for security, ensuring it's never
    /// accidentally exposed in API responses.
    fn from(user_with_password: UserWithPassword) -> Self {
        User {
            id: user_with_password.id,
            name: user_with_password.name,
            email: user_with_password.email,
            email_verified: user_with_password.email_verified,
            profile_picture_url: user_with_password.profile_picture_url,
            created_at: user_with_password.created_at,
            updated_at: user_with_password.updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_with_password_conversion() {
        let user_with_password = UserWithPassword {
            id: Uuid::new_v4(),
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            password_hash: Some("hashed_password".to_string()),
            email_verified: true,
            profile_picture_url: Some("https://example.com/avatar.jpg".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let user: User = user_with_password.into();

        // Verify the conversion preserves all fields except password_hash
        assert_eq!(user.name, "Test User");
        assert_eq!(user.email, "test@example.com");
        assert_eq!(
            user.profile_picture_url,
            Some("https://example.com/avatar.jpg".to_string())
        );
    }
}
