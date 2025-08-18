//! OAuth Models
//!
//! Data structures for OAuth 2.0 authentication flows and provider management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// OAuth provider record for linking external authentication accounts
///
/// This struct represents a connection between a local user account and an
/// external OAuth provider like Google, GitHub, etc. It stores the provider-specific
/// user ID and email, along with optional metadata.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct OAuthProvider {
    /// Unique identifier for this OAuth provider record
    pub id: Uuid,

    /// Reference to the local user account
    pub user_id: Uuid,

    /// OAuth provider name (e.g., "google", "github")
    pub provider: String,

    /// User ID from the OAuth provider
    pub provider_user_id: String,

    /// Email address from the OAuth provider
    pub provider_email: String,

    /// Additional provider-specific data (e.g., profile info, tokens)
    pub provider_data: Option<JsonValue>,

    /// Timestamp when the OAuth account was linked
    pub created_at: DateTime<Utc>,

    /// Timestamp when the record was last updated
    pub updated_at: DateTime<Utc>,
}

/// OAuth state token for CSRF protection during OAuth flows
///
/// This struct represents a temporary state token used to prevent CSRF attacks
/// during OAuth authorization flows. The token is generated when initiating
/// the OAuth flow and validated when the user returns from the provider.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct OAuthState {
    /// Unique identifier for this state record
    pub id: Uuid,

    /// Secure random state token
    pub state_token: String,

    /// Token expiration timestamp (typically 10 minutes from creation)
    pub expires_at: DateTime<Utc>,

    /// Optional redirect URL after successful authentication
    pub redirect_url: Option<String>,

    /// Timestamp when the state token was created
    pub created_at: DateTime<Utc>,
}

/// Google OAuth user information from the userinfo endpoint
///
/// This struct represents the user data returned by Google's OAuth2 userinfo
/// endpoint. It contains the essential user information needed to create or
/// link user accounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleUserInfo {
    /// Google user ID (unique identifier)
    pub id: String,

    /// User's email address
    pub email: String,

    /// Whether the email is verified by Google
    pub verified_email: bool,

    /// User's full name
    pub name: String,

    /// User's given name (first name)
    pub given_name: Option<String>,

    /// User's family name (last name)
    pub family_name: Option<String>,

    /// URL to user's profile picture
    pub picture: Option<String>,

    /// User's locale/language preference
    pub locale: Option<String>,
}

/// Request to initiate Google OAuth flow
///
/// This struct represents the request body for starting a Google OAuth
/// authentication flow. It allows specifying a redirect URL for after
/// successful authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleOAuthInitRequest {
    /// Optional redirect URL after successful authentication
    /// If not provided, a default redirect will be used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
}

/// Response from initiating Google OAuth flow
///
/// This struct represents the response returned when initiating a Google OAuth
/// flow. It contains the authorization URL where the user should be redirected
/// and the state token for CSRF protection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleOAuthInitResponse {
    /// Google OAuth authorization URL where user should be redirected
    pub authorization_url: String,

    /// State token for CSRF protection (should be validated on callback)
    pub state: String,
}

/// Google OAuth callback query parameters
///
/// This struct represents the query parameters that Google sends back to our
/// callback endpoint after user authorization. It includes the authorization
/// code and state token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleOAuthCallbackQuery {
    /// Authorization code from Google (exchanged for access token)
    pub code: Option<String>,

    /// State token for CSRF protection (must match our stored state)
    pub state: Option<String>,

    /// Error code if authorization was denied or failed
    pub error: Option<String>,

    /// Human-readable error description
    pub error_description: Option<String>,
}

/// Response from Google OAuth callback
///
/// This struct represents the response returned after successfully processing
/// a Google OAuth callback. It includes JWT tokens, user information, and
/// whether this was a new user registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleOAuthCallbackResponse {
    /// JWT access token for authenticated requests
    pub access_token: String,

    /// JWT refresh token for renewing access tokens
    pub refresh_token: String,

    /// User account information
    pub user: crate::models::user::User,

    /// Whether this was a new user registration (true) or existing user login (false)
    pub is_new_user: bool,
}

/// OAuth provider type enumeration
///
/// This enum represents the supported OAuth providers. It's used for
/// type-safe provider identification and can be extended to support
/// additional providers in the future.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OAuthProviderType {
    /// Google OAuth 2.0 provider
    Google,
}

impl std::fmt::Display for OAuthProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OAuthProviderType::Google => write!(f, "google"),
        }
    }
}

impl std::str::FromStr for OAuthProviderType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "google" => Ok(OAuthProviderType::Google),
            _ => Err(format!("Unknown OAuth provider: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_oauth_provider_type_display() {
        assert_eq!(OAuthProviderType::Google.to_string(), "google");
    }

    #[test]
    fn test_oauth_provider_type_from_str() {
        assert_eq!(
            "google".parse::<OAuthProviderType>().unwrap(),
            OAuthProviderType::Google
        );
        assert_eq!(
            "GOOGLE".parse::<OAuthProviderType>().unwrap(),
            OAuthProviderType::Google
        );
        assert!("invalid".parse::<OAuthProviderType>().is_err());
    }

    #[test]
    fn test_google_oauth_init_request_serialization() {
        let request = GoogleOAuthInitRequest {
            redirect_url: Some("https://example.com/dashboard".to_string()),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("redirect_url"));

        let request_without_redirect = GoogleOAuthInitRequest { redirect_url: None };

        let json = serde_json::to_string(&request_without_redirect).unwrap();
        assert!(!json.contains("redirect_url"));
    }

    #[test]
    fn test_google_user_info_deserialization() {
        let json = json!({
            "id": "123456789",
            "email": "user@example.com",
            "verified_email": true,
            "name": "John Doe",
            "given_name": "John",
            "family_name": "Doe",
            "picture": "https://example.com/avatar.jpg",
            "locale": "en"
        });

        let user_info: GoogleUserInfo = serde_json::from_value(json).unwrap();
        assert_eq!(user_info.id, "123456789");
        assert_eq!(user_info.email, "user@example.com");
        assert_eq!(user_info.name, "John Doe");
        assert_eq!(user_info.verified_email, true);
    }

    #[test]
    fn test_oauth_callback_query_deserialization() {
        let query = GoogleOAuthCallbackQuery {
            code: Some("auth_code_123".to_string()),
            state: Some("secure_state_token".to_string()),
            error: None,
            error_description: None,
        };

        let json = serde_json::to_string(&query).unwrap();
        let parsed: GoogleOAuthCallbackQuery = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.code, Some("auth_code_123".to_string()));
        assert_eq!(parsed.state, Some("secure_state_token".to_string()));
    }
}
