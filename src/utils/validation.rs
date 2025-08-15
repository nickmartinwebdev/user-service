//! Validation Utilities
//!
//! Input validation functions for user data and API requests.

use regex::Regex;
use std::sync::OnceLock;
use validator::ValidationError;

/// Validates email address format using a comprehensive regex pattern
pub fn validate_email(email: &str) -> bool {
    static EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = EMAIL_REGEX.get_or_init(|| {
        Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
            .expect("Failed to compile email regex")
    });

    regex.is_match(email)
}

/// Normalizes email address to lowercase and removes whitespace
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Validates that a name contains only allowed characters and length
pub fn validate_name(name: &str) -> bool {
    let trimmed = name.trim();

    // Name must be between 1 and 255 characters
    if trimmed.is_empty() || trimmed.len() > 255 {
        return false;
    }

    // Allow letters, spaces, hyphens, and apostrophes
    static NAME_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = NAME_REGEX
        .get_or_init(|| Regex::new(r"^[a-zA-Z\s\-']+$").expect("Failed to compile name regex"));

    regex.is_match(trimmed)
}

/// Validates URL format for profile pictures and other URLs
pub fn validate_url(url: &str) -> bool {
    if url.is_empty() {
        return true; // Empty URLs are allowed for optional fields
    }

    // Basic URL validation - starts with http:// or https://
    static URL_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = URL_REGEX.get_or_init(|| {
        Regex::new(r"^https?://[^\s/$.?#].[^\s]*$").expect("Failed to compile URL regex")
    });

    regex.is_match(url) && url.len() <= 512
}

/// Validates UUID format
pub fn validate_uuid(uuid_str: &str) -> bool {
    uuid::Uuid::parse_str(uuid_str).is_ok()
}

/// Validates that a string contains only alphanumeric characters and basic punctuation
pub fn validate_safe_string(input: &str) -> bool {
    static SAFE_STRING_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = SAFE_STRING_REGEX.get_or_init(|| {
        Regex::new(r"^[a-zA-Z0-9\s\-_.,!?()]+$").expect("Failed to compile safe string regex")
    });

    regex.is_match(input)
}

/// Sanitizes input by removing potentially dangerous characters
pub fn sanitize_input(input: &str) -> String {
    input
        .chars()
        .filter(|c| {
            c.is_alphanumeric()
                || c.is_whitespace()
                || matches!(
                    *c,
                    '-' | '_' | '.' | '@' | '!' | '?' | '(' | ')' | ',' | '\'' | '"'
                )
        })
        .collect::<String>()
        .trim()
        .to_string()
}

/// Custom validator for email fields using the validator crate
pub fn email_validator(email: &str) -> Result<(), ValidationError> {
    if validate_email(email) {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_email"))
    }
}

/// Custom validator for name fields using the validator crate
pub fn name_validator(name: &str) -> Result<(), ValidationError> {
    if validate_name(name) {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_name"))
    }
}

/// Custom validator for URL fields using the validator crate
pub fn url_validator(url: &str) -> Result<(), ValidationError> {
    if validate_url(url) {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_url"))
    }
}

/// Validation error messages for user-friendly responses
pub mod messages {
    pub const INVALID_EMAIL: &str = "Please enter a valid email address";
    pub const INVALID_NAME: &str =
        "Name must contain only letters, spaces, hyphens, and apostrophes";
    pub const INVALID_URL: &str = "Please enter a valid URL starting with http:// or https://";
    pub const INVALID_UUID: &str = "Invalid identifier format";
    pub const FIELD_REQUIRED: &str = "This field is required";
    pub const FIELD_TOO_LONG: &str = "This field is too long";
    pub const FIELD_TOO_SHORT: &str = "This field is too short";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_email() {
        assert!(validate_email("user@example.com"));
        assert!(validate_email("test.user+tag@domain.co.uk"));
        assert!(!validate_email("invalid.email"));
        assert!(!validate_email("@domain.com"));
        assert!(!validate_email("user@"));
        assert!(!validate_email(""));
    }

    #[test]
    fn test_normalize_email() {
        assert_eq!(normalize_email("  USER@EXAMPLE.COM  "), "user@example.com");
        assert_eq!(normalize_email("Test@Domain.org"), "test@domain.org");
    }

    #[test]
    fn test_validate_name() {
        assert!(validate_name("John Doe"));
        assert!(validate_name("Mary-Jane O'Connor"));
        assert!(!validate_name(""));
        assert!(!validate_name("John123"));
        assert!(!validate_name("John@Doe"));
        assert!(!validate_name(&"a".repeat(256))); // Too long
    }

    #[test]
    fn test_validate_url() {
        assert!(validate_url("https://example.com"));
        assert!(validate_url("http://example.com/path?query=1"));
        assert!(validate_url("")); // Empty is allowed
        assert!(!validate_url("ftp://example.com"));
        assert!(!validate_url("not-a-url"));
        assert!(!validate_url("https://"));
    }

    #[test]
    fn test_validate_uuid() {
        assert!(validate_uuid("123e4567-e89b-12d3-a456-426614174000"));
        assert!(!validate_uuid("not-a-uuid"));
        assert!(!validate_uuid(""));
    }

    #[test]
    fn test_sanitize_input() {
        assert_eq!(
            sanitize_input("Hello <script>alert('xss')</script>"),
            "Hello scriptalert('xss')script"
        );
        assert_eq!(sanitize_input("  normal text  "), "normal text");
        assert_eq!(sanitize_input("user@example.com"), "user@example.com");
    }

    #[test]
    fn test_validate_safe_string() {
        assert!(validate_safe_string("Hello, world!"));
        assert!(validate_safe_string("Test 123"));
        assert!(!validate_safe_string("Hello <script>"));
        assert!(!validate_safe_string("Test & string"));
    }
}
