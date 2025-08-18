# Service-Specific Error Types Implementation

This document summarizes the implementation of specific error types for the JWT, Email, and OAuth services in the user service codebase.

## Overview

Previously, all services used generic `AppError` and `ServiceError` types. This implementation introduces specific error types for each service to provide better error handling, clearer error messages, and improved debugging capabilities.

## Implemented Error Types

### 1. JwtServiceError

**Location**: `src/service/jwt.rs`

**Error Variants**:
- `TokenGeneration(String)` - JWT token generation failures
- `InvalidToken(String)` - Invalid or malformed tokens
- `TokenExpired` - Expired tokens
- `DatabaseError(sqlx::Error)` - Database operation failures
- `SessionNotFound` - Session not found
- `SessionExpired` - Expired sessions
- `InvalidSession(String)` - Invalid session data
- `InvalidUuid(uuid::Error)` - UUID parsing errors
- `InternalError(String)` - Internal service errors

**Key Features**:
- Automatic conversion from `sqlx::Error` and `uuid::Error`
- Converts to appropriate `AppError` variants
- Type alias: `JwtServiceResult<T> = Result<T, JwtServiceError>`

### 2. EmailServiceError

**Location**: `src/service/email_service.rs`

**Error Variants**:
- `SmtpConfig(String)` - SMTP configuration errors
- `TemplateError(String)` - Email template errors
- `SendFailure(String)` - Email sending failures
- `InvalidEmailAddress(String)` - Email address parsing errors
- `ConnectionError(String)` - SMTP connection errors
- `RenderError(String)` - Template rendering errors
- `ConfigurationError(String)` - General configuration errors
- `InternalError(String)` - Internal service errors

**Key Features**:
- Specific errors for each email operation
- Template-related error handling
- SMTP and email address validation errors
- Type alias: `EmailServiceResult<T> = Result<T, EmailServiceError>`

### 3. OAuthServiceError

**Location**: `src/service/oauth_service.rs`

**Error Variants**:
- `ConfigurationError(String)` - OAuth configuration errors
- `InvalidState(String)` - OAuth state validation errors
- `StateExpired` - Expired OAuth state
- `StateNotFound` - OAuth state not found
- `InvalidAuthorizationCode(String)` - Authorization code errors
- `TokenExchangeError(String)` - Token exchange failures
- `ProviderError(String)` - OAuth provider errors
- `UserInfoError(String)` - User info fetch errors
- `AccountLinkingError(String)` - Account linking errors
- `DatabaseError(sqlx::Error)` - Database operation failures
- `JwtServiceError(String)` - JWT service integration errors
- `HttpError(String)` - HTTP request errors
- `SerializationError(String)` - JSON serialization errors
- `InvalidUuid(uuid::Error)` - UUID parsing errors
- `InternalError(String)` - Internal service errors

**Key Features**:
- OAuth flow-specific error handling
- Provider integration error types
- Automatic conversion from `sqlx::Error` and `uuid::Error`
- Type alias: `OAuthServiceResult<T> = Result<T, OAuthServiceError>`

## Updated UserService Integration

### Modified UserServiceError

**Location**: `src/service/user.rs`

**Updated Variants**:
```rust
/// Email service error
#[error("Email service error: {0}")]
EmailServiceError(#[from] EmailServiceError),

/// JWT service error
#[error("JWT service error: {0}")]
JwtServiceError(#[from] JwtServiceError),
```

**Key Changes**:
- Changed from `EmailServiceError(String)` to `EmailServiceError(#[from] EmailServiceError)`
- Added `JwtServiceError(#[from] JwtServiceError)`
- Automatic conversion using `#[from]` attribute
- Updated `From<UserServiceError> for AppError` implementation

## Error Conversion Flow

```
Specific Service Error -> UserServiceError -> AppError -> HTTP Response
```

### Example Flow:
1. `EmailServiceError::SendFailure` occurs in email service
2. Automatically converts to `UserServiceError::EmailServiceError`
3. Converts to `AppError::ExternalService`
4. Returns appropriate HTTP status code and error message

## Benefits of This Implementation

### 1. **Better Error Granularity**
- Each service has errors specific to its domain
- More precise error handling and debugging
- Clearer error messages for developers

### 2. **Improved Debugging**
- Service-specific error types make it easier to identify the source of errors
- Better error context and information
- Clearer stack traces

### 3. **Type Safety**
- Compile-time error checking
- Prevents generic error handling anti-patterns
- Forces explicit error handling

### 4. **Maintainability**
- Errors are co-located with service code
- Easy to add new error variants as services evolve
- Clear separation of concerns

### 5. **API Consistency**
- Each service follows the same error pattern
- Consistent error handling across the codebase
- Predictable error conversion flow

## Usage Examples

### JWT Service
```rust
// Before
let token = jwt_service.generate_token_pair(user_id, None, None)
    .await
    .map_err(|e| AppError::Internal(format!("JWT error: {}", e)))?;

// After
let token = jwt_service.generate_token_pair(user_id, None, None).await?;
// Error automatically converts through the chain
```

### Email Service
```rust
// Before
email_service.send_verification_email(email, name, code, 10)
    .await
    .map_err(|e| UserServiceError::EmailServiceError(e.to_string()))?;

// After
email_service.send_verification_email(email, name, code, 10).await?;
// Error automatically converts through the chain
```

### OAuth Service
```rust
// Before
let user_info = self.fetch_google_user_info(access_token)
    .await
    .map_err(|e| AppError::External(format!("OAuth error: {}", e)))?;

// After
let user_info = self.fetch_google_user_info(access_token).await?;
// Error automatically converts through the chain
```

## Testing

All existing tests pass with the new error types. The error conversion is transparent to existing code that uses the `?` operator, making this a backward-compatible change.

### Test Results
- **Total Tests**: 117 passed
- **Build Status**: ✅ Success
- **Doc Tests**: ✅ All pass

## Migration Notes

### For Existing Code
- Most existing code works without changes due to automatic error conversion
- Code using explicit error conversion can be simplified
- Remove manual error string formatting in favor of automatic conversion

### For New Code
- Use service-specific result types (`JwtServiceResult`, `EmailServiceResult`, `OAuthServiceResult`)
- Let errors convert automatically through the chain
- Add new error variants to service-specific enums as needed

## Future Enhancements

1. **Error Codes**: Add structured error codes for better API integration
2. **Error Context**: Add more contextual information to errors
3. **Metrics**: Integrate with monitoring for error tracking
4. **Localization**: Support for multiple languages in error messages
5. **Error Recovery**: Implement retry logic for transient errors

## Conclusion

This implementation provides a robust, type-safe, and maintainable error handling system that scales with the application. Each service now has complete control over its error types while maintaining compatibility with the existing error handling infrastructure.