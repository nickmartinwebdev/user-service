# User Service API Documentation for LLM Code Generation

## Repository Overview

This is a comprehensive passwordless authentication service built in Rust, providing enterprise-grade user management, multiple authentication flows, and security features. The service follows a microservices architecture with clear separation of concerns.

## API Endpoints Reference

### Public Endpoints (No Authentication Required)

#### Health & System
- **GET** `/health` - Health check endpoint
  - Response: `{"success": true, "data": {"status": "healthy", "timestamp": "...", "version": "0.1.0"}}`

#### User Management
- **POST** `/users` - Create new user account
  - Request: `{"name": "string", "email": "string", "password": "string", "profile_picture_url": "string?"}`
  - Response: `{"success": true, "data": {"id": "uuid", "name": "string", "email": "string", "profile_picture_url": "string?", "created_at": "datetime"}}`

#### Token Management
- **POST** `/auth/refresh` - Refresh JWT access token
  - Request: `{"refresh_token": "string"}`
  - Response: `{"success": true, "data": {"access_token": "string", "token_type": "Bearer", "expires_in": 3600}}`

#### Passwordless Authentication Flow
- **POST** `/auth/signup/email` - Initiate passwordless signup
  - Request: `{"name": "string", "email": "string"}`
  - Response: `{"success": true, "data": {"message": "string", "user_id": "uuid", "expires_in": 900}}`

- **POST** `/auth/verify-email` - Complete email verification
  - Request: `{"email": "string", "verification_code": "string"}`
  - Response: `{"success": true, "data": {"access_token": "string", "refresh_token": "string", "token_type": "Bearer", "expires_in": 3600, "user": {...}}}`

#### OTP Sign-in Flow (for existing verified users)
- **POST** `/auth/signin/email` - Request OTP for sign-in
  - Request: `{"email": "string"}`
  - Response: `{"success": true, "data": {"message": "string", "expires_in": 900}}`

- **POST** `/auth/signin/otp` - Verify OTP and sign in
  - Request: `{"email": "string", "otp_code": "string"}`
  - Response: `{"success": true, "data": {"access_token": "string", "refresh_token": "string", "token_type": "Bearer", "expires_in": 3600, "user": {...}}}`

#### OAuth Authentication Flow
- **POST** `/auth/signup/google` - Initiate Google OAuth
  - Request: `{"redirect_url": "string?"}`
  - Response: `{"success": true, "data": {"auth_url": "string", "state": "string"}}`

- **GET** `/auth/callback/google?code=...&state=...` - Handle OAuth callback
  - Query Params: `code`, `state`
  - Response: Redirect with tokens or error

#### WebAuthn/Passkey Authentication Flow
- **POST** `/auth/register/passkey/begin` - Start passkey registration
  - Request: `{"credential_name": "string?"}`
  - Response: `{"success": true, "data": {"challenge": "...", "options": {...}}}`

- **POST** `/auth/register/passkey/finish` - Complete passkey registration
  - Request: `{"credential": {...}, "credential_name": "string?"}`
  - Response: `{"success": true, "data": {"credential_id": "string", "success": true}}`

- **POST** `/auth/signin/passkey/begin` - Start passkey authentication
  - Request: `{"email": "string?"}`
  - Response: `{"success": true, "data": {"challenge": "...", "options": {...}}}`

- **POST** `/auth/signin/passkey/finish` - Complete passkey authentication
  - Request: `{"credential": {...}}`
  - Response: `{"success": true, "data": {"access_token": "string", "refresh_token": "string", "token_type": "Bearer", "expires_in": 3600, "user": {...}}}`

- **POST** `/auth/webauthn/cleanup` - Clean up expired challenges
  - Request: `{}`
  - Response: `{"success": true, "data": {"deleted_count": 0}}`

### Protected Endpoints (Authentication Required)

All protected endpoints require `Authorization: Bearer <access_token>` header.

#### User Profile Management
- **GET** `/users/{id}` - Get user by ID
  - Response: `{"success": true, "data": {"id": "uuid", "name": "string", "email": "string", "profile_picture_url": "string?", "created_at": "datetime", "updated_at": "datetime", "email_verified": true}}`

- **PUT** `/users/{id}` - Update user profile
  - Request: `{"name": "string?", "email": "string?", "profile_picture_url": "string?"}`
  - Response: `{"success": true, "data": {...}}`

- **POST** `/users/{id}/verify-password` - Verify user's password
  - Request: `{"password": "string"}`
  - Response: `{"success": true, "data": {"valid": true}}`

- **PUT** `/users/{id}/profile-picture` - Update profile picture
  - Request: `{"profile_picture_url": "string?"}`
  - Response: `{"success": true, "data": {...}}`

- **DELETE** `/users/{id}/profile-picture` - Remove profile picture
  - Response: `{"success": true, "data": {...}}`

#### OAuth Provider Management
- **GET** `/auth/oauth/providers` - List user's OAuth providers
  - Response: `{"success": true, "data": [{"provider": "google", "email": "string", "linked_at": "datetime"}]}`

- **DELETE** `/auth/oauth/providers/{provider}` - Unlink OAuth provider
  - Response: `{"success": true, "data": {"message": "Provider unlinked successfully"}}`

#### Passkey Management
- **GET** `/auth/passkeys` - List user's passkeys
  - Query: `?name_filter=string`
  - Response: `{"success": true, "data": {"passkeys": [{"credential_id": "string", "name": "string", "created_at": "datetime", "last_used": "datetime?"}]}}`

- **PUT** `/auth/passkeys/{credential_id}` - Update passkey name
  - Request: `{"credential_name": "string"}`
  - Response: `{"success": true, "data": {"success": true}}`

- **DELETE** `/auth/passkeys/{credential_id}` - Delete passkey
  - Response: `{"success": true, "data": {"success": true}}`

## Service Layer Architecture

### 1. User Service (`UserService`)

**Purpose**: Core user management and business logic

**Key Features**:
- CRUD operations for users
- Password hashing and verification using bcrypt
- Passwordless signup and email verification flows
- OTP generation and verification for sign-in
- Profile picture management
- Email address validation and normalization
- Integration with all other services

**Key Methods**:
- `create_user(request)` - Create new user with password
- `get_user_by_id(id)` - Retrieve user by UUID
- `get_user_by_email(email)` - Retrieve user by email
- `update_user(id, request)` - Update user profile
- `verify_password(id, password)` - Verify user's password
- `passwordless_signup(request)` - Initiate passwordless signup
- `verify_email(request)` - Complete email verification
- `request_signin_otp(email)` - Send OTP for existing users
- `verify_signin_otp(request)` - Verify OTP and generate tokens
- `update_profile_picture(id, url)` - Update profile picture
- `remove_profile_picture(id)` - Remove profile picture
- `health_check()` - Database connectivity check

**Database Tables**:
- `users` - Core user information
- `email_verifications` - Email verification codes
- `login_otps` - OTP codes for sign-in

### 2. JWT Service (`JwtService`)

**Purpose**: JWT token generation, validation, and session management

**Key Features**:
- Access token generation (short-lived, typically 1 hour)
- Refresh token generation (long-lived, typically 30 days)
- Token validation with proper expiration checking
- Token refresh flow
- User session management
- Secure secret key handling

**Key Methods**:
- `generate_token_pair(user_id)` - Generate access + refresh token pair
- `validate_access_token(token)` - Validate and decode access token
- `validate_refresh_token(token)` - Validate refresh token
- `refresh_access_token(refresh_token)` - Exchange refresh token for new access token
- `revoke_refresh_token(token)` - Invalidate refresh token
- `cleanup_expired_tokens()` - Remove expired tokens from database

**Database Tables**:
- `refresh_tokens` - Active refresh tokens with expiration

### 3. Email Service (`EmailService`)

**Purpose**: Email notifications and template management

**Key Features**:
- SMTP email sending with connection pooling
- HTML and plain text email templates using Tera
- Email verification code generation and sending
- OTP code generation and sending
- Template management for different email types
- Email delivery error handling and retry logic

**Key Methods**:
- `send_verification_email(email, code, name)` - Send email verification
- `send_otp_email(email, code, name)` - Send OTP for sign-in
- `send_welcome_email(email, name)` - Send welcome message
- `send_password_reset_email(email, code, name)` - Send password reset
- `verify_smtp_connection()` - Test email server connectivity

**Email Templates**:
- Verification email with 6-digit code
- OTP sign-in email with 6-digit code
- Welcome email after successful verification
- Password reset email (if implemented)

**Configuration**:
- SMTP server settings
- Email templates directory
- From address and display name
- Connection pooling settings

### 4. OAuth Service (`OAuthService`)

**Purpose**: OAuth 2.0 social authentication integration

**Key Features**:
- Google OAuth 2.0 integration
- OAuth state management with CSRF protection
- Account linking and unlinking
- Provider information management
- Extensible for additional OAuth providers

**Key Methods**:
- `initiate_google_oauth(redirect_url?)` - Start Google OAuth flow
- `handle_google_callback(code, state)` - Process OAuth callback
- `get_user_oauth_providers(user_id)` - List linked providers
- `unlink_oauth_provider(user_id, provider)` - Remove provider link
- `cleanup_expired_states()` - Clean up expired OAuth states
- `link_oauth_account(user_id, provider, external_id)` - Link accounts

**Supported Providers**:
- Google (implemented)
- Framework for additional providers (Facebook, GitHub, etc.)

**Database Tables**:
- `oauth_providers` - User-provider links
- `oauth_states` - CSRF protection states

### 5. WebAuthn Service (`WebAuthnService`)

**Purpose**: FIDO2/WebAuthn passkey authentication

**Key Features**:
- Passkey registration flow
- Passkey authentication flow
- Credential management (list, update, delete)
- Challenge-response security
- Cross-platform passkey support
- Biometric and security key support

**Key Methods**:
- `begin_passkey_registration(user_id, name?)` - Start passkey registration
- `finish_passkey_registration(user_id, credential)` - Complete registration
- `begin_passkey_authentication(email?)` - Start authentication
- `finish_passkey_authentication(credential)` - Complete authentication
- `list_user_passkeys(user_id)` - Get user's passkeys
- `update_passkey_name(user_id, credential_id, name)` - Rename passkey
- `delete_passkey(user_id, credential_id)` - Remove passkey
- `cleanup_expired_challenges()` - Clean expired challenges

**Database Tables**:
- `webauthn_credentials` - User passkey credentials
- `webauthn_challenges` - Active authentication challenges

### 6. Rate Limit Service (`RateLimitService`)

**Purpose**: Abuse prevention and request throttling

**Key Features**:
- IP-based rate limiting
- Email-based rate limiting
- Configurable rate limits per operation type
- Sliding window rate limiting
- Integration with all authentication flows
- Automatic cleanup of expired entries

**Key Methods**:
- `check_ip_rate_limit(ip, operation)` - Check IP-based limits
- `check_email_rate_limit(email, operation)` - Check email-based limits
- `record_ip_attempt(ip, operation, success)` - Record IP attempt
- `record_email_attempt(email, operation, success)` - Record email attempt
- `cleanup_expired_entries()` - Remove old rate limit entries

**Rate Limit Categories**:
- Email verification (5 per hour per email)
- OTP requests (3 per hour per email)
- Password attempts (10 per hour per IP)
- Account creation (5 per hour per IP)
- OAuth attempts (10 per hour per IP)

**Database Tables**:
- `rate_limits` - Rate limiting counters by IP/email

### 7. Security Audit Service (`SecurityAuditService`)

**Purpose**: Comprehensive security event logging and monitoring

**Key Features**:
- Authentication event logging
- Failed login attempt tracking
- Security event categorization
- User activity monitoring
- Compliance audit trails
- Suspicious activity detection

**Key Methods**:
- `log_auth_event(event_type, user_id?, ip, details)` - Log authentication events
- `log_user_creation(user_id, ip, method)` - Log user registrations
- `log_login_attempt(email, ip, success, method)` - Log login attempts
- `log_password_verification(user_id, ip, success)` - Log password checks
- `log_oauth_event(user_id?, provider, event, ip)` - Log OAuth events
- `log_passkey_event(user_id?, event, ip)` - Log WebAuthn events
- `get_user_audit_log(user_id)` - Retrieve user's audit trail
- `cleanup_old_logs()` - Archive or delete old logs

**Event Types**:
- User registration (passwordless, OAuth, traditional)
- Login attempts (OTP, passkey, OAuth)
- Password verifications
- Profile updates
- OAuth linking/unlinking
- Passkey registration/deletion
- Security events (rate limiting, suspicious activity)

**Database Tables**:
- `security_audit_logs` - Comprehensive security event log

## Data Models

### Core User Model
```rust
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub password_hash: Option<String>, // None for passwordless users
    pub profile_picture_url: Option<String>,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

### Request Models
```rust
// User Management
pub struct CreateUserRequest {
    pub name: String,              // 1-255 chars
    pub email: String,             // Valid email format
    pub password: String,          // 8-128 chars, complexity required
    pub profile_picture_url: Option<String>,
}

pub struct UpdateUserRequest {
    pub name: Option<String>,
    pub email: Option<String>,
    pub profile_picture_url: Option<String>,
}

// Authentication
pub struct PasswordlessSignupRequest {
    pub name: String,
    pub email: String,
}

pub struct VerifyEmailRequest {
    pub email: String,
    pub verification_code: String, // 6-digit code
}

pub struct OtpSigninEmailRequest {
    pub email: String,
}

pub struct OtpSigninVerifyRequest {
    pub email: String,
    pub otp_code: String, // 6-digit code
}

pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

// OAuth
pub struct GoogleOAuthInitRequest {
    pub redirect_url: Option<String>,
}

// WebAuthn
pub struct PasskeyRegistrationBeginRequest {
    pub credential_name: Option<String>,
}

pub struct PasskeyRegistrationFinishRequest {
    pub credential: serde_json::Value,
    pub credential_name: Option<String>,
}

pub struct PasskeyAuthenticationBeginRequest {
    pub email: Option<String>,
}

pub struct PasskeyAuthenticationFinishRequest {
    pub credential: serde_json::Value,
}

pub struct UpdatePasskeyRequest {
    pub credential_name: String,
}
```

### Response Models
```rust
pub struct CreateUserResponse {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub profile_picture_url: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub struct VerifyEmailResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user: User,
}

pub struct RefreshTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

pub struct HealthCheckResponse {
    pub status: String,
    pub timestamp: DateTime<Utc>,
    pub version: String,
}

// Standard wrapper for all successful responses
pub struct SuccessResponse<T> {
    pub success: bool,
    pub data: T,
}
```

### Authentication Models
- Email verification codes (6-digit, expires in 15 minutes)
- OTP codes (6-digit, expires in 15 minutes)
- JWT refresh tokens (stored in database with expiration)
- OAuth state tokens (CSRF protection)
- WebAuthn challenges and credentials
- Rate limiting counters
- Audit log entries

## Security Features

### Authentication Security
- bcrypt password hashing (configurable cost, default 12)
- JWT tokens with proper expiration
- CSRF protection for OAuth flows
- Challenge-response for WebAuthn
- Rate limiting on all authentication endpoints
- Comprehensive audit logging

### Input Validation
- Email format and domain validation
- Password strength requirements (8+ chars, complexity)
- Name length limits (1-255 chars)
- URL validation for profile pictures
- Request size limits
- SQL injection prevention with prepared statements

### Security Headers & Middleware
- CORS configuration
- Content Security Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Security audit middleware
- Rate limiting middleware
- Password detection middleware

## Error Handling

All endpoints return consistent error formats:

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid email format",
    "details": {...}
  }
}
```

Common error types:
- `VALIDATION_ERROR` - Input validation failures
- `NOT_FOUND` - Resource not found
- `UNAUTHORIZED` - Authentication required
- `FORBIDDEN` - Insufficient permissions
- `RATE_LIMITED` - Too many requests
- `INTERNAL_ERROR` - Server errors
- `CONFIGURATION_ERROR` - Service misconfiguration

## Authentication Flows

### Passwordless Registration Flow
1. `POST /auth/signup/email` - User provides name and email
2. Email verification code sent to user
3. `POST /auth/verify-email` - User submits email and 6-digit code
4. User account created and JWT tokens returned

### OTP Sign-in Flow (Existing Users)
1. `POST /auth/signin/email` - User provides email
2. OTP code sent to verified email
3. `POST /auth/signin/otp` - User submits email and 6-digit OTP
4. JWT tokens returned for authenticated session

### OAuth Flow
1. `POST /auth/signup/google` - Initiate OAuth with optional redirect
2. User redirected to Google for authentication
3. `GET /auth/callback/google` - Handle callback with code and state
4. Account created/linked and JWT tokens returned

### WebAuthn/Passkey Flow
1. `POST /auth/register/passkey/begin` - Start passkey registration
2. Browser creates passkey with user interaction
3. `POST /auth/register/passkey/finish` - Complete registration
4. For authentication: `POST /auth/signin/passkey/begin` then `POST /auth/signin/passkey/finish`

### Token Refresh Flow
1. `POST /auth/refresh` - Exchange refresh token for new access token
2. New access token returned with same expiration time
3. Refresh token remains valid until expiration or revocation

## Configuration

### Environment Variables
- `DATABASE_URL` - PostgreSQL connection string
- `JWT_ACCESS_SECRET` - JWT access token secret key
- `JWT_REFRESH_SECRET` - JWT refresh token secret key
- `JWT_ACCESS_EXPIRES_HOURS` - Access token expiration (default: 1)
- `JWT_REFRESH_EXPIRES_DAYS` - Refresh token expiration (default: 30)
- `SMTP_HOST` - Email server host
- `SMTP_PORT` - Email server port
- `SMTP_USERNAME` - Email server username
- `SMTP_PASSWORD` - Email server password
- `GOOGLE_CLIENT_ID` - Google OAuth client ID
- `GOOGLE_CLIENT_SECRET` - Google OAuth client secret
- `WEBAUTHN_RP_ID` - WebAuthn relying party ID
- `WEBAUTHN_ORIGIN` - WebAuthn origin URL

### Service Dependencies
- PostgreSQL 12+ database
- SMTP email server
- Google OAuth 2.0 credentials (optional)
- SSL/TLS certificates for WebAuthn (production)

This documentation provides the complete API reference and service architecture for LLM-assisted code generation, including all endpoints, request/response formats, service capabilities, and security considerations.