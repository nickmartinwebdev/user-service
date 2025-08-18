# Google OAuth 2.0 Integration

This document provides a comprehensive guide for integrating Google OAuth 2.0 authentication with the user service.

## Overview

The OAuth implementation allows users to sign up and sign in using their Google accounts. It supports:

- **New User Registration**: Creates user accounts automatically from Google profile data
- **Account Linking**: Links Google accounts to existing email-based accounts
- **Secure State Management**: CSRF protection with time-limited state tokens
- **JWT Integration**: Seamless integration with existing JWT authentication system

## Database Schema

The OAuth implementation requires two additional database tables:

### oauth_providers

Stores OAuth provider account linkages for external authentication.

```sql
CREATE TABLE oauth_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    provider_email VARCHAR(255) NOT NULL,
    provider_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(provider, provider_user_id),
    UNIQUE(provider, provider_email)
);
```

### oauth_states

Stores temporary state tokens for CSRF protection during OAuth flows.

```sql
CREATE TABLE oauth_states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    state_token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    redirect_url VARCHAR(512),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

## Environment Configuration

Set the following environment variables for Google OAuth:

```bash
# Google OAuth 2.0 Configuration
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=http://localhost:3000/auth/callback/google

# Optional: OAuth state token expiration (default: 10 minutes)
OAUTH_STATE_EXPIRES_MINUTES=10

# Required JWT Configuration
JWT_ACCESS_SECRET=your_jwt_access_secret
JWT_REFRESH_SECRET=your_jwt_refresh_secret
```

## Google Cloud Console Setup

1. **Create a new project** in the [Google Cloud Console](https://console.cloud.google.com/)

2. **Enable the Google+ API**:
   - Go to "APIs & Services" → "Library"
   - Search for "Google+ API" and enable it

3. **Create OAuth 2.0 credentials**:
   - Go to "APIs & Services" → "Credentials"
   - Click "Create Credentials" → "OAuth client ID"
   - Choose "Web application"
   - Add authorized redirect URIs:
     - `http://localhost:3000/auth/callback/google` (development)
     - `https://yourdomain.com/auth/callback/google` (production)

4. **Copy the credentials**:
   - Use the Client ID as `GOOGLE_CLIENT_ID`
   - Use the Client Secret as `GOOGLE_CLIENT_SECRET`

## API Endpoints

### POST /auth/signup/google

Initiates the Google OAuth flow by generating an authorization URL and secure state token.

**Request:**
```json
{
  "redirect_url": "https://example.com/dashboard" // optional
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "authorization_url": "https://accounts.google.com/oauth/authorize?...",
    "state": "secure_random_state_token"
  }
}
```

**Usage:**
1. Call this endpoint to get the authorization URL
2. Redirect the user to the `authorization_url`
3. Store the `state` token for validation (handled automatically)

### GET /auth/callback/google

Handles the callback from Google OAuth and completes the authentication flow.

**Query Parameters:**
- `code`: Authorization code from Google
- `state`: State token for CSRF protection
- `error`: Error code if authorization failed (optional)
- `error_description`: Human-readable error description (optional)

**Response (JSON when Accept: application/json):**
```json
{
  "success": true,
  "data": {
    "access_token": "jwt_access_token",
    "refresh_token": "jwt_refresh_token",
    "user": {
      "id": "uuid",
      "name": "John Doe",
      "email": "john@gmail.com",
      "email_verified": true,
      "profile_picture_url": "https://lh3.googleusercontent.com/...",
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-01T00:00:00Z"
    },
    "is_new_user": true
  }
}
```

**Response (HTML redirect for web browsers):**
- Redirects to `/auth/success` with tokens as query parameters
- In production, implement secure token handling (HTTP-only cookies)

### GET /auth/oauth/providers 🔒

Lists OAuth providers linked to the authenticated user's account.

**Headers:**
```
Authorization: Bearer <jwt_access_token>
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "uuid",
      "provider": "google",
      "provider_email": "user@gmail.com",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### DELETE /auth/oauth/providers/{provider} 🔒

Unlinks an OAuth provider from the authenticated user's account.

**Headers:**
```
Authorization: Bearer <jwt_access_token>
```

**Path Parameters:**
- `provider`: OAuth provider name (e.g., "google")

**Response:**
```json
{
  "success": true,
  "data": {
    "unlinked": true,
    "provider": "google"
  }
}
```

## Code Integration

### Basic Setup

```rust
use user_service::{
    api::{AppState, RouterBuilder, auth_middleware},
    config::{GoogleOAuthConfig, JwtConfig},
    database::DatabaseConfig,
    service::{JwtService, OAuthService, UserService},
};
use axum::{middleware::from_fn_with_state, routing::get, Router};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let database_config = DatabaseConfig::from_env()?;
    let jwt_config = JwtConfig::from_env()?;
    let google_oauth_config = GoogleOAuthConfig::from_env()?;

    // Setup database
    let database_pool = database_config.create_pool().await?;
    sqlx::migrate!("./migrations").run(&database_pool).await?;

    // Initialize services
    let user_service = UserService::new(database_pool.clone());
    let jwt_service = JwtService::with_expiration(
        database_pool.clone(),
        jwt_config.access_secret,
        jwt_config.refresh_secret,
        chrono::Duration::hours(jwt_config.access_token_expires_hours),
        chrono::Duration::days(jwt_config.refresh_token_expires_days),
    );
    let oauth_service = OAuthService::new(
        database_pool.clone(),
        google_oauth_config,
        jwt_service.clone(),
    )?;

    // Create application state
    let app_state = AppState {
        user_service: Arc::new(user_service),
        jwt_service: Arc::new(jwt_service),
        oauth_service: Some(Arc::new(oauth_service)),
    };

    // Build routes
    let public_routes = RouterBuilder::new()
        .health_check(true)
        .create_user(true)
        .google_oauth_init(true)
        .google_oauth_callback(true)
        .build();

    let protected_routes = Router::new()
        .route("/auth/oauth/providers", get(oauth_handlers::get_user_oauth_providers))
        .route("/auth/oauth/providers/{provider}", 
               axum::routing::delete(oauth_handlers::unlink_oauth_provider))
        .layer(from_fn_with_state(app_state.jwt_service.clone(), auth_middleware));

    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(app_state);

    // Start server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

### Frontend Integration

#### JavaScript/TypeScript Example

```typescript
class OAuthService {
  async initiateGoogleOAuth(redirectUrl?: string): Promise<{authorization_url: string, state: string}> {
    const response = await fetch('/auth/signup/google', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ redirect_url: redirectUrl })
    });
    
    if (!response.ok) {
      throw new Error('Failed to initiate OAuth');
    }
    
    const data = await response.json();
    return data.data;
  }

  async handleOAuthCallback(code: string, state: string): Promise<{access_token: string, refresh_token: string, user: any}> {
    const response = await fetch(`/auth/callback/google?code=${code}&state=${state}`, {
      headers: { 'Accept': 'application/json' }
    });
    
    if (!response.ok) {
      throw new Error('OAuth callback failed');
    }
    
    const data = await response.json();
    return data.data;
  }

  async getLinkedProviders(accessToken: string): Promise<any[]> {
    const response = await fetch('/auth/oauth/providers', {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    
    if (!response.ok) {
      throw new Error('Failed to get linked providers');
    }
    
    const data = await response.json();
    return data.data;
  }
}

// Usage
const oauthService = new OAuthService();

// Start OAuth flow
const { authorization_url } = await oauthService.initiateGoogleOAuth('https://myapp.com/dashboard');
window.location.href = authorization_url;

// Handle callback (in your callback page)
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');
const state = urlParams.get('state');

if (code && state) {
  const { access_token, refresh_token, user } = await oauthService.handleOAuthCallback(code, state);
  
  // Store tokens securely
  localStorage.setItem('access_token', access_token);
  localStorage.setItem('refresh_token', refresh_token);
  
  // Redirect to app
  window.location.href = '/dashboard';
}
```

## Security Considerations

### State Token Management
- State tokens expire after 10 minutes (configurable)
- Tokens are cryptographically secure random strings
- Used tokens are immediately deleted to prevent reuse
- Automatic cleanup of expired tokens

### Account Security
- Google email verification is required
- Provider data is validated before account creation
- Duplicate account linking is prevented
- Account takeover protection through email verification

### Token Security
- JWT tokens follow the same security model as password-based authentication
- Access tokens expire after 1 hour (configurable)
- Refresh tokens expire after 30 days (configurable)
- Session management with proper cleanup

## Error Handling

### Common Error Scenarios

1. **Invalid State Token**
   ```json
   {
     "success": false,
     "error": {
       "type": "BadRequest",
       "message": "Invalid or expired state token"
     }
   }
   ```

2. **OAuth Authorization Denied**
   ```json
   {
     "success": false,
     "error": {
       "type": "BadRequest",
       "message": "OAuth error: access_denied - User denied access"
     }
   }
   ```

3. **Unverified Google Email**
   ```json
   {
     "success": false,
     "error": {
       "type": "BadRequest",
       "message": "Google account email is not verified"
     }
   }
   ```

4. **OAuth Service Not Configured**
   ```json
   {
     "success": false,
     "error": {
       "type": "Internal",
       "message": "OAuth service not configured"
     }
   }
   ```

## Testing

### Integration Tests

Run the OAuth integration tests:

```bash
# Set test database URL
export TEST_DATABASE_URL="postgres://postgres:password@localhost/user_service_test"

# Run OAuth-specific tests
cargo test oauth_integration_tests

# Run all tests
cargo test
```

### Manual Testing

1. **Start the development server**:
   ```bash
   cargo run
   ```

2. **Visit the demo page**:
   ```
   http://localhost:3000
   ```

3. **Test OAuth flow**:
   - Click "Start Google OAuth"
   - Authorize with Google
   - Verify token generation and user creation

### Production Testing

1. **Deploy with production credentials**
2. **Test with real Google accounts**
3. **Verify HTTPS redirect URIs**
4. **Test error scenarios**

## Monitoring and Maintenance

### Database Maintenance

Periodic cleanup of expired OAuth states:

```sql
DELETE FROM oauth_states WHERE expires_at < NOW();
```

Or use the service method:

```rust
let removed_count = oauth_service.cleanup_expired_states().await?;
```

### Metrics to Monitor

- OAuth flow success/failure rates
- State token expiration rates
- New user registration vs. account linking ratios
- Token generation errors

### Logging

The service logs important OAuth events:

- OAuth flow initiation
- Successful authentications
- Account creation vs. linking
- Error scenarios with context

## Troubleshooting

### Common Issues

1. **"OAuth service not configured"**
   - Verify `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_REDIRECT_URI` are set
   - Check that the OAuth service is properly initialized

2. **"Invalid redirect URI"**
   - Ensure the redirect URI in environment matches Google Cloud Console configuration
   - Verify HTTPS in production environments

3. **"State token expired"**
   - Default expiration is 10 minutes
   - Increase `OAUTH_STATE_EXPIRES_MINUTES` if needed
   - Check for clock synchronization issues

4. **"Google account email is not verified"**
   - User must verify their email with Google first
   - Cannot be resolved programmatically

5. **Database migration errors**
   - Ensure migrations are run: `sqlx migrate run`
   - Check database permissions for table creation

### Debug Mode

Enable debug logging:

```bash
export RUST_LOG=debug
cargo run
```

This will show detailed OAuth flow information and help diagnose issues.

## Examples

Complete working examples are available in:

- `examples/oauth_example.rs` - Full OAuth demo with web interface
- `tests/oauth_integration_tests.rs` - Comprehensive test suite

Run the example:

```bash
cargo run --example oauth_example
```

Then visit `http://localhost:3000` for an interactive OAuth demo.