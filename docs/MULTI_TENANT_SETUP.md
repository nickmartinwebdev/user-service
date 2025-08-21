# Multi-Tenant User Service Setup Guide

This guide explains how to set up and use the User Service in multi-tenant mode, where multiple applications can use the same service instance with complete data isolation.

## Overview

The multi-tenant architecture allows multiple unrelated applications to share the same User Service instance while maintaining complete data isolation. Each application (tenant) has:

- Separate user databases (logically isolated)
- Individual API credentials
- Custom configuration (email templates, OAuth settings, UI branding)
- Independent rate limiting and security policies
- Isolated audit logs

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Application   │    │   Application   │    │   Application   │
│      A          │    │      B          │    │      C          │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │ API Key A             │ API Key B             │ API Key C
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────────────────────┐
                    │     Multi-Tenant User Service   │
                    │                                 │
                    │  ┌─────────────────────────────┐ │
                    │  │  Application Auth Layer    │ │
                    │  └─────────────────────────────┘ │
                    │  ┌─────────────────────────────┐ │
                    │  │     Business Logic          │ │
                    │  └─────────────────────────────┘ │
                    │  ┌─────────────────────────────┐ │
                    │  │  Tenant-Isolated Database   │ │
                    │  │  ├─ App A Users             │ │
                    │  │  ├─ App B Users             │ │
                    │  │  └─ App C Users             │ │
                    │  └─────────────────────────────┘ │
                    └─────────────────────────────────┘
```

## Installation & Setup

### 1. Database Migration

First, run the multi-tenant migrations on your existing database:

```bash
# Run the multi-tenant migration
sqlx migrate run --source migrations/

# This will add:
# - applications table for tenant management
# - application_id columns to all existing tables
# - proper indexes and constraints
```

### 2. Environment Configuration

Update your environment variables to support multi-tenant mode:

```bash
# Database
DATABASE_URL=postgres://username:password@localhost/user_service

# JWT (used for user authentication within applications)
JWT_ACCESS_SECRET=your-access-token-secret
JWT_REFRESH_SECRET=your-refresh-token-secret

# Email (optional, for passwordless authentication)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=your-username
SMTP_PASSWORD=your-password

# OAuth (optional, per-application configuration available)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# WebAuthn (optional)
WEBAUTHN_RP_ID=your-domain.com
WEBAUTHN_ORIGIN=https://your-domain.com

# Server
PORT=3000
HOST=0.0.0.0
LOG_LEVEL=info

# Development mode (creates sample application)
ENVIRONMENT=development
```

### 3. Start the Multi-Tenant Server

```bash
# Option 1: Using the example server
cargo run --example multi_tenant_server

# Option 2: Use the main binary (single-tenant mode)
cargo run

# Option 3: Create your own server with custom configuration
```

## Application Management

### Creating Applications

Applications are managed through admin endpoints (no application auth required):

```bash
# Create a new application
curl -X POST http://localhost:3000/admin/applications \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Web App",
    "allowed_origins": ["https://myapp.com", "https://www.myapp.com"],
    "settings": {
      "ui_settings": {
        "app_name": "My Web App",
        "primary_color": "#007bff",
        "support_email": "support@myapp.com"
      },
      "rate_limits": {
        "email_verification_per_hour": 5,
        "otp_requests_per_hour": 3
      }
    }
  }'
```

Response:
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "My Web App",
    "api_key": "ak_1234567890abcdef1234567890abcdef",
    "api_secret": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    "allowed_origins": ["https://myapp.com", "https://www.myapp.com"],
    "settings": { ... },
    "created_at": "2025-01-20T12:00:00Z"
  }
}
```

### Managing Applications

```bash
# List all applications
curl http://localhost:3000/admin/applications

# Get application details
curl http://localhost:3000/admin/applications/{app_id}

# Update application settings
curl -X PUT http://localhost:3000/admin/applications/{app_id} \
  -H "Content-Type: application/json" \
  -d '{"name": "Updated App Name"}'

# Get application statistics
curl http://localhost:3000/admin/applications/{app_id}/stats

# Rotate API credentials
curl -X POST http://localhost:3000/admin/applications/{app_id}/rotate-credentials

# Deactivate application
curl -X POST http://localhost:3000/admin/applications/{app_id}/deactivate
```

## Client Integration

### Authentication Methods

Applications authenticate using API credentials in one of two ways:

#### Method 1: Custom Headers (Recommended)
```javascript
const response = await fetch('http://localhost:3000/users', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': 'ak_1234567890abcdef1234567890abcdef',
    'X-API-Secret': 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
  },
  body: JSON.stringify({
    name: 'John Doe',
    email: 'john@example.com',
    password: 'SecurePassword123!'
  })
});
```

#### Method 2: Bearer Token
```javascript
const credentials = 'ak_1234567890abcdef1234567890abcdef:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';
const token = btoa(credentials); // Base64 encode

const response = await fetch('http://localhost:3000/users', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${credentials}` // Note: Not base64 encoded for Bearer
  },
  body: JSON.stringify({ ... })
});
```

### JavaScript SDK Example

```javascript
class UserServiceClient {
  constructor(apiKey, apiSecret, baseUrl = 'https://auth.yourservice.com') {
    this.apiKey = apiKey;
    this.apiSecret = apiSecret;
    this.baseUrl = baseUrl;
  }

  async createUser(userData) {
    return this.request('POST', '/users', userData);
  }

  async getUser(userId) {
    return this.request('GET', `/users/${userId}`);
  }

  async passwordlessSignup(name, email) {
    return this.request('POST', '/auth/signup/email', { name, email });
  }

  async verifyEmail(email, code) {
    return this.request('POST', '/auth/verify-email', {
      email,
      verification_code: code
    });
  }

  async request(method, path, body = null) {
    const response = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': this.apiKey,
        'X-API-Secret': this.apiSecret
      },
      body: body ? JSON.stringify(body) : null
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error?.message || 'API request failed');
    }

    return response.json();
  }
}

// Usage
const client = new UserServiceClient(
  'ak_1234567890abcdef1234567890abcdef',
  'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
);

// Create a user
const user = await client.createUser({
  name: 'Jane Doe',
  email: 'jane@example.com',
  password: 'SecurePassword123!'
});

// Passwordless signup
await client.passwordlessSignup('John Smith', 'john@example.com');
// User receives email with verification code
await client.verifyEmail('john@example.com', '123456');
```

## API Endpoints

All endpoints (except admin endpoints) require application authentication:

### User Management
- `POST /users` - Create user account
- `GET /users/{id}` - Get user details (requires user auth)
- `PUT /users/{id}` - Update user profile (requires user auth)
- `POST /users/{id}/verify-password` - Verify password (requires user auth)

### Authentication
- `POST /auth/signup/email` - Passwordless signup
- `POST /auth/verify-email` - Verify email and complete signup
- `POST /auth/signin/email` - Request OTP for signin
- `POST /auth/signin/otp` - Verify OTP and signin
- `POST /auth/refresh` - Refresh JWT tokens

### OAuth
- `POST /auth/signup/google` - Initiate Google OAuth
- `GET /auth/callback/google` - Handle OAuth callback
- `GET /auth/oauth/providers` - List linked providers (requires user auth)
- `DELETE /auth/oauth/providers/{provider}` - Unlink provider (requires user auth)

### WebAuthn/Passkeys
- `POST /auth/register/passkey/begin` - Start passkey registration
- `POST /auth/register/passkey/finish` - Complete passkey registration
- `POST /auth/signin/passkey/begin` - Start passkey authentication
- `POST /auth/signin/passkey/finish` - Complete passkey authentication
- `GET /auth/passkeys` - List user's passkeys (requires user auth)
- `PUT /auth/passkeys/{id}` - Update passkey name (requires user auth)
- `DELETE /auth/passkeys/{id}` - Delete passkey (requires user auth)

### Admin Endpoints (No Application Auth Required)
- `POST /admin/applications` - Create application
- `GET /admin/applications` - List applications
- `GET /admin/applications/{id}` - Get application details
- `PUT /admin/applications/{id}` - Update application
- `GET /admin/applications/{id}/stats` - Get application statistics
- `POST /admin/applications/{id}/rotate-credentials` - Rotate API credentials
- `POST /admin/applications/{id}/deactivate` - Deactivate application
- `GET /admin/health` - Admin health check

## Configuration Options

### Application Settings

Each application can have custom configuration:

```json
{
  "email_config": {
    "from_name": "My App",
    "from_email": "noreply@myapp.com",
    "smtp_host": "smtp.myapp.com",
    "smtp_port": 587,
    "smtp_username": "username",
    "smtp_password": "password",
    "templates": {
      "verification_subject": "Verify your email",
      "verification_template": "Click here to verify: {{verification_url}}",
      "otp_subject": "Your login code",
      "otp_template": "Your code is: {{otp_code}}"
    }
  },
  "oauth_config": {
    "google": {
      "client_id": "app-specific-google-client-id",
      "client_secret": "app-specific-google-client-secret",
      "redirect_uri": "https://myapp.com/auth/callback"
    }
  },
  "jwt_settings": {
    "access_token_expires_hours": 24,
    "refresh_token_expires_days": 30,
    "issuer": "myapp.com",
    "audience": "myapp-users"
  },
  "rate_limits": {
    "email_verification_per_hour": 5,
    "otp_requests_per_hour": 3,
    "password_attempts_per_hour": 10,
    "account_creation_per_hour": 5,
    "oauth_attempts_per_hour": 10
  },
  "webauthn_config": {
    "rp_id": "myapp.com",
    "rp_name": "My App",
    "rp_origin": "https://myapp.com"
  },
  "ui_settings": {
    "app_name": "My App",
    "logo_url": "https://myapp.com/logo.png",
    "primary_color": "#007bff",
    "login_url": "https://myapp.com/login",
    "signup_url": "https://myapp.com/signup",
    "support_email": "support@myapp.com"
  }
}
```

## Security Considerations

### Data Isolation
- All user data is completely isolated by `application_id`
- Users in one application cannot access data from another application
- SQL queries are automatically scoped to the authenticated application

### Authentication Security
- API keys and secrets are bcrypt-hashed in the database
- Failed authentication attempts are logged for monitoring
- Rate limiting is applied per application
- CORS origins are enforced per application

### Monitoring & Auditing
- All authentication events are logged with application context
- Failed API authentication attempts are tracked
- Application usage statistics are available
- Security audit logs include application information

## Migration from Single-Tenant

If you have an existing single-tenant installation:

1. **Backup your database** before running migrations
2. **Run the multi-tenant migrations**
3. **Create a default application** for existing data
4. **Update existing records** to reference the default application:

```sql
-- Create a default application for existing data
INSERT INTO applications (name, api_key, api_secret_hash, allowed_origins)
VALUES ('Default App', 'ak_default123', '$2b$12$...', ARRAY['*']);

-- Get the application ID
SELECT id FROM applications WHERE name = 'Default App';

-- Update all existing records (replace UUID with actual application ID)
UPDATE users SET application_id = 'your-application-uuid' WHERE application_id IS NULL;
UPDATE auth_sessions SET application_id = 'your-application-uuid' WHERE application_id IS NULL;
-- ... repeat for all tables
```

4. **Run the second migration** to make application_id required
5. **Update your client applications** to use API credentials

## Troubleshooting

### Common Issues

**"Missing X-API-Key header"**
- Ensure your client is sending the `X-API-Key` and `X-API-Secret` headers
- Or use the `Authorization: Bearer api_key:api_secret` format

**"Invalid API key"**
- Check that the API key exists and is active
- Verify the API secret is correct (check for copy/paste errors)

**"Origin not allowed for this application"**
- Add your domain to the application's `allowed_origins`
- Use `["*"]` for development (not recommended for production)

**"Application not found"**
- Ensure the application exists and is active
- Check the application ID in admin endpoints

### Debugging

Enable debug logging to see detailed request information:
```bash
RUST_LOG=debug cargo run --example multi_tenant_server
```

Check application statistics:
```bash
curl http://localhost:3000/admin/applications/{app_id}/stats
```

## Performance Considerations

- **Database Indexes**: All tables have optimized indexes for multi-tenant queries
- **Connection Pooling**: Shared connection pool across all applications
- **Caching**: JWT validation is stateless for high performance
- **Rate Limiting**: Prevents abuse while maintaining performance for legitimate traffic

## Production Deployment

### Load Balancing
- Use a load balancer (nginx, HAProxy, ALB) in front of multiple service instances
- All instances share the same database for consistent application management
- Session stickiness is not required (stateless JWT tokens)

### Database Scaling
- Use PostgreSQL read replicas for read-heavy workloads
- Consider connection pooling (PgBouncer) for high-concurrency scenarios
- Monitor database performance with application-scoped queries

### Monitoring
- Set up alerts for failed authentication attempts per application
- Monitor API key usage and rate limiting events
- Track application-specific user growth and activity

### Backup & Recovery
- Regular database backups including application configurations
- Test restore procedures with application data isolation
- Document application credential recovery procedures

## API Rate Limits

Default rate limits per application (configurable per app):

- Email verification: 5 per hour per email
- OTP requests: 3 per hour per email
- Password attempts: 10 per hour per IP
- Account creation: 5 per hour per IP
- OAuth attempts: 10 per hour per IP

Rate limits are enforced at both IP and email level for comprehensive protection.