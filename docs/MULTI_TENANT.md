# Multi-Tenant User Service Documentation

## Overview

The User Service has been enhanced to support multi-tenant architecture, allowing a single service instance to serve multiple independent applications (tenants) with complete data isolation and per-tenant configuration.

## Table of Contents

- [Architecture](#architecture)
- [Getting Started](#getting-started)
- [Application Management](#application-management)
- [API Authentication](#api-authentication)
- [Tenant Isolation](#tenant-isolation)
- [Configuration](#configuration)
- [CLI Tools](#cli-tools)
- [API Reference](#api-reference)
- [Migration Guide](#migration-guide)
- [Security Considerations](#security-considerations)
- [Performance](#performance)
- [Monitoring](#monitoring)

## Architecture

### Core Concepts

**Application/Tenant**: Each tenant is represented as an `Application` with:
- Unique API credentials (key + secret)
- Custom configuration (JWT settings, rate limits, UI branding)
- Allowed CORS origins
- Complete data isolation

**Data Isolation**: All user data tables include an `application_id` field ensuring complete separation between tenants.

**Authentication**: Two-level authentication:
1. Application-level: API key + secret for tenant identification
2. User-level: JWT tokens for individual user authentication

### Database Schema

The multi-tenant implementation adds:

```sql
-- Applications table (tenant management)
CREATE TABLE applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    api_key VARCHAR(64) UNIQUE NOT NULL,
    api_secret_hash VARCHAR(255) NOT NULL,
    allowed_origins TEXT[] NOT NULL DEFAULT '{}',
    settings JSONB NOT NULL DEFAULT '{}',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- All existing tables get application_id column
ALTER TABLE users ADD COLUMN application_id UUID REFERENCES applications(id);
-- ... (and all other tables)
```

### Request Flow

```
Client Request → Application Auth Middleware → CORS Check → Route Handler → Service Layer → Database (filtered by application_id)
```

## Getting Started

### 1. Setup and Initialization

First, ensure your database is migrated to support multi-tenancy:

```bash
# Run migrations
sqlx migrate run

# Initialize your first application
cargo run --bin app-admin init --name "My First App"
```

### 2. Create Your First Application

Using the CLI tool:

```bash
cargo run --bin app-admin create \
  --name "My E-commerce App" \
  --origins "https://mystore.com,https://admin.mystore.com" \
  --support-email "support@mystore.com"
```

This will output:
```
✅ Application created successfully!

📋 Application Details:
   ID: 123e4567-e89b-12d3-a456-426614174000
   Name: My E-commerce App

🔑 API Credentials (SAVE THESE SECURELY):
   API Key: ak_abc123...
   API Secret: xyz789...
```

### 3. Using the API

All tenant API calls require authentication headers:

```bash
curl -X POST http://localhost:3000/auth/signup/email \
  -H "X-API-Key: ak_abc123..." \
  -H "X-API-Secret: xyz789..." \
  -H "Content-Type: application/json" \
  -d '{"name": "John Doe", "email": "john@example.com"}'
```

Or using Bearer token format:
```bash
curl -X POST http://localhost:3000/auth/signup/email \
  -H "Authorization: Bearer ak_abc123...:xyz789..." \
  -H "Content-Type: application/json" \
  -d '{"name": "John Doe", "email": "john@example.com"}'
```

## Application Management

### Creating Applications

Applications are created through the admin API or CLI tool:

```bash
# CLI
cargo run --bin app-admin create --name "Corporate App" --origins "https://corp.example.com"

# HTTP API
POST /admin/applications
{
  "name": "Corporate App",
  "allowed_origins": ["https://corp.example.com"],
  "settings": {
    "jwt_settings": {
      "access_token_expires_hours": 2,
      "refresh_token_expires_days": 7
    },
    "ui_settings": {
      "app_name": "Corporate Portal",
      "primary_color": "#0066cc"
    }
  }
}
```

### Managing Applications

```bash
# List all applications
cargo run --bin app-admin list

# Get application details
cargo run --bin app-admin get <app-id>

# Update application
cargo run --bin app-admin update <app-id> --name "New Name"

# Get usage statistics
cargo run --bin app-admin stats <app-id>

# Rotate API credentials
cargo run --bin app-admin rotate <app-id>

# Deactivate application
cargo run --bin app-admin deactivate <app-id>
```

## API Authentication

### Application-Level Authentication

Every API request (except admin endpoints) requires application credentials:

**Headers Method:**
```
X-API-Key: ak_your_api_key
X-API-Secret: your_api_secret
```

**Bearer Token Method:**
```
Authorization: Bearer ak_your_api_key:your_api_secret
```

### User-Level Authentication

After application authentication, user endpoints require JWT tokens:

```
Authorization: Bearer <jwt_access_token>
```

### Authentication Flow

1. **Application Auth**: Middleware validates API key/secret and injects application context
2. **CORS Check**: Validates request origin against application's allowed origins
3. **User Auth** (if required): Validates JWT token for user-specific endpoints

## Tenant Isolation

### Database Level

- All data tables include `application_id` column with NOT NULL constraint
- Unique constraints are scoped per application (e.g., email uniqueness)
- Foreign key cascades ensure data cleanup when applications are deleted
- Optimized indexes for multi-tenant query patterns

### Application Level

- Middleware ensures all queries are automatically filtered by `application_id`
- No cross-tenant data access possible
- Services are application-context aware

### Examples of Isolation

```sql
-- Users with same email in different tenants (allowed)
INSERT INTO users (application_id, email, name) VALUES 
  ('app1-uuid', 'john@example.com', 'John from App 1'),
  ('app2-uuid', 'john@example.com', 'John from App 2');

-- Cross-tenant access (blocked by application_id filter)
SELECT * FROM users 
WHERE application_id = 'app1-uuid' AND id = 'user-from-app2'; -- Returns empty
```

## Configuration

### Application Settings

Each application can configure:

```json
{
  "email_config": {
    "from_name": "My App",
    "from_email": "noreply@myapp.com",
    "smtp_host": "smtp.myapp.com",
    "templates": {
      "verification_subject": "Welcome to My App!",
      "verification_template": "<html>Custom template</html>"
    }
  },
  "jwt_settings": {
    "access_token_expires_hours": 1,
    "refresh_token_expires_days": 30,
    "issuer": "my-app",
    "audience": "my-app-users"
  },
  "rate_limits": {
    "email_verification_per_hour": 5,
    "otp_requests_per_hour": 3,
    "password_attempts_per_hour": 10
  },
  "ui_settings": {
    "app_name": "My App",
    "primary_color": "#007bff",
    "logo_url": "https://myapp.com/logo.png",
    "support_email": "support@myapp.com"
  }
}
```

### Environment Configuration

The service supports standard environment variables plus:

```env
# Database (required)
DATABASE_URL=postgres://user:pass@localhost/userservice

# Server
SERVER_HOST=127.0.0.1
SERVER_PORT=3000

# JWT secrets (required)
JWT_ACCESS_SECRET=your-access-secret
JWT_REFRESH_SECRET=your-refresh-secret

# Optional: OAuth, WebAuthn, Email, etc.
```

## CLI Tools

### app-admin

The `app-admin` CLI provides full application management:

```bash
# Initialize first application
cargo run --bin app-admin init

# Create new application
cargo run --bin app-admin create --name "App Name" --origins "https://app.com"

# List applications
cargo run --bin app-admin list

# Get application details
cargo run --bin app-admin get <uuid>

# Update application
cargo run --bin app-admin update <uuid> --name "New Name"

# Get statistics
cargo run --bin app-admin stats <uuid>

# Rotate credentials (invalidates old ones)
cargo run --bin app-admin rotate <uuid>

# Deactivate application
cargo run --bin app-admin deactivate <uuid>
```

## API Reference

### Admin Endpoints (No Application Auth Required)

#### Create Application
```
POST /admin/applications
Content-Type: application/json

{
  "name": "string",
  "allowed_origins": ["string"],
  "settings": ApplicationSettings
}

Response: CreateApplicationResponse (includes API secret)
```

#### List Applications
```
GET /admin/applications

Response: Array<Application>
```

#### Get Application
```
GET /admin/applications/{id}

Response: Application
```

#### Update Application
```
PUT /admin/applications/{id}
Content-Type: application/json

{
  "name": "string",
  "allowed_origins": ["string"],
  "settings": ApplicationSettings,
  "active": boolean
}

Response: Application
```

#### Get Application Statistics
```
GET /admin/applications/{id}/stats

Response: {
  "total_users": number,
  "active_users_24h": number,
  "auth_events_24h": number,
  "failed_auth_events_24h": number
}
```

#### Rotate Application Credentials
```
POST /admin/applications/{id}/rotate-credentials

Response: {
  "api_key": "string",
  "api_secret": "string",
  "message": "string"
}
```

### Tenant Endpoints (Require Application Auth)

All existing user management endpoints require application authentication:

- `POST /auth/signup/email` - Passwordless signup
- `POST /auth/verify-email` - Email verification
- `POST /auth/signin/email` - Request OTP signin
- `POST /auth/signin/otp` - Verify OTP signin
- `GET /users/{id}` - Get user (requires user JWT)
- `PUT /users/{id}` - Update user (requires user JWT)
- And all other user/auth endpoints...

## Migration Guide

### From Single-Tenant to Multi-Tenant

1. **Backup your database** before running migrations

2. **Run migrations:**
   ```bash
   sqlx migrate run
   ```

3. **Create default application for existing data:**
   ```bash
   # This must be done before the second migration runs
   cargo run --bin app-admin init --name "Legacy Application"
   ```

4. **Update existing data:**
   ```sql
   -- If you have existing data, assign it to your default application
   UPDATE users SET application_id = 'your-default-app-uuid' WHERE application_id IS NULL;
   UPDATE auth_sessions SET application_id = 'your-default-app-uuid' WHERE application_id IS NULL;
   -- ... for all other tables
   ```

5. **Update client applications:**
   - Add API key and secret to your client configuration
   - Include authentication headers in all API requests
   - Update CORS origins in the application settings

### Breaking Changes

- **All API endpoints** (except admin) now require application authentication
- **CORS configuration** moved from server-level to per-application
- **Email uniqueness** is now per-application, not global
- **JWT tokens** are still application-agnostic but user sessions are application-scoped

## Security Considerations

### API Key Management

- **API secrets are hashed** using bcrypt before storage
- **API keys are prefixed** with `ak_` for easy identification
- **Credentials should be rotated** regularly
- **Use environment variables** or secure secret management in production

### Tenant Isolation

- **Database-level isolation** prevents cross-tenant data access
- **Application middleware** ensures all queries include application_id filter
- **No shared secrets** between applications
- **Independent rate limiting** per application

### CORS Security

- **Per-application CORS** configuration prevents unauthorized cross-origin access
- **Strict origin checking** - wildcard (*) should be avoided in production
- **Preflight request handling** for complex CORS scenarios

### Best Practices

1. **Rotate API credentials** regularly
2. **Use HTTPS** in production
3. **Implement proper logging** and monitoring
4. **Set restrictive CORS origins**
5. **Monitor for suspicious activity** across tenants
6. **Use environment-specific configurations**

## Performance

### Database Optimization

The multi-tenant implementation includes optimized indexes:

```sql
-- Application-scoped indexes for performance
CREATE INDEX idx_users_app_email ON users(application_id, email);
CREATE INDEX idx_auth_sessions_app_id ON auth_sessions(application_id);
CREATE INDEX idx_auth_audit_log_app_user ON auth_audit_log(application_id, user_id, created_at DESC);
```

### Caching Considerations

- **Application settings** can be cached per application
- **JWT validation** benefits from application-aware caching
- **Rate limiting** is per-application for fair resource usage

### Scaling

- **Horizontal scaling**: Multiple service instances can serve the same tenants
- **Database sharding**: Consider sharding by application_id for very large deployments
- **Connection pooling**: Database connections are shared across all tenants

## Monitoring

### Application-Level Metrics

Each application provides statistics:
- Total users
- Active users (24h)
- Authentication events (24h)
- Failed authentication events (24h)

### Health Checks

- `/health` - General service health
- `/admin/health` - Application service specific health

### Logging

All authentication events are logged with:
- Application ID
- User ID (if available)
- IP address
- Success/failure status
- Event type

### Alerts

Consider monitoring:
- Failed authentication attempts per application
- Unusual API usage patterns
- Application credential rotation needs
- Cross-tenant access attempts (should never happen)

## Example Integration

### JavaScript/TypeScript Client

```typescript
class MultiTenantUserService {
  constructor(
    private baseUrl: string,
    private apiKey: string,
    private apiSecret: string
  ) {}

  private getAuthHeaders() {
    return {
      'X-API-Key': this.apiKey,
      'X-API-Secret': this.apiSecret,
      'Content-Type': 'application/json'
    };
  }

  async signupWithEmail(name: string, email: string) {
    const response = await fetch(`${this.baseUrl}/auth/signup/email`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify({ name, email })
    });
    return response.json();
  }

  async verifyEmail(email: string, verificationCode: string) {
    const response = await fetch(`${this.baseUrl}/auth/verify-email`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify({ email, verification_code: verificationCode })
    });
    return response.json();
  }
}

// Usage
const userService = new MultiTenantUserService(
  'http://localhost:3000',
  'ak_your_api_key',
  'your_api_secret'
);
```

### Python Client

```python
import requests
from typing import Dict, Any

class MultiTenantUserService:
    def __init__(self, base_url: str, api_key: str, api_secret: str):
        self.base_url = base_url
        self.api_key = api_key
        self.api_secret = api_secret
    
    def _get_headers(self) -> Dict[str, str]:
        return {
            'X-API-Key': self.api_key,
            'X-API-Secret': self.api_secret,
            'Content-Type': 'application/json'
        }
    
    def signup_with_email(self, name: str, email: str) -> Dict[str, Any]:
        response = requests.post(
            f"{self.base_url}/auth/signup/email",
            headers=self._get_headers(),
            json={"name": name, "email": email}
        )
        response.raise_for_status()
        return response.json()
```

## Troubleshooting

### Common Issues

1. **"Missing X-API-Key header"**
   - Ensure you're including the API credentials in every request
   - Check that headers are properly formatted

2. **"Origin not allowed for this application"**
   - Verify the request origin is in the application's allowed_origins
   - Check CORS configuration in your application settings

3. **"Invalid API key"**
   - Verify the API key is correct and the application is active
   - Check if credentials need to be rotated

4. **"User not found" across tenants**
   - Remember that users are isolated per application
   - The same email can exist in multiple applications as different users

### Debug Tips

1. **Check application status:**
   ```bash
   cargo run --bin app-admin get <app-id>
   ```

2. **Verify API credentials:**
   ```bash
   curl -X GET http://localhost:3000/admin/health \
     -H "X-API-Key: your-key" \
     -H "X-API-Secret: your-secret"
   ```

3. **Monitor logs** for authentication failures and CORS issues

4. **Use the health endpoint** to verify service status

## Contributing

When contributing to the multi-tenant functionality:

1. **Ensure tenant isolation** in all new features
2. **Add application_id** to any new data tables
3. **Update CLI tools** for new administrative functions
4. **Include migration scripts** for database changes
5. **Test cross-tenant isolation** thoroughly
6. **Update documentation** for API changes

---

For more examples and advanced configurations, see the `examples/` directory in the repository.