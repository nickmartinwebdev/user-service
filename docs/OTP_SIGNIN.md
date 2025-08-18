# Email OTP Sign-in System

This document describes the Email OTP (One-Time Password) sign-in system implemented for existing verified users.

## Overview

The OTP sign-in system provides passwordless authentication for users who have already verified their email addresses. This feature enhances security and user experience by eliminating the need to remember passwords.

## Features

- 🔐 **Secure 6-digit OTP codes** - Cryptographically generated codes
- ⏰ **5-minute expiration** - OTPs automatically expire for security
- 🛡️ **Rate limiting** - Maximum 3 OTP requests per hour per user
- 📧 **Email verification required** - Only works for verified email addresses
- 🔄 **Automatic invalidation** - Previous unused OTPs are invalidated on new requests
- 📊 **Security logging** - IP address and user agent tracking
- 🎯 **JWT integration** - Returns standard access and refresh tokens

## API Endpoints

### 1. Request OTP for Sign-in

**Endpoint:** `POST /auth/signin/email`

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "OTP sent to your email",
    "expires_in": 300
  }
}
```

**Error Responses:**
- `400 Bad Request` - Invalid email format or email not verified
- `404 Not Found` - User not found
- `429 Too Many Requests` - Rate limit exceeded (3 requests per hour)
- `500 Internal Server Error` - Email service failure

### 2. Verify OTP and Complete Sign-in

**Endpoint:** `POST /auth/signin/otp`

**Request Body:**
```json
{
  "email": "user@example.com",
  "otp_code": "123456"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "user": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "John Doe",
      "email": "user@example.com",
      "email_verified": true,
      "profile_picture_url": null,
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-01T00:00:00Z"
    }
  }
}
```

**Error Responses:**
- `400 Bad Request` - Invalid OTP code, expired OTP, or OTP already used
- `404 Not Found` - User not found
- `429 Too Many Requests` - Too many verification attempts (3 per OTP)

## Database Schema

The OTP sign-in system uses the `login_otps` table:

```sql
CREATE TABLE login_otps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    otp_code VARCHAR(6) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    attempts INTEGER DEFAULT 0,
    used_at TIMESTAMP WITH TIME ZONE,
    ip_address INET,
    user_agent TEXT,
    UNIQUE(user_id, otp_code)
);
```

## Configuration

### Environment Variables

```bash
# Email Service Configuration
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=your-username
SMTP_PASSWORD=your-password
FROM_EMAIL=noreply@yourdomain.com
FROM_NAME="Your Service Name"

# JWT Configuration
JWT_ACCESS_SECRET=your-access-secret-key
JWT_REFRESH_SECRET=your-refresh-secret-key
JWT_ACCESS_EXPIRES_HOURS=1
JWT_REFRESH_EXPIRES_DAYS=30

# Database Configuration
DATABASE_URL=postgres://user:password@localhost/database
```

### Service Setup

```rust
use std::sync::Arc;
use user_service::{
    config::JwtConfig,
    service::{EmailConfig, EmailService, JwtService, UserService},
    database::DatabaseConfig,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup database
    let db_config = DatabaseConfig::from_env()?;
    let pool = db_config.create_pool().await?;

    // Setup email service
    let email_config = EmailConfig::from_env()?;
    let email_service = Arc::new(EmailService::new(email_config).await?);

    // Setup JWT service
    let jwt_config = JwtConfig::from_env()?;
    let jwt_service = Arc::new(JwtService::new(jwt_config));

    // Create user service with OTP capabilities
    let user_service = UserService::with_email_service(
        pool,
        email_service,
        jwt_service,
    );

    // Use in your application...
    Ok(())
}
```

### Router Configuration

```rust
use user_service::api::RouterBuilder;

// Enable OTP endpoints
let app = RouterBuilder::new()
    .health_check(true)
    .signin_otp_request(true)    // POST /auth/signin/email
    .signin_otp_verify(true)     // POST /auth/signin/otp
    .build()
    .with_state(app_state);
```

## Security Considerations

### Rate Limiting

- **OTP Requests**: Maximum 3 per hour per user
- **Verification Attempts**: Maximum 3 per OTP code
- **Progressive Delays**: Consider implementing progressive delays for repeated failures

### OTP Security

- **Cryptographic Generation**: Uses secure random number generation
- **Short Expiration**: 5-minute window reduces exposure time
- **Single Use**: OTPs are marked as used after successful verification
- **Invalidation**: New OTP requests invalidate previous unused codes

### Email Security

- **Verified Addresses Only**: OTPs only sent to email-verified accounts
- **Security Context**: Emails include warning about unauthorized requests
- **Template Protection**: Uses secure email templates with proper escaping

### Logging and Monitoring

- **IP Address Tracking**: Log source IP for all OTP requests
- **User Agent Logging**: Track client information for security analysis
- **Attempt Monitoring**: Log all verification attempts for abuse detection

## Email Templates

### OTP Email (HTML)

The system sends professional HTML emails with:
- Clear OTP code display
- Expiration time information
- Security warnings
- Branded styling

### OTP Email (Text)

Plain text fallback includes:
- 6-digit OTP code
- Expiration information
- Security instructions

## Error Handling

### Common Error Scenarios

1. **Email Not Verified**
   - Status: 400 Bad Request
   - Message: "Email address is not verified"
   - Solution: User must verify email first

2. **Rate Limit Exceeded**
   - Status: 429 Too Many Requests
   - Message: "Too many OTP requests. Please try again later"
   - Solution: Wait 1 hour before next request

3. **OTP Expired**
   - Status: 400 Bad Request
   - Message: "Verification code has expired"
   - Solution: Request new OTP

4. **Invalid OTP Code**
   - Status: 400 Bad Request
   - Message: "Invalid verification code"
   - Solution: Check code and try again

5. **Too Many Attempts**
   - Status: 429 Too Many Requests
   - Message: "Too many verification attempts"
   - Solution: Request new OTP

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_otp_validation() {
        // Test OTP expiration logic
        // Test attempt counting
        // Test usage tracking
    }

    #[sqlx::test]
    async fn test_otp_signin_flow(pool: PgPool) {
        // Test complete OTP signin flow
        // Test rate limiting
        // Test error conditions
    }
}
```

### Integration Testing

1. **Complete Flow Testing**
   - Create verified user
   - Request OTP
   - Verify OTP
   - Validate JWT tokens

2. **Security Testing**
   - Rate limiting verification
   - Expired OTP handling
   - Invalid code rejection
   - Unverified email blocking

3. **Email Service Testing**
   - Template rendering
   - SMTP connectivity
   - Delivery confirmation

## Monitoring and Metrics

### Key Metrics to Track

- **OTP Request Rate**: Requests per hour/day
- **OTP Success Rate**: Successful verifications vs attempts
- **Email Delivery Rate**: Successful email deliveries
- **Rate Limit Hits**: Number of rate limit violations
- **Error Rates**: Failed requests by type

### Alerting

Set up alerts for:
- High rate limit violation rates
- Low OTP success rates
- Email service failures
- Unusual request patterns

## Migration Guide

### From Password-based Authentication

1. **Maintain Backward Compatibility**
   - Keep existing password endpoints
   - Add OTP endpoints alongside
   - Allow users to choose authentication method

2. **Gradual Migration**
   - Encourage OTP usage for verified users
   - Provide clear migration instructions
   - Monitor adoption rates

3. **User Education**
   - Explain OTP benefits
   - Provide clear instructions
   - Offer support for issues

## Troubleshooting

### Common Issues

1. **OTPs Not Received**
   - Check email service configuration
   - Verify SMTP credentials
   - Check spam/junk folders
   - Validate email address format

2. **Rate Limiting Issues**
   - Check user's request history
   - Verify rate limiting logic
   - Consider adjusting limits for legitimate use

3. **JWT Token Issues**
   - Verify JWT secret configuration
   - Check token expiration settings
   - Validate token generation logic

### Debugging Commands

```bash
# Check OTP records for user
SELECT * FROM login_otps WHERE user_id = 'user-uuid' ORDER BY created_at DESC;

# Check rate limiting status
SELECT user_id, COUNT(*) as otp_count 
FROM login_otps 
WHERE created_at > NOW() - INTERVAL '1 hour' 
GROUP BY user_id;

# Check email verification status
SELECT email, email_verified FROM users WHERE email = 'user@example.com';
```

## Best Practices

1. **Security First**
   - Use HTTPS for all OTP endpoints
   - Implement proper CORS policies
   - Log security events
   - Regular security audits

2. **User Experience**
   - Clear error messages
   - Reasonable expiration times
   - Intuitive UI/UX design
   - Mobile-friendly implementation

3. **Operational Excellence**
   - Monitor system health
   - Set up proper alerting
   - Regular backup procedures
   - Disaster recovery planning

4. **Performance**
   - Database query optimization
   - Connection pooling
   - Caching strategies
   - Load testing

## Support and Documentation

For additional support:
- Check the API documentation
- Review the example implementations
- Run the provided test suites
- Consult the troubleshooting guide

For feature requests or issues:
- Create detailed bug reports
- Include relevant logs and configurations
- Provide steps to reproduce issues
- Follow the contribution guidelines