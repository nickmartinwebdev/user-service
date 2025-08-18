# WebAuthn/Passkey Authentication

This document describes the WebAuthn/Passkey authentication implementation in the User Service, providing comprehensive guidance for integration, configuration, and usage.

## Overview

WebAuthn (Web Authentication) is a web standard published by the W3C and FIDO Alliance that enables passwordless authentication using biometric authenticators, security keys, or platform authenticators (like TouchID, FaceID, Windows Hello).

Our implementation provides:
- **Passkey Registration**: Allow users to register biometric authenticators
- **Passkey Authentication**: Passwordless login using registered authenticators
- **Cross-Platform Support**: Works on iOS, Android, macOS, Windows, and Linux
- **Multiple Authenticators**: Users can register multiple passkeys per account
- **Security**: Cryptographic authentication with replay protection

## Features

### Core Authentication Flow
- ✅ Passkey registration for authenticated users
- ✅ Passwordless authentication with passkeys
- ✅ Challenge-response based security
- ✅ Support for multiple passkeys per user
- ✅ JWT token issuance upon successful authentication

### Security Features
- ✅ Cryptographically secure challenge generation
- ✅ Replay attack protection via signature counters
- ✅ Time-limited challenges (configurable timeout)
- ✅ Secure credential storage with raw binary data
- ✅ User verification support (biometric/PIN)

### Management Features
- ✅ List user's registered passkeys
- ✅ Update passkey names for identification
- ✅ Delete individual passkeys
- ✅ Automatic cleanup of expired challenges

## API Endpoints

### Passkey Registration (Authenticated Users)

#### Begin Registration
```http
POST /auth/register/passkey/begin
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "credential_name": "iPhone Touch ID"  // Optional
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "challenge": "base64_challenge_data",
    "rp": {
      "name": "User Service",
      "id": "yourdomain.com"
    },
    "user": {
      "id": "base64_user_handle",
      "name": "user@example.com",
      "displayName": "John Doe"
    },
    "pubKeyCredParams": [
      {"type": "public-key", "alg": -7},
      {"type": "public-key", "alg": -257}
    ],
    "timeout": 60000,
    "excludeCredentials": [/* existing credentials */]
  }
}
```

#### Finish Registration
```http
POST /auth/register/passkey/finish
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "credential": {
    "id": "credential_id",
    "rawId": "base64_raw_id",
    "response": {
      "attestationObject": "base64_attestation",
      "clientDataJSON": "base64_client_data"
    },
    "type": "public-key"
  },
  "credential_name": "iPhone Touch ID"  // Optional
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Passkey registered successfully",
    "credential": {
      "id": "uuid",
      "user_id": "uuid",
      "credential_id": "base64_credential_id",
      "credential_name": "iPhone Touch ID",
      "created_at": "2024-01-15T10:30:00Z",
      "last_used_at": null
    }
  }
}
```

### Passkey Authentication (Public)

#### Begin Authentication
```http
POST /auth/signin/passkey/begin
Content-Type: application/json

{
  "email": "user@example.com"  // Optional hint for UX
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "challenge": "base64_challenge_data",
    "allowCredentials": [/* allowed credentials */],
    "timeout": 60000,
    "rpId": "yourdomain.com",
    "userVerification": "preferred"
  }
}
```

#### Finish Authentication
```http
POST /auth/signin/passkey/finish
Content-Type: application/json

{
  "credential": {
    "id": "credential_id",
    "rawId": "base64_raw_id",
    "response": {
      "authenticatorData": "base64_auth_data",
      "clientDataJSON": "base64_client_data",
      "signature": "base64_signature",
      "userHandle": "base64_user_handle"
    },
    "type": "public-key"
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "access_token": "jwt_access_token",
    "refresh_token": "jwt_refresh_token",
    "token_type": "Bearer",
    "expires_in": 3600,
    "user": {
      "id": "uuid",
      "name": "John Doe",
      "email": "user@example.com",
      "email_verified": true,
      "profile_picture_url": null,
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-15T10:30:00Z"
    }
  }
}
```

### Passkey Management (Authenticated Users)

#### List Passkeys
```http
GET /auth/passkeys
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "name_filter": "iPhone"  // Optional
}
```

#### Update Passkey Name
```http
PUT /auth/passkeys/{credential_id}
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "credential_name": "New Device Name"
}
```

#### Delete Passkey
```http
DELETE /auth/passkeys/{credential_id}
Authorization: Bearer <jwt_token>
```

## Configuration

### Environment Variables

```bash
# Required for production
WEBAUTHN_RP_ID=yourdomain.com
WEBAUTHN_RP_ORIGIN=https://yourdomain.com

# Optional configuration
WEBAUTHN_RP_NAME="Your Service Name"
WEBAUTHN_CHALLENGE_TIMEOUT_SECONDS=60
WEBAUTHN_REQUIRE_USER_VERIFICATION=false
WEBAUTHN_ALLOWED_ALGORITHMS=-7,-257
```

### Configuration Object

```rust
use user_service::WebAuthnConfig;

let config = WebAuthnConfig {
    rp_id: "yourdomain.com".to_string(),
    rp_name: "Your Service".to_string(),
    rp_origin: "https://yourdomain.com".to_string(),
    challenge_timeout_seconds: 60,
    require_user_verification: false,
    allowed_algorithms: vec![-7, -257], // ES256, RS256
};
```

## Frontend Integration

### Registration Flow

```javascript
// 1. Begin registration
const beginResponse = await fetch('/auth/register/passkey/begin', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    credential_name: 'My Device'
  })
});

const { data: options } = await beginResponse.json();

// 2. Create credential
const credential = await navigator.credentials.create({
  publicKey: options
});

// 3. Finish registration
const finishResponse = await fetch('/auth/register/passkey/finish', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    credential: {
      id: credential.id,
      rawId: arrayBufferToBase64(credential.rawId),
      response: {
        attestationObject: arrayBufferToBase64(credential.response.attestationObject),
        clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON)
      },
      type: credential.type
    },
    credential_name: 'My Device'
  })
});
```

### Authentication Flow

```javascript
// 1. Begin authentication
const beginResponse = await fetch('/auth/signin/passkey/begin', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'user@example.com' // Optional
  })
});

const { data: options } = await beginResponse.json();

// 2. Get credential
const credential = await navigator.credentials.get({
  publicKey: options
});

// 3. Finish authentication
const finishResponse = await fetch('/auth/signin/passkey/finish', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    credential: {
      id: credential.id,
      rawId: arrayBufferToBase64(credential.rawId),
      response: {
        authenticatorData: arrayBufferToBase64(credential.response.authenticatorData),
        clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
        signature: arrayBufferToBase64(credential.response.signature),
        userHandle: credential.response.userHandle ? 
          arrayBufferToBase64(credential.response.userHandle) : null
      },
      type: credential.type
    }
  })
});

const { data: authResult } = await finishResponse.json();
// Store tokens: authResult.access_token, authResult.refresh_token
```

### Utility Functions

```javascript
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
```

## Database Schema

### user_credentials Table

```sql
CREATE TABLE user_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    credential_name VARCHAR(255),
    authenticator_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id, credential_id)
);
```

### webauthn_challenges Table

```sql
CREATE TABLE webauthn_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_type VARCHAR(20) NOT NULL CHECK (challenge_type IN ('registration', 'authentication')),
    challenge BYTEA NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    user_handle BYTEA
);
```

## Security Considerations

### Production Deployment

1. **HTTPS Required**: WebAuthn only works over HTTPS in production
2. **Domain Configuration**: Set correct `WEBAUTHN_RP_ID` and `WEBAUTHN_RP_ORIGIN`
3. **User Verification**: Consider enabling `WEBAUTHN_REQUIRE_USER_VERIFICATION=true`
4. **Challenge Cleanup**: Run periodic cleanup of expired challenges

### Best Practices

1. **Fallback Authentication**: Always provide alternative authentication methods
2. **User Education**: Guide users through passkey setup and usage
3. **Device Management**: Allow users to manage their registered devices
4. **Backup Recovery**: Implement account recovery for users who lose all devices
5. **Privacy**: Store minimal authenticator data, respect user privacy

### Rate Limiting

Consider implementing rate limiting on WebAuthn endpoints:
- Registration attempts: 5 per hour per user
- Authentication attempts: 10 per minute per IP
- Challenge generation: 20 per minute per IP

## Error Handling

### Common Error Scenarios

1. **Challenge Expired**: User took too long to complete the flow
2. **Invalid Signature**: Replay attack or corrupted data
3. **Credential Not Found**: User's device was reset or credential deleted
4. **User Verification Failed**: Biometric/PIN verification failed
5. **Unsupported Algorithm**: Authenticator doesn't support required algorithms

### Error Response Format

```json
{
  "error": "CHALLENGE_EXPIRED",
  "message": "Challenge has expired",
  "details": {
    "challenge_timeout_seconds": 60,
    "retry_after": "2024-01-15T10:31:00Z"
  }
}
```

## Testing

### Unit Tests

```rust
#[tokio::test]
async fn test_passkey_registration_flow() {
    let config = WebAuthnConfig::default_dev();
    let service = WebAuthnService::new(pool, config, jwt_service).unwrap();
    
    // Test begin registration
    let begin_request = PasskeyRegistrationBeginRequest {
        credential_name: Some("Test Device".to_string()),
    };
    
    let begin_response = service
        .begin_passkey_registration(user_id, begin_request)
        .await
        .unwrap();
    
    assert!(!begin_response.options.challenge.is_empty());
}
```

### Integration Tests

Use tools like:
- **webauthn-rs test vectors** for cryptographic validation
- **Chrome DevTools** for WebAuthn API testing
- **FIDO2 test tools** for comprehensive testing

## Browser Compatibility

### Supported Browsers

| Browser | Desktop | Mobile | Notes |
|---------|---------|--------|-------|
| Chrome  | ✅ 67+  | ✅ 70+ | Full support |
| Firefox | ✅ 60+  | ✅ 68+ | Full support |
| Safari  | ✅ 14+  | ✅ 14+ | iOS/macOS only |
| Edge    | ✅ 18+  | ❌     | Windows only |

### Feature Detection

```javascript
if (!window.PublicKeyCredential) {
  // Fallback to password authentication
  console.log('WebAuthn not supported');
} else {
  // WebAuthn is available
  console.log('WebAuthn supported');
}
```

## Troubleshooting

### Common Issues

1. **"Invalid RP ID"**: Check domain configuration
2. **"Challenge verification failed"**: Time synchronization issues
3. **"User verification failed"**: User canceled biometric prompt
4. **"Credential excluded"**: User trying to register existing credential

### Debug Mode

Enable debug logging for WebAuthn operations:

```bash
RUST_LOG=user_service::service::webauthn_service=debug
```

### Health Checks

Monitor WebAuthn service health:

```http
GET /health
```

Should include WebAuthn service status in the response.

## Migration Guide

### From Password-Only Authentication

1. Deploy WebAuthn endpoints alongside existing password auth
2. Allow users to register passkeys while logged in via password
3. Encourage passkey adoption with UX incentives
4. Monitor adoption rates and user feedback
5. Consider making passkeys the primary authentication method

### Database Migration

The migration is automatically applied when starting the service:

```sql
-- Applied automatically
\i migrations/20250119000004_create_webauthn_tables.sql
```

## Support and Resources

### Documentation
- [WebAuthn Specification](https://www.w3.org/TR/webauthn-3/)
- [webauthn-rs Documentation](https://docs.rs/webauthn-rs/)
- [FIDO Alliance Resources](https://fidoalliance.org/resources/)

### Tools
- [WebAuthn Debugger](https://webauthn.io/debugger)
- [Chrome DevTools WebAuthn Tab](https://developer.chrome.com/docs/devtools/webauthn/)
- [FIDO2 Conformance Tools](https://fidoalliance.org/certification/functional-certification/conformance/)

For implementation questions or issues, refer to the service documentation or create an issue in the project repository.