# Database Schema: Timestamp Fields Documentation

This document provides a comprehensive overview of all timestamp fields in the user service database schema, confirming that all required date fields are properly constrained as NOT NULL.

## Overview

All timestamp fields in the user service use `TIMESTAMP WITH TIME ZONE` for proper timezone handling and are constrained as `NOT NULL` to ensure data integrity.

## Tables and Timestamp Fields

### Users Table (`users`)

| Column Name | Data Type | Constraints | Default Value | Description |
|-------------|-----------|-------------|---------------|-------------|
| `created_at` | `TIMESTAMP WITH TIME ZONE` | `NOT NULL` | `NOW()` | Account creation timestamp |
| `updated_at` | `TIMESTAMP WITH TIME ZONE` | `NOT NULL` | `NOW()` | Last profile update timestamp (auto-updated via trigger) |

**Rust Model Mapping:**
```rust
pub struct User {
    pub created_at: DateTime<Utc>,  // NOT NULL
    pub updated_at: DateTime<Utc>,  // NOT NULL
}
```

### Authentication Sessions Table (`auth_sessions`)

| Column Name | Data Type | Constraints | Default Value | Description |
|-------------|-----------|-------------|---------------|-------------|
| `created_at` | `TIMESTAMP WITH TIME ZONE` | `NOT NULL` | `NOW()` | Session creation timestamp |
| `last_used_at` | `TIMESTAMP WITH TIME ZONE` | `NOT NULL` | `NOW()` | Last session usage timestamp (auto-updated via trigger) |
| `expires_at` | `TIMESTAMP WITH TIME ZONE` | `NOT NULL` | None | Session expiration timestamp |

**Rust Model Mapping:**
```rust
pub struct AuthSession {
    pub created_at: DateTime<Utc>,   // NOT NULL
    pub last_used_at: DateTime<Utc>, // NOT NULL  
    pub expires_at: DateTime<Utc>,   // NOT NULL
}
```

## Database Constraints Summary

### NOT NULL Constraints
All timestamp fields are properly constrained with `NOT NULL` to prevent:
- Data integrity issues
- Unexpected null pointer exceptions in application code
- Inconsistent sorting and filtering behavior
- Audit trail gaps

### Default Values
- `created_at` fields: Use `NOW()` default for automatic timestamp insertion
- `updated_at` and `last_used_at` fields: Use `NOW()` default with triggers for automatic updates
- `expires_at` fields: No default value (must be explicitly set by application)

### Automatic Updates
Database triggers are configured to automatically update certain timestamp fields:

1. **Users Table Trigger**: `update_users_updated_at`
   - Updates `updated_at` to `NOW()` on any row update
   - Ensures accurate tracking of profile modifications

2. **Auth Sessions Table Trigger**: `update_auth_sessions_last_used_at` 
   - Updates `last_used_at` to `NOW()` on any row update
   - Tracks session activity for security monitoring

## Verification

The schema can be verified programmatically using the built-in verification functions:

```rust
use user_service::database::verify_database_schema;

// Verify all timestamp constraints are properly configured
verify_database_schema(&pool).await?;
```

This verification includes:
- Checking that all timestamp fields are `NOT NULL`
- Confirming proper data types (`TIMESTAMP WITH TIME ZONE`)
- Validating required database extensions are installed

## Migration History

- **20240815000001**: Created users table with NOT NULL timestamp constraints
- **20240815000002**: Created auth_sessions table with NOT NULL timestamp constraints

## Best Practices

1. **Always use UTC**: All timestamps are stored in UTC and converted to local time in the application layer
2. **NOT NULL enforcement**: All business-critical timestamp fields are constrained as NOT NULL
3. **Automatic triggers**: Use database triggers for fields that should update automatically
4. **Explicit expiration**: Expiration timestamps must be explicitly set by the application logic
5. **Index optimization**: All timestamp fields that are frequently queried have database indexes

## Schema Verification Tests

The following automated tests ensure schema integrity:

- `test_timestamp_constraints_verification()`: Validates NOT NULL constraints
- `test_database_extensions_verification()`: Confirms required extensions
- `test_complete_schema_verification()`: Comprehensive schema validation

These tests run as part of the CI/CD pipeline to catch schema regressions early.