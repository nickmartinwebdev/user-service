# User Service API Documentation

This document provides comprehensive documentation for the User Service REST API.

## Base URL

```
http://localhost:3000
```

## Authentication

Currently, the service does not implement authentication middleware. This is intended for internal microservice communication or for use behind an API gateway that handles authentication.

## Content Type

All requests and responses use `application/json` content type.

## Error Handling

All errors follow a consistent format:

```json
{
  "error": "ERROR_CODE",
  "message": "Human readable error message",
  "details": {} // Optional additional error details
}
```

### Common Error Codes

- `VALIDATION_ERROR` (400) - Invalid input data
- `NOT_FOUND` (404) - Resource not found
- `CONFLICT` (409) - Resource already exists (e.g., duplicate email)
- `DATABASE_ERROR` (500) - Internal database error
- `INTERNAL_ERROR` (500) - Unexpected server error

## Endpoints

### Health Check

#### GET /health

Checks the health status of the service and database connectivity.

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "timestamp": "2024-08-15T10:30:00Z",
    "version": "0.1.0"
  }
}
```

### User Management

#### POST /users

Creates a new user account.

**Request Body:**
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "SecurePassword123!",
  "profile_picture_url": "https://example.com/avatar.jpg" // Optional
}
```

**Validation Rules:**
- `name`: 1-255 characters, letters, spaces, hyphens, and apostrophes only
- `email`: Valid RFC-compliant email format
- `password`: 8-128 characters, must contain uppercase, lowercase, digit, and special character
- `profile_picture_url`: Valid HTTP/HTTPS URL (optional)

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "name": "John Doe",
    "email": "john@example.com",
    "profile_picture_url": "https://example.com/avatar.jpg",
    "created_at": "2024-08-15T10:30:00Z"
  }
}
```

**Error Responses:**
- `400 VALIDATION_ERROR` - Invalid input data
- `409 CONFLICT` - Email already exists

#### GET /users/{id}

Retrieves a user by their unique ID.

**Path Parameters:**
- `id` (UUID) - User's unique identifier

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "name": "John Doe",
    "email": "john@example.com",
    "profile_picture_url": "https://example.com/avatar.jpg",
    "created_at": "2024-08-15T10:30:00Z",
    "updated_at": "2024-08-15T10:30:00Z"
  }
}
```

**Error Responses:**
- `404 NOT_FOUND` - User not found
- `400 VALIDATION_ERROR` - Invalid UUID format

#### PUT /users/{id}

Updates an existing user's profile information. All fields are optional - only provided fields will be updated.

**Path Parameters:**
- `id` (UUID) - User's unique identifier

**Request Body:**
```json
{
  "name": "John Smith", // Optional
  "email": "john.smith@example.com", // Optional
  "profile_picture_url": "https://example.com/new-avatar.jpg" // Optional
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "name": "John Smith",
    "email": "john.smith@example.com",
    "profile_picture_url": "https://example.com/new-avatar.jpg",
    "created_at": "2024-08-15T10:30:00Z",
    "updated_at": "2024-08-15T11:00:00Z"
  }
}
```

**Error Responses:**
- `404 NOT_FOUND` - User not found
- `400 VALIDATION_ERROR` - Invalid input data
- `409 CONFLICT` - Email already exists

### Password Management

#### POST /users/{id}/verify-password

Verifies a user's password without exposing the hash.

**Path Parameters:**
- `id` (UUID) - User's unique identifier

**Request Body:**
```json
{
  "password": "SecurePassword123!"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "valid": true
  }
}
```

**Error Responses:**
- `404 NOT_FOUND` - User not found
- `400 VALIDATION_ERROR` - Empty password

### Profile Picture Management

#### PUT /users/{id}/profile-picture

Updates a user's profile picture URL.

**Path Parameters:**
- `id` (UUID) - User's unique identifier

**Request Body:**
```json
{
  "profile_picture_url": "https://example.com/new-avatar.jpg" // Can be null to remove
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "name": "John Doe",
    "email": "john@example.com",
    "profile_picture_url": "https://example.com/new-avatar.jpg",
    "created_at": "2024-08-15T10:30:00Z",
    "updated_at": "2024-08-15T11:30:00Z"
  }
}
```

#### DELETE /users/{id}/profile-picture

Removes a user's profile picture (sets to null).

**Path Parameters:**
- `id` (UUID) - User's unique identifier

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "name": "John Doe",
    "email": "john@example.com",
    "profile_picture_url": null,
    "created_at": "2024-08-15T10:30:00Z",
    "updated_at": "2024-08-15T11:45:00Z"
  }
}
```

## cURL Examples

### Create User
```bash
curl -X POST http://localhost:3000/users \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Alice Johnson",
    "email": "alice@example.com",
    "password": "SecurePass123!",
    "profile_picture_url": "https://example.com/alice.jpg"
  }'
```

### Get User
```bash
curl http://localhost:3000/users/123e4567-e89b-12d3-a456-426614174000
```

### Update User
```bash
curl -X PUT http://localhost:3000/users/123e4567-e89b-12d3-a456-426614174000 \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Alice Smith",
    "email": "alice.smith@example.com"
  }'
```

### Verify Password
```bash
curl -X POST http://localhost:3000/users/123e4567-e89b-12d3-a456-426614174000/verify-password \
  -H "Content-Type: application/json" \
  -d '{
    "password": "SecurePass123!"
  }'
```

### Update Profile Picture
```bash
curl -X PUT http://localhost:3000/users/123e4567-e89b-12d3-a456-426614174000/profile-picture \
  -H "Content-Type: application/json" \
  -d '{
    "profile_picture_url": "https://example.com/new-avatar.jpg"
  }'
```

### Remove Profile Picture
```bash
curl -X DELETE http://localhost:3000/users/123e4567-e89b-12d3-a456-426614174000/profile-picture
```

### Health Check
```bash
curl http://localhost:3000/health
```

## Rate Limiting

Currently not implemented. For production use, consider implementing rate limiting at the API gateway level or adding middleware.

## Security Considerations

1. **Password Security**: Passwords are hashed using bcrypt with cost factor 12
2. **SQL Injection**: All queries use prepared statements
3. **Input Validation**: Comprehensive validation on all inputs
4. **Error Handling**: Sensitive information is not exposed in error messages
5. **HTTPS**: Use HTTPS in production environments
6. **Authentication**: Implement authentication middleware for production use