# User Service

A standalone, production-ready user management service built in Rust. This service provides comprehensive user CRUD operations, authentication, and profile management designed for microservices architecture.

## Features

### Core Functionality
- **User Management**: Create, read, update, and delete user accounts
- **Profile Pictures**: Upload and manage user profile pictures
- **Password Security**: bcrypt password hashing with configurable cost
- **Email Validation**: RFC-compliant email validation and normalization
- **Input Validation**: Comprehensive validation with detailed error messages
- **JWT Authentication**: Complete JWT infrastructure with access and refresh tokens
- **OTP Sign-in**: Email-based one-time password authentication for verified users
- **Passwordless Authentication**: Complete passwordless signup and verification flow
- **OAuth 2.0 Integration**: Google OAuth authentication with account linking
- **Social Login**: Seamless integration with external OAuth providers

### Security & Performance
- **SQL Injection Prevention**: Prepared statements with SQLx
- **Password Strength**: Enforced password complexity requirements
- **Rate Limiting Ready**: Built-in structures for rate limiting
- **Connection Pooling**: Efficient database connection management
- **Type Safety**: Compile-time query verification with SQLx

### API Design
- **RESTful Endpoints**: Clean, intuitive API design
- **JSON Responses**: Structured error and success responses
- **Health Checks**: Built-in health monitoring endpoints
- **CORS Support**: Cross-origin resource sharing configuration
- **Security Headers**: Standard security headers included

## Quick Start

### Prerequisites
- Rust 1.70+
- PostgreSQL 12+
- Docker (optional)

### Environment Setup

1. Clone the repository:
```bash
git clone https://github.com/nickmartinwebdev/user-service.git
cd user-service
```

2. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your database configuration
```

3. Start PostgreSQL (using Docker):
```bash
docker run --name user-service-db \
  -e POSTGRES_DB=user_service \
  -e POSTGRES_USER=user_service \
  -e POSTGRES_PASSWORD=your_password \
  -p 5432:5432 \
  -d postgres:15
```

4. Run database migrations:
```bash
cargo install sqlx-cli
sqlx migrate run
```

5. Start the service:
```bash
cargo run
```

The service will be available at `http://localhost:3000`.

## API Endpoints

### User Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/users` | Create a new user |
| GET | `/users/{id}` | Get user by ID |
| PUT | `/users/{id}` | Update user profile |
| POST | `/users/{id}/verify-password` | Verify user password |
| PUT | `/users/{id}/profile-picture` | Update profile picture |
| DELETE | `/users/{id}/profile-picture` | Remove profile picture |

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/refresh` | Refresh JWT access token |

### System

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check endpoint |

## Authentication & Route Configuration

The RouterBuilder provides flexible configuration for API routes with automatic authentication middleware. Routes are categorized into public (no authentication required) and protected (authentication required).

### RouterBuilder with Authentication

```rust
use user_service::{api::{AppState, RouterBuilder}, service::JwtService};
use std::sync::Arc;

// Create a router with automatic authentication on protected routes
let router = RouterBuilder::new()
    .with_auth(jwt_service_arc.clone()) // Configure JWT service for auth middleware
    .with_all_routes() // Enable all routes
    .build();

// Or configure specific routes
let custom_router = RouterBuilder::new()
    .with_auth(jwt_service_arc.clone())
    .health_check(true)     // Public route
    .create_user(true)      // Public route
    .get_user(true)         // Protected route (auth required)
    .update_user(true)      // Protected route (auth required)
    .refresh_token(true)    // Public route
    .build();
```

### Route Categories

#### 🔓 Public Routes (No Authentication Required)
- `GET /health` - Health check
- `POST /users` - Create new user
- `POST /auth/refresh` - Refresh JWT tokens
- `POST /auth/signup/email` - Passwordless signup
- `POST /auth/verify-email` - Verify email
- `POST /auth/signin/email` - Request OTP signin
- `POST /auth/signin/otp` - Verify OTP signin
- `POST /auth/signup/google` - Google OAuth signup
- `GET /auth/callback/google` - Google OAuth callback
- All WebAuthn registration and signin flows

#### 🔒 Protected Routes (Authentication Required)
- `GET /users/{id}` - Get user details
- `PUT /users/{id}` - Update user
- `POST /users/{id}/verify-password` - Verify password
- `PUT /users/{id}/profile-picture` - Update profile picture
- `DELETE /users/{id}/profile-picture` - Remove profile picture
- `GET /auth/oauth/providers` - List OAuth providers
- `DELETE /auth/oauth/providers/{provider}` - Unlink OAuth provider
- `GET /auth/passkeys` - List user's passkeys
- `PUT /auth/passkeys/{credential_id}` - Update passkey
- `DELETE /auth/passkeys/{credential_id}` - Delete passkey

### Preset Configurations

```rust
// All routes enabled with authentication
let full_router = RouterBuilder::new()
    .with_auth(jwt_service)
    .with_all_routes()
    .build();

// Core user management only
let core_router = RouterBuilder::new()
    .with_auth(jwt_service)
    .with_core_routes()
    .build();

// Read-only routes
let readonly_router = RouterBuilder::new()
    .with_auth(jwt_service)
    .with_readonly_routes()
    .build();

// Public routes only (no auth middleware)
let public_router = RouterBuilder::new()
    .health_check(true)
    .create_user(true)
    .refresh_token(true)
    .build(); // No .with_auth() call
```

### Example Requests

#### Create User
```bash
curl -X POST http://localhost:3000/users \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "SecurePass123!",
    "profile_picture_url": "https://example.com/avatar.jpg"
  }'
```

#### Get User
```bash
curl http://localhost:3000/users/123e4567-e89b-12d3-a456-426614174000
```

#### Update User
```bash
curl -X PUT http://localhost:3000/users/123e4567-e89b-12d3-a456-426614174000 \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Smith",
    "email": "john.smith@example.com"
  }'
```

#### Refresh JWT Token
```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "your_refresh_token_here"
  }'
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|----------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `PORT` | Server port | `3000` |
| `HOST` | Server host | `0.0.0.0` |
| `LOG_LEVEL` | Log level (trace, debug, info, warn, error) | `info` |
| `DB_MAX_CONNECTIONS` | Maximum database connections | `20` |
| `DB_MIN_CONNECTIONS` | Minimum database connections | `1` |
| `BCRYPT_COST` | bcrypt cost factor | `12` |
| `JWT_ACCESS_SECRET` | JWT access token secret key | Required |
| `JWT_REFRESH_SECRET` | JWT refresh token secret key | Required |
| `JWT_ACCESS_EXPIRES_HOURS` | Access token expiration (hours) | `1` |
| `JWT_REFRESH_EXPIRES_DAYS` | Refresh token expiration (days) | `30` |

### Docker Deployment

```dockerfile
# Build stage
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/user-service /usr/local/bin/
EXPOSE 3000
CMD ["user-service"]
```

## Development

### Running Tests
```bash
# Unit tests
cargo test

# Integration tests with database
cargo test --features test-helpers
```

### Code Quality
```bash
# Format code
cargo fmt

# Lint code
cargo clippy

# Security audit
cargo audit
```

### Database Migrations

Create a new migration:
```bash
sqlx migrate add create_users_table
```

Run migrations:
```bash
sqlx migrate run
```

Revert last migration:
```bash
sqlx migrate revert
```

## Library Usage

This service can also be used as a library in other Rust applications:

```toml
[dependencies]
user-service = { git = "https://github.com/nickmartinwebdev/user-service" }
```

```rust
use user_service::{UserService, CreateUserRequest};
use sqlx::PgPool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = PgPool::connect("postgres://localhost/mydb").await?;
    let user_service = UserService::new(pool);
    
    let request = CreateUserRequest {
        name: "Alice".to_string(),
        email: "alice@example.com".to_string(),
        password: "SecurePass123!".to_string(),
        profile_picture_url: None,
    };
    
    let user = user_service.create_user(request).await?;
    println!("Created user: {}", user.name);
    
    Ok(())
}
```

## Architecture

### Project Structure
```
src/
├── lib.rs              # Library interface
├── main.rs             # Binary entry point
├── api/                # HTTP API layer
│   ├── mod.rs
│   ├── handlers.rs     # Request handlers
│   ├── routes.rs       # Route definitions
│   └── middleware.rs   # Custom middleware
├── service/            # Business logic layer
│   ├── mod.rs
│   ├── user.rs         # User service implementation
│   └── validation.rs   # Input validation
├── models/             # Data models
│   ├── mod.rs
│   ├── user.rs         # User data structures
│   └── requests.rs     # Request/response types
├── database/           # Database layer
│   ├── mod.rs
│   ├── connection.rs   # Connection management
│   └── migrations.rs   # Migration utilities
└── utils/              # Shared utilities
    ├── mod.rs
    ├── security.rs     # Security utilities
    ├── validation.rs   # Validation helpers
    └── error.rs        # Error handling
```

### Design Principles

1. **Separation of Concerns**: Clear boundaries between API, business logic, and data layers
2. **Type Safety**: Leverage Rust's type system for compile-time correctness
3. **Security First**: Secure defaults with comprehensive input validation
4. **Performance**: Async/await with connection pooling for high throughput
5. **Testability**: Dependency injection and modular design for easy testing
6. **Observability**: Structured logging and health checks for monitoring

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Guidelines

- Follow Rust naming conventions
- Add tests for new functionality
- Update documentation for API changes
- Ensure all tests pass
- Format code with `cargo fmt`
- Check lints with `cargo clippy`

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions:

- Create an [issue](https://github.com/nickmartinwebdev/user-service/issues)
- Check existing [documentation](https://docs.rs/user-service)
- Review [examples](examples/)

## Roadmap

- [x] JWT authentication integration
- [ ] OAuth2 provider support
- [ ] User roles and permissions
- [ ] Email verification workflow
- [ ] Password reset functionality
- [ ] Audit logging
- [ ] Metrics and observability
- [ ] GraphQL API support
- [ ] Multi-tenant support