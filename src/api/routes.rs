//! API Route Definitions
//!
//! This module defines all HTTP routes and their corresponding handlers using a flexible
//! builder pattern. The RouterBuilder allows selective enabling/disabling of API endpoints
//! for different deployment scenarios, such as microservices or feature-specific services.

use axum::{
    routing::{delete, get, post, put},
    Router,
};

use super::handlers::*;

/// Builder for creating API routes with configurable endpoints
///
/// The RouterBuilder provides a fluent interface for constructing routers with
/// only the endpoints you need. This is useful for:
/// - Microservice architectures where different services handle different endpoints
/// - Feature flagging and gradual rollouts
/// - Security hardening by disabling unused endpoints
/// - Environment-specific configurations
#[derive(Default)]
pub struct RouterBuilder {
    /// Whether to enable the health check endpoint (GET /health)
    health_check: bool,
    /// Whether to enable user creation endpoint (POST /users)
    create_user: bool,
    /// Whether to enable user retrieval endpoint (GET /users/{id})
    get_user: bool,
    /// Whether to enable user update endpoint (PUT /users/{id})
    update_user: bool,
    /// Whether to enable password verification endpoint (POST /users/{id}/verify-password)
    verify_password: bool,
    /// Whether to enable profile picture update endpoint (PUT /users/{id}/profile-picture)
    update_profile_picture: bool,
    /// Whether to enable profile picture removal endpoint (DELETE /users/{id}/profile-picture)
    remove_profile_picture: bool,
    /// Whether to enable token refresh endpoint (POST /auth/refresh)
    refresh_token: bool,
    /// Whether to enable passwordless signup endpoint (POST /auth/signup/email)
    passwordless_signup: bool,
    /// Whether to enable email verification endpoint (POST /auth/verify-email)
    verify_email: bool,
    /// Whether to enable OTP signin email request endpoint (POST /auth/signin/email)
    signin_otp_request: bool,
    /// Whether to enable OTP signin verification endpoint (POST /auth/signin/otp)
    signin_otp_verify: bool,
}

impl RouterBuilder {
    /// Creates a new router builder with all routes disabled by default
    ///
    /// Use this when you want to explicitly enable only specific routes.
    /// For common configurations, consider using the preset methods like
    /// `with_all_routes()` or `with_core_routes()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a router builder with all routes enabled
    ///
    /// This is equivalent to the original `create_routes()` function and provides
    /// full user management functionality including profile pictures and password
    /// verification.
    pub fn with_all_routes() -> Self {
        Self {
            health_check: true,
            create_user: true,
            get_user: true,
            update_user: true,
            verify_password: true,
            update_profile_picture: true,
            remove_profile_picture: true,
            refresh_token: true,
            passwordless_signup: true,
            verify_email: true,
            signin_otp_request: true,
            signin_otp_verify: true,
        }
    }

    /// Creates a router builder with core user management routes
    ///
    /// Includes basic CRUD operations for users but excludes advanced features
    /// like profile picture management and password verification. Suitable for
    /// basic user management services.
    pub fn with_core_routes() -> Self {
        Self {
            health_check: true,
            create_user: true,
            get_user: true,
            update_user: true,
            verify_password: false,
            update_profile_picture: false,
            remove_profile_picture: false,
            refresh_token: true,
            passwordless_signup: true,
            verify_email: true,
            signin_otp_request: true,
            signin_otp_verify: true,
        }
    }

    /// Creates a router builder with read-only routes
    /// Creates a router with only essential read-only user operations
    ///
    /// Includes health check, user retrieval, and password verification.
    /// Excludes user creation, updates, and profile picture management.
    /// Good for authentication services or read-only user directories.
    pub fn with_readonly_routes() -> Self {
        Self {
            health_check: true,
            create_user: false,
            get_user: true,
            update_user: false,
            verify_password: true,
            update_profile_picture: false,
            remove_profile_picture: false,
            refresh_token: false,
            passwordless_signup: false,
            verify_email: false,
            signin_otp_request: false,
            signin_otp_verify: false,
        }
    }

    /// Creates a router with minimal routes for monitoring
    ///
    /// Useful for monitoring services or as a base configuration when you
    /// want to add only specific routes. Only includes the health check endpoint.
    pub fn with_minimal_routes() -> Self {
        Self {
            health_check: true,
            create_user: false,
            get_user: false,
            update_user: false,
            verify_password: false,
            update_profile_picture: false,
            remove_profile_picture: false,
            refresh_token: false,
            passwordless_signup: false,
            verify_email: false,
            signin_otp_request: false,
            signin_otp_verify: false,
        }
    }

    /// Enables or disables the health check endpoint (GET /health)
    ///
    /// The health check endpoint is recommended for all deployments as it
    /// allows monitoring systems and load balancers to verify service health.
    pub fn health_check(mut self, enabled: bool) -> Self {
        self.health_check = enabled;
        self
    }

    /// Enables or disables the user creation endpoint (POST /users)
    ///
    /// Disable this for read-only services or when user creation is handled
    /// by a separate registration service.
    pub fn create_user(mut self, enabled: bool) -> Self {
        self.create_user = enabled;
        self
    }

    /// Enables or disables the user retrieval endpoint (GET /users/{id})
    ///
    /// This endpoint is commonly needed for most user-related services as it
    /// provides basic user information lookup.
    pub fn get_user(mut self, enabled: bool) -> Self {
        self.get_user = enabled;
        self
    }

    /// Enables or disables the user update endpoint (PUT /users/{id})
    ///
    /// Disable this for read-only services or when user updates are handled
    /// by a separate profile management service.
    pub fn update_user(mut self, enabled: bool) -> Self {
        self.update_user = enabled;
        self
    }

    /// Enables or disables the password verification endpoint (POST /users/{id}/verify-password)
    ///
    /// Essential for authentication services but can be disabled for services
    /// that only need user profile information.
    pub fn verify_password(mut self, enabled: bool) -> Self {
        self.verify_password = enabled;
        self
    }

    /// Enables or disables the profile picture update endpoint (PUT /users/{id}/profile-picture)
    ///
    /// Can be disabled for services that don't handle profile pictures or when
    /// profile picture management is handled by a separate media service.
    pub fn update_profile_picture(mut self, enabled: bool) -> Self {
        self.update_profile_picture = enabled;
        self
    }

    /// Enables or disables the profile picture removal endpoint (DELETE /users/{id}/profile-picture)
    ///
    /// Typically paired with the update profile picture endpoint. Disable for
    /// services that don't handle profile pictures.
    pub fn remove_profile_picture(mut self, enabled: bool) -> Self {
        self.remove_profile_picture = enabled;
        self
    }

    /// Enables or disables the token refresh endpoint (POST /auth/refresh)
    ///
    /// Essential for JWT authentication flows. Allows clients to obtain new
    /// access tokens using valid refresh tokens.
    pub fn refresh_token(mut self, enabled: bool) -> Self {
        self.refresh_token = enabled;
        self
    }

    /// Enables or disables the passwordless signup endpoint (POST /auth/signup/email)
    ///
    /// Allows users to create accounts without passwords by receiving verification
    /// codes via email. Essential for passwordless authentication flows.
    pub fn passwordless_signup(mut self, enabled: bool) -> Self {
        self.passwordless_signup = enabled;
        self
    }

    /// Enables or disables the email verification endpoint (POST /auth/verify-email)
    ///
    /// Verifies email addresses using codes sent during passwordless signup.
    /// Returns authentication tokens upon successful verification.
    pub fn verify_email(mut self, enable: bool) -> Self {
        self.verify_email = enable;
        self
    }

    /// Enables or disables the OTP signin email request endpoint
    pub fn signin_otp_request(mut self, enable: bool) -> Self {
        self.signin_otp_request = enable;
        self
    }

    /// Enables or disables the OTP signin verification endpoint
    pub fn signin_otp_verify(mut self, enable: bool) -> Self {
        self.signin_otp_verify = enable;
        self
    }

    /// Builds the Axum router with the configured routes
    ///
    /// Returns a `Router<AppState>` that can be used with Axum. Only the enabled
    /// routes will be registered, which improves performance and security by
    /// reducing the attack surface.
    pub fn build(self) -> Router<AppState> {
        let mut router = Router::new();

        if self.health_check {
            router = router.route("/health", get(health_check));
        }

        if self.create_user {
            router = router.route("/users", post(create_user));
        }

        if self.get_user {
            router = router.route("/users/{id}", get(get_user));
        }

        if self.update_user {
            router = router.route("/users/{id}", put(update_user));
        }

        if self.verify_password {
            router = router.route("/users/{id}/verify-password", post(verify_password));
        }

        if self.update_profile_picture {
            router = router.route("/users/{id}/profile-picture", put(update_profile_picture));
        }

        if self.remove_profile_picture {
            router = router.route(
                "/users/{id}/profile-picture",
                delete(remove_profile_picture),
            );
        }

        if self.refresh_token {
            router = router.route("/auth/refresh", post(refresh_token));
        }

        if self.passwordless_signup {
            router = router.route("/auth/signup/email", post(passwordless_signup));
        }

        if self.verify_email {
            router = router.route("/auth/verify-email", post(verify_email));
        }

        if self.signin_otp_request {
            router = router.route("/auth/signin/email", post(request_signin_otp));
        }

        if self.signin_otp_verify {
            router = router.route("/auth/signin/otp", post(verify_signin_otp));
        }

        router
    }
}

/// Creates all API routes (maintains backward compatibility)
///
/// This function provides the same functionality as the original router
/// before the builder pattern was introduced. It's equivalent to
/// `RouterBuilder::with_all_routes().build()`.
pub fn create_routes() -> Router<AppState> {
    RouterBuilder::with_all_routes().build()
}

/// Creates router with core user management functionality
///
/// Convenience function for creating a router with essential user CRUD
/// operations. Excludes advanced features like profile pictures.
pub fn create_core_routes() -> Router<AppState> {
    RouterBuilder::with_core_routes().build()
}

/// Creates router with read-only functionality
///
/// Convenience function for creating a router suitable for authentication
/// services or user directories that don't modify user data.
pub fn create_readonly_routes() -> Router<AppState> {
    RouterBuilder::with_readonly_routes().build()
}

/// Creates router with minimal functionality (health check only)
///
/// Convenience function for creating a router with only the health check
/// endpoint enabled. Useful for monitoring-only services.
pub fn create_minimal_routes() -> Router<AppState> {
    RouterBuilder::with_minimal_routes().build()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that RouterBuilder::new() creates a builder with all routes disabled
    #[test]
    fn test_router_builder_new() {
        let builder = RouterBuilder::new();

        // All routes should be disabled by default
        assert!(!builder.health_check);
        assert!(!builder.create_user);
        assert!(!builder.get_user);
        assert!(!builder.update_user);
        assert!(!builder.verify_password);
        assert!(!builder.update_profile_picture);
        assert!(!builder.remove_profile_picture);
    }

    /// Test that with_all_routes() enables all available routes
    #[test]
    fn test_router_builder_with_all_routes() {
        let builder = RouterBuilder::with_all_routes();

        // All routes should be enabled
        assert!(builder.health_check);
        assert!(builder.create_user);
        assert!(builder.get_user);
        assert!(builder.update_user);
        assert!(builder.verify_password);
        assert!(builder.update_profile_picture);
        assert!(builder.remove_profile_picture);
        assert!(builder.refresh_token);
        assert!(builder.passwordless_signup);
        assert!(builder.verify_email);
    }

    /// Test that with_core_routes() enables only core user management routes
    #[test]
    fn test_router_builder_with_core_routes() {
        let builder = RouterBuilder::with_core_routes();

        // Core routes should be enabled
        assert!(builder.health_check);
        assert!(builder.create_user);
        assert!(builder.get_user);
        assert!(builder.update_user);

        // Optional routes should be disabled
        assert!(!builder.verify_password);
        assert!(!builder.update_profile_picture);
        assert!(!builder.remove_profile_picture);
        // Auth routes should be enabled for core functionality
        assert!(builder.refresh_token);
        assert!(builder.passwordless_signup);
        assert!(builder.verify_email);
    }

    /// Test that with_readonly_routes() enables only read-only routes
    #[test]
    fn test_router_builder_with_readonly_routes() {
        let builder = RouterBuilder::with_readonly_routes();

        // Read-only routes should be enabled
        assert!(builder.health_check);
        assert!(builder.get_user);
        assert!(builder.verify_password);

        // Write routes should be disabled
        assert!(!builder.create_user);
        assert!(!builder.update_user);
        assert!(!builder.update_profile_picture);
        assert!(!builder.remove_profile_picture);
        assert!(!builder.refresh_token);
        assert!(!builder.passwordless_signup);
        assert!(!builder.verify_email);
    }

    /// Test that with_minimal_routes() enables only health check
    #[test]
    fn test_router_builder_with_minimal_routes() {
        let builder = RouterBuilder::with_minimal_routes();

        // Only health check should be enabled
        assert!(builder.health_check);

        // All other routes should be disabled
        assert!(!builder.create_user);
        assert!(!builder.get_user);
        assert!(!builder.update_user);
        assert!(!builder.verify_password);
        assert!(!builder.update_profile_picture);
        assert!(!builder.remove_profile_picture);
        assert!(!builder.refresh_token);
        assert!(!builder.passwordless_signup);
        assert!(!builder.verify_email);
    }

    /// Test that individual route configuration methods work correctly
    #[test]
    fn test_router_builder_individual_methods() {
        let builder = RouterBuilder::new()
            .health_check(true)
            .create_user(true)
            .get_user(false)
            .update_user(true)
            .verify_password(false)
            .update_profile_picture(true)
            .remove_profile_picture(false)
            .refresh_token(true)
            .passwordless_signup(false)
            .verify_email(true);

        assert!(builder.health_check);
        assert!(builder.create_user);
        assert!(!builder.get_user);
        assert!(builder.update_user);
        assert!(!builder.verify_password);
        assert!(builder.update_profile_picture);
        assert!(!builder.remove_profile_picture);
        assert!(builder.refresh_token);
        assert!(!builder.passwordless_signup);
        assert!(builder.verify_email);
    }

    /// Test that convenience functions and backward compatibility work
    #[test]
    fn test_backward_compatibility() {
        // Ensure create_routes() still works as before
        let _router = create_routes();
        let _core_router = create_core_routes();
        let _readonly_router = create_readonly_routes();
        let _minimal_router = create_minimal_routes();
    }

    /// Test that health endpoint configuration works as expected
    #[tokio::test]
    async fn test_health_endpoint_configuration() {
        // Test that health endpoint is properly configured when enabled
        // This would require a full integration test setup
        // TODO: Add proper health endpoint configuration testing
    }

    /// Test that user route configuration works as expected
    #[tokio::test]
    async fn test_user_routes_configuration() {
        // Test that user routes are properly configured based on builder settings
        // This would require a full integration test setup
        // TODO: Add proper user routes configuration testing
    }
}
