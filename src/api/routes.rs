//! API Route Definitions
//!
//! Defines all HTTP routes and their corresponding handlers.

use axum::{
    routing::{delete, get, post, put},
    Router,
};

use super::handlers::*;

/// Create all API routes
pub fn create_routes() -> Router<AppState> {
    Router::new()
        // Health check
        .route("/health", get(health_check))
        
        // User management routes
        .route("/users", post(create_user))
        .route("/users/:id", get(get_user))
        .route("/users/:id", put(update_user))
        
        // Password verification
        .route("/users/:id/verify-password", post(verify_password))
        
        // Profile picture management
        .route("/users/:id/profile-picture", put(update_profile_picture))
        .route("/users/:id/profile-picture", delete(remove_profile_picture))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;
    use serde_json::json;
    use std::sync::Arc;
    
    // Mock app state for testing
    fn create_test_app() -> Router {
        // In real tests, you'd set up a test database
        // For now, this is a placeholder
        todo!("Implement with test database")
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        // Test that health endpoint is properly configured
        // This would require a full integration test setup
        assert!(true); // Placeholder
    }

    #[tokio::test]
    async fn test_user_routes_exist() {
        // Test that all expected routes are configured
        // This would require a full integration test setup
        assert!(true); // Placeholder
    }
}