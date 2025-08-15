//! User Service Development Server
//!
//! This is a simple development server for the user service library.
//! It provides a basic HTTP server with all API endpoints enabled for
//! local development and testing purposes.
//!
//! For production deployments with custom router configurations, use the
//! RouterBuilder in your own application or see `examples/production_server.rs`.

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use dotenv::dotenv;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use user_service::{
    api::{create_routes, AppState},
    config::*,
    database::DatabaseConfig,
    service::UserService,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables from .env file if present
    dotenv().ok();

    // Initialize structured logging for development
    let log_level = env::var("LOG_LEVEL").unwrap_or_else(|_| DEFAULT_LOG_LEVEL.to_string());
    env::set_var("RUST_LOG", log_level);
    env_logger::init();

    log::info!(
        "Starting User Service v{} (Development Server)",
        user_service::VERSION
    );
    log::info!(
        "This is a development server - for production use, see examples/production_server.rs"
    );

    // Database configuration and connection
    let database_config = DatabaseConfig::from_env()
        .map_err(|e| format!("Failed to load database configuration: {}", e))?;

    log::info!("Connecting to database...");
    let database_pool = database_config
        .create_pool()
        .await
        .map_err(|e| format!("Failed to create database pool: {}", e))?;

    // Run database migrations
    log::info!("Running database migrations...");
    sqlx::migrate!("./migrations")
        .run(&database_pool)
        .await
        .map_err(|e| format!("Failed to run migrations: {}", e))?;

    // Initialize user service
    let user_service = UserService::new(database_pool.clone());

    // Create application state
    let app_state = AppState {
        user_service: Arc::new(user_service),
    };

    // Build the application with all routes enabled for development
    // Note: This includes all endpoints for easy testing and development
    let app = Router::new()
        .merge(create_routes()) // All routes enabled for dev convenience
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http()) // Request/response logging
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any) // Permissive CORS for development
                        .allow_methods(Any)
                        .allow_headers(Any),
                )
                .into_inner(),
        )
        .with_state(app_state);

    // Server configuration with development defaults
    let host = env::var("HOST").unwrap_or_else(|_| DEFAULT_HOST.to_string());
    let port = env::var("PORT")
        .unwrap_or_else(|_| DEFAULT_PORT.to_string())
        .parse::<u16>()
        .unwrap_or(DEFAULT_PORT);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    log::info!("Development server starting on {}:{}", host, port);
    log::info!("All routes enabled for development and testing");
    log::info!("Available endpoints:");
    log::info!("  GET  /health                            - Health check");
    log::info!("  POST /users                             - Create user");
    log::info!("  GET  /users/{{id}}                        - Get user");
    log::info!("  PUT  /users/{{id}}                        - Update user");
    log::info!("  POST /users/{{id}}/verify-password        - Verify password");
    log::info!("  PUT  /users/{{id}}/profile-picture        - Update profile picture");
    log::info!("  DEL  /users/{{id}}/profile-picture        - Remove profile picture");

    // Start the development server
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("Failed to bind to address {}: {}", addr, e))?;

    log::info!("Server ready for requests");
    axum::serve(listener, app)
        .await
        .map_err(|e| format!("Server error: {}", e))?;

    Ok(())
}
