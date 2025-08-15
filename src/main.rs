//! User Service Binary
//!
//! Standalone HTTP server providing user management API endpoints.
//! This binary sets up the web server, database connections, and middleware.

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
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
    // Load environment variables from .env file
    dotenv().ok();

    // Initialize logging
    let log_level = env::var("LOG_LEVEL").unwrap_or_else(|_| DEFAULT_LOG_LEVEL.to_string());
    env::set_var("RUST_LOG", log_level);
    env_logger::init();

    log::info!("Starting User Service v{}", user_service::VERSION);

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

    // Build the application with middleware
    let app = Router::new()
        .merge(create_routes())
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods(Any)
                        .allow_headers(Any),
                )
                .into_inner(),
        )
        .with_state(app_state);

    // Server configuration
    let host = env::var("HOST").unwrap_or_else(|_| DEFAULT_HOST.to_string());
    let port = env::var("PORT")
        .unwrap_or_else(|_| DEFAULT_PORT.to_string())
        .parse::<u16>()
        .unwrap_or(DEFAULT_PORT);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    log::info!("Server starting on {}:{}", host, port);

    // Start the server
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("Failed to bind to address {}: {}", addr, e))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| format!("Server error: {}", e))?;

    Ok(())
}