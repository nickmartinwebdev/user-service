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

use axum::{middleware::from_fn_with_state, routing::get, Router};
use dotenv::dotenv;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use user_service::{
    api::{auth_middleware, create_routes, AppState, RouterBuilder},
    config::*,
    database::DatabaseConfig,
    service::{JwtService, OAuthService, UserService},
    GoogleOAuthConfig, JwtConfig,
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

    // JWT configuration
    let jwt_config =
        JwtConfig::from_env().map_err(|e| format!("Failed to load JWT configuration: {}", e))?;

    // Google OAuth configuration (optional)
    let google_oauth_config = GoogleOAuthConfig::from_env().ok();
    if google_oauth_config.is_some() {
        log::info!("Google OAuth configuration loaded - OAuth endpoints will be available");
    } else {
        log::warn!("Google OAuth configuration not found - OAuth endpoints will be disabled");
        log::warn!(
            "Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and GOOGLE_REDIRECT_URI to enable OAuth"
        );
    }

    // Initialize services
    let user_service = UserService::new(database_pool.clone());
    let jwt_service = JwtService::with_expiration(
        database_pool.clone(),
        jwt_config.access_secret,
        jwt_config.refresh_secret,
        chrono::Duration::hours(jwt_config.access_token_expires_hours),
        chrono::Duration::days(jwt_config.refresh_token_expires_days),
    );

    // Initialize OAuth service if configuration is available
    let oauth_service = if let Some(oauth_config) = google_oauth_config {
        match OAuthService::new(database_pool.clone(), oauth_config, jwt_service.clone()) {
            Ok(service) => {
                log::info!("OAuth service initialized successfully");
                Some(Arc::new(service))
            }
            Err(e) => {
                log::error!("Failed to initialize OAuth service: {}", e);
                log::warn!("OAuth endpoints will be disabled");
                None
            }
        }
    } else {
        None
    };

    // Create application state
    let app_state = AppState {
        user_service: Arc::new(user_service),
        jwt_service: Arc::new(jwt_service),
        oauth_service,
    };

    // Build the application with all routes enabled for development
    // Note: This includes all endpoints for easy testing and development
    let oauth_protected_routes = Router::new()
        .route(
            "/auth/oauth/providers",
            get(user_service::api::oauth_handlers::get_user_oauth_providers),
        )
        .route(
            "/auth/oauth/providers/{provider}",
            axum::routing::delete(user_service::api::oauth_handlers::unlink_oauth_provider),
        )
        .layer(from_fn_with_state(
            app_state.jwt_service.clone(),
            auth_middleware,
        ));

    let main_routes = RouterBuilder::new()
        .health_check(true)
        .create_user(true)
        .get_user(true)
        .update_user(true)
        .verify_password(true)
        .update_profile_picture(true)
        .remove_profile_picture(true)
        .refresh_token(true)
        .passwordless_signup(true)
        .verify_email(true)
        .signin_otp_request(true)
        .signin_otp_verify(true)
        .google_oauth_init(true)
        .google_oauth_callback(true)
        .build();

    let has_oauth = app_state.oauth_service.is_some();

    let app = Router::new()
        .merge(main_routes)
        .merge(if has_oauth {
            oauth_protected_routes
        } else {
            Router::new()
        })
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
    log::info!("  POST /auth/refresh                      - Refresh JWT tokens");
    log::info!("  POST /auth/signup/email                 - Passwordless signup");
    log::info!("  POST /auth/verify-email                 - Verify email");
    log::info!("  POST /auth/signin/email                 - Request OTP signin");
    log::info!("  POST /auth/signin/otp                   - Verify OTP signin");

    if has_oauth {
        log::info!("  POST /auth/signup/google                - Initiate Google OAuth");
        log::info!("  GET  /auth/callback/google              - Google OAuth callback");
        log::info!("  GET  /auth/oauth/providers              - List OAuth providers");
        log::info!("  DEL  /auth/oauth/providers/{{provider}}   - Unlink OAuth provider");
    }

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
