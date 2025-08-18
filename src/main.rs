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
    api::{AppState, RouterBuilder},
    config::*,
    database::DatabaseConfig,
    service::{JwtService, OAuthService, UserService},
    GoogleOAuthConfig, JwtConfig, WebAuthnConfig, WebAuthnService,
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

    // WebAuthn configuration (optional)
    let webauthn_config = WebAuthnConfig::from_env().ok();
    if webauthn_config.is_some() {
        log::info!("WebAuthn configuration loaded - Passkey endpoints will be available");
    } else {
        log::warn!("WebAuthn configuration not found - Using development defaults");
        log::warn!("Set WEBAUTHN_RP_ID and WEBAUTHN_RP_ORIGIN for production deployment");
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

    // Initialize WebAuthn service if configuration is available
    let webauthn_service = if let Some(webauthn_config) = webauthn_config {
        match WebAuthnService::new(database_pool.clone(), webauthn_config, jwt_service.clone()) {
            Ok(service) => {
                log::info!("WebAuthn service initialized successfully");
                Some(Arc::new(service))
            }
            Err(e) => {
                log::error!("Failed to initialize WebAuthn service: {}", e);
                log::warn!("Passkey endpoints will be disabled");
                None
            }
        }
    } else {
        // Use development defaults for WebAuthn
        log::info!("Using WebAuthn development configuration");
        match WebAuthnService::new(
            database_pool.clone(),
            WebAuthnConfig::default_dev(),
            jwt_service.clone(),
        ) {
            Ok(service) => {
                log::info!("WebAuthn service initialized with development defaults");
                Some(Arc::new(service))
            }
            Err(e) => {
                log::error!("Failed to initialize WebAuthn service with defaults: {}", e);
                log::warn!("Passkey endpoints will be disabled");
                None
            }
        }
    };

    // Create application state
    // Create application state with all services
    let app_state = AppState {
        user_service: Arc::new(user_service),
        jwt_service: Arc::new(jwt_service),
        oauth_service,
        webauthn_service,
    };

    // Build the application with all routes enabled for development
    // Note: This includes all endpoints for easy testing and development
    let has_oauth = app_state.oauth_service.is_some();
    let has_webauthn = app_state.webauthn_service.is_some();

    let main_routes = RouterBuilder::new()
        .with_auth(app_state.jwt_service.clone())
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
        .google_oauth_init(has_oauth)
        .google_oauth_callback(has_oauth)
        .oauth_providers(has_oauth)
        .oauth_unlink(has_oauth)
        .passkey_register_begin(has_webauthn)
        .passkey_register_finish(has_webauthn)
        .passkey_signin_begin(has_webauthn)
        .passkey_signin_finish(has_webauthn)
        .passkey_list(has_webauthn)
        .passkey_delete(has_webauthn)
        .passkey_update(has_webauthn)
        .webauthn_cleanup(has_webauthn)
        .build();

    let app = Router::new()
        .merge(main_routes)
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

    if has_webauthn {
        log::info!("  POST /auth/register/passkey/begin       - Begin passkey registration");
        log::info!("  POST /auth/register/passkey/finish      - Finish passkey registration");
        log::info!("  POST /auth/signin/passkey/begin         - Begin passkey authentication");
        log::info!("  POST /auth/signin/passkey/finish        - Finish passkey authentication");
        log::info!("  GET  /auth/passkeys                     - List user's passkeys");
        log::info!("  PUT  /auth/passkeys/{{credential_id}}     - Update passkey name");
        log::info!("  DEL  /auth/passkeys/{{credential_id}}     - Delete passkey");
        log::info!("  POST /auth/webauthn/cleanup             - Cleanup expired challenges");
    }

    // Log authentication methods summary
    log::info!("Authentication Methods Available:");
    log::info!("  ✅ Email + OTP (Passwordless)");
    if has_oauth {
        log::info!("  ✅ Google OAuth 2.0");
    } else {
        log::info!("  ❌ Google OAuth 2.0 (not configured)");
    }
    if has_webauthn {
        log::info!("  ✅ WebAuthn/Passkeys");
    } else {
        log::info!("  ❌ WebAuthn/Passkeys (not configured)");
    }

    log::info!("For production deployment:");
    if !has_oauth {
        log::info!("  • Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI for OAuth");
    }
    if !has_webauthn {
        log::info!("  • Set WEBAUTHN_RP_ID and WEBAUTHN_RP_ORIGIN for WebAuthn");
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
