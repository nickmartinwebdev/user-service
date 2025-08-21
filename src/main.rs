//! Multi-Tenant User Service Development Server
//!
//! This is a development server for the multi-tenant user service library.
//! It provides a complete HTTP server with all API endpoints enabled for
//! local development and testing purposes, including multi-tenant application
//! management capabilities.
//!
//! For production deployments with custom router configurations, use the
//! RouterBuilder in your own application or see `examples/production_server.rs`.

use std::sync::Arc;

use dotenv::dotenv;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use user_service::{
    api::{with_security_state, AppState, RouterBuilder},
    config::{AppConfig, GoogleOAuthConfig},
    database::DatabaseConfig,
    service::{
        ApplicationService, JwtService, OAuthService, RateLimitService, SecurityAuditService,
        UserService, WebAuthnService,
    },
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables from .env file if present
    dotenv().ok();

    // Initialize structured logging for development
    env_logger::init();

    log::info!(
        "🚀 Starting Multi-Tenant User Service v{} with Security Features",
        user_service::VERSION
    );

    // Load configuration from environment
    let config = AppConfig::from_env()?;
    config.validate()?;

    log::info!("✅ Configuration loaded and validated");

    // Database configuration and connection
    let db_config = DatabaseConfig {
        url: config.database.url.clone(),
        max_connections: config.database.max_connections,
        min_connections: config.database.min_connections,
        connect_timeout: std::time::Duration::from_secs(config.database.connect_timeout_seconds),
        idle_timeout: std::time::Duration::from_secs(config.database.idle_timeout_seconds),
        max_lifetime: std::time::Duration::from_secs(config.database.max_lifetime_seconds),
    };
    let database_pool = db_config.create_pool().await?;

    // Run database migrations
    log::info!("🔄 Running database migrations...");
    sqlx::migrate!("./migrations").run(&database_pool).await?;

    log::info!("✅ Database migrations completed");

    // Initialize core services
    let user_service = Arc::new(UserService::new(database_pool.clone()));
    let application_service = Arc::new(ApplicationService::new(database_pool.clone()));
    let jwt_service = Arc::new(JwtService::new(
        database_pool.clone(),
        config.jwt.access_secret.clone(),
        config.jwt.refresh_secret.clone(),
    ));

    log::info!("✅ Core services initialized");
    log::info!("✅ Multi-tenant application service initialized");
    log::info!("   - Application service (multi-tenant management)");
    log::info!("   - User service");
    log::info!("   - JWT service");

    // Initialize security services
    let rate_limit_service = Arc::new(RateLimitService::new(
        database_pool.clone(),
        config.security.get_rate_limit_config().clone(),
    ));

    let security_audit_service = Arc::new(SecurityAuditService::new(database_pool.clone()));

    log::info!("✅ Security services initialized");
    log::info!(
        "   - Rate limiting: {}",
        config.security.is_rate_limiting_enabled()
    );
    log::info!(
        "   - Audit logging: {}",
        config.security.is_audit_logging_enabled()
    );

    // Initialize optional services
    let oauth_service = if let Some(oauth_config) = &config.oauth {
        if let (Some(client_id), Some(client_secret), Some(redirect_uri)) = (
            &oauth_config.google_client_id,
            &oauth_config.google_client_secret,
            &oauth_config.google_redirect_uri,
        ) {
            let google_config = GoogleOAuthConfig {
                client_id: client_id.clone(),
                client_secret: client_secret.clone(),
                redirect_uri: redirect_uri.clone(),
                state_expires_minutes: oauth_config.state_expires_minutes,
            };
            let service =
                OAuthService::new(database_pool.clone(), google_config, (*jwt_service).clone())?;
            log::info!("✅ OAuth service initialized");
            Some(Arc::new(service))
        } else {
            log::warn!("⚠️  OAuth service not fully configured");
            None
        }
    } else {
        log::warn!("⚠️  OAuth service not configured");
        None
    };

    let webauthn_service = if let Some(webauthn_config) = &config.webauthn {
        let service = WebAuthnService::new(
            database_pool.clone(),
            user_service::WebAuthnConfig {
                rp_id: webauthn_config.rp_id.clone(),
                rp_name: webauthn_config.rp_name.clone(),
                rp_origin: webauthn_config.rp_origin.clone(),
                challenge_timeout_seconds: 60,
                require_user_verification: webauthn_config.user_verification == "required",
                allowed_algorithms: vec![-7, -257], // ES256 and RS256
            },
            (*jwt_service).clone(),
        )?;
        log::info!("✅ WebAuthn service initialized");
        Some(Arc::new(service))
    } else {
        log::warn!("⚠️  WebAuthn service not configured");
        None
    };

    // Create application state with multi-tenant support
    // Create application state
    let app_state = AppState {
        user_service,
        application_service,
        jwt_service: jwt_service.clone(),
        oauth_service,
        webauthn_service,
        rate_limit_service: rate_limit_service.clone(),
        security_audit_service: security_audit_service.clone(),
    };

    // Build the application with all routes and security enabled
    let has_oauth = app_state.oauth_service.is_some();
    let has_webauthn = app_state.webauthn_service.is_some();

    let router = RouterBuilder::with_all_routes()
        .with_auth(jwt_service)
        .with_application_auth() // Enable multi-tenant authentication
        .build(app_state.clone());

    let app = with_security_state(router, rate_limit_service, security_audit_service)
        .with_state(app_state)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any) // Permissive CORS for development
                        .allow_methods(Any)
                        .allow_headers(Any),
                )
                .into_inner(),
        );

    // Server configuration
    let bind_addr = format!("{}:{}", config.server.host, config.server.port);
    log::info!("🌐 Starting multi-tenant server on {}", bind_addr);

    log::info!("✅ Multi-Tenant Features Enabled:");
    log::info!("   - Application authentication middleware");
    log::info!("   - Per-application CORS configuration");
    log::info!("   - Tenant-isolated data access");
    log::info!("   - Application management API");

    log::info!("✅ Security middleware enabled:");
    log::info!("   - Rate limiting on authentication endpoints");
    log::info!("   - Security audit logging");
    log::info!("   - Password field detection and blocking");
    log::info!("   - Security headers (CSP, HSTS, X-Frame-Options, etc.)");

    log::info!("📊 Security Configuration:");
    log::info!(
        "   - Email signup: {} attempts per {} minutes",
        config
            .security
            .rate_limiting
            .limits
            .email_signup
            .max_attempts,
        config
            .security
            .rate_limiting
            .limits
            .email_signup
            .window_minutes
    );
    log::info!(
        "   - OTP verification: {} attempts per {} minutes",
        config
            .security
            .rate_limiting
            .limits
            .otp_verification
            .max_attempts,
        config
            .security
            .rate_limiting
            .limits
            .otp_verification
            .window_minutes
    );

    log::info!("🔐 Authentication Methods Available:");
    log::info!("   ✅ Email + OTP (Passwordless)");
    if has_oauth {
        log::info!("   ✅ Google OAuth 2.0");
    } else {
        log::info!("   ❌ Google OAuth 2.0 (not configured)");
    }
    if has_webauthn {
        log::info!("   ✅ WebAuthn/Passkeys");
    } else {
        log::info!("   ❌ WebAuthn/Passkeys (not configured)");
    }

    log::info!("📋 Multi-Tenant API Endpoints:");
    log::info!("   📦 Application Management (Admin):");
    log::info!("     POST /admin/applications - Create new application/tenant");
    log::info!("     GET  /admin/applications - List all applications");
    log::info!("     GET  /admin/applications/:id - Get application details");
    log::info!("     PUT  /admin/applications/:id - Update application settings");
    log::info!("     GET  /admin/applications/:id/stats - Get usage statistics");
    log::info!("     POST /admin/applications/:id/rotate-credentials - Rotate API keys");
    log::info!("     POST /admin/applications/:id/deactivate - Deactivate application");
    log::info!("     GET  /admin/health - Application service health check");

    log::info!("   👥 User Management (Per-Tenant):");
    log::info!("     GET  /health - Health check");
    log::info!("     POST /users - Create user (requires app auth)");
    log::info!("     GET  /users/:id - Get user (requires app auth)");
    log::info!("     PUT  /users/:id - Update user (requires app auth)");
    log::info!("     POST /auth/signup/email - Passwordless signup");
    log::info!("     POST /auth/verify-email - Verify email");
    log::info!("     POST /auth/signin/email - Request OTP signin");
    log::info!("     POST /auth/signin/otp - Verify OTP signin");
    log::info!("     POST /auth/refresh - Refresh JWT tokens");

    if has_oauth {
        log::info!("     POST /auth/signup/google - Initiate Google OAuth");
        log::info!("     GET  /auth/callback/google - Google OAuth callback");
        log::info!("     GET  /auth/oauth/providers - List OAuth providers");
        log::info!("     DELETE /auth/oauth/providers/:provider - Unlink OAuth");
    }

    if has_webauthn {
        log::info!("     POST /auth/register/passkey/begin - Begin passkey registration");
        log::info!("     POST /auth/register/passkey/finish - Complete passkey registration");
        log::info!("     POST /auth/signin/passkey/begin - Begin passkey authentication");
        log::info!("     POST /auth/signin/passkey/finish - Complete passkey authentication");
        log::info!("     GET  /auth/passkeys - List user's passkeys");
        log::info!("     DELETE /auth/passkeys/:id - Delete passkey");
        log::info!("     PUT  /auth/passkeys/:id - Update passkey");
    }

    log::info!("🔧 Multi-Tenant Configuration:");
    log::info!("   - API Authentication: X-API-Key + X-API-Secret headers");
    log::info!("   - Alternative: Authorization: Bearer <api_key>:<api_secret>");
    log::info!("   - CORS: Per-application origin configuration");
    log::info!("   - Data Isolation: Complete tenant separation");
    log::info!("   - Rate Limiting: Per-application limits");

    log::info!("📝 Getting Started:");
    log::info!("   1. Create an application: POST /admin/applications");
    log::info!("   2. Save the returned API key and secret");
    log::info!("   3. Include credentials in all tenant API calls");
    log::info!("   4. Configure allowed origins for CORS");

    // Start the server
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    log::info!("✅ Multi-tenant server listening and ready for requests");
    axum::serve(listener, app).await?;

    Ok(())
}
