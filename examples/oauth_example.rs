//! Google OAuth 2.0 Authentication Example
//!
//! This example demonstrates how to set up and use Google OAuth 2.0 authentication
//! with the user service. It shows how to configure the OAuth service, handle
//! the complete authentication flow, and integrate with existing JWT authentication.
//!
//! ## Setup Requirements
//!
//! 1. **Google OAuth Application**: Create a Google OAuth 2.0 application in the
//!    Google Cloud Console and obtain client credentials.
//!
//! 2. **Environment Variables**: Set the following environment variables:
//!    ```bash
//!    export GOOGLE_CLIENT_ID="your_google_client_id"
//!    export GOOGLE_CLIENT_SECRET="your_google_client_secret"
//!    export GOOGLE_REDIRECT_URI="http://localhost:3000/auth/callback/google"
//!    export JWT_ACCESS_SECRET="your_jwt_access_secret"
//!    export JWT_REFRESH_SECRET="your_jwt_refresh_secret"
//!    export DATABASE_URL="postgres://username:password@localhost/database"
//!    ```
//!
//! 3. **Database Setup**: Ensure PostgreSQL is running and the database exists.
//!
//! ## Running the Example
//!
//! ```bash
//! cargo run --example oauth_example
//! ```
//!
//! ## Testing the OAuth Flow
//!
//! 1. **Initiate OAuth**: POST to `/auth/signup/google`
//! 2. **Visit Authorization URL**: Open the returned URL in a browser
//! 3. **Complete Authorization**: Authorize the application with Google
//! 4. **Callback Processing**: Google redirects to `/auth/callback/google`
//! 5. **Receive Tokens**: Get JWT access and refresh tokens

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    middleware::from_fn_with_state,
    response::{Html, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::cors::{Any, CorsLayer};

use user_service::{
    api::{auth_middleware, handlers::SuccessResponse, AppState, RouterBuilder},
    config::{GoogleOAuthConfig, JwtConfig},
    database::DatabaseConfig,
    models::oauth::{GoogleOAuthCallbackQuery, GoogleOAuthInitRequest},
    service::{JwtService, OAuthService, UserService},
};

#[derive(Debug, Serialize, Deserialize)]
struct OAuthDemoRequest {
    redirect_url: Option<String>,
}

/// Example handler for the demo page
async fn demo_page() -> Html<&'static str> {
    Html(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>Google OAuth 2.0 Demo</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .container { background: #f5f5f5; padding: 20px; border-radius: 8px; }
        .button { background: #4285f4; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .button:hover { background: #3367d6; }
        .result { background: white; padding: 15px; margin: 20px 0; border-radius: 4px; border-left: 4px solid #4285f4; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 4px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Google OAuth 2.0 Demo</h1>
        <p>This demo shows how to integrate Google OAuth 2.0 with the user service.</p>

        <h2>Step 1: Initiate OAuth Flow</h2>
        <form id="oauthForm">
            <label for="redirectUrl">Redirect URL (optional):</label><br>
            <input type="url" id="redirectUrl" name="redirectUrl" placeholder="https://example.com/dashboard" style="width: 300px; padding: 5px; margin: 10px 0;"><br>
            <button type="submit" class="button">🚀 Start Google OAuth</button>
        </form>

        <div id="result"></div>

        <h2>Step 2: Available Endpoints</h2>
        <ul>
            <li><strong>POST /auth/signup/google</strong> - Initiate Google OAuth flow</li>
            <li><strong>GET /auth/callback/google</strong> - Handle Google OAuth callback</li>
            <li><strong>GET /auth/oauth/providers</strong> - List linked OAuth providers (requires auth)</li>
            <li><strong>DELETE /auth/oauth/providers/google</strong> - Unlink Google account (requires auth)</li>
        </ul>

        <h2>Step 3: Example Usage</h2>
        <pre><code>// Initiate OAuth flow
const response = await fetch('/auth/signup/google', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ redirect_url: 'https://myapp.com/dashboard' })
});

const data = await response.json();
// Redirect user to data.authorization_url
window.location.href = data.data.authorization_url;</code></pre>

        <h2>Environment Configuration</h2>
        <p>Make sure you have set the following environment variables:</p>
        <pre><code>GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=http://localhost:3000/auth/callback/google
JWT_ACCESS_SECRET=your_jwt_access_secret
JWT_REFRESH_SECRET=your_jwt_refresh_secret
DATABASE_URL=postgres://username:password@localhost/database</code></pre>
    </div>

    <script>
        document.getElementById('oauthForm').addEventListener('submit', async (e) => {
            e.preventDefault();

            const redirectUrl = document.getElementById('redirectUrl').value;
            const resultDiv = document.getElementById('result');

            try {
                const response = await fetch('/auth/signup/google', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        redirect_url: redirectUrl || null
                    })
                });

                const data = await response.json();

                if (data.success) {
                    resultDiv.innerHTML = `
                        <div class="result">
                            <h3>✅ OAuth Flow Initiated</h3>
                            <p><strong>State Token:</strong> ${data.data.state}</p>
                            <p><strong>Next Step:</strong> Click the button below to authorize with Google</p>
                            <a href="${data.data.authorization_url}" class="button" target="_blank">
                                🔗 Authorize with Google
                            </a>
                            <details style="margin-top: 15px;">
                                <summary>Raw Response</summary>
                                <pre>${JSON.stringify(data, null, 2)}</pre>
                            </details>
                        </div>
                    `;
                } else {
                    resultDiv.innerHTML = `
                        <div class="result" style="border-left-color: #dc3545;">
                            <h3>❌ Error</h3>
                            <pre>${JSON.stringify(data, null, 2)}</pre>
                        </div>
                    `;
                }
            } catch (error) {
                resultDiv.innerHTML = `
                    <div class="result" style="border-left-color: #dc3545;">
                        <h3>❌ Network Error</h3>
                        <p>${error.message}</p>
                    </div>
                `;
            }
        });
    </script>
</body>
</html>
        "#,
    )
}

/// Custom OAuth initiation handler for the demo
async fn demo_oauth_init(
    State(state): State<AppState>,
    Json(request): Json<OAuthDemoRequest>,
) -> Result<Json<SuccessResponse<serde_json::Value>>, StatusCode> {
    let oauth_service = state
        .oauth_service
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let oauth_request = GoogleOAuthInitRequest {
        redirect_url: request.redirect_url,
    };

    match oauth_service
        .initiate_google_oauth(oauth_request.redirect_url)
        .await
    {
        Ok(response) => {
            let demo_response = json!({
                "authorization_url": response.authorization_url,
                "state": response.state,
                "instructions": "Visit the authorization_url to complete Google OAuth flow",
                "callback_url": "/auth/callback/google"
            });
            Ok(Json(SuccessResponse::new(demo_response)))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Custom callback handler for the demo
async fn demo_oauth_callback(
    State(state): State<AppState>,
    Query(query): Query<GoogleOAuthCallbackQuery>,
) -> Html<String> {
    let oauth_service = match state.oauth_service.as_ref() {
        Some(service) => service,
        None => {
            return Html(format!(
                r#"
                <html><body>
                <h1>❌ OAuth Service Not Available</h1>
                <p>OAuth service is not configured. Please check your environment variables.</p>
                </body></html>
                "#
            ));
        }
    };

    match oauth_service.handle_google_callback(query).await {
        Ok(response) => Html(format!(
            r#"
                <html>
                <head>
                    <title>OAuth Success</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
                        .success {{ background: #d4edda; border: 1px solid #c3e6cb; padding: 20px; border-radius: 8px; }}
                        .user-info {{ background: #f8f9fa; padding: 15px; margin: 15px 0; border-radius: 4px; }}
                        .tokens {{ background: #fff3cd; padding: 15px; margin: 15px 0; border-radius: 4px; border: 1px solid #ffeaa7; }}
                        pre {{ background: #f8f9fa; padding: 10px; border-radius: 4px; font-size: 12px; overflow-x: auto; }}
                        .button {{ background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block; margin: 10px 5px 0 0; }}
                    </style>
                </head>
                <body>
                    <div class="success">
                        <h1>🎉 OAuth Authentication Successful!</h1>

                        <div class="user-info">
                            <h3>👤 User Information</h3>
                            <p><strong>Name:</strong> {}</p>
                            <p><strong>Email:</strong> {}</p>
                            <p><strong>User ID:</strong> {}</p>
                            <p><strong>New User:</strong> {}</p>
                            <p><strong>Email Verified:</strong> {}</p>
                        </div>

                        <div class="tokens">
                            <h3>🔑 JWT Tokens</h3>
                            <p><strong>Access Token:</strong></p>
                            <pre>{}</pre>
                            <p><strong>Refresh Token:</strong></p>
                            <pre>{}</pre>
                            <p><em>💡 In a real application, tokens should be stored securely (e.g., HTTP-only cookies)</em></p>
                        </div>

                        <h3>📝 Next Steps</h3>
                        <ul>
                            <li>Use the access token for authenticated API requests</li>
                            <li>Store tokens securely in your frontend application</li>
                            <li>Implement token refresh logic using the refresh token</li>
                            <li>Add logout functionality to revoke tokens</li>
                        </ul>

                        <a href="/" class="button">🏠 Back to Demo</a>
                        <a href="/auth/oauth/providers" class="button">👥 View OAuth Providers</a>
                    </div>

                    <details style="margin-top: 20px;">
                        <summary>📊 Full Response Data</summary>
                        <pre>{}</pre>
                    </details>
                </body>
                </html>
                "#,
            response.user.name,
            response.user.email,
            response.user.id,
            if response.is_new_user { "Yes" } else { "No" },
            if response.user.email_verified {
                "Yes"
            } else {
                "No"
            },
            response.access_token,
            response.refresh_token,
            serde_json::to_string_pretty(&json!({
                "access_token": response.access_token,
                "refresh_token": response.refresh_token,
                "user": response.user,
                "is_new_user": response.is_new_user
            }))
            .unwrap_or_else(|_| "Error serializing response".to_string())
        )),
        Err(error) => Html(format!(
            r#"
                <html>
                <head>
                    <title>OAuth Error</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
                        .error {{ background: #f8d7da; border: 1px solid #f5c6cb; padding: 20px; border-radius: 8px; }}
                        .button {{ background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block; margin: 10px 0; }}
                    </style>
                </head>
                <body>
                    <div class="error">
                        <h1>❌ OAuth Authentication Failed</h1>
                        <p><strong>Error:</strong> {}</p>
                        <p>Please try the OAuth flow again or check your configuration.</p>
                        <a href="/" class="button">🏠 Back to Demo</a>
                    </div>
                </body>
                </html>
                "#,
            error
        )),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenv::dotenv().ok();
    env_logger::init();

    println!("🚀 Starting Google OAuth 2.0 Demo Server");
    println!("📖 This example demonstrates Google OAuth integration with the user service");

    // Database configuration
    let database_config = DatabaseConfig::from_env()
        .map_err(|e| format!("Failed to load database configuration: {}", e))?;

    println!("🔗 Connecting to database...");
    let database_pool = database_config.create_pool().await?;

    // Run migrations
    println!("🔄 Running database migrations...");
    sqlx::migrate!("./migrations").run(&database_pool).await?;

    // JWT configuration
    let jwt_config =
        JwtConfig::from_env().map_err(|e| format!("Failed to load JWT configuration: {}", e))?;

    // Google OAuth configuration
    let google_oauth_config = GoogleOAuthConfig::from_env()
        .map_err(|e| format!("Failed to load Google OAuth configuration: {}", e))?;

    println!("⚙️  OAuth Configuration:");
    println!("   Client ID: {}", google_oauth_config.client_id);
    println!("   Redirect URI: {}", google_oauth_config.redirect_uri);
    println!(
        "   State Expires: {} minutes",
        google_oauth_config.state_expires_minutes
    );

    // Initialize services
    let user_service = UserService::new(database_pool.clone());
    let jwt_service = JwtService::with_expiration(
        database_pool.clone(),
        jwt_config.access_secret,
        jwt_config.refresh_secret,
        chrono::Duration::hours(jwt_config.access_token_expires_hours),
        chrono::Duration::days(jwt_config.refresh_token_expires_days),
    );

    let oauth_service = OAuthService::new(
        database_pool.clone(),
        google_oauth_config,
        jwt_service.clone(),
    )?;

    // Create application state
    let app_state = AppState {
        user_service: Arc::new(user_service),
        jwt_service: Arc::new(jwt_service),
        oauth_service: Some(Arc::new(oauth_service)),
    };

    // Build router with OAuth endpoints
    let oauth_router = RouterBuilder::new()
        .health_check(true)
        .google_oauth_init(true)
        .google_oauth_callback(true)
        .build();

    // Create protected OAuth routes with authentication middleware
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

    // Create demo routes
    let demo_router = Router::new()
        .route("/", get(demo_page))
        .route("/auth/signup/google", post(demo_oauth_init))
        .route("/auth/callback/google", get(demo_oauth_callback));

    // Combine routers
    let app = Router::new()
        .merge(demo_router)
        .merge(oauth_router)
        .merge(oauth_protected_routes)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(app_state);

    // Start server
    let addr = "0.0.0.0:3000";
    println!("🌐 Demo server starting on http://{}", addr);
    println!("📋 Available endpoints:");
    println!("   GET  /                           - Demo page with OAuth flow");
    println!("   POST /auth/signup/google         - Initiate Google OAuth");
    println!("   GET  /auth/callback/google       - Google OAuth callback");
    println!("   GET  /auth/oauth/providers       - List OAuth providers (auth required)");
    println!("   DELETE /auth/oauth/providers/google - Unlink Google account (auth required)");
    println!("   GET  /health                     - Health check");
    println!();
    println!("🔧 Setup Instructions:");
    println!("1. Create a Google OAuth 2.0 application in Google Cloud Console");
    println!("2. Set authorized redirect URI to: http://localhost:3000/auth/callback/google");
    println!("3. Set environment variables for Google OAuth credentials");
    println!("4. Visit http://localhost:3000 to start the demo");
    println!();
    println!("✅ Server ready for requests!");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
