//! Passwordless Email Signup Demo
//!
//! This example demonstrates the passwordless email signup and verification flow.
//! It shows how to:
//! 1. Create a user account without a password
//! 2. Send an email verification code
//! 3. Verify the email and activate the account
//! 4. Receive authentication tokens upon verification
//!
//! To run this example:
//! ```bash
//! # Set required environment variables
//! export DATABASE_URL="postgresql://username:password@localhost/dbname"
//! export JWT_ACCESS_SECRET="your-access-secret-key"
//! export JWT_REFRESH_SECRET="your-refresh-secret-key"
//! export SMTP_USERNAME="your-smtp-username"
//! export SMTP_PASSWORD="your-smtp-password"
//! export FROM_EMAIL="noreply@yourdomain.com"
//!
//! # Run the example
//! cargo run --example passwordless_demo
//! ```

use std::sync::Arc;
use user_service::{
    database::DatabaseConfig,
    models::{PasswordlessSignupRequest, VerifyEmailRequest},
    service::{EmailConfig, EmailService, JwtService, UserService},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    println!("🚀 Starting Passwordless Email Signup Demo");
    println!("==========================================");

    // Load configuration from environment
    let db_config = DatabaseConfig::from_env()?;
    let email_config = EmailConfig::from_env()?;

    // Create database connection pool
    println!("📊 Connecting to database...");
    let pool = db_config.create_pool().await?;

    // Run database migrations
    println!("🔄 Running database migrations...");
    sqlx::migrate!("./migrations").run(&pool).await?;

    // Create services
    println!("⚙️  Initializing services...");
    let email_service = Arc::new(EmailService::new(email_config)?);

    // Create JWT service with secrets from environment
    let jwt_access_secret = std::env::var("JWT_ACCESS_SECRET")
        .expect("JWT_ACCESS_SECRET environment variable is required");
    let jwt_refresh_secret = std::env::var("JWT_REFRESH_SECRET")
        .expect("JWT_REFRESH_SECRET environment variable is required");

    let jwt_service = Arc::new(JwtService::new(
        pool.clone(),
        jwt_access_secret,
        jwt_refresh_secret,
    ));

    // Create user service with email support
    let user_service =
        UserService::with_email_service(pool.clone(), email_service.clone(), jwt_service.clone());

    println!("✅ Services initialized successfully");
    println!();

    // Demo user data
    let demo_email = "demo.user@example.com";
    let demo_name = "Demo User";

    println!("👤 Demo: Passwordless User Signup");
    println!("==================================");

    // Step 1: Passwordless signup
    println!("📝 Step 1: Creating passwordless user account...");
    let signup_request = PasswordlessSignupRequest {
        name: demo_name.to_string(),
        email: demo_email.to_string(),
    };

    match user_service.passwordless_signup(signup_request).await {
        Ok(response) => {
            println!("✅ Passwordless signup successful!");
            println!("   User ID: {}", response.user_id);
            println!("   Message: {}", response.message);
            println!("   Code expires in: {} seconds", response.expires_in);
            println!();

            println!(
                "📧 An email with a 6-digit verification code has been sent to: {}",
                demo_email
            );
            println!("   (In a real application, the user would receive this email)");
            println!();

            // In a real application, the user would receive the email and enter the code
            // For this demo, we'll simulate entering a verification code
            println!("🔑 Step 2: Email Verification");
            println!("=============================");
            println!("In a real application, the user would:");
            println!("1. Check their email for the verification code");
            println!("2. Enter the 6-digit code in the app");
            println!("3. The app would call the verify_email endpoint");
            println!();

            // For demo purposes, let's show what would happen with a mock verification
            println!("📱 Simulating email verification process...");

            // Note: In a real demo, you'd need to extract the actual verification code
            // from the database or email. For this example, we'll show the structure.
            println!("   The verify_email request would look like:");
            println!("   {{");
            println!("     \"email\": \"{}\",", demo_email);
            println!("     \"verification_code\": \"123456\"");
            println!("   }}");
            println!();

            println!("✅ Upon successful verification, the user would receive:");
            println!("   - Access token (for API authentication)");
            println!("   - Refresh token (for obtaining new access tokens)");
            println!("   - User profile data");
            println!("   - Welcome email confirmation");
            println!();

            // Show what the verification response would contain
            println!("📋 Example verification response structure:");
            println!("   {{");
            println!("     \"access_token\": \"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...\",");
            println!("     \"refresh_token\": \"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...\",");
            println!("     \"token_type\": \"Bearer\",");
            println!("     \"expires_in\": 3600,");
            println!("     \"user\": {{");
            println!("       \"id\": \"{}\",", response.user_id);
            println!("       \"name\": \"{}\",", demo_name);
            println!("       \"email\": \"{}\",", demo_email);
            println!("       \"email_verified\": true,");
            println!("       \"created_at\": \"2024-01-01T00:00:00Z\",");
            println!("       \"updated_at\": \"2024-01-01T00:00:00Z\"");
            println!("     }}");
            println!("   }}");
            println!();

            println!("🔐 Security Features:");
            println!("   ✓ No passwords stored or transmitted");
            println!("   ✓ 6-digit verification codes expire in 10 minutes");
            println!("   ✓ Maximum 3 verification attempts per code");
            println!("   ✓ Email addresses are normalized and validated");
            println!("   ✓ JWT tokens with configurable expiration");
            println!("   ✓ Rate limiting to prevent abuse");
            println!();

            println!("🎯 Benefits of Passwordless Authentication:");
            println!("   • Improved user experience (no password to remember)");
            println!("   • Enhanced security (no password reuse or breaches)");
            println!("   • Reduced support burden (no password resets)");
            println!("   • Better conversion rates (faster signup process)");
            println!("   • Email verification is built into the flow");
        }
        Err(e) => {
            println!("❌ Passwordless signup failed: {}", e);

            if e.to_string().contains("Email already exists") {
                println!("   This email is already registered. In a real app, you might:");
                println!("   - Send a login link instead");
                println!("   - Offer account recovery options");
                println!("   - Redirect to traditional login");
            }
        }
    }

    println!();
    println!("🏁 Demo completed!");
    println!();
    println!("💡 Next steps for integration:");
    println!("   1. Set up email service configuration (SMTP)");
    println!("   2. Customize email templates for your brand");
    println!("   3. Implement rate limiting and security measures");
    println!("   4. Add frontend UI for signup and verification");
    println!("   5. Configure JWT token expiration policies");
    println!("   6. Set up monitoring and analytics");

    Ok(())
}
