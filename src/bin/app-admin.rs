//! Multi-Tenant Application Administration CLI
//!
//! This CLI tool provides administrative functions for managing multi-tenant
//! applications in the user service. It allows creating, updating, and managing
//! tenant applications without going through the HTTP API.

use std::sync::Arc;

use clap::{Args, Parser, Subcommand};
use dotenv::dotenv;
use uuid::Uuid;

use user_service::{
    config::AppConfig,
    database::DatabaseConfig,
    models::application::{
        ApplicationSettings, CreateApplicationRequest, UpdateApplicationRequest,
    },
    service::ApplicationService,
};

/// Multi-tenant application administration CLI
#[derive(Parser)]
#[command(
    name = "app-admin",
    about = "Multi-tenant application administration CLI",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new application/tenant
    Create(CreateArgs),
    /// List all applications
    List,
    /// Get application details
    Get(GetArgs),
    /// Update application settings
    Update(UpdateArgs),
    /// Get application statistics
    Stats(StatsArgs),
    /// Rotate application credentials
    Rotate(RotateArgs),
    /// Deactivate an application
    Deactivate(DeactivateArgs),
    /// Initialize the first admin application
    Init(InitArgs),
}

#[derive(Args)]
struct CreateArgs {
    /// Application name
    #[arg(short, long)]
    name: String,

    /// Allowed CORS origins (comma-separated)
    #[arg(short, long, value_delimiter = ',')]
    origins: Vec<String>,

    /// Application description
    #[arg(short, long)]
    description: Option<String>,

    /// JWT access token expiration hours
    #[arg(long, default_value = "1")]
    jwt_access_hours: i64,

    /// JWT refresh token expiration days
    #[arg(long, default_value = "30")]
    jwt_refresh_days: i64,

    /// Primary color for UI
    #[arg(long, default_value = "#007bff")]
    primary_color: String,

    /// Support email
    #[arg(long)]
    support_email: Option<String>,
}

#[derive(Args)]
struct GetArgs {
    /// Application ID
    id: Uuid,
}

#[derive(Args)]
struct UpdateArgs {
    /// Application ID
    id: Uuid,

    /// New application name
    #[arg(short, long)]
    name: Option<String>,

    /// New allowed CORS origins (comma-separated)
    #[arg(short, long, value_delimiter = ',')]
    origins: Option<Vec<String>>,

    /// Activate or deactivate the application
    #[arg(short, long)]
    active: Option<bool>,

    /// Primary color for UI
    #[arg(long)]
    primary_color: Option<String>,

    /// Support email
    #[arg(long)]
    support_email: Option<String>,
}

#[derive(Args)]
struct StatsArgs {
    /// Application ID
    id: Uuid,
}

#[derive(Args)]
struct RotateArgs {
    /// Application ID
    id: Uuid,
}

#[derive(Args)]
struct DeactivateArgs {
    /// Application ID
    id: Uuid,
}

#[derive(Args)]
struct InitArgs {
    /// Initial application name
    #[arg(short, long, default_value = "Default Application")]
    name: String,

    /// Allowed CORS origins (comma-separated)
    #[arg(
        short,
        long,
        value_delimiter = ',',
        default_value = "http://localhost:3000,https://localhost:3000"
    )]
    origins: Vec<String>,

    /// Support email
    #[arg(long, default_value = "support@example.com")]
    support_email: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    env_logger::init();

    let cli = Cli::parse();

    // Initialize database connection
    let config = AppConfig::from_env()?;
    let db_config = DatabaseConfig {
        url: config.database.url.clone(),
        max_connections: config.database.max_connections,
        min_connections: config.database.min_connections,
        connect_timeout: std::time::Duration::from_secs(config.database.connect_timeout_seconds),
        idle_timeout: std::time::Duration::from_secs(config.database.idle_timeout_seconds),
        max_lifetime: std::time::Duration::from_secs(config.database.max_lifetime_seconds),
    };
    let database_pool = db_config.create_pool().await?;

    // Run migrations to ensure database is up to date
    sqlx::migrate!("./migrations").run(&database_pool).await?;

    let app_service = Arc::new(ApplicationService::new(database_pool));

    match cli.command {
        Commands::Create(args) => create_application(&app_service, args).await?,
        Commands::List => list_applications(&app_service).await?,
        Commands::Get(args) => get_application(&app_service, args).await?,
        Commands::Update(args) => update_application(&app_service, args).await?,
        Commands::Stats(args) => get_application_stats(&app_service, args).await?,
        Commands::Rotate(args) => rotate_credentials(&app_service, args).await?,
        Commands::Deactivate(args) => deactivate_application(&app_service, args).await?,
        Commands::Init(args) => init_application(&app_service, args).await?,
    }

    Ok(())
}

async fn create_application(
    service: &ApplicationService,
    args: CreateArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 Creating new application...");

    let mut settings = ApplicationSettings::default();

    // Configure JWT settings
    settings.jwt_settings.access_token_expires_hours = args.jwt_access_hours;
    settings.jwt_settings.refresh_token_expires_days = args.jwt_refresh_days;

    // Configure UI settings
    settings.ui_settings.app_name = args.name.clone();
    settings.ui_settings.primary_color = args.primary_color;
    if let Some(support_email) = args.support_email {
        settings.ui_settings.support_email = support_email;
    }

    let request = CreateApplicationRequest {
        name: args.name,
        allowed_origins: args.origins,
        settings,
    };

    let response = service.create_application(request).await?;

    println!("✅ Application created successfully!");
    println!();
    println!("📋 Application Details:");
    println!("   ID: {}", response.id);
    println!("   Name: {}", response.name);
    println!("   Created: {}", response.created_at);
    println!();
    println!("🔑 API Credentials (SAVE THESE SECURELY):");
    println!("   API Key: {}", response.api_key);
    println!("   API Secret: {}", response.api_secret);
    println!();
    println!("🌐 Allowed Origins:");
    for origin in &response.allowed_origins {
        println!("   - {}", origin);
    }
    println!();
    println!("⚠️  WARNING: The API secret is only shown once. Save it securely!");
    println!();
    println!("📖 Usage Instructions:");
    println!("   Include these headers in all API requests:");
    println!("   X-API-Key: {}", response.api_key);
    println!("   X-API-Secret: {}", response.api_secret);
    println!();
    println!("   Or use Bearer token format:");
    println!(
        "   Authorization: Bearer {}:{}",
        response.api_key, response.api_secret
    );

    Ok(())
}

async fn list_applications(service: &ApplicationService) -> Result<(), Box<dyn std::error::Error>> {
    println!("📋 Listing all applications...");

    let applications = service.list_applications().await?;

    if applications.is_empty() {
        println!("No applications found.");
        println!("Create your first application with: app-admin create --name \"My App\" --origins \"https://myapp.com\"");
        return Ok(());
    }

    println!();
    println!(
        "{:<38} {:<30} {:<8} {:<20}",
        "ID", "Name", "Active", "Created"
    );
    println!("{}", "-".repeat(96));

    for app in applications {
        println!(
            "{:<38} {:<30} {:<8} {:<20}",
            app.id,
            truncate_string(&app.name, 29),
            if app.active { "✅" } else { "❌" },
            app.created_at.format("%Y-%m-%d %H:%M")
        );
    }

    println!();
    println!("Use 'app-admin get <id>' to see detailed information about an application.");

    Ok(())
}

async fn get_application(
    service: &ApplicationService,
    args: GetArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Getting application details...");

    let app = service.get_application(args.id).await?;

    println!();
    println!("📋 Application Details:");
    println!("   ID: {}", app.id);
    println!("   Name: {}", app.name);
    println!("   API Key: {}", app.api_key);
    println!("   Active: {}", if app.active { "✅ Yes" } else { "❌ No" });
    println!("   Created: {}", app.created_at);
    println!("   Updated: {}", app.updated_at);
    println!();
    println!("🌐 Allowed Origins:");
    for origin in &app.allowed_origins {
        println!("   - {}", origin);
    }
    println!();
    println!("⚙️  Settings:");
    println!(
        "   JWT Access Token Expires: {} hours",
        app.settings.jwt_settings.access_token_expires_hours
    );
    println!(
        "   JWT Refresh Token Expires: {} days",
        app.settings.jwt_settings.refresh_token_expires_days
    );
    println!("   JWT Issuer: {}", app.settings.jwt_settings.issuer);
    println!("   JWT Audience: {}", app.settings.jwt_settings.audience);
    println!();
    println!("🎨 UI Settings:");
    println!("   App Name: {}", app.settings.ui_settings.app_name);
    println!(
        "   Primary Color: {}",
        app.settings.ui_settings.primary_color
    );
    println!(
        "   Support Email: {}",
        app.settings.ui_settings.support_email
    );
    println!("   Login URL: {}", app.settings.ui_settings.login_url);
    println!("   Signup URL: {}", app.settings.ui_settings.signup_url);

    if let Some(logo_url) = &app.settings.ui_settings.logo_url {
        println!("   Logo URL: {}", logo_url);
    }

    println!();
    println!("📊 Rate Limits:");
    println!(
        "   Email Verification: {} per hour",
        app.settings.rate_limits.email_verification_per_hour
    );
    println!(
        "   OTP Requests: {} per hour",
        app.settings.rate_limits.otp_requests_per_hour
    );
    println!(
        "   Password Attempts: {} per hour",
        app.settings.rate_limits.password_attempts_per_hour
    );
    println!(
        "   Account Creation: {} per hour",
        app.settings.rate_limits.account_creation_per_hour
    );
    println!(
        "   OAuth Attempts: {} per hour",
        app.settings.rate_limits.oauth_attempts_per_hour
    );

    Ok(())
}

async fn update_application(
    service: &ApplicationService,
    args: UpdateArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("✏️  Updating application...");

    let mut settings = None;

    // If we have UI-related updates, we need to get current settings and update them
    if args.primary_color.is_some() || args.support_email.is_some() {
        let current_app = service.get_application(args.id).await?;
        let mut app_settings = current_app.settings;

        if let Some(color) = args.primary_color {
            app_settings.ui_settings.primary_color = color;
        }

        if let Some(email) = args.support_email {
            app_settings.ui_settings.support_email = email;
        }

        settings = Some(app_settings);
    }

    let request = UpdateApplicationRequest {
        name: args.name,
        allowed_origins: args.origins,
        settings,
        active: args.active,
    };

    let updated_app = service.update_application(args.id, request).await?;

    println!("✅ Application updated successfully!");
    println!();
    println!("📋 Updated Application:");
    println!("   ID: {}", updated_app.id);
    println!("   Name: {}", updated_app.name);
    println!(
        "   Active: {}",
        if updated_app.active {
            "✅ Yes"
        } else {
            "❌ No"
        }
    );
    println!("   Updated: {}", updated_app.updated_at);

    Ok(())
}

async fn get_application_stats(
    service: &ApplicationService,
    args: StatsArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("📊 Getting application statistics...");

    let stats = service.get_application_stats(args.id).await?;

    println!();
    println!("📈 Application Statistics:");
    println!("   Total Users: {}", stats.total_users);
    println!("   Active Users (24h): {}", stats.active_users_24h);
    println!("   Auth Events (24h): {}", stats.auth_events_24h);
    println!(
        "   Failed Auth Events (24h): {}",
        stats.failed_auth_events_24h
    );

    if stats.auth_events_24h > 0 {
        let success_rate = ((stats.auth_events_24h - stats.failed_auth_events_24h) as f64
            / stats.auth_events_24h as f64)
            * 100.0;
        println!("   Success Rate (24h): {:.1}%", success_rate);
    }

    Ok(())
}

async fn rotate_credentials(
    service: &ApplicationService,
    args: RotateArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔄 Rotating application credentials...");
    println!("⚠️  WARNING: This will invalidate the current API key and secret!");

    println!("Are you sure you want to continue? (y/N): ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
        println!("Operation cancelled.");
        return Ok(());
    }

    let (api_key, api_secret) = service.rotate_credentials(args.id).await?;

    println!("✅ Credentials rotated successfully!");
    println!();
    println!("🔑 New API Credentials (SAVE THESE SECURELY):");
    println!("   API Key: {}", api_key);
    println!("   API Secret: {}", api_secret);
    println!();
    println!("⚠️  WARNING: The old credentials are now invalid!");
    println!("⚠️  Update your application configuration immediately!");
    println!();
    println!("📖 Usage Instructions:");
    println!("   Include these headers in all API requests:");
    println!("   X-API-Key: {}", api_key);
    println!("   X-API-Secret: {}", api_secret);
    println!();
    println!("   Or use Bearer token format:");
    println!("   Authorization: Bearer {}:{}", api_key, api_secret);

    Ok(())
}

async fn deactivate_application(
    service: &ApplicationService,
    args: DeactivateArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("❌ Deactivating application...");
    println!("⚠️  WARNING: This will disable all API access for this application!");

    println!("Are you sure you want to continue? (y/N): ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
        println!("Operation cancelled.");
        return Ok(());
    }

    service.deactivate_application(args.id).await?;

    println!("✅ Application deactivated successfully!");
    println!("The application and all its data remain in the database but API access is disabled.");

    Ok(())
}

async fn init_application(
    service: &ApplicationService,
    args: InitArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Initializing first application...");

    // Check if any applications already exist
    let existing_apps = service.list_applications().await?;
    if !existing_apps.is_empty() {
        println!("⚠️  Applications already exist. Use 'create' command to add more applications.");
        println!("Existing applications:");
        for app in existing_apps.iter().take(5) {
            println!("   - {} ({})", app.name, app.id);
        }
        return Ok(());
    }

    let mut settings = ApplicationSettings::default();
    settings.ui_settings.app_name = args.name.clone();
    settings.ui_settings.support_email = args.support_email;

    let request = CreateApplicationRequest {
        name: args.name,
        allowed_origins: args.origins,
        settings,
    };

    let response = service.create_application(request).await?;

    println!("✅ First application initialized successfully!");
    println!();
    println!("🎉 Welcome to Multi-Tenant User Service!");
    println!();
    println!("📋 Your Application:");
    println!("   ID: {}", response.id);
    println!("   Name: {}", response.name);
    println!();
    println!("🔑 API Credentials (SAVE THESE SECURELY):");
    println!("   API Key: {}", response.api_key);
    println!("   API Secret: {}", response.api_secret);
    println!();
    println!("🌐 Allowed Origins:");
    for origin in &response.allowed_origins {
        println!("   - {}", origin);
    }
    println!();
    println!("🚀 Next Steps:");
    println!("   1. Save the API credentials in a secure location");
    println!("   2. Configure your client application to use these credentials");
    println!("   3. Start making API requests to create users and authenticate");
    println!();
    println!("📖 Example API Usage:");
    println!("   curl -X POST http://localhost:3000/auth/signup/email \\");
    println!("     -H \"X-API-Key: {}\" \\", response.api_key);
    println!("     -H \"X-API-Secret: {}\" \\", response.api_secret);
    println!("     -H \"Content-Type: application/json\" \\");
    println!("     -d '{{\"name\": \"John Doe\", \"email\": \"john@example.com\"}}'");

    Ok(())
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}
