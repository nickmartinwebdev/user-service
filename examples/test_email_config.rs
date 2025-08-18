//! Email Configuration Test Script
//!
//! This example demonstrates how to test your Microsoft Outlook email configuration
//! without going through the full user signup flow.
//!
//! Usage:
//! ```bash
//! # Set your environment variables first
//! export SMTP_HOST="smtp.live.com"
//! export SMTP_PORT="587"
//! export SMTP_USERNAME="your-email@outlook.com"
//! export SMTP_PASSWORD="your-app-password"
//! export FROM_EMAIL="your-email@outlook.com"
//! export FROM_NAME="Your Service Name"
//! export APP_BASE_URL="http://localhost:3000"
//!
//! # Run the test
//! cargo run --example test_email_config
//! ```

use std::io::{self, Write};
use user_service::service::{EmailConfig, EmailService};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    println!("📧 Email Configuration Test");
    println!("============================");
    println!();

    // Load email configuration from environment
    println!("📋 Loading email configuration...");
    let email_config = match EmailConfig::from_env() {
        Ok(config) => {
            println!("✅ Email configuration loaded successfully");
            println!("   SMTP Host: {}", config.smtp_host);
            println!("   SMTP Port: {}", config.smtp_port);
            println!("   Username: {}", config.smtp_username);
            println!("   From Email: {}", config.from_email);
            println!("   From Name: {}", config.from_name);
            config
        }
        Err(e) => {
            eprintln!("❌ Failed to load email configuration: {}", e);
            eprintln!();
            eprintln!("Required environment variables:");
            eprintln!("  SMTP_HOST (e.g., smtp.live.com)");
            eprintln!("  SMTP_PORT (e.g., 587)");
            eprintln!("  SMTP_USERNAME (your Outlook email)");
            eprintln!("  SMTP_PASSWORD (your App Password)");
            eprintln!("  FROM_EMAIL (your Outlook email)");
            eprintln!();
            eprintln!("Optional environment variables:");
            eprintln!("  FROM_NAME (default: 'User Service')");
            eprintln!("  APP_BASE_URL (default: 'http://localhost:3000')");
            return Err(e.into());
        }
    };

    println!();

    // Create email service
    println!("🔧 Initializing email service...");
    let email_service = match EmailService::new(email_config) {
        Ok(service) => {
            println!("✅ Email service initialized successfully");
            service
        }
        Err(e) => {
            eprintln!("❌ Failed to initialize email service: {}", e);
            return Err(e.into());
        }
    };

    println!();

    // Test connection
    println!("🔌 Testing email service connection...");
    match email_service.test_connection().await {
        Ok(_) => println!("✅ Email service connection test passed"),
        Err(e) => {
            eprintln!("❌ Email service connection test failed: {}", e);
            return Err(e.into());
        }
    }

    println!();

    // Ask user if they want to send a test email
    print!("🧪 Would you like to send a test verification email? (y/n): ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if input.trim().to_lowercase() == "y" || input.trim().to_lowercase() == "yes" {
        print!("📬 Enter recipient email address: ");
        io::stdout().flush()?;

        let mut recipient = String::new();
        io::stdin().read_line(&mut recipient)?;
        let recipient = recipient.trim();

        if recipient.is_empty() {
            println!("❌ No recipient provided, skipping test email");
            return Ok(());
        }

        println!();
        println!("📤 Sending test verification email to: {}", recipient);

        // Send test verification email
        match email_service
            .send_verification_email(recipient, "Test User", "123456", 10)
            .await
        {
            Ok(_) => {
                println!("✅ Test verification email sent successfully!");
                println!("   Check your inbox for the verification email");
                println!("   The test code is: 123456");
            }
            Err(e) => {
                eprintln!("❌ Failed to send test email: {}", e);
                return Err(e.into());
            }
        }

        println!();

        // Ask if they want to send a welcome email too
        print!("🎉 Would you like to send a test welcome email? (y/n): ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if input.trim().to_lowercase() == "y" || input.trim().to_lowercase() == "yes" {
            println!("📤 Sending test welcome email to: {}", recipient);

            match email_service
                .send_welcome_email(recipient, "Test User")
                .await
            {
                Ok(_) => {
                    println!("✅ Test welcome email sent successfully!");
                    println!("   Check your inbox for the welcome email");
                }
                Err(e) => {
                    eprintln!("❌ Failed to send welcome email: {}", e);
                    return Err(e.into());
                }
            }
        }
    }

    println!();
    println!("🎯 Email Configuration Test Complete");
    println!("=====================================");
    println!();
    println!("If all tests passed, your email configuration is working correctly!");
    println!("You can now use the passwordless signup feature with confidence.");
    println!();
    println!("📖 For more information, see:");
    println!("   - docs/outlook-email-setup.md");
    println!("   - examples/passwordless_demo.rs");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_outlook_config_validation() {
        // Test Outlook.com configuration
        env::set_var("SMTP_HOST", "smtp.live.com");
        env::set_var("SMTP_PORT", "587");
        env::set_var("SMTP_USERNAME", "test@outlook.com");
        env::set_var("SMTP_PASSWORD", "test-app-password");
        env::set_var("FROM_EMAIL", "test@outlook.com");
        env::set_var("FROM_NAME", "Test Service");
        env::set_var("APP_BASE_URL", "https://test.com");

        let config = EmailConfig::from_env();
        assert!(config.is_ok());

        let config = config.unwrap();
        assert_eq!(config.smtp_host, "smtp.live.com");
        assert_eq!(config.smtp_port, 587);
        assert_eq!(config.smtp_username, "test@outlook.com");
        assert_eq!(config.from_email, "test@outlook.com");
    }

    #[test]
    fn test_office365_config_validation() {
        // Test Office 365 configuration
        env::set_var("SMTP_HOST", "smtp.office365.com");
        env::set_var("SMTP_PORT", "587");
        env::set_var("SMTP_USERNAME", "test@company.com");
        env::set_var("SMTP_PASSWORD", "test-app-password");
        env::set_var("FROM_EMAIL", "test@company.com");
        env::set_var("FROM_NAME", "Company Service");
        env::set_var("APP_BASE_URL", "https://company.com");

        let config = EmailConfig::from_env();
        assert!(config.is_ok());

        let config = config.unwrap();
        assert_eq!(config.smtp_host, "smtp.office365.com");
        assert_eq!(config.smtp_port, 587);
        assert_eq!(config.smtp_username, "test@company.com");
        assert_eq!(config.from_email, "test@company.com");
    }
}
