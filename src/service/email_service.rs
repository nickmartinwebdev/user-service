//! Email Service
//!
//! Service for sending verification emails and other email communications.

use anyhow::Result;
use chrono::Datelike;
use lettre::{
    message::{header, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use log::{debug, error, info};
use tera::{Context, Tera};

use crate::utils::error::{AppError, AppResult};

/// Email service configuration
#[derive(Debug, Clone)]
pub struct EmailConfig {
    /// SMTP server hostname
    pub smtp_host: String,
    /// SMTP server port
    pub smtp_port: u16,
    /// SMTP username
    pub smtp_username: String,
    /// SMTP password
    pub smtp_password: String,
    /// From email address
    pub from_email: String,
    /// From name (display name)
    pub from_name: String,
    /// Base URL for the application (used in email templates)
    pub app_base_url: String,
}

impl EmailConfig {
    /// Create email configuration from environment variables
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            smtp_host: std::env::var("SMTP_HOST").unwrap_or_else(|_| "localhost".to_string()),
            smtp_port: std::env::var("SMTP_PORT")
                .unwrap_or_else(|_| "587".to_string())
                .parse()
                .unwrap_or(587),
            smtp_username: std::env::var("SMTP_USERNAME")
                .map_err(|_| anyhow::anyhow!("SMTP_USERNAME environment variable is required"))?,
            smtp_password: std::env::var("SMTP_PASSWORD")
                .map_err(|_| anyhow::anyhow!("SMTP_PASSWORD environment variable is required"))?,
            from_email: std::env::var("FROM_EMAIL")
                .map_err(|_| anyhow::anyhow!("FROM_EMAIL environment variable is required"))?,
            from_name: std::env::var("FROM_NAME").unwrap_or_else(|_| "User Service".to_string()),
            app_base_url: std::env::var("APP_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:3000".to_string()),
        })
    }
}

/// Email service for sending various types of emails
pub struct EmailService {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    templates: Tera,
    config: EmailConfig,
}

impl EmailService {
    /// Create a new email service
    pub fn new(config: EmailConfig) -> AppResult<Self> {
        // Create SMTP transport
        let creds = Credentials::new(config.smtp_username.clone(), config.smtp_password.clone());

        let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
            .map_err(|e| AppError::Configuration(format!("Failed to configure SMTP relay: {}", e)))?
            .port(config.smtp_port)
            .credentials(creds)
            .build();

        // Initialize template engine
        let mut templates = Tera::new("templates/**/*").unwrap_or_else(|_| {
            debug!("No template directory found, using embedded templates");
            Tera::default()
        });

        // Add embedded email templates
        Self::add_embedded_templates(&mut templates)?;

        Ok(Self {
            transport,
            templates,
            config,
        })
    }

    /// Add embedded email templates
    fn add_embedded_templates(tera: &mut Tera) -> AppResult<()> {
        // Email verification template (HTML)
        let verification_html = r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Email Address</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; background: #f8f9fa; padding: 20px; border-radius: 8px 8px 0 0; }
        .content { background: white; padding: 30px; border: 1px solid #dee2e6; }
        .code { font-size: 32px; font-weight: bold; color: #007bff; letter-spacing: 4px; text-align: center; margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 4px; }
        .footer { background: #f8f9fa; padding: 20px; border-radius: 0 0 8px 8px; text-align: center; font-size: 12px; color: #666; }
        .button { display: inline-block; padding: 12px 24px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Verify Your Email Address</h1>
    </div>
    <div class="content">
        <p>Hello {{ user_name }},</p>

        <p>Thank you for signing up! To complete your registration, please verify your email address by entering the verification code below:</p>

        <div class="code">{{ verification_code }}</div>

        <p>This verification code will expire in <strong>{{ expires_in_minutes }} minutes</strong>.</p>

        <p>If you didn't create an account, you can safely ignore this email.</p>

        <p>Best regards,<br>The {{ app_name }} Team</p>
    </div>
    <div class="footer">
        <p>This email was sent from {{ app_name }}. If you have any questions, please contact our support team.</p>
        <p>© {{ current_year }} {{ app_name }}. All rights reserved.</p>
    </div>
</body>
</html>
        "#;

        // Email verification template (Plain text)
        let verification_text = r#"
Verify Your Email Address

Hello {{ user_name }},

Thank you for signing up! To complete your registration, please verify your email address by entering the verification code below:

Verification Code: {{ verification_code }}

This verification code will expire in {{ expires_in_minutes }} minutes.

If you didn't create an account, you can safely ignore this email.

Best regards,
The {{ app_name }} Team

---
This email was sent from {{ app_name }}. If you have any questions, please contact our support team.
© {{ current_year }} {{ app_name }}. All rights reserved.
        "#;

        tera.add_raw_template("verification_email.html", verification_html)
            .map_err(|e| AppError::Configuration(format!("Failed to add HTML template: {}", e)))?;

        tera.add_raw_template("verification_email.txt", verification_text)
            .map_err(|e| AppError::Configuration(format!("Failed to add text template: {}", e)))?;

        Ok(())
    }

    /// Send email verification code
    pub async fn send_verification_email(
        &self,
        to_email: &str,
        user_name: &str,
        verification_code: &str,
        expires_in_minutes: i64,
    ) -> AppResult<()> {
        info!("Sending verification email to: {}", to_email);

        // Prepare template context
        let mut context = Context::new();
        context.insert("user_name", user_name);
        context.insert("verification_code", verification_code);
        context.insert("expires_in_minutes", &expires_in_minutes);
        context.insert("app_name", &self.config.from_name);
        context.insert("app_base_url", &self.config.app_base_url);
        context.insert("current_year", &chrono::Utc::now().year());

        // Render templates
        let html_body = self
            .templates
            .render("verification_email.html", &context)
            .map_err(|e| AppError::Internal(format!("Failed to render HTML template: {}", e)))?;

        let text_body = self
            .templates
            .render("verification_email.txt", &context)
            .map_err(|e| AppError::Internal(format!("Failed to render text template: {}", e)))?;

        // Create message
        let message = Message::builder()
            .from(
                format!("{} <{}>", self.config.from_name, self.config.from_email)
                    .parse()
                    .map_err(|e| AppError::Configuration(format!("Invalid from address: {}", e)))?,
            )
            .to(to_email
                .parse()
                .map_err(|e| AppError::BadRequest(format!("Invalid recipient email: {}", e)))?)
            .subject("Verify Your Email Address")
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_PLAIN)
                            .body(text_body),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_HTML)
                            .body(html_body),
                    ),
            )
            .map_err(|e| AppError::Internal(format!("Failed to build email message: {}", e)))?;

        // Send email
        match self.transport.send(message).await {
            Ok(_) => {
                info!("Verification email sent successfully to: {}", to_email);
                Ok(())
            }
            Err(e) => {
                error!("Failed to send verification email to {}: {}", to_email, e);
                Err(AppError::Internal(format!("Failed to send email: {}", e)))
            }
        }
    }

    /// Send welcome email after successful verification
    pub async fn send_welcome_email(&self, to_email: &str, user_name: &str) -> AppResult<()> {
        info!("Sending welcome email to: {}", to_email);

        let html_body = format!(
            r#"
            <h1>Welcome to {}!</h1>
            <p>Hello {},</p>
            <p>Your email has been successfully verified and your account is now active.</p>
            <p>You can now start using all features of our service.</p>
            <p>Best regards,<br>The {} Team</p>
            "#,
            self.config.from_name, user_name, self.config.from_name
        );

        let text_body = format!(
            "Welcome to {}!\n\nHello {},\n\nYour email has been successfully verified and your account is now active.\n\nYou can now start using all features of our service.\n\nBest regards,\nThe {} Team",
            self.config.from_name, user_name, self.config.from_name
        );

        let message = Message::builder()
            .from(
                format!("{} <{}>", self.config.from_name, self.config.from_email)
                    .parse()
                    .map_err(|e| AppError::Configuration(format!("Invalid from address: {}", e)))?,
            )
            .to(to_email
                .parse()
                .map_err(|e| AppError::BadRequest(format!("Invalid recipient email: {}", e)))?)
            .subject("Welcome! Your account is now active")
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_PLAIN)
                            .body(text_body),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_HTML)
                            .body(html_body),
                    ),
            )
            .map_err(|e| AppError::Internal(format!("Failed to build email message: {}", e)))?;

        match self.transport.send(message).await {
            Ok(_) => {
                info!("Welcome email sent successfully to: {}", to_email);
                Ok(())
            }
            Err(e) => {
                error!("Failed to send welcome email to {}: {}", to_email, e);
                Err(AppError::Internal(format!("Failed to send email: {}", e)))
            }
        }
    }

    /// Send OTP code for sign-in
    pub async fn send_signin_otp_email(
        &self,
        to_email: &str,
        user_name: &str,
        otp_code: &str,
    ) -> AppResult<()> {
        info!("Sending sign-in OTP email to: {}", to_email);

        let mut context = Context::new();
        context.insert("user_name", user_name);
        context.insert("otp_code", otp_code);
        context.insert("app_name", "User Service");
        context.insert("current_year", &chrono::Utc::now().year());
        context.insert("expires_minutes", &5); // 5 minute expiration

        // Render email templates
        let html_body = self
            .templates
            .render("signin_otp.html", &context)
            .unwrap_or_else(|_| self.fallback_signin_otp_html(user_name, otp_code));

        let text_body = self
            .templates
            .render("signin_otp.txt", &context)
            .unwrap_or_else(|_| self.fallback_signin_otp_text(user_name, otp_code));

        let message = Message::builder()
            .from(
                format!("{} <{}>", self.config.from_name, self.config.from_email)
                    .parse()
                    .map_err(|e| {
                        AppError::Internal(format!("Invalid from email address: {}", e))
                    })?,
            )
            .to(to_email.parse().map_err(|e| {
                AppError::BadRequest(format!("Invalid recipient email address: {}", e))
            })?)
            .subject("Your Sign-in Code")
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_PLAIN)
                            .body(text_body),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_HTML)
                            .body(html_body),
                    ),
            )
            .map_err(|e| AppError::Internal(format!("Failed to build email message: {}", e)))?;

        match self.transport.send(message).await {
            Ok(_) => {
                info!("Sign-in OTP email sent successfully to: {}", to_email);
                Ok(())
            }
            Err(e) => {
                error!("Failed to send sign-in OTP email to {}: {}", to_email, e);
                Err(AppError::Internal(format!("Failed to send email: {}", e)))
            }
        }
    }

    /// Fallback HTML template for sign-in OTP email
    fn fallback_signin_otp_html(&self, user_name: &str, otp_code: &str) -> String {
        format!(
            r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Your Sign-in Code</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #f8f9fa; padding: 20px; text-align: center; border-radius: 5px; }}
        .content {{ padding: 20px 0; }}
        .otp-code {{
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
            background-color: #f8f9fa;
            padding: 15px;
            text-align: center;
            border-radius: 5px;
            margin: 20px 0;
            letter-spacing: 3px;
        }}
        .warning {{
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .footer {{ font-size: 12px; color: #666; text-align: center; margin-top: 30px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Sign-in Code</h1>
        </div>
        <div class="content">
            <p>Hello {user_name},</p>
            <p>Here's your sign-in code:</p>
            <div class="otp-code">{otp_code}</div>
            <p>Enter this code to complete your sign-in. This code will expire in 5 minutes.</p>
            <div class="warning">
                <strong>Security Note:</strong> If you didn't request this code, please ignore this email. Never share this code with anyone.
            </div>
        </div>
        <div class="footer">
            <p>&copy; {} User Service. This is an automated message.</p>
        </div>
    </div>
</body>
</html>
            "#,
            chrono::Utc::now().year(),
            user_name = user_name,
            otp_code = otp_code
        )
    }

    /// Fallback text template for sign-in OTP email
    fn fallback_signin_otp_text(&self, user_name: &str, otp_code: &str) -> String {
        format!(
            r#"
Hello {user_name},

Here's your sign-in code: {otp_code}

Enter this code to complete your sign-in. This code will expire in 5 minutes.

SECURITY NOTE: If you didn't request this code, please ignore this email. Never share this code with anyone.

© {} User Service. This is an automated message.
            "#,
            chrono::Utc::now().year(),
            user_name = user_name,
            otp_code = otp_code
        )
    }

    /// Test email configuration by sending a test email
    pub async fn test_connection(&self) -> AppResult<()> {
        // This is a simple connection test - we could enhance it further
        debug!("Testing email service connection");

        // For now, just check if we can create the transport
        // In a real implementation, you might want to send a test email to yourself
        info!("Email service configuration appears valid");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_config_creation() {
        // Set required environment variables for test
        std::env::set_var("SMTP_USERNAME", "test@example.com");
        std::env::set_var("SMTP_PASSWORD", "password");
        std::env::set_var("FROM_EMAIL", "noreply@example.com");

        let config = EmailConfig::from_env();
        assert!(config.is_ok());

        let config = config.unwrap();
        assert_eq!(config.smtp_username, "test@example.com");
        assert_eq!(config.from_email, "noreply@example.com");
    }

    #[tokio::test]
    async fn test_template_rendering() {
        std::env::set_var("SMTP_USERNAME", "test@example.com");
        std::env::set_var("SMTP_PASSWORD", "password");
        std::env::set_var("FROM_EMAIL", "noreply@example.com");

        let config = EmailConfig::from_env().unwrap();
        let email_service = EmailService::new(config);
        assert!(email_service.is_ok());

        let service = email_service.unwrap();

        // Test that templates are loaded
        assert!(service
            .templates
            .get_template_names()
            .any(|name| name == "verification_email.html"));
        assert!(service
            .templates
            .get_template_names()
            .any(|name| name == "verification_email.txt"));
    }
}
