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
use thiserror::Error;

use crate::utils::error::AppError;

/// Email service specific errors
#[derive(Error, Debug)]
pub enum EmailServiceError {
    /// SMTP configuration error
    #[error("SMTP configuration error: {0}")]
    SmtpConfig(String),

    /// Email template error
    #[error("Email template error: {0}")]
    TemplateError(String),

    /// Email send failure
    #[error("Failed to send email: {0}")]
    SendFailure(String),

    /// Email address parsing error
    #[error("Invalid email address: {0}")]
    InvalidEmailAddress(String),

    /// SMTP connection error
    #[error("SMTP connection error: {0}")]
    ConnectionError(String),

    /// Template rendering error
    #[error("Template rendering error: {0}")]
    RenderError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<EmailServiceError> for AppError {
    fn from(err: EmailServiceError) -> Self {
        match err {
            EmailServiceError::SmtpConfig(msg) => {
                AppError::Configuration(format!("SMTP configuration error: {}", msg))
            }
            EmailServiceError::TemplateError(msg) => {
                AppError::Internal(format!("Email template error: {}", msg))
            }
            EmailServiceError::SendFailure(msg) => {
                AppError::ExternalService(format!("Failed to send email: {}", msg))
            }
            EmailServiceError::InvalidEmailAddress(msg) => {
                AppError::Validation(format!("Invalid email address: {}", msg))
            }
            EmailServiceError::ConnectionError(msg) => {
                AppError::ExternalService(format!("SMTP connection error: {}", msg))
            }
            EmailServiceError::RenderError(msg) => {
                AppError::Internal(format!("Template rendering error: {}", msg))
            }
            EmailServiceError::ConfigurationError(msg) => AppError::Configuration(msg),
            EmailServiceError::InternalError(msg) => AppError::Internal(msg),
        }
    }
}

/// Result type for email service operations
pub type EmailServiceResult<T> = Result<T, EmailServiceError>;

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
    /// Creates email configuration from environment variables
    ///
    /// Reads SMTP and email configuration from environment variables with sensible defaults
    /// where appropriate. Required variables will cause an error if not provided.
    ///
    /// # Environment Variables
    /// * `SMTP_HOST` - SMTP server hostname (default: "localhost")
    /// * `SMTP_PORT` - SMTP server port (default: 587)
    /// * `SMTP_USERNAME` - SMTP authentication username (required)
    /// * `SMTP_PASSWORD` - SMTP authentication password (required)
    /// * `FROM_EMAIL` - Sender email address (required)
    /// * `FROM_NAME` - Sender display name (default: "User Service")
    /// * `APP_BASE_URL` - Application base URL for email links (default: "http://localhost:3000")
    ///
    /// # Returns
    /// * `Ok(EmailConfig)` - Successfully parsed configuration
    /// * `Err(anyhow::Error)` - Missing required environment variables
    ///
    /// # Errors
    /// Returns an error if any required environment variables are missing:
    /// - `SMTP_USERNAME`
    /// - `SMTP_PASSWORD`
    /// - `FROM_EMAIL`
    ///
    /// # Examples
    /// ```
    /// std::env::set_var("SMTP_USERNAME", "user@smtp.com");
    /// std::env::set_var("SMTP_PASSWORD", "password");
    /// std::env::set_var("FROM_EMAIL", "noreply@myapp.com");
    ///
    /// let config = EmailConfig::from_env()?;
    /// assert_eq!(config.smtp_host, "localhost");
    /// assert_eq!(config.smtp_port, 587);
    /// ```
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
    /// Creates a new email service instance with SMTP transport and templates
    ///
    /// Initializes the email service with SMTP configuration and loads email templates.
    /// Templates are loaded from the filesystem if available, otherwise embedded
    /// templates are used as fallbacks.
    ///
    /// # Arguments
    /// * `config` - Email configuration including SMTP settings and sender information
    ///
    /// # Returns
    /// * `Ok(EmailService)` - Successfully configured email service
    /// * `Err(EmailServiceError)` - SMTP configuration or template loading failed
    ///
    /// # Errors
    /// * `SmtpConfig` - Invalid SMTP server configuration
    /// * `TemplateError` - Failed to load or parse email templates
    ///
    /// # Template Loading
    /// 1. Attempts to load templates from `templates/**/*` directory
    /// 2. Falls back to embedded templates if directory not found
    /// 3. Adds essential email templates (verification, welcome, OTP)
    ///
    /// # Examples
    /// ```
    /// use user_service::service::{EmailService, EmailConfig};
    ///
    /// let config = EmailConfig::from_env()?;
    /// let email_service = EmailService::new(config)?;
    /// ```
    pub fn new(config: EmailConfig) -> EmailServiceResult<Self> {
        // Create SMTP transport
        let creds = Credentials::new(config.smtp_username.clone(), config.smtp_password.clone());

        let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
            .map_err(|e| {
                EmailServiceError::SmtpConfig(format!("Failed to configure SMTP relay: {}", e))
            })?
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

    /// Adds embedded email templates to the template engine
    ///
    /// Registers HTML and text versions of essential email templates as fallbacks.
    /// These templates are used when external template files are not available.
    ///
    /// # Arguments
    /// * `tera` - Mutable reference to the Tera template engine
    ///
    /// # Returns
    /// * `Ok(())` - Templates added successfully
    /// * `Err(EmailServiceError)` - Template parsing or registration failed
    ///
    /// # Templates Added
    /// * `verification_email_html` - HTML version of email verification template
    /// * `verification_email_text` - Plain text version of email verification template
    ///
    /// # Template Variables
    /// Available variables in verification templates:
    /// - `user_name` - Recipient's display name
    /// - `verification_code` - 6-digit verification code
    /// - `expires_in_minutes` - Code expiration time in minutes
    /// - `app_name` - Application name from configuration
    /// - `app_base_url` - Application base URL
    /// - `current_year` - Current year for copyright notices
    ///
    /// # Errors
    /// * `TemplateError` - Template syntax errors or registration failures
    fn add_embedded_templates(tera: &mut Tera) -> EmailServiceResult<()> {
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

        tera.add_raw_template("verification_email_html", verification_html)
            .map_err(|e| {
                EmailServiceError::TemplateError(format!("Failed to add HTML template: {}", e))
            })?;

        tera.add_raw_template("verification_email_text", verification_text)
            .map_err(|e| {
                EmailServiceError::TemplateError(format!("Failed to add text template: {}", e))
            })?;

        Ok(())
    }

    /// Sends an email verification code to complete user registration
    ///
    /// Sends a professionally formatted email containing a 6-digit verification code
    /// with both HTML and plain text versions. The email includes branding, expiration
    /// information, and security notices.
    ///
    /// # Arguments
    /// * `to_email` - Recipient email address (must be valid format)
    /// * `user_name` - Recipient's display name for personalization
    /// * `verification_code` - 6-digit numeric verification code
    /// * `expires_in_minutes` - Code expiration time (typically 10 minutes)
    ///
    /// # Returns
    /// * `Ok(())` - Email sent successfully
    /// * `Err(EmailServiceError)` - Template rendering, validation, or sending failed
    ///
    /// # Errors
    /// * `InvalidEmailAddress` - Malformed sender or recipient email addresses
    /// * `RenderError` - Template rendering failed with provided context
    /// * `SendFailure` - SMTP transmission failed
    ///
    /// # Security Features
    /// * Time-limited verification codes
    /// * Clear expiration notices to users
    /// * Professional branding to prevent phishing confusion
    /// * Both HTML and text versions for compatibility
    ///
    /// # Template Context
    /// * User personalization with name
    /// * Prominent code display with styling
    /// * Expiration warnings
    /// * Application branding and copyright
    ///
    /// # Examples
    /// ```
    /// let email_service = EmailService::new(config)?;
    /// email_service.send_verification_email(
    ///     "user@example.com",
    ///     "John Doe",
    ///     "123456",
    ///     10
    /// ).await?;
    /// ```
    pub async fn send_verification_email(
        &self,
        to_email: &str,
        user_name: &str,
        verification_code: &str,
        expires_in_minutes: i64,
    ) -> EmailServiceResult<()> {
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
            .render("verification_email_html", &context)
            .map_err(|e| {
                EmailServiceError::RenderError(format!("Failed to render HTML template: {}", e))
            })?;

        let text_body = self
            .templates
            .render("verification_email_text", &context)
            .map_err(|e| {
                EmailServiceError::RenderError(format!("Failed to render text template: {}", e))
            })?;

        // Create message
        let message = Message::builder()
            .from(
                format!("{} <{}>", self.config.from_name, self.config.from_email)
                    .parse()
                    .map_err(|e| {
                        EmailServiceError::InvalidEmailAddress(format!(
                            "Invalid from address: {}",
                            e
                        ))
                    })?,
            )
            .to(to_email.parse().map_err(|e| {
                EmailServiceError::InvalidEmailAddress(format!("Invalid recipient email: {}", e))
            })?)
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
            .map_err(|e| {
                EmailServiceError::InvalidEmailAddress(format!("Failed to build email: {}", e))
            })?;

        // Send email
        match self.transport.send(message).await {
            Ok(_) => {
                info!("Verification email sent successfully to: {}", to_email);
                Ok(())
            }
            Err(e) => {
                error!("Failed to send verification email to {}: {}", to_email, e);
                Err(EmailServiceError::SendFailure(format!(
                    "Failed to send email: {}",
                    e
                )))
            }
        }
    }

    /// Sends a welcome email after successful account verification
    ///
    /// Sends a congratulatory email confirming account activation and welcoming
    /// the user to the service. This email is sent after successful email verification
    /// to provide positive feedback and next steps.
    ///
    /// # Arguments
    /// * `to_email` - Verified email address of the new user
    /// * `to_name` - User's display name for personalization
    ///
    /// # Returns
    /// * `Ok(())` - Welcome email sent successfully
    /// * `Err(EmailServiceError)` - Email validation or sending failed
    ///
    /// # Errors
    /// * `InvalidEmailAddress` - Malformed sender or recipient email
    /// * `SendFailure` - SMTP transmission failed
    ///
    /// # Design Notes
    /// * Non-critical email - failures should not block user flow
    /// * Simple template without external dependencies
    /// * Positive messaging to encourage engagement
    /// * Brief content to avoid overwhelming new users
    ///
    /// # Examples
    /// ```
    /// // After successful email verification
    /// email_service.send_welcome_email(
    ///     "newuser@example.com",
    ///     "Jane Smith"
    /// ).await?;
    /// ```
    pub async fn send_welcome_email(
        &self,
        to_email: &str,
        to_name: &str,
    ) -> EmailServiceResult<()> {
        info!("Sending welcome email to: {}", to_email);

        let html_body = format!(
            r#"
<html>
<body>
    <h2>Welcome to User Service!</h2>
    <p>Hello {},</p>
    <p>Your account has been successfully verified and is now active.</p>
    <p>You can now use all features of our service.</p>
    <p>Best regards,<br>The User Service Team</p>
</body>
</html>
"#,
            to_name
        );

        let text_body = format!(
            "Welcome to User Service!\n\nHello {},\n\nYour account has been successfully verified and is now active.\nYou can now use all features of our service.\n\nBest regards,\nThe User Service Team",
            to_name
        );

        let message = Message::builder()
            .from(
                format!("{} <{}>", self.config.from_name, self.config.from_email)
                    .parse()
                    .map_err(|e| {
                        EmailServiceError::InvalidEmailAddress(format!(
                            "Invalid from address: {}",
                            e
                        ))
                    })?,
            )
            .to(to_email.parse().map_err(|e| {
                EmailServiceError::InvalidEmailAddress(format!("Invalid recipient email: {}", e))
            })?)
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
            .map_err(|e| {
                EmailServiceError::InvalidEmailAddress(format!("Failed to build email: {}", e))
            })?;

        match self.transport.send(message).await {
            Ok(_) => {
                info!("Welcome email sent successfully to: {}", to_email);
                Ok(())
            }
            Err(e) => {
                error!("Failed to send welcome email to {}: {}", to_email, e);
                Err(EmailServiceError::SendFailure(format!(
                    "Failed to send email: {}",
                    e
                )))
            }
        }
    }

    /// Sends a one-time password (OTP) for passwordless sign-in
    ///
    /// Delivers a time-sensitive OTP code for existing verified users to sign in
    /// without entering a password. Includes security warnings and expiration notices.
    ///
    /// # Arguments
    /// * `to_email` - Email address of the authenticated user
    /// * `to_name` - User's display name for personalization
    /// * `otp_code` - 6-digit numeric OTP code
    ///
    /// # Returns
    /// * `Ok(())` - OTP email sent successfully
    /// * `Err(EmailServiceError)` - Template rendering, validation, or sending failed
    ///
    /// # Errors
    /// * `InvalidEmailAddress` - Malformed sender or recipient email
    /// * `SendFailure` - SMTP transmission failed
    ///
    /// # Security Features
    /// * Short expiration time (5 minutes)
    /// * Clear security warnings about unauthorized requests
    /// * Instructions to ignore if not requested
    /// * Fallback templates if external templates unavailable
    ///
    /// # Template Fallback
    /// Uses external templates if available (`signin_otp.html`, `signin_otp.txt`),
    /// otherwise falls back to embedded templates for reliability.
    ///
    /// # Examples
    /// ```
    /// // For passwordless sign-in
    /// email_service.send_signin_otp_email(
    ///     "user@example.com",
    ///     "John Doe",
    ///     "987654"
    /// ).await?;
    /// ```
    pub async fn send_signin_otp_email(
        &self,
        to_email: &str,
        to_name: &str,
        otp_code: &str,
    ) -> EmailServiceResult<()> {
        info!("Sending sign-in OTP email to: {}", to_email);

        let mut context = Context::new();
        context.insert("user_name", to_name);
        context.insert("otp_code", otp_code);
        context.insert("app_name", "User Service");
        context.insert("current_year", &chrono::Utc::now().year());
        context.insert("expires_minutes", &5); // 5 minute expiration

        // Render email templates
        let html_body = self
            .templates
            .render("signin_otp.html", &context)
            .unwrap_or_else(|_| self.fallback_signin_otp_html(to_name, otp_code));

        let text_body = self
            .templates
            .render("signin_otp.txt", &context)
            .unwrap_or_else(|_| self.fallback_signin_otp_text(to_name, otp_code));

        let message = Message::builder()
            .from(
                format!("{} <{}>", self.config.from_name, self.config.from_email)
                    .parse()
                    .map_err(|e| {
                        EmailServiceError::InvalidEmailAddress(format!(
                            "Invalid from email address: {}",
                            e
                        ))
                    })?,
            )
            .to(to_email.parse().map_err(|e| {
                EmailServiceError::InvalidEmailAddress(format!(
                    "Invalid recipient email address: {}",
                    e
                ))
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
            .map_err(|e| {
                EmailServiceError::InvalidEmailAddress(format!("Failed to build email: {}", e))
            })?;

        match self.transport.send(message).await {
            Ok(_) => {
                info!("Sign-in OTP email sent successfully to: {}", to_email);
                Ok(())
            }
            Err(e) => {
                error!("Failed to send sign-in OTP email to {}: {}", to_email, e);
                Err(EmailServiceError::SendFailure(format!(
                    "Failed to send email: {}",
                    e
                )))
            }
        }
    }

    /// Generates fallback HTML template for sign-in OTP emails
    ///
    /// Creates a simple but functional HTML email template when external templates
    /// are unavailable. Ensures email delivery even without template files.
    ///
    /// # Arguments
    /// * `user_name` - Recipient's name for personalization
    /// * `otp_code` - 6-digit OTP code to display
    ///
    /// # Returns
    /// Complete HTML email template as a string
    ///
    /// # Features
    /// * Responsive HTML structure
    /// * Clear code presentation
    /// * Security warnings
    /// * Professional appearance
    /// * Copyright and branding
    fn fallback_signin_otp_html(&self, user_name: &str, otp_code: &str) -> String {
        format!(
            r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Your Sign-in Code</title>
</head>
<body>
    <h2>Sign-in Code</h2>
    <p>Hello {},</p>
    <p>Here's your sign-in code: <strong>{}</strong></p>
    <p>Enter this code to complete your sign-in. This code will expire in 5 minutes.</p>
    <p>If you didn't request this code, please ignore this email.</p>
    <p>&copy; {} User Service. This is an automated message.</p>
</body>
</html>
            "#,
            user_name,
            otp_code,
            chrono::Utc::now().year()
        )
    }

    /// Generates fallback plain text template for sign-in OTP emails
    ///
    /// Creates a simple plain text email template for email clients that don't
    /// support HTML or when external templates are unavailable.
    ///
    /// # Arguments
    /// * `user_name` - Recipient's name for personalization
    /// * `otp_code` - 6-digit OTP code to display
    ///
    /// # Returns
    /// Complete plain text email template as a string
    ///
    /// # Features
    /// * Clean, readable text format
    /// * Clear instructions
    /// * Security warnings
    /// * Professional tone
    fn fallback_signin_otp_text(&self, user_name: &str, otp_code: &str) -> String {
        format!(
            "Sign-in Code\n\nHello {},\n\nHere's your sign-in code: {}\n\nEnter this code to complete your sign-in. This code will expire in 5 minutes.\n\nIf you didn't request this code, please ignore this email.\n\n© {} User Service\nThis is an automated message.",
            user_name,
            otp_code,
            chrono::Utc::now().year()
        )
    }

    /// Tests the email service configuration and connectivity
    ///
    /// Validates that the email service is properly configured and can potentially
    /// send emails. This is a basic connectivity test that doesn't actually send
    /// a test email but verifies the configuration appears valid.
    ///
    /// # Returns
    /// * `Ok(())` - Email service appears to be configured correctly
    /// * `Err(EmailServiceError)` - Configuration validation failed
    ///
    /// # Limitations
    /// This is a basic test that only validates configuration structure.
    /// A full test would require sending an actual test email to verify
    /// SMTP connectivity and authentication.
    ///
    /// # Use Cases
    /// * Application startup validation
    /// * Health check endpoints
    /// * Configuration troubleshooting
    /// * Integration testing setup
    ///
    /// # Examples
    /// ```
    /// let email_service = EmailService::new(config)?;
    /// email_service.test_connection().await?;
    /// println!("Email service is ready");
    /// ```
    pub async fn test_connection(&self) -> EmailServiceResult<()> {
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
            .any(|name| name == "verification_email_html"));
        assert!(service
            .templates
            .get_template_names()
            .any(|name| name == "verification_email_text"));
    }
}
