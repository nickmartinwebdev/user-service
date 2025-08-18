# Microsoft Outlook Email Configuration Guide

This guide explains how to configure the user service to send emails through Microsoft Outlook accounts.

## Overview

The user service supports sending verification emails through SMTP. To use Microsoft Outlook as your email provider, you need to configure the appropriate SMTP settings and authentication.

## Configuration Options

### Option 1: Personal Outlook.com Account

For personal Outlook.com, Hotmail.com, or Live.com accounts:

```bash
# Microsoft Outlook SMTP Configuration
SMTP_HOST=smtp.live.com
SMTP_PORT=587
SMTP_USERNAME=your-email@outlook.com
SMTP_PASSWORD=your-app-password
FROM_EMAIL=your-email@outlook.com
FROM_NAME="Your Service Name"
APP_BASE_URL=https://your-domain.com
```

### Option 2: Office 365 Business Account

For business accounts using Office 365:

```bash
# Microsoft Office 365 SMTP Configuration
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USERNAME=your-email@yourdomain.com
SMTP_PASSWORD=your-app-password
FROM_EMAIL=your-email@yourdomain.com
FROM_NAME="Your Service Name"
APP_BASE_URL=https://your-domain.com
```

## Required Security Setup

### 1. Enable Two-Factor Authentication

App passwords require 2FA to be enabled on your Microsoft account:

1. Go to [Microsoft Account Security](https://account.microsoft.com/security)
2. Sign in with your Outlook account
3. Navigate to **Security** → **Two-step verification**
4. Follow the setup process to enable 2FA

### 2. Create an App Password

Microsoft requires App Passwords for SMTP authentication:

1. Go to [Microsoft Account Security](https://account.microsoft.com/security)
2. Sign in with your Outlook account
3. Navigate to **Security** → **Advanced security options**
4. Under **App passwords**, click **Create a new app password**
5. Give it a descriptive name like "User Service SMTP"
6. Copy the generated password (it looks like: `abcd-efgh-ijkl-mnop`)
7. Use this password as your `SMTP_PASSWORD` environment variable

⚠️ **Important**: Use the App Password, NOT your regular Microsoft account password!

## Environment Variable Setup

### Development Environment

Create a `.env` file in your project root:

```bash
# Database Configuration
DATABASE_URL=postgresql://username:password@localhost/user_service

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-here
JWT_EXPIRATION_HOURS=24

# Email Configuration (Outlook)
SMTP_HOST=smtp.live.com
SMTP_PORT=587
SMTP_USERNAME=your-email@outlook.com
SMTP_PASSWORD=abcd-efgh-ijkl-mnop
FROM_EMAIL=your-email@outlook.com
FROM_NAME="Your App Name"
APP_BASE_URL=http://localhost:3000

# Rate Limiting
RATE_LIMIT_PER_MINUTE=5
```

### Production Environment

Set these environment variables in your production deployment:

```bash
export SMTP_HOST=smtp.live.com
export SMTP_PORT=587
export SMTP_USERNAME=your-email@outlook.com
export SMTP_PASSWORD=abcd-efgh-ijkl-mnop
export FROM_EMAIL=your-email@outlook.com
export FROM_NAME="Your App Name"
export APP_BASE_URL=https://your-production-domain.com
```

## Testing the Configuration

### Using the Demo Application

The service includes a demo application to test email functionality:

```bash
# Set environment variables
export SMTP_HOST=smtp.live.com
export SMTP_PORT=587
export SMTP_USERNAME=your-email@outlook.com
export SMTP_PASSWORD=your-app-password
export FROM_EMAIL=your-email@outlook.com

# Run the demo
cargo run --example passwordless_demo
```

### Manual Testing

You can also test the email service programmatically:

```rust
use user_service::service::{EmailConfig, EmailService};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let email_config = EmailConfig::from_env()?;
    
    // Create email service
    let email_service = EmailService::new(email_config)?;
    
    // Test sending a verification email
    email_service.send_verification_email(
        "test@example.com",
        "Test User",
        "123456",
        10
    ).await?;
    
    println!("Test email sent successfully!");
    Ok(())
}
```

## Troubleshooting

### Common Issues

1. **Authentication Failed (535 error)**
   - Ensure you're using an App Password, not your regular password
   - Verify 2FA is enabled on your Microsoft account
   - Double-check the username and app password

2. **Connection Timeout**
   - Verify the SMTP host and port are correct
   - Check if your firewall/network allows outbound connections on port 587
   - Some networks block SMTP traffic

3. **Invalid From Address**
   - The `FROM_EMAIL` must match your authenticated account
   - You cannot send from arbitrary email addresses

4. **Rate Limiting**
   - Microsoft limits the number of emails you can send per day
   - Personal accounts: ~300 emails/day
   - Business accounts: Higher limits based on subscription

### Debug Logging

Enable debug logging to troubleshoot issues:

```bash
export RUST_LOG=debug
cargo run --example passwordless_demo
```

## Security Best Practices

1. **Never commit credentials to git**
   - Always use environment variables
   - Add `.env` to your `.gitignore`

2. **Use App Passwords**
   - Never use your main Microsoft account password
   - Rotate app passwords regularly

3. **Secure Environment Variables**
   - Use secure secret management in production
   - Consider using Azure Key Vault or similar services

4. **Monitor Usage**
   - Keep track of email sending volume
   - Set up alerts for authentication failures

## Alternative SMTP Ports

If port 587 doesn't work, try these alternatives:

- **Port 25**: Often blocked by ISPs
- **Port 465**: SSL/TLS (requires code changes to enable SSL)
- **Port 587**: STARTTLS (recommended, current default)

## Production Considerations

### For High Volume Email

For production applications sending many emails, consider:

1. **Dedicated Email Service**
   - SendGrid, AWS SES, or Mailgun
   - Better deliverability and analytics
   - Higher sending limits

2. **Microsoft Graph API**
   - More robust than SMTP
   - Better integration with Office 365
   - Requires OAuth setup

3. **Load Balancing**
   - Multiple email accounts
   - Queue-based email sending
   - Retry mechanisms

## Support

If you encounter issues:

1. Check the logs for detailed error messages
2. Verify your Microsoft account security settings
3. Test with a simple SMTP client first
4. Consult Microsoft's official SMTP documentation

For more advanced configurations or issues, refer to the [lettre crate documentation](https://lettre.rs/) which is used internally by this service.