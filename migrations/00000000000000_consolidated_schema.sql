-- Consolidated Migration: Complete Multi-Tenant User Service Schema
-- This migration creates the entire database schema from scratch for a multi-tenant user service
-- Run this on a fresh database to set up all required tables and indexes

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Function to update updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- ============================================================================
-- APPLICATIONS TABLE (Multi-tenant management)
-- ============================================================================

CREATE TABLE applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    api_key VARCHAR(64) UNIQUE NOT NULL,
    api_secret_hash VARCHAR(255) NOT NULL,
    allowed_origins TEXT[] NOT NULL DEFAULT '{}',
    settings JSONB NOT NULL DEFAULT '{}',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Applications indexes
CREATE INDEX idx_applications_api_key ON applications(api_key);
CREATE INDEX idx_applications_active ON applications(active) WHERE active = true;

-- Applications trigger
CREATE TRIGGER update_applications_updated_at
    BEFORE UPDATE ON applications
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- USERS TABLE
-- ============================================================================

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL CHECK (char_length(name) > 0),
    email VARCHAR(255) NOT NULL CHECK (char_length(email) > 0),
    password_hash VARCHAR(255),
    profile_picture_url TEXT,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT valid_email CHECK (email ~* '^[A-Za-z0-9._+%-]+@[A-Za-z0-9.-]+[.][A-Za-z]+$')
);

-- Users indexes
CREATE UNIQUE INDEX idx_users_app_email_unique ON users(application_id, email);
CREATE INDEX idx_users_app_id ON users(application_id);
CREATE INDEX idx_users_app_email ON users(application_id, email);
CREATE INDEX idx_users_app_created ON users(application_id, created_at DESC);
CREATE INDEX idx_users_app_email_verified ON users(application_id, email_verified);

-- Users trigger
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- AUTH SESSIONS TABLE
-- ============================================================================

CREATE TABLE auth_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) NOT NULL UNIQUE,
    refresh_token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    refresh_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Auth sessions indexes
CREATE INDEX idx_auth_sessions_app_id ON auth_sessions(application_id);
CREATE INDEX idx_auth_sessions_user_id ON auth_sessions(user_id);
CREATE INDEX idx_auth_sessions_token ON auth_sessions(session_token);
CREATE INDEX idx_auth_sessions_refresh_token ON auth_sessions(refresh_token);
CREATE INDEX idx_auth_sessions_expires_at ON auth_sessions(expires_at);

-- Auth sessions trigger
CREATE TRIGGER update_auth_sessions_updated_at
    BEFORE UPDATE ON auth_sessions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- EMAIL VERIFICATIONS TABLE
-- ============================================================================

CREATE TABLE email_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    verification_code VARCHAR(6) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    verified_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Email verifications indexes
CREATE INDEX idx_email_verifications_app_id ON email_verifications(application_id);
CREATE INDEX idx_email_verifications_user_id ON email_verifications(user_id);
CREATE INDEX idx_email_verifications_code ON email_verifications(verification_code);
CREATE INDEX idx_email_verifications_expires_at ON email_verifications(expires_at);
CREATE INDEX idx_email_verifications_app_email_code ON email_verifications(application_id, email, verification_code);

-- ============================================================================
-- LOGIN OTPS TABLE
-- ============================================================================

CREATE TABLE login_otps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    used_at TIMESTAMP WITH TIME ZONE,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Login OTPs indexes
CREATE INDEX idx_login_otps_app_id ON login_otps(application_id);
CREATE INDEX idx_login_otps_user_id ON login_otps(user_id);
CREATE INDEX idx_login_otps_code ON login_otps(otp_code);
CREATE INDEX idx_login_otps_expires_at ON login_otps(expires_at);
CREATE INDEX idx_login_otps_app_email_code ON login_otps(application_id, email, otp_code);

-- ============================================================================
-- OAUTH PROVIDERS TABLE
-- ============================================================================

CREATE TABLE oauth_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_type VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    provider_email VARCHAR(255),
    provider_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(application_id, provider_type, provider_user_id)
);

-- OAuth providers indexes
CREATE INDEX idx_oauth_providers_app_id ON oauth_providers(application_id);
CREATE INDEX idx_oauth_providers_user_id ON oauth_providers(user_id);
CREATE INDEX idx_oauth_providers_provider_type ON oauth_providers(provider_type);
CREATE INDEX idx_oauth_providers_app_user_provider ON oauth_providers(application_id, user_id, provider_type);

-- OAuth providers trigger
CREATE TRIGGER update_oauth_providers_updated_at
    BEFORE UPDATE ON oauth_providers
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- OAUTH STATES TABLE
-- ============================================================================

CREATE TABLE oauth_states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    state_token VARCHAR(255) NOT NULL UNIQUE,
    provider_type VARCHAR(50) NOT NULL,
    redirect_uri TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- OAuth states indexes
CREATE INDEX idx_oauth_states_app_id ON oauth_states(application_id);
CREATE INDEX idx_oauth_states_token ON oauth_states(state_token);
CREATE INDEX idx_oauth_states_expires_at ON oauth_states(expires_at);

-- ============================================================================
-- WEBAUTHN CREDENTIALS TABLE
-- ============================================================================

CREATE TABLE webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- WebAuthn credentials indexes
CREATE INDEX idx_webauthn_credentials_app_id ON webauthn_credentials(application_id);
CREATE INDEX idx_webauthn_credentials_user_id ON webauthn_credentials(user_id);
CREATE INDEX idx_webauthn_credentials_app_user ON webauthn_credentials(application_id, user_id);

-- WebAuthn credentials trigger
CREATE TRIGGER update_webauthn_credentials_updated_at
    BEFORE UPDATE ON webauthn_credentials
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- WEBAUTHN CHALLENGES TABLE
-- ============================================================================

CREATE TABLE webauthn_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge BYTEA NOT NULL,
    challenge_type VARCHAR(20) NOT NULL CHECK (challenge_type IN ('register', 'authenticate')),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- WebAuthn challenges indexes
CREATE INDEX idx_webauthn_challenges_app_id ON webauthn_challenges(application_id);
CREATE INDEX idx_webauthn_challenges_user_id ON webauthn_challenges(user_id);
CREATE INDEX idx_webauthn_challenges_expires_at ON webauthn_challenges(expires_at);

-- ============================================================================
-- AUTH RATE LIMITS TABLE
-- ============================================================================

CREATE TABLE auth_rate_limits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    identifier VARCHAR(255) NOT NULL,
    endpoint VARCHAR(100) NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 1,
    window_start TIMESTAMP WITH TIME ZONE NOT NULL,
    blocked_until TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(application_id, identifier, endpoint, window_start)
);

-- Auth rate limits indexes
CREATE INDEX idx_auth_rate_limits_app_id ON auth_rate_limits(application_id);
CREATE INDEX idx_auth_rate_limits_identifier ON auth_rate_limits(identifier, endpoint);
CREATE INDEX idx_auth_rate_limits_window_start ON auth_rate_limits(window_start);
CREATE INDEX idx_auth_rate_limits_blocked_until ON auth_rate_limits(blocked_until) WHERE blocked_until IS NOT NULL;
CREATE INDEX idx_auth_rate_limits_app_identifier ON auth_rate_limits(application_id, identifier, endpoint);

-- Auth rate limits trigger
CREATE TRIGGER update_auth_rate_limits_updated_at
    BEFORE UPDATE ON auth_rate_limits
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- AUTH AUDIT LOG TABLE
-- ============================================================================

CREATE TABLE auth_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID REFERENCES applications(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Auth audit log indexes
CREATE INDEX idx_auth_audit_log_app_id ON auth_audit_log(application_id);
CREATE INDEX idx_auth_audit_log_user_id ON auth_audit_log(user_id);
CREATE INDEX idx_auth_audit_log_event_type ON auth_audit_log(event_type);
CREATE INDEX idx_auth_audit_log_created_at ON auth_audit_log(created_at DESC);
CREATE INDEX idx_auth_audit_log_success ON auth_audit_log(success);
CREATE INDEX idx_auth_audit_log_app_user ON auth_audit_log(application_id, user_id, created_at DESC);

-- ============================================================================
-- COMMENTS FOR DOCUMENTATION
-- ============================================================================

-- Applications table
COMMENT ON TABLE applications IS 'Application/tenant configuration for multi-tenant authentication service. Each application represents a separate tenant with isolated data and configuration.';
COMMENT ON COLUMN applications.id IS 'Unique application identifier (UUID)';
COMMENT ON COLUMN applications.name IS 'Human-readable application name';
COMMENT ON COLUMN applications.api_key IS 'Public API key for application authentication';
COMMENT ON COLUMN applications.api_secret_hash IS 'Hashed API secret for secure authentication';
COMMENT ON COLUMN applications.allowed_origins IS 'Array of allowed CORS origins for this application';
COMMENT ON COLUMN applications.settings IS 'Application-specific configuration (email, OAuth, UI settings)';
COMMENT ON COLUMN applications.active IS 'Whether this application is currently active';

-- Users table
COMMENT ON TABLE users IS 'User accounts with multi-tenant isolation via application_id';
COMMENT ON COLUMN users.application_id IS 'Application/tenant this user belongs to (required)';
COMMENT ON COLUMN users.name IS 'User display name';
COMMENT ON COLUMN users.email IS 'User email address (unique per application)';
COMMENT ON COLUMN users.password_hash IS 'Hashed password (nullable for passwordless accounts)';
COMMENT ON COLUMN users.email_verified IS 'Whether the user has verified their email address';

-- Auth sessions table
COMMENT ON TABLE auth_sessions IS 'JWT session tokens and refresh tokens for authenticated users';
COMMENT ON COLUMN auth_sessions.application_id IS 'Application/tenant for this session (required)';

-- Email verifications table
COMMENT ON TABLE email_verifications IS 'Email verification codes for account signup and email changes';
COMMENT ON COLUMN email_verifications.application_id IS 'Application/tenant for this verification (required)';

-- Login OTPs table
COMMENT ON TABLE login_otps IS 'One-time passwords for passwordless authentication';
COMMENT ON COLUMN login_otps.application_id IS 'Application/tenant for this OTP (required)';

-- OAuth providers table
COMMENT ON TABLE oauth_providers IS 'OAuth provider links for social authentication';
COMMENT ON COLUMN oauth_providers.application_id IS 'Application/tenant for this OAuth link (required)';

-- OAuth states table
COMMENT ON TABLE oauth_states IS 'OAuth state tokens for CSRF protection during OAuth flows';
COMMENT ON COLUMN oauth_states.application_id IS 'Application/tenant for this OAuth state (required)';

-- WebAuthn credentials table
COMMENT ON TABLE webauthn_credentials IS 'WebAuthn/FIDO2 credentials for passkey authentication';
COMMENT ON COLUMN webauthn_credentials.application_id IS 'Application/tenant for this credential (required)';

-- WebAuthn challenges table
COMMENT ON TABLE webauthn_challenges IS 'WebAuthn challenges for registration and authentication ceremonies';
COMMENT ON COLUMN webauthn_challenges.application_id IS 'Application/tenant for this challenge (required)';

-- Auth rate limits table
COMMENT ON TABLE auth_rate_limits IS 'Rate limiting tracking for authentication endpoints to prevent abuse';
COMMENT ON COLUMN auth_rate_limits.application_id IS 'Application/tenant for this rate limit (required)';
COMMENT ON COLUMN auth_rate_limits.identifier IS 'IP address or email address being rate limited';
COMMENT ON COLUMN auth_rate_limits.endpoint IS 'Authentication endpoint being accessed';

-- Auth audit log table
COMMENT ON TABLE auth_audit_log IS 'Comprehensive audit log for all authentication events and security monitoring';
COMMENT ON COLUMN auth_audit_log.application_id IS 'Application/tenant for this audit event (nullable for unauthenticated requests)';
COMMENT ON COLUMN auth_audit_log.event_type IS 'Type of authentication event (login, signup, etc.)';
COMMENT ON COLUMN auth_audit_log.success IS 'Whether the authentication event was successful';

-- ============================================================================
-- INITIAL DATA (Optional)
-- ============================================================================

-- You can uncomment and modify this section to create a default application
-- for development purposes

-- INSERT INTO applications (name, api_key, api_secret_hash, allowed_origins, settings) VALUES (
--     'Development Application',
--     'ak_dev_' || encode(gen_random_bytes(16), 'hex'),
--     crypt('dev_secret_change_in_production', gen_salt('bf')),
--     ARRAY['http://localhost:3000', 'https://localhost:3000', 'http://127.0.0.1:3000'],
--     '{
--         "jwt_settings": {
--             "access_token_expires_hours": 1,
--             "refresh_token_expires_days": 30,
--             "issuer": "user-service-dev",
--             "audience": "user-service-dev-clients"
--         },
--         "rate_limits": {
--             "email_verification_per_hour": 10,
--             "otp_requests_per_hour": 5,
--             "password_attempts_per_hour": 20,
--             "account_creation_per_hour": 10,
--             "oauth_attempts_per_hour": 10
--         },
--         "ui_settings": {
--             "app_name": "Development App",
--             "primary_color": "#007bff",
--             "support_email": "dev@localhost"
--         }
--     }'::jsonb
-- );
