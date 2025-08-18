-- Migration: Create auth_audit_log table for security audit logging
-- Description: This table tracks all authentication events for security monitoring,
-- compliance, and incident response. Supports passwordless authentication flows only.

CREATE TABLE auth_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL, -- signup_email, signin_otp, signin_passkey, signin_oauth, email_verification
    event_data JSONB,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    request_id VARCHAR(100), -- For request correlation
    session_id VARCHAR(100), -- For session tracking
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for efficient querying and monitoring
CREATE INDEX idx_auth_audit_log_user_id ON auth_audit_log(user_id);
CREATE INDEX idx_auth_audit_log_created_at ON auth_audit_log(created_at);
CREATE INDEX idx_auth_audit_log_event_type ON auth_audit_log(event_type);
CREATE INDEX idx_auth_audit_log_ip_address ON auth_audit_log(ip_address);
CREATE INDEX idx_auth_audit_log_success ON auth_audit_log(success);
CREATE INDEX idx_auth_audit_log_event_data ON auth_audit_log USING GIN(event_data);

-- Composite indexes for common query patterns
CREATE INDEX idx_auth_audit_log_user_events ON auth_audit_log(user_id, created_at DESC);
CREATE INDEX idx_auth_audit_log_ip_events ON auth_audit_log(ip_address, created_at DESC);
CREATE INDEX idx_auth_audit_log_failed_events ON auth_audit_log(success, created_at DESC) WHERE success = false;

-- Partial index for monitoring suspicious activity
CREATE INDEX idx_auth_audit_log_suspicious ON auth_audit_log(ip_address, event_type, created_at)
WHERE success = false;

-- Comments for documentation
COMMENT ON TABLE auth_audit_log IS 'Security audit log for all authentication events in passwordless flows';
COMMENT ON COLUMN auth_audit_log.user_id IS 'Reference to the user (NULL for failed authentication attempts where user is unknown)';
COMMENT ON COLUMN auth_audit_log.event_type IS 'Type of authentication event (signup_email, signin_otp, signin_passkey, signin_oauth, email_verification)';
COMMENT ON COLUMN auth_audit_log.event_data IS 'Additional event-specific data in JSON format (excluding sensitive information)';
COMMENT ON COLUMN auth_audit_log.ip_address IS 'IP address of the client making the request';
COMMENT ON COLUMN auth_audit_log.user_agent IS 'User agent string from the client request';
COMMENT ON COLUMN auth_audit_log.success IS 'Whether the authentication attempt was successful';
COMMENT ON COLUMN auth_audit_log.error_message IS 'Error message if the authentication attempt failed';
COMMENT ON COLUMN auth_audit_log.request_id IS 'Unique identifier for request correlation and debugging';
COMMENT ON COLUMN auth_audit_log.session_id IS 'Session identifier for tracking user sessions';

-- Check constraint to ensure event_type is valid for passwordless authentication
ALTER TABLE auth_audit_log ADD CONSTRAINT chk_auth_audit_log_event_type
CHECK (event_type IN (
    'signup_email',
    'email_verification',
    'signin_otp_request',
    'signin_otp_verify',
    'signin_passkey_begin',
    'signin_passkey_finish',
    'signin_oauth_init',
    'signin_oauth_callback',
    'token_refresh',
    'password_attempt_detected' -- For security alerts when password fields are submitted
));

-- Check constraint to ensure error_message is provided when success is false
ALTER TABLE auth_audit_log ADD CONSTRAINT chk_auth_audit_log_error_message
CHECK ((success = true AND error_message IS NULL) OR (success = false AND error_message IS NOT NULL));
