-- Migration: Create auth_rate_limits table for IP and email-based rate limiting
-- Description: This table tracks rate limiting attempts for various authentication endpoints
-- to prevent abuse and brute force attacks on passwordless authentication flows.

CREATE TABLE auth_rate_limits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identifier VARCHAR(255) NOT NULL, -- IP address or email
    endpoint VARCHAR(100) NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 1,
    window_start TIMESTAMP WITH TIME ZONE NOT NULL,
    blocked_until TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(identifier, endpoint, window_start)
);

-- Indexes for efficient querying
CREATE INDEX idx_auth_rate_limits_identifier ON auth_rate_limits(identifier, endpoint);
CREATE INDEX idx_auth_rate_limits_window_start ON auth_rate_limits(window_start);
CREATE INDEX idx_auth_rate_limits_blocked_until ON auth_rate_limits(blocked_until) WHERE blocked_until IS NOT NULL;

-- Function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_auth_rate_limits_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update the updated_at field
CREATE TRIGGER trigger_auth_rate_limits_updated_at
    BEFORE UPDATE ON auth_rate_limits
    FOR EACH ROW
    EXECUTE FUNCTION update_auth_rate_limits_updated_at();

-- Comments for documentation
COMMENT ON TABLE auth_rate_limits IS 'Rate limiting tracking for authentication endpoints to prevent abuse';
COMMENT ON COLUMN auth_rate_limits.identifier IS 'IP address or email address being rate limited';
COMMENT ON COLUMN auth_rate_limits.endpoint IS 'Authentication endpoint being accessed (e.g., email_signup, otp_verification)';
COMMENT ON COLUMN auth_rate_limits.attempt_count IS 'Number of attempts within the current time window';
COMMENT ON COLUMN auth_rate_limits.window_start IS 'Start time of the current rate limiting window';
COMMENT ON COLUMN auth_rate_limits.blocked_until IS 'Timestamp until which the identifier is blocked (NULL if not blocked)';
