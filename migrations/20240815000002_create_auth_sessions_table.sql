-- Create auth_sessions table for JWT refresh token management
-- This migration sets up the session management table for handling
-- refresh tokens and tracking user authentication sessions.

-- Create auth_sessions table
CREATE TABLE auth_sessions (
    -- Primary key using UUID for session identification
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Reference to the user who owns this session
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Hashed refresh token for security (never store plaintext tokens)
    refresh_token_hash VARCHAR(255) NOT NULL UNIQUE,

    -- Session expiration timestamp
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Session creation timestamp
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Last time this session was used (updated on token refresh)
    last_used_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Optional client information for security tracking
    user_agent TEXT,
    ip_address INET
);

-- Create indexes for performance and security
CREATE INDEX idx_auth_sessions_user_id ON auth_sessions(user_id);
CREATE INDEX idx_auth_sessions_refresh_token_hash ON auth_sessions(refresh_token_hash);
CREATE INDEX idx_auth_sessions_expires_at ON auth_sessions(expires_at);
CREATE INDEX idx_auth_sessions_created_at ON auth_sessions(created_at);

-- Create trigger to automatically update last_used_at timestamp
CREATE OR REPLACE FUNCTION update_last_used_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_used_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_auth_sessions_last_used_at
    BEFORE UPDATE ON auth_sessions
    FOR EACH ROW
    EXECUTE FUNCTION update_last_used_at_column();

-- Add comments for documentation
COMMENT ON TABLE auth_sessions IS 'Authentication sessions table for JWT refresh token management';
COMMENT ON COLUMN auth_sessions.id IS 'Unique session identifier (UUID)';
COMMENT ON COLUMN auth_sessions.user_id IS 'Foreign key reference to users table';
COMMENT ON COLUMN auth_sessions.refresh_token_hash IS 'Hashed refresh token (SHA-256)';
COMMENT ON COLUMN auth_sessions.expires_at IS 'Session expiration timestamp';
COMMENT ON COLUMN auth_sessions.created_at IS 'Session creation timestamp';
COMMENT ON COLUMN auth_sessions.last_used_at IS 'Last session usage timestamp (auto-updated)';
COMMENT ON COLUMN auth_sessions.user_agent IS 'Client user agent string for tracking';
COMMENT ON COLUMN auth_sessions.ip_address IS 'Client IP address for security tracking';
