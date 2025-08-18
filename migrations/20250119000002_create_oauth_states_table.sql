-- Create OAuth states table for secure OAuth flow state management
-- This migration adds support for CSRF protection in OAuth flows

CREATE TABLE oauth_states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    state_token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    redirect_url VARCHAR(512),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for performance and cleanup
CREATE INDEX idx_oauth_states_state_token ON oauth_states(state_token);
CREATE INDEX idx_oauth_states_expires_at ON oauth_states(expires_at);
CREATE INDEX idx_oauth_states_created_at ON oauth_states(created_at);

-- Add comments for documentation
COMMENT ON TABLE oauth_states IS 'OAuth state tokens for CSRF protection during OAuth flows';
COMMENT ON COLUMN oauth_states.id IS 'Unique state record identifier';
COMMENT ON COLUMN oauth_states.state_token IS 'Secure random state token for OAuth flow';
COMMENT ON COLUMN oauth_states.expires_at IS 'Token expiration timestamp (typically 10 minutes)';
COMMENT ON COLUMN oauth_states.redirect_url IS 'Optional redirect URL after successful authentication';
COMMENT ON COLUMN oauth_states.created_at IS 'State token creation timestamp';
