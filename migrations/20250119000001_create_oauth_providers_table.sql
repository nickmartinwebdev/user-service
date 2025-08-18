-- Create OAuth providers table for linking external authentication providers
-- This migration adds support for OAuth 2.0 authentication with providers like Google

CREATE TABLE oauth_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    provider_email VARCHAR(255) NOT NULL,
    provider_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Ensure unique provider account associations
    UNIQUE(provider, provider_user_id),
    UNIQUE(provider, provider_email)
);

-- Create indexes for performance
CREATE INDEX idx_oauth_providers_user_id ON oauth_providers(user_id);
CREATE INDEX idx_oauth_providers_provider ON oauth_providers(provider);
CREATE INDEX idx_oauth_providers_provider_user_id ON oauth_providers(provider, provider_user_id);
CREATE INDEX idx_oauth_providers_provider_email ON oauth_providers(provider, provider_email);
CREATE INDEX idx_oauth_providers_created_at ON oauth_providers(created_at);

-- Create trigger to automatically update updated_at timestamp
CREATE TRIGGER update_oauth_providers_updated_at
    BEFORE UPDATE ON oauth_providers
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Add comments for documentation
COMMENT ON TABLE oauth_providers IS 'OAuth provider account linkages for external authentication';
COMMENT ON COLUMN oauth_providers.id IS 'Unique OAuth provider record identifier';
COMMENT ON COLUMN oauth_providers.user_id IS 'Reference to the local user account';
COMMENT ON COLUMN oauth_providers.provider IS 'OAuth provider name (e.g., google, github)';
COMMENT ON COLUMN oauth_providers.provider_user_id IS 'User ID from the OAuth provider';
COMMENT ON COLUMN oauth_providers.provider_email IS 'Email address from the OAuth provider';
COMMENT ON COLUMN oauth_providers.provider_data IS 'Additional provider-specific data (JSON)';
COMMENT ON COLUMN oauth_providers.created_at IS 'Account linking timestamp';
COMMENT ON COLUMN oauth_providers.updated_at IS 'Last update timestamp (auto-updated)';
