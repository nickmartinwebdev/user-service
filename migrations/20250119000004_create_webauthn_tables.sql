-- Create WebAuthn/Passkey authentication tables
-- This migration adds support for WebAuthn-based passkey authentication

-- Table for storing user credentials (passkeys)
CREATE TABLE user_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    credential_name VARCHAR(255),
    authenticator_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id, credential_id)
);

-- Table for managing WebAuthn challenges
CREATE TABLE webauthn_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_type VARCHAR(20) NOT NULL CHECK (challenge_type IN ('registration', 'authentication')),
    challenge BYTEA NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    user_handle BYTEA
);

-- Create indexes for performance
CREATE INDEX idx_user_credentials_user_id ON user_credentials(user_id);
CREATE INDEX idx_user_credentials_credential_id ON user_credentials(credential_id);
CREATE INDEX idx_user_credentials_last_used_at ON user_credentials(last_used_at);
CREATE INDEX idx_user_credentials_created_at ON user_credentials(created_at);

CREATE INDEX idx_webauthn_challenges_user_id ON webauthn_challenges(user_id);
CREATE INDEX idx_webauthn_challenges_expires_at ON webauthn_challenges(expires_at);
CREATE INDEX idx_webauthn_challenges_challenge_type ON webauthn_challenges(challenge_type);
CREATE INDEX idx_webauthn_challenges_created_at ON webauthn_challenges(created_at);

-- Add comments for documentation
COMMENT ON TABLE user_credentials IS 'WebAuthn/Passkey user credentials for passwordless authentication';
COMMENT ON COLUMN user_credentials.id IS 'Unique credential record identifier';
COMMENT ON COLUMN user_credentials.user_id IS 'Reference to the user account';
COMMENT ON COLUMN user_credentials.credential_id IS 'WebAuthn credential ID (raw bytes)';
COMMENT ON COLUMN user_credentials.public_key IS 'WebAuthn credential public key (raw bytes)';
COMMENT ON COLUMN user_credentials.sign_count IS 'WebAuthn signature counter for replay protection';
COMMENT ON COLUMN user_credentials.credential_name IS 'User-friendly name for the credential';
COMMENT ON COLUMN user_credentials.authenticator_data IS 'Additional authenticator-specific data (JSON)';
COMMENT ON COLUMN user_credentials.created_at IS 'Credential registration timestamp';
COMMENT ON COLUMN user_credentials.last_used_at IS 'Last authentication timestamp';

COMMENT ON TABLE webauthn_challenges IS 'WebAuthn challenges for registration and authentication flows';
COMMENT ON COLUMN webauthn_challenges.id IS 'Unique challenge record identifier';
COMMENT ON COLUMN webauthn_challenges.user_id IS 'Reference to the user account (nullable for authentication)';
COMMENT ON COLUMN webauthn_challenges.challenge_type IS 'Type of challenge: registration or authentication';
COMMENT ON COLUMN webauthn_challenges.challenge IS 'WebAuthn challenge bytes';
COMMENT ON COLUMN webauthn_challenges.expires_at IS 'Challenge expiration timestamp';
COMMENT ON COLUMN webauthn_challenges.created_at IS 'Challenge creation timestamp';
COMMENT ON COLUMN webauthn_challenges.user_handle IS 'WebAuthn user handle (raw bytes)';
