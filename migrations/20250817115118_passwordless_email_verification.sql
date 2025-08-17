-- Migration for passwordless email verification system
-- This migration removes password requirements and adds email verification functionality

-- Remove password requirement from users table and add email verification field
ALTER TABLE users
    ALTER COLUMN password_hash DROP NOT NULL,
    ADD COLUMN email_verified BOOLEAN DEFAULT FALSE;

-- Create email verifications table for managing verification codes
CREATE TABLE email_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    verification_code VARCHAR(6) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    attempts INTEGER DEFAULT 0,
    verified_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id, verification_code)
);

-- Create indexes for performance
CREATE INDEX idx_email_verifications_user_id ON email_verifications(user_id);
CREATE INDEX idx_email_verifications_code ON email_verifications(verification_code);
CREATE INDEX idx_email_verifications_expires_at ON email_verifications(expires_at);
CREATE INDEX idx_email_verifications_created_at ON email_verifications(created_at);

-- Add comments for documentation
COMMENT ON TABLE email_verifications IS 'Email verification codes for passwordless authentication';
COMMENT ON COLUMN email_verifications.id IS 'Unique verification record identifier';
COMMENT ON COLUMN email_verifications.user_id IS 'Reference to user account';
COMMENT ON COLUMN email_verifications.verification_code IS '6-digit numeric verification code';
COMMENT ON COLUMN email_verifications.expires_at IS 'Expiration timestamp for the verification code';
COMMENT ON COLUMN email_verifications.created_at IS 'When the verification code was generated';
COMMENT ON COLUMN email_verifications.attempts IS 'Number of verification attempts made';
COMMENT ON COLUMN email_verifications.verified_at IS 'When the code was successfully verified';

COMMENT ON COLUMN users.email_verified IS 'Whether the user email address has been verified';
