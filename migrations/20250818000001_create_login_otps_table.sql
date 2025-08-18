-- Migration for Email OTP Sign-in System
-- This migration creates the login_otps table for managing OTP codes for existing verified users

-- Create login_otps table for OTP-based authentication
CREATE TABLE login_otps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    otp_code VARCHAR(6) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    attempts INTEGER DEFAULT 0,
    used_at TIMESTAMP WITH TIME ZONE,
    ip_address INET,
    user_agent TEXT,
    UNIQUE(user_id, otp_code)
);

-- Create indexes for performance
CREATE INDEX idx_login_otps_user_id ON login_otps(user_id);
CREATE INDEX idx_login_otps_expires_at ON login_otps(expires_at);
CREATE INDEX idx_login_otps_created_at ON login_otps(created_at);
CREATE INDEX idx_login_otps_otp_code ON login_otps(otp_code);

-- Add comments for documentation
COMMENT ON TABLE login_otps IS 'OTP codes for email-based sign-in of existing verified users';
COMMENT ON COLUMN login_otps.id IS 'Unique OTP record identifier';
COMMENT ON COLUMN login_otps.user_id IS 'Reference to existing user account';
COMMENT ON COLUMN login_otps.otp_code IS '6-digit numeric OTP code for sign-in';
COMMENT ON COLUMN login_otps.expires_at IS 'Expiration timestamp for the OTP code (typically 5 minutes)';
COMMENT ON COLUMN login_otps.created_at IS 'When the OTP code was generated';
COMMENT ON COLUMN login_otps.attempts IS 'Number of verification attempts made (max 3)';
COMMENT ON COLUMN login_otps.used_at IS 'When the OTP was successfully used for sign-in';
COMMENT ON COLUMN login_otps.ip_address IS 'IP address from which the OTP was requested';
COMMENT ON COLUMN login_otps.user_agent IS 'User agent string from the OTP request';
