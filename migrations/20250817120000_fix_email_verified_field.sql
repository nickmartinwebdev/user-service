-- Fix email_verified field to be properly NOT NULL with correct defaults
-- This migration ensures existing users are marked as email verified (traditional signup)
-- and new passwordless users default to unverified

-- Set existing users as email verified (they used traditional signup with passwords)
UPDATE users SET email_verified = TRUE WHERE email_verified IS NULL;

-- Make email_verified not null to ensure data consistency
ALTER TABLE users ALTER COLUMN email_verified SET NOT NULL;

-- Update default for new users to be unverified
ALTER TABLE users ALTER COLUMN email_verified SET DEFAULT FALSE;

-- Add comment for documentation
COMMENT ON COLUMN users.email_verified IS 'Whether the user email address has been verified (NOT NULL, defaults to FALSE for new users)';
