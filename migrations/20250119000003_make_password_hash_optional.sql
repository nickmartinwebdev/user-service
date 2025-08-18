-- Make password_hash optional for OAuth-only users
-- This migration allows users to authenticate only through OAuth providers
-- without requiring a traditional password

-- Remove NOT NULL constraint from password_hash column
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

-- Add comment to document the change
COMMENT ON COLUMN users.password_hash IS 'bcrypt hashed password (optional for OAuth-only users)';
