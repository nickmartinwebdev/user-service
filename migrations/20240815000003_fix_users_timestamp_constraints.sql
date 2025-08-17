-- Fix NOT NULL constraints on users table timestamp columns
-- This migration ensures that created_at and updated_at columns are properly
-- constrained as NOT NULL to match the intended schema design.

-- Add NOT NULL constraints to timestamp columns
-- These columns should never be null as they have default values
ALTER TABLE users ALTER COLUMN created_at SET NOT NULL;
ALTER TABLE users ALTER COLUMN updated_at SET NOT NULL;

-- Update any existing NULL values to current timestamp (safety measure)
-- This should not be necessary if defaults worked correctly, but ensures data integrity
UPDATE users SET created_at = NOW() WHERE created_at IS NULL;
UPDATE users SET updated_at = NOW() WHERE updated_at IS NULL;

-- Add comments to clarify the constraint addition
COMMENT ON COLUMN users.created_at IS 'Account creation timestamp (NOT NULL with NOW() default)';
COMMENT ON COLUMN users.updated_at IS 'Last profile update timestamp (NOT NULL with NOW() default, auto-updated)';
