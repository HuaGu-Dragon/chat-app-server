-- Add migration script here
ALTER TABLE users
ALTER COLUMN username TYPE VARCHAR(50);
-- This migration script alters the length of the username column in the users table to 50 characters.
-- This is a placeholder for the migration script.
-- Make sure to replace the table and column names with the actual ones in your database.
-- This migration script is intended to be run in a PostgreSQL database.