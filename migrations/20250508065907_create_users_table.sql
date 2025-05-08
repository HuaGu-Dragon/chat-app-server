-- Add migration script here

CREATE TABLE create_users_table (
    email VARCHAR(255) UNIQUE NOT NULL,
    pin VARCHAR(6) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_create_email ON create_users_table(email);