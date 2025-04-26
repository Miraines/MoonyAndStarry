CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
                       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                       email VARCHAR(255) NOT NULL UNIQUE,
                       username VARCHAR(100) NOT NULL UNIQUE,
                       password_hash VARCHAR(255) NOT NULL,
                       first_name VARCHAR(100) NOT NULL,
                       last_name VARCHAR(100) NOT NULL,
                       gender VARCHAR(10) NOT NULL
                           CHECK (gender IN ('male','female','other')),
                       date_of_birth DATE,
                       profile_photo_url VARCHAR(500),
                       bio TEXT,
                       timezone VARCHAR(100) NOT NULL,
                       settings JSONB NOT NULL DEFAULT '{}'::jsonb,
                       created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                       updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
