-- Включаем расширение pgcrypto для работы с UUID, если есть права
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- В некоторых окружениях функция gen_random_uuid недоступна,
-- поэтому идентификаторы будем задавать из приложения
CREATE TABLE users (
                       id UUID PRIMARY KEY,
                       email VARCHAR(255) NOT NULL UNIQUE,
                       username VARCHAR(100) NOT NULL UNIQUE,
                       password_hash VARCHAR(255) NOT NULL,
                       first_name VARCHAR(100),
                       last_name VARCHAR(100),
                       gender VARCHAR(10)
                           CHECK (gender IN ('male','female','other')),
                       date_of_birth DATE,
                       profile_photo_url VARCHAR(500),
                       bio TEXT,
                       timezone VARCHAR(100),
                       settings JSONB NOT NULL DEFAULT '{}'::jsonb,
                       created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                       updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
