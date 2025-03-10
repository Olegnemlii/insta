CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    is_confirmed BOOLEAN DEFAULT false
);

CREATE TABLE IF NOT EXISTS tokens (
    id SERIAL PRIMARY KEY,
    access_token VARCHAR NOT NULL,
    refresh_token VARCHAR NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS codes_signatures (
    code UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    signature UUID NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id),
    is_used BOOLEAN DEFAULT false,
    expires_at TIMESTAMPTZ NOT NULL
);