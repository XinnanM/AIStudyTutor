CREATE SCHEMA IF NOT EXISTS account_service;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";



CREATE TABLE IF NOT EXISTS account_service.users (
   id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
   username VARCHAR(50) UNIQUE NOT NULL,
   email VARCHAR(255) UNIQUE NOT NULL,
   password_hash VARCHAR(255) NOT NULL,
   first_name VARCHAR(100),
   last_name VARCHAR(100),
   date_of_birth DATE,
   gender VARCHAR(20),
   phone_number VARCHAR(20),
   address VARCHAR(255),
   created_at TIMESTAMP NOT NULL DEFAULT NOW(),
   updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE account_service.roles (
   id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
   name VARCHAR(50) UNIQUE NOT NULL
);

CREATE TABLE account_service.user_roles (
    user_id UUID NOT NULL,
    role_id UUID NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS account_service.token
(
    id UUID PRIMARY KEY,
    token VARCHAR(255) UNIQUE,
    token_type VARCHAR(255) NOT NULL DEFAULT 'BEARER',
    revoked BOOLEAN NOT NULL DEFAULT false,
    expired BOOLEAN NOT NULL DEFAULT false,
    user_id UUID,
    FOREIGN KEY (user_id) REFERENCES account_service.users(id)
);