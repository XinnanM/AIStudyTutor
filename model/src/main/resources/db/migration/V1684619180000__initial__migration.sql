CREATE SCHEMA IF NOT EXISTS ai_study_tutor;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";


CREATE TABLE IF NOT EXISTS ai_study_tutor.user (
    id UUID NOT NULL DEFAULT uuid_generate_v4(),
    username VARCHAR(16) NOT NULL,
    password VARCHAR(72) NOT NULL,
    first_name VARCHAR(16),
    last_name VARCHAR(16),
    email VARCHAR(24),
    phone VARCHAR(24),
    user_status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE',
    role VARCHAR(16) NOT NULL DEFAULT 'ROLE_USER',
    PRIMARY KEY(id)
);

CREATE TABLE IF NOT EXISTS ai_study_tutor.plan (
    id UUID NOT NULL DEFAULT uuid_generate_v4(),
    topic VARCHAR(255) NOT NULL,
    past_experience SMALLINT NOT NULL,
    study_depth SMALLINT NOT NULL,
    study_intensity SMALLINT NOT NULL,
    study_language SMALLINT NOT NULL,
    study_style SMALLINT NOT NULL,
    test_difficulty SMALLINT NOT NULL,
    user_id UUID NOT NULL UNIQUE,
    FOREIGN KEY(user_id)
    REFERENCES ai_study_tutor.user(id),
    PRIMARY KEY(id)
);