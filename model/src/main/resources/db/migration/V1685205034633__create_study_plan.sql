CREATE TABLE IF NOT EXISTS ai_study_tutor.plan_detail
(
    id               UUID         NOT NULL DEFAULT uuid_generate_v4(),
    plan_instruction VARCHAR(255) NOT NULL,
    prompt           VARCHAR(255) NOT NULL,
    plan_id          UUID         NOT NULL UNIQUE,
    FOREIGN KEY (plan_id)
        REFERENCES ai_study_tutor.plan (id),
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS ai_study_tutor.study_material
(
    id           UUID         NOT NULL DEFAULT uuid_generate_v4(),
    name         VARCHAR(255) NOT NULL,
    s3_key       int          NOT NULL,
    original_url VARCHAR(255) NOT NULL,
    type         VARCHAR(16)  NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS ai_study_tutor.study_material_summary
(
    id                UUID         NOT NULL DEFAULT uuid_generate_v4(),
    summary           VARCHAR(255) NOT NULL,
    study_material_id UUID         NOT NULL UNIQUE,
    FOREIGN KEY (study_material_id)
        REFERENCES ai_study_tutor.study_material (id),
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS ai_study_tutor.plan_detail_study_material
(
    id                UUID NOT NULL DEFAULT uuid_generate_v4(),
    plan_detail_id    UUID NOT NULL UNIQUE,
    study_material_id UUID NOT NULL UNIQUE,
    FOREIGN KEY (study_material_id)
        REFERENCES ai_study_tutor.study_material (id),
    FOREIGN KEY (plan_detail_id)
        REFERENCES ai_study_tutor.plan_detail (id),
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS ai_study_tutor.plan_detail_study_material
(
    id                UUID NOT NULL DEFAULT uuid_generate_v4(),
    plan_detail_id    UUID NOT NULL UNIQUE,
    study_material_id UUID NOT NULL UNIQUE,
    FOREIGN KEY (study_material_id)
        REFERENCES ai_study_tutor.study_material (id),
    FOREIGN KEY (plan_detail_id)
        REFERENCES ai_study_tutor.plan_detail (id),
    PRIMARY KEY (id)
);


CREATE TABLE IF NOT EXISTS ai_study_tutor.plan_detail_study_material
(
    id                UUID NOT NULL DEFAULT uuid_generate_v4(),
    plan_detail_id    UUID NOT NULL UNIQUE,
    study_material_id UUID NOT NULL UNIQUE,
    FOREIGN KEY (study_material_id)
        REFERENCES ai_study_tutor.study_material (id),
    FOREIGN KEY (plan_detail_id)
        REFERENCES ai_study_tutor.plan_detail (id),
    PRIMARY KEY (id)
);
