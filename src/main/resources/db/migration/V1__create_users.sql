
CREATE TABLE users (
    id UUID primary key,
    email varchar(255) unique not null,
    password_hash varchar(255) not null,
    display_name varchar(100) not null,
    status varchar(20) not null default 'ACTIVE',

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT ck_users_email_normalized
    CHECK (email = LOWER(BTRIM(email))),

    CONSTRAINT ck_users_display_name
    CHECK (CHAR_LENGTH(BTRIM(display_name)) BETWEEN 2 AND 100),

    CONSTRAINT ck_users_status
    CHECK (status IN ('ACTIVE', 'DISABLED'))
);