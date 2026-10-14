
CREATE TABLE auth_sessions (
    id UUID PRIMARY KEY,
    user_id UUID not null REFERENCES users(id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,

    CONSTRAINT ck_auth_sessions_expiration
    CHECK (expires_at > created_at)
);