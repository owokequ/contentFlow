ALTER TABLE auth_sessions ADD COLUMN client_type VARCHAR(10) NOT NULL DEFAULT 'API';
ALTER TABLE auth_sessions ADD CONSTRAINT ck_auth_sessions_client_type CHECK (client_type IN ('WEB', 'API'));
UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE revoked_at IS NULL;

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES auth_sessions(id),
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    CONSTRAINT ck_refresh_tokens_expiration CHECK (expires_at > created_at),
    CONSTRAINT ck_refresh_tokens_used_at CHECK (used_at IS NULL OR used_at >= created_at)
);
CREATE INDEX ix_refresh_tokens_session_id ON refresh_tokens(session_id);
