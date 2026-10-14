ALTER TABLE users ADD COLUMN version BIGINT NOT NULL DEFAULT 0;

CREATE INDEX ix_auth_sessions_user_id ON auth_sessions(user_id);
