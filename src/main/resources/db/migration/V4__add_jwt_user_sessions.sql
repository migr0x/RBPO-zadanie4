CREATE TABLE user_sessions (
    id UUID PRIMARY KEY,
    username VARCHAR(80) NOT NULL,
    device_id TEXT,
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    access_token_expiry TIMESTAMP WITH TIME ZONE NOT NULL,
    refresh_token_expiry TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(20) NOT NULL,
    CONSTRAINT uq_user_sessions_refresh_token UNIQUE (refresh_token),
    CONSTRAINT chk_user_sessions_status CHECK (status IN ('ACTIVE', 'USED', 'REVOKED')),
    CONSTRAINT chk_user_sessions_username CHECK (length(trim(username)) > 0)
);

CREATE INDEX idx_user_sessions_username ON user_sessions (username);

-- Flyway uses the application's datasource role (see db/init/10-create-app-user.sh).
-- This role owns the table and also receives the required privileges explicitly.
GRANT SELECT, INSERT, UPDATE ON TABLE user_sessions TO CURRENT_USER;
