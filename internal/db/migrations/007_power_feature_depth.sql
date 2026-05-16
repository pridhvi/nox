CREATE TABLE provider_statuses (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    provider    TEXT NOT NULL,
    module      TEXT NOT NULL,
    status      TEXT NOT NULL,
    message     TEXT NOT NULL DEFAULT '',
    metadata    TEXT NOT NULL DEFAULT '{}',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_provider_statuses_session ON provider_statuses(session_id, created_at DESC);
CREATE INDEX idx_provider_statuses_provider ON provider_statuses(session_id, provider);

CREATE TABLE power_callbacks (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    finding_id  TEXT REFERENCES findings(id) ON DELETE SET NULL,
    provider    TEXT NOT NULL,
    token       TEXT NOT NULL,
    url         TEXT NOT NULL DEFAULT '',
    source_ip   TEXT NOT NULL DEFAULT '',
    raw_event   TEXT NOT NULL DEFAULT '',
    received    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_power_callbacks_session ON power_callbacks(session_id, created_at DESC);
CREATE INDEX idx_power_callbacks_token ON power_callbacks(token);
CREATE INDEX idx_power_callbacks_finding ON power_callbacks(finding_id);
