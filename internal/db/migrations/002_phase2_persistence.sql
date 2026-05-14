ALTER TABLE cve_matches ADD COLUMN affected_version TEXT NOT NULL DEFAULT '';
ALTER TABLE cve_matches ADD COLUMN fixed_version TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_cve_technology ON cve_matches(technology_id);

CREATE TABLE plugins (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    binary     TEXT NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX idx_plugins_name ON plugins(name);

