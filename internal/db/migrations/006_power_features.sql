CREATE TABLE payloads (
    id                 TEXT PRIMARY KEY,
    finding_id         TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    session_id         TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    payload_type       TEXT NOT NULL,
    payload            TEXT NOT NULL,
    context            TEXT NOT NULL DEFAULT '',
    target_waf         TEXT NOT NULL DEFAULT '',
    target_db          TEXT NOT NULL DEFAULT '',
    bypass_technique   TEXT NOT NULL DEFAULT '',
    confidence         REAL NOT NULL DEFAULT 0.0,
    validated          BOOLEAN NOT NULL DEFAULT FALSE,
    validated_response TEXT NOT NULL DEFAULT '',
    rank               INTEGER NOT NULL DEFAULT 0,
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_payloads_finding ON payloads(finding_id);
CREATE INDEX idx_payloads_session ON payloads(session_id);
CREATE INDEX idx_payloads_session_type ON payloads(session_id, payload_type);

CREATE TABLE credential_findings (
    id               TEXT PRIMARY KEY,
    session_id       TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    target_id        TEXT REFERENCES targets(id) ON DELETE SET NULL,
    finding_id       TEXT REFERENCES findings(id) ON DELETE SET NULL,
    credential_type  TEXT NOT NULL,
    username         TEXT NOT NULL DEFAULT '',
    password         TEXT NOT NULL DEFAULT '',
    service          TEXT NOT NULL DEFAULT '',
    url              TEXT NOT NULL DEFAULT '',
    valid            BOOLEAN NOT NULL DEFAULT FALSE,
    lockout_detected BOOLEAN NOT NULL DEFAULT FALSE,
    evidence         TEXT NOT NULL DEFAULT '',
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_credential_findings_session ON credential_findings(session_id);
CREATE INDEX idx_credential_findings_target ON credential_findings(target_id);
CREATE INDEX idx_credential_findings_valid ON credential_findings(valid);
CREATE INDEX idx_credential_findings_type ON credential_findings(credential_type);

CREATE TABLE osint_findings (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    value       TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL DEFAULT '',
    confidence  REAL NOT NULL DEFAULT 0.0,
    target_id   TEXT REFERENCES targets(id) ON DELETE SET NULL,
    metadata    TEXT NOT NULL DEFAULT '{}',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_osint_findings_session ON osint_findings(session_id);
CREATE INDEX idx_osint_findings_kind ON osint_findings(kind);
CREATE INDEX idx_osint_findings_source ON osint_findings(source);

CREATE TABLE ad_entities (
    id                  TEXT PRIMARY KEY,
    session_id          TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    entity_type         TEXT NOT NULL,
    name                TEXT NOT NULL DEFAULT '',
    domain              TEXT NOT NULL DEFAULT '',
    sid                 TEXT NOT NULL DEFAULT '',
    distinguished_name  TEXT NOT NULL DEFAULT '',
    metadata            TEXT NOT NULL DEFAULT '{}',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_ad_entities_session ON ad_entities(session_id);
CREATE INDEX idx_ad_entities_type ON ad_entities(session_id, entity_type);
CREATE INDEX idx_ad_entities_name ON ad_entities(session_id, name);

CREATE TABLE ad_relationships (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    from_entity_id  TEXT NOT NULL REFERENCES ad_entities(id) ON DELETE CASCADE,
    to_entity_id    TEXT NOT NULL REFERENCES ad_entities(id) ON DELETE CASCADE,
    relation        TEXT NOT NULL,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_ad_relationships_session ON ad_relationships(session_id);
CREATE INDEX idx_ad_relationships_from ON ad_relationships(session_id, from_entity_id);
CREATE INDEX idx_ad_relationships_to ON ad_relationships(session_id, to_entity_id);

CREATE TABLE ad_artifacts (
    id             TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    artifact_type  TEXT NOT NULL,
    path           TEXT NOT NULL DEFAULT '',
    summary        TEXT NOT NULL DEFAULT '',
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_ad_artifacts_session ON ad_artifacts(session_id);

CREATE TABLE block_events (
    id               TEXT PRIMARY KEY,
    session_id        TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    target_id         TEXT REFERENCES targets(id) ON DELETE SET NULL,
    tool_id           TEXT NOT NULL DEFAULT '',
    url               TEXT NOT NULL DEFAULT '',
    status_code       INTEGER NOT NULL DEFAULT 0,
    signal            TEXT NOT NULL DEFAULT '',
    response_snippet  TEXT NOT NULL DEFAULT '',
    backoff_ms        INTEGER NOT NULL DEFAULT 0,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_block_events_session ON block_events(session_id);
CREATE INDEX idx_block_events_target ON block_events(target_id);

CREATE TABLE poc_results (
    id                TEXT PRIMARY KEY,
    session_id        TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    finding_id        TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    target_id         TEXT REFERENCES targets(id) ON DELETE SET NULL,
    poc_type          TEXT NOT NULL,
    status            TEXT NOT NULL,
    payload_id        TEXT REFERENCES payloads(id) ON DELETE SET NULL,
    request_raw       TEXT NOT NULL DEFAULT '',
    response_raw      TEXT NOT NULL DEFAULT '',
    response_code     INTEGER NOT NULL DEFAULT 0,
    response_time_ms  INTEGER NOT NULL DEFAULT 0,
    evidence          TEXT NOT NULL DEFAULT '',
    canary_token      TEXT NOT NULL DEFAULT '',
    callback_received BOOLEAN NOT NULL DEFAULT FALSE,
    impact_narrative  TEXT NOT NULL DEFAULT '',
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at      DATETIME
);
CREATE INDEX idx_poc_results_session ON poc_results(session_id);
CREATE INDEX idx_poc_results_finding ON poc_results(finding_id);
CREATE INDEX idx_poc_results_status ON poc_results(status);
