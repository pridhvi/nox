CREATE TABLE tool_runs_new (
    id             TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    target_id      TEXT REFERENCES targets(id) ON DELETE SET NULL,
    tool_id        TEXT NOT NULL,
    args           TEXT NOT NULL DEFAULT '[]',
    stdout_path    TEXT NOT NULL DEFAULT '',
    stderr_path    TEXT NOT NULL DEFAULT '',
    exit_code      INTEGER NOT NULL DEFAULT 0,
    duration_ms    INTEGER NOT NULL DEFAULT 0,
    finding_count  INTEGER NOT NULL DEFAULT 0,
    normalized_at  DATETIME,
    started_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO tool_runs_new (
    id, session_id, target_id, tool_id, args, stdout_path, stderr_path,
    exit_code, duration_ms, finding_count, normalized_at, started_at
)
SELECT
    id, session_id, target_id, tool_id, args, '', '',
    exit_code, duration_ms, finding_count, normalized_at, started_at
FROM tool_runs;

DROP TABLE tool_runs;
ALTER TABLE tool_runs_new RENAME TO tool_runs;
CREATE INDEX idx_tool_runs_session ON tool_runs(session_id);
