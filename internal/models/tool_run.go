package models

import "time"

type ToolRun struct {
	ID           string     `json:"id"`
	SessionID    string     `json:"session_id"`
	TargetID     string     `json:"target_id,omitempty"`
	ToolID       string     `json:"tool_id"`
	Args         []string   `json:"args"`
	StdoutRaw    string     `json:"stdout_raw"`
	StderrRaw    string     `json:"stderr_raw"`
	ExitCode     int        `json:"exit_code"`
	DurationMS   int64      `json:"duration_ms"`
	FindingCount int        `json:"finding_count"`
	NormalizedAt *time.Time `json:"normalized_at,omitempty"`
	StartedAt    time.Time  `json:"started_at"`
}
