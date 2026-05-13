package models

import "time"

type SessionStatus string

const (
	SessionStatusPending   SessionStatus = "pending"
	SessionStatusRunning   SessionStatus = "running"
	SessionStatusCompleted SessionStatus = "completed"
	SessionStatusFailed    SessionStatus = "failed"
	SessionStatusCancelled SessionStatus = "cancelled"
)

type ScanMode string

const (
	ScanModePassive ScanMode = "passive"
	ScanModeActive  ScanMode = "active"
	ScanModeStealth ScanMode = "stealth"
)

type Session struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	Status        SessionStatus `json:"status"`
	Mode          ScanMode      `json:"mode"`
	TargetInput   string        `json:"target_input"`
	InScope       []string      `json:"in_scope"`
	OutOfScope    []string      `json:"out_of_scope"`
	EnabledPhases []string      `json:"enabled_phases"`
	LLMModel      string        `json:"llm_model"`
	LLMBaseURL    string        `json:"llm_base_url"`
	TargetCount   int           `json:"target_count"`
	FindingCount  int           `json:"finding_count"`
	StartedAt     *time.Time    `json:"started_at,omitempty"`
	CompletedAt   *time.Time    `json:"completed_at,omitempty"`
	CreatedAt     time.Time     `json:"created_at"`
}
