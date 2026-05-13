package models

import "time"

type AttackVector struct {
	ID               string       `json:"id"`
	SessionID        string       `json:"session_id"`
	Title            string       `json:"title"`
	Description      string       `json:"description"`
	Narrative        string       `json:"narrative"`
	OWASPCategory    string       `json:"owasp_category"`
	Severity         Severity     `json:"severity"`
	Confidence       float64      `json:"confidence"`
	Steps            []AttackStep `json:"steps"`
	PrereqFindingIDs []string     `json:"prereq_finding_ids"`
	LLMReviewed      bool         `json:"llm_reviewed"`
	LLMNotes         string       `json:"llm_notes"`
	CreatedAt        time.Time    `json:"created_at"`
}

type AttackStep struct {
	Order         int    `json:"order"`
	Description   string `json:"description"`
	FindingID     string `json:"finding_id,omitempty"`
	ToolSuggested string `json:"tool_suggested,omitempty"`
}
