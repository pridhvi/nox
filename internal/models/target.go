package models

import "time"

type Target struct {
	ID           string       `json:"id"`
	SessionID    string       `json:"session_id"`
	Host         string       `json:"host"`
	IP           string       `json:"ip"`
	Port         int          `json:"port"`
	Protocol     string       `json:"protocol"`
	IsAlive      bool         `json:"is_alive"`
	Technologies []Technology `json:"technologies,omitempty"`
	Findings     []Finding    `json:"findings,omitempty"`
	DiscoveredBy string       `json:"discovered_by"`
	CreatedAt    time.Time    `json:"created_at"`
}

type Technology struct {
	ID         string  `json:"id"`
	TargetID   string  `json:"target_id"`
	Name       string  `json:"name"`
	Version    string  `json:"version"`
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
	SourceTool string  `json:"source_tool"`
}
