package models

import "time"

type PluginRecord struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Binary    string    `json:"binary"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
