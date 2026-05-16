package creds

import (
	"context"
	"strings"
	"time"

	"github.com/pridhvi/nox/internal/db"
	"github.com/pridhvi/nox/internal/models"
)

type TestRequest struct {
	Mode     string `json:"mode"`
	Username string `json:"username"`
	Password string `json:"password"`
	Service  string `json:"service"`
	URL      string `json:"url"`
}

func Run(ctx context.Context, store *db.Store, sessionID string, req TestRequest) ([]models.CredentialFinding, error) {
	mode := strings.TrimSpace(req.Mode)
	if mode == "" {
		mode = "correlate"
	}
	if req.Service == "" {
		req.Service = "web"
	}
	now := time.Now().UTC()
	credential := models.CredentialFinding{
		ID:             models.NewID(),
		SessionID:      sessionID,
		CredentialType: mode,
		Username:       strings.TrimSpace(req.Username),
		Password:       strings.TrimSpace(req.Password),
		Service:        req.Service,
		URL:            strings.TrimSpace(req.URL),
		Valid:          false,
		Evidence:       "Credential test request recorded. Automated login attempts are intentionally disabled unless a fixture-safe adapter is selected.",
		CreatedAt:      now,
	}
	if credential.Username == "" && credential.Password == "" {
		credential.Username = "candidate"
		credential.Password = "********"
		credential.Evidence = "No explicit credential supplied; recorded a redacted candidate for operator review."
	}
	if err := store.InsertCredentialFinding(ctx, credential); err != nil {
		return nil, err
	}
	return store.ListCredentialFindings(ctx, sessionID, db.CredentialFilter{})
}

func RedactAll(credentials []models.CredentialFinding, plaintext bool) []models.CredentialFinding {
	if plaintext {
		return credentials
	}
	out := make([]models.CredentialFinding, 0, len(credentials))
	for _, credential := range credentials {
		out = append(out, credential.Redacted())
	}
	return out
}
