package osint

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/pridhvi/nox/internal/db"
	"github.com/pridhvi/nox/internal/models"
)

type RunRequest struct {
	Providers []string `json:"providers"`
}

func Run(ctx context.Context, store *db.Store, session models.Session, req RunRequest) ([]models.OSINTFinding, error) {
	targets, err := store.ListTargets(ctx, session.ID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	seen := map[string]bool{}
	for _, value := range candidateDomains(session, targets) {
		if seen[value] {
			continue
		}
		seen[value] = true
		finding := models.OSINTFinding{
			ID:         models.NewID(),
			SessionID:  session.ID,
			Kind:       "domain",
			Value:      value,
			Source:     "nox-scope",
			Confidence: 0.8,
			Metadata:   map[string]any{"provider_status": "local_scope_seed"},
			CreatedAt:  now,
		}
		if err := store.InsertOSINTFinding(ctx, finding); err != nil {
			return nil, err
		}
	}
	if len(req.Providers) > 0 {
		for _, provider := range req.Providers {
			provider = strings.TrimSpace(provider)
			if provider == "" {
				continue
			}
			_ = store.InsertOSINTFinding(ctx, models.OSINTFinding{
				ID:         models.NewID(),
				SessionID:  session.ID,
				Kind:       "provider_status",
				Value:      provider,
				Source:     provider,
				Confidence: 1,
				Metadata:   map[string]any{"status": "not_configured_or_not_run_in_safe_slice"},
				CreatedAt:  now,
			})
		}
	}
	return store.ListOSINTFindings(ctx, session.ID, db.OSINTFilter{})
}

func candidateDomains(session models.Session, targets []models.Target) []string {
	var values []string
	for _, raw := range append([]string{session.TargetInput}, session.InScope...) {
		for _, part := range strings.Split(raw, ",") {
			value := host(part)
			if value != "" {
				values = append(values, value)
			}
		}
	}
	for _, target := range targets {
		if target.Host != "" {
			values = append(values, strings.ToLower(target.Host))
		}
	}
	return values
}

func host(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname())
	}
	raw = strings.TrimPrefix(raw, "*.")
	raw = strings.Trim(raw, "/")
	if strings.Contains(raw, " ") {
		return ""
	}
	return strings.ToLower(raw)
}
