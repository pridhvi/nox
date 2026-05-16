package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	appconfig "github.com/pridhvi/nox/internal/config"
	"github.com/pridhvi/nox/internal/db"
	"github.com/pridhvi/nox/internal/models"
)

type RunRequest struct {
	Providers   []string `json:"providers"`
	ConfirmSeed bool     `json:"confirm_seed"`
}

func Run(ctx context.Context, store *db.Store, session models.Session, req RunRequest) ([]models.OSINTFinding, error) {
	return RunWithConfig(ctx, store, session, req, appconfig.PowerConfig{}, nil)
}

func RunWithConfig(ctx context.Context, store *db.Store, session models.Session, req RunRequest, cfg appconfig.PowerConfig, client interface {
	Do(*http.Request) (*http.Response, error)
}) ([]models.OSINTFinding, error) {
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
		runProviders(ctx, store, session, req, cfg, client, now)
	}
	return store.ListOSINTFindings(ctx, session.ID, db.OSINTFilter{})
}

func runProviders(ctx context.Context, store *db.Store, session models.Session, req RunRequest, cfg appconfig.PowerConfig, client interface {
	Do(*http.Request) (*http.Response, error)
}, now time.Time) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	for _, provider := range req.Providers {
		provider = strings.ToLower(strings.TrimSpace(provider))
		if provider == "" {
			continue
		}
		switch provider {
		case "github":
			if cfg.Providers.GitHubToken == "" {
				recordProvider(ctx, store, session.ID, "osint", provider, "skipped", "GitHub token is not configured", nil, now)
				continue
			}
			runGitHub(ctx, store, session, client, cfg.Providers.GitHubToken, now)
		case "shodan":
			if cfg.Providers.ShodanAPIKey == "" {
				recordProvider(ctx, store, session.ID, "osint", provider, "skipped", "Shodan API key is not configured", nil, now)
				continue
			}
			runShodan(ctx, store, session, client, cfg.Providers.ShodanAPIKey, now)
		case "securitytrails", "passivedns":
			if cfg.Providers.SecurityTrailsAPIKey == "" {
				recordProvider(ctx, store, session.ID, "osint", provider, "skipped", "SecurityTrails API key is not configured", nil, now)
				continue
			}
			recordProvider(ctx, store, session.ID, "osint", provider, "configured", "Provider key configured; passive DNS collection is ready for a targeted run", nil, now)
		default:
			recordProvider(ctx, store, session.ID, "osint", provider, "skipped", "Unknown optional provider", nil, now)
		}
	}
}

func runGitHub(ctx context.Context, store *db.Store, session models.Session, client interface {
	Do(*http.Request) (*http.Response, error)
}, token string, now time.Time) {
	domain := first(candidateDomains(session, nil))
	if domain == "" {
		recordProvider(ctx, store, session.ID, "osint", "github", "skipped", "No domain available for GitHub search", nil, now)
		return
	}
	endpoint := "https://api.github.com/search/code?q=" + url.QueryEscape(domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		recordProvider(ctx, store, session.ID, "osint", "github", "failed", err.Error(), nil, now)
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		recordProvider(ctx, store, session.ID, "osint", "github", "failed", err.Error(), nil, now)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var parsed struct {
		TotalCount int `json:"total_count"`
	}
	_ = json.Unmarshal(body, &parsed)
	recordProvider(ctx, store, session.ID, "osint", "github", "completed", fmt.Sprintf("GitHub code search returned HTTP %d", resp.StatusCode), map[string]any{"total_count": parsed.TotalCount}, now)
	if parsed.TotalCount > 0 {
		_ = store.InsertOSINTFinding(ctx, models.OSINTFinding{ID: models.NewID(), SessionID: session.ID, Kind: "github_signal", Value: domain, Source: "github", Confidence: 0.45, Metadata: map[string]any{"total_count": parsed.TotalCount}, CreatedAt: now})
	}
}

func runShodan(ctx context.Context, store *db.Store, session models.Session, client interface {
	Do(*http.Request) (*http.Response, error)
}, apiKey string, now time.Time) {
	domain := first(candidateDomains(session, nil))
	if domain == "" {
		recordProvider(ctx, store, session.ID, "osint", "shodan", "skipped", "No domain available for Shodan lookup", nil, now)
		return
	}
	endpoint := "https://api.shodan.io/dns/domain/" + url.PathEscape(domain) + "?key=" + url.QueryEscape(apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		recordProvider(ctx, store, session.ID, "osint", "shodan", "failed", err.Error(), nil, now)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		recordProvider(ctx, store, session.ID, "osint", "shodan", "failed", err.Error(), nil, now)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	var parsed struct {
		Subdomains []string `json:"subdomains"`
	}
	_ = json.Unmarshal(body, &parsed)
	recordProvider(ctx, store, session.ID, "osint", "shodan", "completed", fmt.Sprintf("Shodan lookup returned HTTP %d", resp.StatusCode), map[string]any{"subdomain_count": len(parsed.Subdomains)}, now)
	for _, subdomain := range parsed.Subdomains {
		value := strings.Trim(strings.TrimSpace(subdomain)+"."+domain, ".")
		if value != "" {
			_ = store.InsertOSINTFinding(ctx, models.OSINTFinding{ID: models.NewID(), SessionID: session.ID, Kind: "domain", Value: value, Source: "shodan", Confidence: 0.65, Metadata: map[string]any{"seed_requires_confirmation": true}, CreatedAt: now})
		}
	}
}

func recordProvider(ctx context.Context, store *db.Store, sessionID, module, provider, status, message string, metadata map[string]any, now time.Time) {
	_ = store.InsertProviderStatus(ctx, models.ProviderStatus{
		ID:        models.NewID(),
		SessionID: sessionID,
		Provider:  provider,
		Module:    module,
		Status:    status,
		Message:   message,
		Metadata:  metadata,
		CreatedAt: now,
	})
	_ = store.InsertOSINTFinding(ctx, models.OSINTFinding{
		ID:         models.NewID(),
		SessionID:  sessionID,
		Kind:       "provider_status",
		Value:      provider,
		Source:     provider,
		Confidence: 1,
		Metadata:   map[string]any{"status": status, "message": message},
		CreatedAt:  now,
	})
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

func first(values []string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
