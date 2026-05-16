package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/pridhvi/nox/internal/models"
	"github.com/pridhvi/nox/internal/state"
)

func Alert(ctx context.Context, store *state.Store, config models.MonitorConfig, changes []models.SurfaceChange) error {
	selected := alertableChanges(config.AlertOn, changes)
	if len(selected) == 0 {
		return nil
	}
	message := fmt.Sprintf("Nox monitor %q observed %d attack-surface change(s).", config.Name, len(selected))
	if config.NotificationConfig.SlackWebhookURL != "" {
		if err := postWebhook(ctx, config.NotificationConfig.SlackWebhookURL, map[string]string{"text": message}); err != nil {
			return err
		}
	}
	if config.NotificationConfig.DiscordWebhookURL != "" {
		if err := postWebhook(ctx, config.NotificationConfig.DiscordWebhookURL, map[string]string{"content": message}); err != nil {
			return err
		}
	}
	if config.NotificationConfig.SlackWebhookURL == "" && config.NotificationConfig.DiscordWebhookURL == "" {
		return nil
	}
	for _, change := range selected {
		if err := store.MarkSurfaceChangeAlerted(ctx, change.ID); err != nil {
			return err
		}
	}
	return nil
}

func alertableChanges(triggers []string, changes []models.SurfaceChange) []models.SurfaceChange {
	if len(triggers) == 0 {
		return nil
	}
	triggerSet := map[string]bool{}
	for _, trigger := range triggers {
		trigger = strings.TrimSpace(trigger)
		if trigger != "" {
			triggerSet[trigger] = true
		}
	}
	var selected []models.SurfaceChange
	for _, change := range changes {
		if triggerSet["any"] || triggerSet[string(change.ChangeType)] || (change.ChangeType == models.SurfaceChangeNewFinding && severityRank(change.Severity) >= severityRank(models.SeverityHigh)) {
			selected = append(selected, change)
		}
	}
	return selected
}

func postWebhook(ctx context.Context, webhookURL string, payload map[string]string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}
