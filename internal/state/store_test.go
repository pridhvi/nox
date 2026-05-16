package state

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/pridhvi/nox/internal/db"
	"github.com/pridhvi/nox/internal/models"
)

func TestMonitorConfigCRUDAndRedaction(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "nox-state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	config := models.MonitorConfig{
		ID:          models.NewID(),
		Name:        "fixture",
		TargetInput: "https://example.test",
		Schedule:    "@daily",
		Enabled:     true,
		NotificationConfig: models.MonitorNotificationConfig{
			SlackWebhookURL: "https://hooks.slack.test/secret",
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := store.UpsertMonitorConfig(ctx, config); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetMonitorConfig(ctx, config.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TargetInput != config.TargetInput || !got.Enabled {
		t.Fatalf("unexpected config: %#v", got)
	}
	if redacted := got.Redacted(); redacted.NotificationConfig.SlackWebhookURL != "********" {
		t.Fatalf("expected redacted webhook, got %#v", redacted.NotificationConfig)
	}
	if err := store.UpdateMonitorEnabled(ctx, config.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	got, err = store.GetMonitorConfig(ctx, config.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled {
		t.Fatalf("expected disabled monitor")
	}
	if err := store.DeleteMonitorConfig(ctx, config.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetMonitorConfig(ctx, config.ID); err != db.ErrNotFound {
		t.Fatalf("expected not found after delete, got %v", err)
	}
}

func TestMonitorRunsAndSurfaceChanges(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "nox-state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	config := models.MonitorConfig{ID: models.NewID(), Name: "fixture", TargetInput: "https://example.test", Schedule: "@daily", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := store.UpsertMonitorConfig(ctx, config); err != nil {
		t.Fatal(err)
	}
	run := models.MonitorRun{ID: models.NewID(), ConfigID: config.ID, SessionID: "session-1", Status: models.MonitorRunStatusCompleted, ChangesFound: true, StartedAt: now, CompletedAt: &now}
	if err := store.InsertMonitorRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	change := models.SurfaceChange{
		ID:           models.NewID(),
		MonitorRunID: run.ID,
		SessionID:    run.SessionID,
		ChangeType:   models.SurfaceChangeNewFinding,
		Severity:     models.SeverityHigh,
		Description:  "New finding",
		FindingID:    "finding-1",
		CreatedAt:    now,
	}
	if err := store.InsertSurfaceChange(ctx, change); err != nil {
		t.Fatal(err)
	}
	runs, err := store.ListMonitorRuns(ctx, MonitorRunFilter{ConfigID: config.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].ID != run.ID || !runs[0].ChangesFound {
		t.Fatalf("unexpected runs: %#v", runs)
	}
	changes, err := store.ListSurfaceChanges(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Severity != models.SeverityHigh {
		t.Fatalf("unexpected changes: %#v", changes)
	}
	if err := store.MarkSurfaceChangeAlerted(ctx, change.ID); err != nil {
		t.Fatal(err)
	}
	changes, err = store.ListSurfaceChangesByConfig(ctx, config.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || !changes[0].Alerted {
		t.Fatalf("expected alerted change, got %#v", changes)
	}
}
