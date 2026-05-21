package monitor

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/pridhvi/nyx/internal/models"
	"github.com/pridhvi/nyx/internal/state"
)

func TestSchedulerStartRunsOneCatchUpForOverdueConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store, err := state.Open(ctx, filepath.Join(t.TempDir(), "nyx-state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Now().UTC()
	past := now.Add(-48 * time.Hour)
	future := now.Add(24 * time.Hour)
	configs := []models.MonitorConfig{
		{
			ID:          "overdue",
			Name:        "overdue",
			TargetInput: "https://example.test",
			Schedule:    "@daily",
			NextRunAt:   &past,
			Enabled:     true,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          "future",
			Name:        "future",
			TargetInput: "https://future.example.test",
			Schedule:    "@daily",
			NextRunAt:   &future,
			Enabled:     true,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          "disabled",
			Name:        "disabled",
			TargetInput: "https://disabled.example.test",
			Schedule:    "@daily",
			NextRunAt:   &past,
			Enabled:     false,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}
	for _, config := range configs {
		if err := store.UpsertMonitorConfig(ctx, config); err != nil {
			t.Fatal(err)
		}
	}

	calls := make(chan string, 4)
	scheduler := NewScheduler(store, t.TempDir(), nil)
	scheduler.runNow = func(ctx context.Context, configID string) (models.MonitorRun, []models.SurfaceChange, error) {
		calls <- configID
		completed := time.Now().UTC()
		next, err := NextRun("@daily", completed)
		if err != nil {
			return models.MonitorRun{}, nil, err
		}
		_ = store.UpdateMonitorRunMetadata(ctx, configID, "", &completed, &next)
		return models.MonitorRun{ID: "run-" + configID, ConfigID: configID, Status: models.MonitorRunStatusCompleted, StartedAt: completed, CompletedAt: &completed}, nil, nil
	}

	if err := scheduler.Start(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-calls:
		if got != "overdue" {
			t.Fatalf("expected overdue catch-up, got %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("expected overdue monitor catch-up run")
	}
	select {
	case got := <-calls:
		t.Fatalf("expected exactly one catch-up run, got extra %q", got)
	case <-time.After(150 * time.Millisecond):
	}
	updated, err := store.GetMonitorConfig(ctx, "overdue")
	if err != nil {
		t.Fatal(err)
	}
	if updated.NextRunAt == nil || !updated.NextRunAt.After(now) {
		t.Fatalf("expected overdue monitor next run to move into the future, got %#v", updated.NextRunAt)
	}
}
