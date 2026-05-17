package monitor

import (
	"context"
	"log/slog"
	"sync"

	"github.com/pridhvi/nyx/internal/adapters"
	"github.com/pridhvi/nyx/internal/models"
	"github.com/pridhvi/nyx/internal/state"
	"github.com/robfig/cron/v3"
)

type Scheduler struct {
	store      *state.Store
	sessionDir string
	httpClient adapters.HTTPDoer
	cron       *cron.Cron
	mu         sync.Mutex
	stopOnce   sync.Once
	jobs       map[string]cron.EntryID
}

func NewScheduler(store *state.Store, sessionDir string, httpClient adapters.HTTPDoer) *Scheduler {
	return &Scheduler{
		store:      store,
		sessionDir: sessionDir,
		httpClient: httpClient,
		cron:       cron.New(cron.WithParser(cronParser)),
		jobs:       map[string]cron.EntryID{},
	}
}

func (s *Scheduler) Start(ctx context.Context) error {
	if err := s.Reload(ctx); err != nil {
		return err
	}
	s.cron.Start()
	go func() {
		<-ctx.Done()
		stopCtx := s.cron.Stop()
		<-stopCtx.Done()
	}()
	return nil
}

func (s *Scheduler) Stop() {
	s.stopOnce.Do(func() {
		stopCtx := s.cron.Stop()
		<-stopCtx.Done()
	})
}

func (s *Scheduler) Reload(ctx context.Context) error {
	configs, err := s.store.ListMonitorConfigs(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range s.jobs {
		s.cron.Remove(id)
	}
	s.jobs = map[string]cron.EntryID{}
	for _, config := range configs {
		if !config.Enabled {
			continue
		}
		config := config
		entryID, err := s.cron.AddFunc(config.Schedule, func() {
			s.runScheduled(config.ID)
		})
		if err != nil {
			slog.Warn("schedule monitor config", "config_id", config.ID, "error", err)
			continue
		}
		s.jobs[config.ID] = entryID
		if entry := s.cron.Entry(entryID); !entry.Next.IsZero() {
			_ = s.store.UpdateMonitorRunMetadata(context.Background(), config.ID, "", nil, &entry.Next)
		}
	}
	return nil
}

func (s *Scheduler) runScheduled(configID string) {
	ctx := context.Background()
	runner := Runner{State: s.store, SessionDir: s.sessionDir, HTTPClient: s.httpClient}
	run, changes, err := runner.RunNow(ctx, configID)
	if err != nil {
		slog.Warn("scheduled monitor run failed", "config_id", configID, "run_id", run.ID, "error", err)
		return
	}
	config, err := s.store.GetMonitorConfig(ctx, configID)
	if err != nil {
		slog.Warn("load monitor config for alerts", "config_id", configID, "error", err)
		return
	}
	if err := Alert(ctx, s.store, config, changes); err != nil {
		slog.Warn("monitor alert dispatch failed", "config_id", configID, "error", err)
	}
}

func RedactConfigs(configs []models.MonitorConfig) []models.MonitorConfig {
	out := make([]models.MonitorConfig, 0, len(configs))
	for _, config := range configs {
		out = append(out, config.Redacted())
	}
	return out
}
