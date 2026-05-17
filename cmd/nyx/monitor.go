package nyx

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/models"
	"github.com/pridhvi/nyx/internal/monitor"
	"github.com/pridhvi/nyx/internal/state"
)

func runMonitor(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("supported monitor commands: create, list, enable, disable, run, changes, delete")
	}
	switch args[0] {
	case "create":
		return monitorCreate(args[1:])
	case "list":
		return monitorList(args[1:])
	case "enable":
		return monitorSetEnabled(args[1:], true)
	case "disable":
		return monitorSetEnabled(args[1:], false)
	case "run":
		return monitorRun(args[1:])
	case "changes":
		return monitorChanges(args[1:])
	case "delete":
		return monitorDelete(args[1:])
	default:
		return fmt.Errorf("supported monitor commands: create, list, enable, disable, run, changes, delete")
	}
}

func monitorCreate(args []string) error {
	fs := flag.NewFlagSet("monitor create", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path")
	target := fs.String("target", "", "target host, URL, or CIDR")
	name := fs.String("name", "", "monitor name")
	schedule := fs.String("schedule", "@daily", "cron schedule or descriptor such as @hourly, @daily, @weekly")
	outOfScope := fs.String("out-of-scope", "", "comma-separated hosts or CIDRs to exclude")
	phases := fs.String("phases", "", "comma-separated scan phases")
	tools := fs.String("tools", "", "comma-separated tool ids")
	alertOn := fs.String("alert-on", "", "comma-separated change types to alert on, or any")
	slackWebhook := fs.String("slack-webhook", "", "Slack webhook URL")
	discordWebhook := fs.String("discord-webhook", "", "Discord webhook URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	config, err := monitor.NormalizeConfig(models.MonitorConfig{
		ID:            models.NewID(),
		Name:          *name,
		TargetInput:   *target,
		OutOfScope:    splitCSV(*outOfScope),
		Schedule:      *schedule,
		EnabledPhases: splitCSV(*phases),
		EnabledTools:  splitCSV(*tools),
		AlertOn:       splitCSV(*alertOn),
		NotificationConfig: models.MonitorNotificationConfig{
			SlackWebhookURL:   strings.TrimSpace(*slackWebhook),
			DiscordWebhookURL: strings.TrimSpace(*discordWebhook),
		},
		Enabled: true,
	}, now)
	if err != nil {
		return err
	}
	if err := monitor.ValidateAlertTriggers(config.AlertOn); err != nil {
		return err
	}
	store, err := openMonitorState(context.Background(), cfg.Database.SessionDir)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.UpsertMonitorConfig(context.Background(), config); err != nil {
		return err
	}
	fmt.Printf("created monitor %s for %s\n", config.ID, config.TargetInput)
	fmt.Printf("schedule: %s\n", config.Schedule)
	if config.NextRunAt != nil {
		fmt.Printf("next run: %s\n", config.NextRunAt.Format(time.RFC3339))
	}
	return nil
}

func monitorList(args []string) error {
	fs := flag.NewFlagSet("monitor list", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	store, err := openMonitorState(context.Background(), cfg.Database.SessionDir)
	if err != nil {
		return err
	}
	defer store.Close()
	configs, err := store.ListMonitorConfigs(context.Background())
	if err != nil {
		return err
	}
	if len(configs) == 0 {
		fmt.Println("no monitors found")
		return nil
	}
	for _, config := range configs {
		state := "disabled"
		if config.Enabled {
			state = "enabled"
		}
		next := "-"
		if config.NextRunAt != nil {
			next = config.NextRunAt.Format(time.RFC3339)
		}
		fmt.Printf("%s\t%s\t%s\t%s\tnext=%s\tbaseline=%s\n", config.ID, state, config.Schedule, config.TargetInput, next, config.BaselineSessionID)
	}
	return nil
}

func monitorSetEnabled(args []string, enabled bool) error {
	if len(args) == 0 {
		return fmt.Errorf("monitor %s requires a config id", map[bool]string{true: "enable", false: "disable"}[enabled])
	}
	fs := flag.NewFlagSet("monitor enable/disable", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	store, err := openMonitorState(context.Background(), cfg.Database.SessionDir)
	if err != nil {
		return err
	}
	defer store.Close()
	config, err := store.GetMonitorConfig(context.Background(), args[0])
	if err != nil {
		return err
	}
	var next *time.Time
	if enabled {
		value, err := monitor.NextRun(config.Schedule, time.Now().UTC())
		if err != nil {
			return err
		}
		next = &value
	}
	if err := store.UpdateMonitorEnabled(context.Background(), args[0], enabled, next); err != nil {
		return err
	}
	fmt.Printf("monitor %s %s\n", args[0], map[bool]string{true: "enabled", false: "disabled"}[enabled])
	return nil
}

func monitorRun(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("monitor run requires a config id")
	}
	fs := flag.NewFlagSet("monitor run", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	store, err := openMonitorState(context.Background(), cfg.Database.SessionDir)
	if err != nil {
		return err
	}
	defer store.Close()
	runner := monitor.Runner{State: store, SessionDir: firstNonEmpty(cfg.Database.SessionDir, db.DefaultSessionsDir())}
	run, changes, err := runner.RunNow(context.Background(), args[0])
	fmt.Printf("created monitor run %s\n", run.ID)
	if run.SessionID != "" {
		fmt.Printf("session: %s\n", run.SessionID)
	}
	fmt.Printf("changes: %d\n", len(changes))
	if err != nil {
		return err
	}
	for _, change := range changes {
		fmt.Printf("%s\t%s\t%s\n", change.Severity, change.ChangeType, change.Description)
	}
	return nil
}

func monitorChanges(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("monitor changes requires a config id")
	}
	fs := flag.NewFlagSet("monitor changes", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	store, err := openMonitorState(context.Background(), cfg.Database.SessionDir)
	if err != nil {
		return err
	}
	defer store.Close()
	changes, err := store.ListSurfaceChangesByConfig(context.Background(), args[0])
	if err != nil {
		return err
	}
	if len(changes) == 0 {
		fmt.Println("no changes found")
		return nil
	}
	for _, change := range changes {
		fmt.Printf("%s\t%s\t%s\t%s\n", change.CreatedAt.Format(time.RFC3339), change.Severity, change.ChangeType, change.Description)
	}
	return nil
}

func monitorDelete(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("monitor delete requires a config id")
	}
	fs := flag.NewFlagSet("monitor delete", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	store, err := openMonitorState(context.Background(), cfg.Database.SessionDir)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.DeleteMonitorConfig(context.Background(), args[0]); err != nil {
		return err
	}
	fmt.Printf("deleted monitor %s\n", args[0])
	return nil
}

func openMonitorState(ctx context.Context, sessionDir string) (*state.Store, error) {
	if strings.TrimSpace(sessionDir) == "" {
		sessionDir = db.DefaultSessionsDir()
	}
	sessionDir = filepath.Clean(sessionDir)
	stateDir := sessionDir
	if filepath.Base(sessionDir) == "sessions" {
		stateDir = filepath.Dir(sessionDir)
	}
	return state.Open(ctx, state.DBPath(stateDir))
}
