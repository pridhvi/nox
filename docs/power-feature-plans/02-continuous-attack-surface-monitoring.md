# Module 2 Implementation Plan: Continuous Attack Surface Monitoring

## Goal And Success Criteria

Current repository state: the first production slice is implemented. Nox now has
global monitor state in `<state-dir>/nox-state.db`, `nox monitor` CLI commands,
`/api/monitor/*` endpoints, scheduler registration during `nox serve`, immediate
monitor runs that create normal session directories, target/technology/finding
diffing into `surface_changes`, Slack/Discord webhook dispatch, and a `/monitor`
operator-console route. Remaining depth should focus on fixture-backed
integration assertions, richer edit forms, source-aware diffs, and additional
notification backends.

Add scheduled monitoring that reruns saved scan configurations, compares each
run against a baseline session, persists attack-surface changes, and optionally
sends alerts. This turns Nox into a recurring local monitoring tool without
changing normal point-in-time scan behavior.

Done means:

- Operators can create, list, update, run, enable, disable, and delete monitor
  configs.
- Immediate monitor runs create normal Nox sessions.
- Diff results are stored as `surface_changes`.
- Scheduled runs execute only when `nox serve` is running.
- Alerts are optional and disabled unless configured.

Out of scope:

- Hosted SaaS monitoring.
- Multi-user notification routing.
- Non-local queue workers.

## Safety Constraints

- Monitor configs are host-privileged global state and require configured API-key
  auth for API writes and manual run triggers.
- Scheduled scans must reuse existing scope validation and runner options.
- Default monitor phases are lightweight: recon and fingerprint.
- Alert secrets must never be returned in full through API responses.
- A failed scheduled run records status and error but does not stop the
  scheduler.

## Data Model And Global Store

Monitoring is cross-session state. Do not store monitor config in a session DB.
Create a global SQLite DB under `stateDir()`, for example
`<state-dir>/nox-state.db`, with its own migration runner.

Tables:

- `monitor_configs`
  - id, name, target_input, in_scope, out_of_scope, schedule, enabled_phases,
    enabled_tools, tool_parameters, runner_options, alert_on,
    notification_config, baseline_session_id, last_run_at, next_run_at,
    enabled, created_at, updated_at.
- `monitor_runs`
  - id, config_id, session_id, status, changes_found, error, started_at,
    completed_at.
- `surface_changes`
  - id, monitor_run_id, session_id, change_type, severity, description,
    previous_value, current_value, target_id, finding_id, alerted, created_at.

Add `internal/models/monitor.go` and `internal/state` or `internal/db/global`
for global-store access. Keep session DB store unchanged except for helper
methods needed by the differ.

## Backend Architecture

Create `internal/monitor`:

- `scheduler.go`: cron lifecycle and config registration.
- `runner.go`: creates pending session, invokes `ScanManager` or engine runner,
  waits for completion, then diffs.
- `differ.go`: compares baseline and current sessions.
- `alerter.go`: dispatches notifications.
- `notifiers/slack.go`, `discord.go`, `email.go`: optional notifiers.

Add dependency:

- `github.com/robfig/cron/v3`

Scheduler behavior:

- `nox serve` initializes global state DB and monitor scheduler.
- Scheduler loads enabled configs.
- Updating a config refreshes the scheduled job.
- Disabled configs are not scheduled.
- Immediate runs do not require the scheduler to be running.

Differ behavior:

- Compare targets by normalized host/protocol/port.
- Compare technologies by target host plus technology name/category/version.
- Compare findings by type/tool/url/parameter/title.
- Compare source findings only when the monitor config includes source path in a
  later extension; initial module can ignore source findings.
- Create changes for new host, new open port, service change, new technology,
  new endpoint, new finding, finding resolved, cert change.
- Severity mapping follows the power-features spec; finding severity wins for
  `new_finding`.

Alerting:

- Implement Slack and Discord webhook first.
- Email can be modelled and stored but may return "not configured" until SMTP
  config is added.
- Redact webhook URLs in API responses.

## API And CLI

API endpoints:

- `POST /api/monitor/configs`
- `GET /api/monitor/configs`
- `GET /api/monitor/configs/{id}`
- `PUT /api/monitor/configs/{id}`
- `DELETE /api/monitor/configs/{id}`
- `POST /api/monitor/configs/{id}/run`
- `GET /api/monitor/runs?config_id=`
- `GET /api/monitor/runs/{id}/changes`
- `PUT /api/monitor/changes/{id}/alert-sent`

All mutating endpoints require configured API-key auth.

CLI:

- `nox monitor create --target ... --schedule ... --name ...`
- `nox monitor list`
- `nox monitor enable <config-id>`
- `nox monitor disable <config-id>`
- `nox monitor run <config-id>`
- `nox monitor changes <config-id>`
- `nox monitor delete <config-id>`

CLI should read the same config and global state path as `serve`.

## Frontend

Add `/monitor` route and sidebar item.

UI states:

- Config list with enabled status, schedule, last run, next run, baseline, and
  recent change count.
- New/edit monitor form:
  - target input,
  - scope exclusions,
  - schedule preset: hourly, daily, weekly, custom cron,
  - phase/tool selection,
  - alert trigger checkboxes,
  - Slack/Discord webhook fields with masked existing values.
- Run history detail with status and generated session link.
- Surface changes feed grouped by severity and change type.
- Diff view showing previous/current values.

## Implementation Order

1. Add global state DB package and migration runner.
2. Add monitor models/store methods and tests.
3. Add differ with fixture sessions and tests.
4. Add immediate monitor runner.
5. Add scheduler lifecycle to `serve`.
6. Add API endpoints and auth tests.
7. Add CLI commands.
8. Add notifier fakes and Slack/Discord implementations.
9. Add Monitor UI page and build.
10. Add docs and integration smoke for immediate monitor run.

## Tests And Acceptance

Run:

```sh
go test ./...
cd web && npm run build
```

Targeted tests:

- Global DB migrations.
- Cron schedule validation.
- Monitor config CRUD.
- Immediate run creates a session and monitor run.
- Differ emits expected new/resolved changes.
- Webhook notifier redacts secrets in API output.
- Scheduler can start/stop cleanly.
- API auth blocks monitor writes without API key.

Acceptance scenario:

1. Create baseline monitor against the vulnerable fixture.
2. Run it once and set baseline.
3. Change fixture data or use synthetic session fixtures.
4. Run again and confirm `surface_changes`.
5. Verify UI and CLI show the changes and link to generated session.
