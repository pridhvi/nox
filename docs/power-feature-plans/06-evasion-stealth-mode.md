# Module 6 Implementation Plan: Evasion And Stealth Mode

Current repository state: an initial production-safe slice is implemented with
runner option fields, scan/API/CLI/UI controls, profile normalization, proxy
redaction, and block-event persistence/API visibility. Remaining depth should
wire policy-aware transports, subprocess argument mapping, adaptive backoff, and
report summaries.

## Goal And Success Criteria

Add reusable request behavior controls: stealth profiles, adaptive backoff,
header/user-agent rotation, proxy chains, WAF-aware pacing, and block detection.
This module should become the shared safety and traffic-shaping layer for later
active modules.

Done means:

- Scan requests can choose safe, normal, stealth, or custom evasion profiles.
- Dynamic HTTP adapters and compatible subprocess adapters honor the selected
  policy.
- Block detection records events and adaptive backoff slows further requests.
- Existing scans behave the same when no evasion options are set.

Out of scope:

- CAPTCHA solving.
- WAF bypass payload generation; that belongs to Module 1.
- Covert traffic or unauthorized evasion guidance.

## Safety Constraints

- Defaults must remain conservative and transparent.
- Proxy URLs must be validated and never logged with credentials.
- Header rotation must not forge internal-only headers by default.
- Adaptive backoff should reduce request rate, never increase it.
- All evasion settings must stay visible in session runner options and reports.

## Data Model And Config

Extend `models.ScanRunnerOptions` with:

- `EvasionProfile string`
- `JitterMS int`
- `ProxyURL string`
- `UserAgentProfile string`
- `HeaderProfile string`
- `AdaptiveBackoff bool`
- `MaxBackoffSeconds int`

Add migration only if runner options are stored as JSON already and no schema
change is needed. Existing sessions should load with zero-value defaults.

Add optional table:

- `block_events`
  - id, session_id, target_id, tool_id, url, status_code, signal,
    response_snippet, backoff_ms, created_at.

Add config defaults under `scan.evasion`.

## Backend Architecture

Create `internal/evasion`:

- `profile.go`: safe/normal/stealth/custom profile normalization.
- `policy.go`: request policy object.
- `transport.go`: proxy-aware HTTP transport builder.
- `headers.go`: user-agent/header profiles.
- `backoff.go`: adaptive limiter.
- `detect.go`: block/WAF response detection.
- `subprocess.go`: maps policy into safe subprocess args where supported.

Integration:

- `ScanManager` converts session runner options into `engine.RunnerOptions`.
- `engine.Runner` passes an evasion policy into adapter input.
- HTTP adapters use a shared request helper or wrapped HTTP client.
- Subprocess adapters append only allowlisted rate/proxy args.
- `security-headers`, `http-probe`, `graphql`, `openapi`, CORS, SSRF, XXE,
  OAuth, SSTI, and cloud checks should use the policy-aware HTTP client.

Profiles:

- `safe`: current defaults, low concurrency.
- `normal`: current behavior.
- `stealth`: lower concurrency, jitter, browser-like headers, adaptive backoff.
- `custom`: explicit fields from request/config.

## API And CLI

Extend scan start request with optional runner/evasion fields:

- `evasion_profile`
- `jitter_ms`
- `proxy_url`
- `user_agent_profile`
- `header_profile`
- `adaptive_backoff`

Add:

- `GET /api/sessions/{id}/block-events`

CLI flags:

- `--evasion-profile safe|normal|stealth|custom`
- `--proxy`
- `--user-agent-profile`
- `--header-profile`
- `--jitter-ms`
- `--adaptive-backoff`

## Frontend

Update Scan Builder:

- Add "Request Behavior" section.
- Segmented profile control: Safe, Normal, Stealth, Custom.
- Show estimated impact: concurrency, delay, jitter, proxy, adaptive backoff.
- Custom fields reveal only when Custom is selected.

Update Dashboard/Reports:

- Show evasion profile in session summary.
- Show block events if present.

## Implementation Order

1. Add runner option fields and request parsing tests.
2. Add `internal/evasion` policy normalization tests.
3. Add proxy transport and header profile tests.
4. Integrate policy into HTTP client creation.
5. Update built-in HTTP adapters to use policy-aware client/helpers.
6. Add subprocess arg mapping for ffuf, nuclei, sqlmap, dalfox where safe.
7. Add block event table/store/API.
8. Update CLI and UI.
9. Add docs/report summary.

## Tests And Acceptance

Run:

```sh
go test ./...
cd web && npm run build
```

Targeted tests:

- Existing scan request JSON still works.
- Stealth profile normalizes expected delays/concurrency.
- Proxy credentials are redacted in logs/API.
- Block response creates block event and increases backoff.
- Out-of-scope validation still happens before request dispatch.
- UI persists selected profile in scan profiles.

Acceptance scenario:

1. Run fixture scan with `--evasion-profile stealth`.
2. Confirm tool runs succeed and session stores runner options.
3. Simulate 403/429 fixture response and confirm block event/backoff.
