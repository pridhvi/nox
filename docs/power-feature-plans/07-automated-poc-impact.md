# Module 7 Implementation Plan: Automated PoC And Impact Demonstration

Current repository state: an initial production-safe slice is implemented with
PoC result persistence, API/CLI/UI visibility, explicit confirm gates, and safe
manual PoC recording. Remaining depth should add scoped fixture-safe validators,
canary callback handling, report sections, and optional LLM impact narratives.

## Goal And Success Criteria

Add manual, safe proof-of-concept execution for selected findings. Nox should
generate bounded PoC attempts, capture evidence, correlate canary callbacks
where available, and produce an impact narrative without turning normal scans
into exploitation.

Done means:

- Operators can run a PoC for supported findings with explicit confirmation.
- Results are persisted and linked to findings.
- Canary/callback infrastructure exists for local and future external providers.
- Reports can include PoC evidence and impact summaries.

Out of scope:

- Automatic exploitation during normal scans.
- Privilege escalation, persistence, or destructive actions.
- Shell access or data extraction beyond safe proof markers.

## Safety Constraints

- PoC execution is disabled by default and never automatic.
- API PoC execution requires configured API-key auth.
- Scope validation must happen before every PoC request.
- PoCs must use harmless markers and bounded timeouts.
- Evidence is truncated and sanitized.
- UI must show a warning/confirmation before execution.

## Data Model And Migration

Add `poc_results`:

- id, session_id, finding_id, target_id,
- poc_type,
- status: pending, running, confirmed, inconclusive, failed,
- payload_id nullable,
- request_raw, response_raw,
- response_code, response_time_ms,
- evidence,
- canary_token, callback_received,
- impact_narrative,
- created_at, completed_at.

Indexes on session, finding, status.

Add `models.PoCResult`.

Store methods:

- `InsertPoCResult`
- `UpdatePoCResult`
- `ListPoCResults(sessionID, filter)`
- `ListPoCResultsByFinding`

## Backend Architecture

Create `internal/poc`:

- `runner.go`: orchestrates PoC execution.
- `canary.go`: built-in local canary token registry.
- `xss.go`, `sqli.go`, `ssrf.go`, `ssti.go`, `xxe.go`, `redirect.go`:
  deterministic safe PoC runners.
- `narrative.go`: LLM impact summary from deterministic evidence.
- `evidence.go`: truncation/sanitization.

Integration:

- Use generated payloads from Module 1 when present.
- If Module 1 is absent, use deterministic safe payloads.
- Use Module 8 collaborator provider if available; otherwise built-in local
  canary supports only local callbacks.
- Insert normal findings only when a PoC confirms a stronger issue and the
  existing finding was not already confirmed.

## API And CLI

API:

- `POST /api/sessions/{id}/findings/{finding_id}/poc/run`
- `GET /api/sessions/{id}/findings/{finding_id}/poc`
- `GET /api/sessions/{id}/poc-results`
- `GET /api/sessions/{id}/poc-results/{poc_id}`

Run endpoint body includes:

- `poc_type`
- `payload_id`
- `confirm=true`

CLI:

- `nox poc run <session-id> --finding <finding-id> [--payload <id>]`
- `nox poc list <session-id> [--finding <id>]`
- `nox poc report <session-id> --output poc.md`

## Frontend

Add `PoC / Impact` tab in finding detail:

- Warning panel explaining active validation.
- Run button requiring confirmation.
- Result timeline with status and evidence.
- Canary callback indicator.
- Impact narrative block.
- Link to payload used when Module 1 exists.

Reports:

- Add optional PoC section for confirmed/inconclusive results.
- Do not include raw full responses; include truncated evidence only.

## Implementation Order

1. Add model/migration/store tests.
2. Add evidence truncation and canary registry.
3. Add safe PoC runner interface.
4. Implement reflected XSS/open redirect/SSTI fixture PoCs first.
5. Add SQLi/SSRF/XXE inconclusive-safe runners.
6. Add API and CLI.
7. Add UI tab.
8. Add report section.
9. Add integration fixture endpoints if needed.

## Tests And Acceptance

Run:

```sh
go test ./...
cd web && npm run build
```

Targeted tests:

- PoC run requires explicit confirmation.
- API auth blocks PoC run without API key.
- Out-of-scope PoC is rejected.
- Reflected fixture PoC confirms safely.
- Inconclusive results persist without creating false confirmed findings.
- Report includes PoC evidence only when requested/available.

Acceptance scenario:

1. Run fixture scan producing a reflected/input finding.
2. Run PoC manually.
3. Confirm persisted `poc_results`, UI tab, CLI list, and report section.
