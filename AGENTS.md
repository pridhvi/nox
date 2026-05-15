# Codex Guidance for Nox

Use `docs/nox-project-spec.md` as the canonical product specification. Keep `README.md`, `AGENTS.md`, and `docs/implementation-plan.md` updated after every major implementation change.

## Current State

This repo has a buildable backend with module path `github.com/pridhvi/nox`, absolute default session storage under `$HOME/.nox/sessions`, a synchronous CLI safe scan path, asynchronous API scan start, Docker packaging, CI, and snapshot release configuration. Active scans run built-in `http-probe` and `security-headers` plus optional subprocess adapters for recon (`subfinder`, `dnsx`, `naabu`, `httpx`, `whois`, `waybackurls`), fingerprinting (`whatweb`, `nuclei-tech`, `testssl.sh`, GraphQL introspection, OpenAPI/Swagger discovery, `wpscan`, `droopescan`), enumeration (`ffuf`, `arjun`, `linkfinder`, `gitleaks`, JavaScript secret scanning, CORS checks, scoped cloud bucket checks), vulnerability scanning (`nuclei-vuln`, `sqlmap`, `dalfox`, SSRFmap, `jwt_tool`, OAuth, SSTI, XXE, `nikto`), CVE intelligence, deterministic attack vector generation, optional local-first LLM analysis with vector annotations, reporting, and `nmap`; `crt.sh` is registered but opt-in. API scans support single-target and multi-target requests, cooperative pause/resume, cancellation, and WebSocket lifecycle events at `GET /api/scan/{id}/events` while keeping polling endpoints as fallback. The API exposes sessions, findings, finding updates, targets, tool runs, stats, vectors, CVEs, LLM history/analysis through `go-openai`, reports, effective config, structured tool inventory, global validated plugin management, API-backed scan profiles, LLM model probing, scan tool selection, validated per-tool parameters, runner options, and optional API-key auth. Configuration uses Viper-backed YAML/TOML/JSON plus env overrides and resolves explicit relative session dirs relative to the config file. The dark-default React/Vite operator console reads real API data for dashboard controls/live terminal feed, multi-target scan building, findings, Cytoscape graph views with safe edge filtering, Recharts severity charts, LLM, CVEs, reports, global plugins, tool status, tool runs, saved scan profiles, settings health panels, and scan configuration. The frontend builds into `internal/api/web/dist`, uses lazy-loaded route chunks and route-level error recovery, and is embedded into the Go binary. The default API port is `6767`. The backend targets Go 1.26; keep it buildable with `go test ./...` after every change.

## Engineering Priorities

- Scope validation is a security boundary. Every adapter that makes network requests must validate target host/IP first.
- Normalize all tool output into `internal/models.Finding`.
- Persist raw evidence. Do not discard stdout, stderr, HTTP requests, or HTTP responses.
- Prefer deterministic rule logic for attack vectors; LLM output should annotate, not decide correctness.
- Keep external scanner tools optional and degrade gracefully when missing.
- Default to local-only operation: no telemetry, no required cloud API keys.

## Suggested Next Tasks

The phase roadmap in `docs/implementation-plan.md` is complete from the repository perspective. Next tasks should be hardening and depth rather than new roadmap phases:

1. Expand external scanner install/version checks in Docker images.
2. Add deeper vulnerable-app integration suites beyond the built-in smoke fixture.
3. Add optional code-splitting for any remaining large frontend graph/chart bundle paths.
4. Evaluate native ProjectDiscovery Go-library adapters where subprocess behavior is too limiting.
