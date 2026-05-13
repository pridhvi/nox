# Codex Guidance for NOX

Use `/Users/kanini/Downloads/nox-project-spec.md` as the product specification until it is superseded by docs in this repository.

## Current State

This repo is a first scaffold, not a complete scanner. Keep the backend buildable with `go test ./...` after every change. The frontend is scaffolded as React/Vite, but package installation is pending because `npm` is not currently available in this environment.

## Engineering Priorities

- Scope validation is a security boundary. Every adapter that makes network requests must validate target host/IP first.
- Normalize all tool output into `internal/models.Finding`.
- Persist raw evidence. Do not discard stdout, stderr, HTTP requests, or HTTP responses.
- Prefer deterministic rule logic for attack vectors; LLM output should annotate, not decide correctness.
- Keep external scanner tools optional and degrade gracefully when missing.
- Default to local-only operation: no telemetry, no required cloud API keys.

## Suggested Next Tasks

1. Add SQLite connection/migration runner.
2. Implement `sessions` persistence and CLI listing.
3. Add a minimal DAG engine with in-process fake adapters for tests.
4. Add `header-check` and `http-probe` adapters before integrating heavier tools.
5. Add API endpoints for session CRUD and scan start/status.

