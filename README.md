# NOX

NOX is a local-first web application penetration testing framework. It is designed around scoped scan sessions, normalized findings, evidence preservation, deterministic attack-vector rules, and optional local LLM analysis.

This repository currently contains the first buildable foundation:

- Go CLI entrypoint with `scan`, `serve`, `sessions`, `plugins`, and `report` commands.
- Canonical models for sessions, targets, findings, CVEs, tool runs, and attack vectors.
- Scope validation before scans.
- Initial SQLite schema migration.
- Subprocess plugin JSON contract and runner.
- React/Vite frontend scaffold for dashboard, graph, LLM, and reports.

## Quick Start

```sh
go test ./...
go run . version
go run . scan --target https://example.com
go run . serve --host 127.0.0.1 --port 8080
```

The frontend scaffold lives in `web/`. This environment has Node installed but not `npm`, so dependencies have not been installed yet.

## Roadmap

1. Persist scan sessions to SQLite and add repository/query layer.
2. Implement the DAG runner and register safe built-in adapters first: scope check, HTTP probe, security headers.
3. Add subprocess adapters for tools that can be optional on PATH.
4. Add CVE correlation with cache/offline mode.
5. Implement attack vector evaluation and report generation.
6. Wire the React UI to the local API and WebSocket scan stream.

## Safety Boundary

NOX must treat scope as a hard control. Every network-touching adapter should call scope validation before making outbound requests. Tool failures should be recorded as `tool_runs`, not crash the whole scan unless the database or session context fails.

