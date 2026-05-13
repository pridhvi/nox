# NOX Implementation Plan

## Phase 0: Foundation

- Create buildable Go module and CLI.
- Add canonical model structs and initial migration.
- Add plugin contract and subprocess runner.
- Add frontend scaffold and repository guidance.

## Phase 1: Local Session Store

- Add SQLite driver and migration runner.
- Store one database file per engagement.
- Implement session create/list/show/delete.
- Add API endpoints for sessions and health.

## Phase 2: Safe Built-In Scanning

- Implement scope-aware `http-probe`.
- Implement `security-headers`.
- Add DAG runner with dependency ordering and tests.
- Stream scan lifecycle events over WebSocket.

## Phase 3: External Tool Adapters

- Add subprocess adapter wrappers for `nmap`, `ffuf`, `sqlmap`, and `dalfox`.
- Record `tool_runs` for success and failure.
- Normalize findings into the shared schema.

## Phase 4: Correlation

- Add technology inventory.
- Add CVE lookup interfaces with cache and offline mode.
- Add rule-based attack vector engine.

## Phase 5: Reporting and LLM

- Generate Markdown and HTML reports from persisted evidence.
- Add OpenAI-compatible local LLM client.
- Use LLM to annotate reports and attack narratives.

## Phase 6: Product Polish

- Wire React UI to APIs.
- Add Docker and release builds.
- Add GitHub Actions for tests and lint.
- Add plugin SDK examples.

