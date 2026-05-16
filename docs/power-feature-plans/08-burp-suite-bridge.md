# Module 8 Implementation Plan: Burp Suite Bridge

Current repository state: an initial production-safe slice is implemented with
Burp XML import/export, global collaborator config/callback state, redaction,
API/CLI/UI visibility, and REST actions returning clear unavailable states.
Remaining depth should add duplicate suppression, fake-server REST tests,
Collaborator/Interactsh polling, and session tool-run import summaries.

## Goal And Success Criteria

Add two-way Burp Suite integration through file import/export and optional Burp
REST API sync. Nox should import Burp issues/evidence, export Nox scope/findings
to Burp formats, and optionally use Burp Collaborator or Interactsh as a
callback provider for later validation modules.

Done means:

- Operators can import Burp XML into an existing session.
- Operators can export Nox targets/findings as Burp-compatible XML.
- Optional Burp REST status/push/pull works against a local fake server in
  tests and degrades when Burp is absent.
- Collaborator/interactsh config is stored globally and redacted in API output.

Out of scope:

- Requiring Burp Pro for file import/export.
- Running Burp active scans automatically from normal Nox scans.
- Storing Burp API keys unredacted in UI/API output.

## Safety Constraints

- Import/export file mode is allowed locally.
- REST push/pull and collaborator setup are host-privileged and require
  configured API-key auth.
- Burp REST base URL defaults to localhost only.
- Pushing URLs to Burp must verify they belong to the selected session and scope.
- Imported findings are marked with `tool_id="burp"` and preserve Burp
  confidence in normalized confidence fields.

## Data Model And Global State

Session DB:

- Reuse targets, findings, HTTP evidence, source findings, and tool runs.
- Add no Burp-specific session table unless import summaries need persistence.

Global state DB:

- `burp_config`
  - id, base_url, api_key, collaborator_provider, collaborator_url,
    interactsh_token, created_at, updated_at.
- `burp_callbacks`
  - id, provider, token, finding_id nullable, session_id nullable,
    source_ip, raw_event, created_at.

Add models:

- `BurpConfig`
- `BurpImportResult`
- `BurpCallback`

## Backend Architecture

Create `internal/burp`:

- `xml/importer.go`: parse Burp XML export.
- `xml/exporter.go`: generate scope and finding XML.
- `client.go`: Burp REST API client.
- `sync.go`: push scope and pull issues.
- `collaborator.go`: provider interface.
- `interactsh.go`: optional interactsh provider.
- `mapping.go`: severity/confidence/type mapping.

Import behavior:

1. Parse XML file with streaming decoder.
2. Extract hosts and create/update targets.
3. Extract request/response pairs as HTTP evidence where possible.
4. Extract issues as findings with deduplication by URL/type/title.
5. Persist a tool run with import summary and sidecar logs.

Export behavior:

- Scope XML includes session targets only.
- Findings XML includes normalized findings with Nox metadata.
- Export endpoints return download content with correct filename/content type.

REST behavior:

- Status checks `GET`/known Burp API route with short timeout.
- Push scope uses session targets.
- Pull issues maps Burp issues into findings and evidence.
- Missing Burp returns a clear unavailable response, not a server error.

## API And CLI

API:

- `POST /api/sessions/{id}/burp/import`
- `GET /api/sessions/{id}/burp/export/scope`
- `GET /api/sessions/{id}/burp/export/findings`
- `POST /api/sessions/{id}/burp/push-scope`
- `POST /api/sessions/{id}/burp/pull-issues`
- `GET /api/burp/status`
- `POST /api/burp/collaborator/setup`
- `GET /api/burp/collaborator/callbacks`

CLI:

- `nox burp import <burp-export.xml> --session <session-id>`
- `nox burp export scope <session-id> --output scope.xml`
- `nox burp export findings <session-id> --output findings.xml`
- `nox burp push-scope <session-id>`
- `nox burp pull-issues <session-id>`
- `nox burp collaborator set --provider interactsh --url ...`

## Frontend

Add a session-scoped Burp panel:

- Connection status.
- File import dropzone.
- Import summary with counts.
- Export buttons for scope and findings.
- REST sync buttons: push scope, pull issues.
- Collaborator section with provider status and recent callbacks.

Placement:

- Add route `/sessions/:sessionID/burp`.
- Add sidebar item only when a session is selected, or place under Tools to
  avoid sidebar growth.

## Implementation Order

1. Add XML parser/exporter with fixtures.
2. Add Burp severity/confidence mapping tests.
3. Add global state config/callback store.
4. Add import service writing session targets/findings/evidence/tool run.
5. Add export service.
6. Add REST client with fake server tests.
7. Add API and CLI.
8. Add UI panel.
9. Add docs and optional report note for imported Burp findings.

## Tests And Acceptance

Run:

```sh
go test ./...
cd web && npm run build
```

Targeted tests:

- Burp XML fixture imports expected targets/findings.
- Duplicate import does not create duplicate findings.
- Scope export matches Burp XML structure.
- REST fake server receives pushed scoped URLs.
- API auth blocks REST/collaborator mutations without API key.
- UI renders file mode when Burp is unavailable.

Acceptance scenario:

1. Import a Burp XML fixture into a Nox session.
2. Confirm findings and evidence are visible.
3. Export scope XML and validate structure.
4. Use fake Burp server to test push/pull.
