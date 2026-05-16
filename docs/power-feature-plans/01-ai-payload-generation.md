# Module 1 Implementation Plan: AI Payload Generation

## Goal And Success Criteria

Add operator-triggered payload generation for confirmed findings. Nox should
assemble target context, generate ranked payloads through the configured
OpenAI-compatible LLM, persist them in the session DB, expose them through API,
CLI, reports, and the finding detail UI, and optionally validate a payload
against the live target.

Done means:

- Payload generation is available for supported finding types: XSS, SQLi, SSRF,
  SSTI, XXE, command injection, and open redirect.
- Payloads are stored per finding and can be regenerated, listed, copied, and
  validated.
- WAF fingerprints are stored as technologies with `category="waf"`.
- Validation is manual, scoped, logged, and never automatic during a normal scan.
- LLM failures or unconfigured LLM state return clear errors without affecting
  existing findings.

Out of scope:

- Fully automated exploitation chains.
- Persistent payload replay scheduling.
- External OAST/collaborator callbacks beyond a placeholder interface for later
  Module 7 or Module 8 integration.

## Safety Constraints

- Payload generation is advisory. It does not send traffic.
- Payload validation sends traffic and must require explicit operator action.
- API validation endpoints require a configured API key.
- Validation must use the existing scope checker against the finding URL or
  target host before sending any request.
- Validation responses are truncated before persistence and report rendering.
- Generated payloads must be treated as untrusted text in the UI: render in code
  blocks, never as HTML.

## Data Model And Migration

Add migration `006_payload_generation.sql` and down migration:

- Create `payloads`:
  - `id TEXT PRIMARY KEY`
  - `finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE`
  - `session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE`
  - `payload_type TEXT NOT NULL`
  - `payload TEXT NOT NULL`
  - `context TEXT NOT NULL DEFAULT ''`
  - `target_waf TEXT NOT NULL DEFAULT ''`
  - `target_db TEXT NOT NULL DEFAULT ''`
  - `bypass_technique TEXT NOT NULL DEFAULT ''`
  - `confidence REAL NOT NULL DEFAULT 0.0`
  - `validated BOOLEAN NOT NULL DEFAULT FALSE`
  - `validated_response TEXT NOT NULL DEFAULT ''`
  - `rank INTEGER NOT NULL DEFAULT 0`
  - `created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP`
- Add indexes on `finding_id`, `session_id`, and `(session_id, payload_type)`.

Add `models.Payload` with JSON fields matching the table. Store confidence as
`float64`, validated as `bool`, and created time as `time.Time`.

Add store methods:

- `InsertPayload(ctx, payload)`
- `ListPayloadsByFinding(ctx, sessionID, findingID)`
- `ListPayloadsBySession(ctx, sessionID, filter)`
- `DeletePayloadsByFinding(ctx, sessionID, findingID)`
- `UpdatePayloadValidation(ctx, sessionID, payloadID, result)`

Migration tests must prove fresh DB creation and migration from the current
schema.

## Backend Architecture

Create `internal/payload`:

- `generator.go`: orchestrates generation and persistence.
- `context.go`: loads finding, target, technologies, HTTP evidence, and prior
  tool payload evidence.
- `prompts.go`: system/user prompts and JSON schema expectations.
- `waf.go`: WAF fingerprint helpers and technology creation helpers.
- `waf_bypass_library.go`: static bypass techniques keyed by WAF and finding
  type.
- `validator.go`: manual validation engine.
- Type-specific helpers: `xss.go`, `sqli.go`, `ssrf.go`, `ssti.go`, `xxe.go`,
  `cmd.go`, `redirect.go`.

Generation flow:

1. Load finding by ID and verify it belongs to the requested session.
2. Reject unsupported or suppressed/dismissed findings unless `force` is set.
3. Build context from finding, technologies, HTTP evidence, target, and tool run
   evidence.
4. If `force_regenerate=false` and payloads already exist, return existing
   payloads.
5. Call the configured LLM using `internal/llm` client conventions.
6. Parse strict JSON array; reject markdown or malformed output.
7. Normalize rank/confidence/type; clamp confidence to `0..1`.
8. Persist payloads.

Validation flow:

1. Load payload and finding; verify session ownership.
2. Build the request from finding method, URL, parameter, content type, and
   payload context.
3. Validate scope before sending.
4. Send with existing HTTP client and runner timeout defaults.
5. Detect success deterministically by type:
   - XSS: reflected payload or unencoded marker.
   - SQLi: SQL error, timing marker, or existing sqlmap evidence pattern.
   - SSTI: math expression marker.
   - Open redirect: safe redirect target control.
   - SSRF/XXE/cmd injection: return "not automatically verifiable" until Module
     7/8 callback support exists.
6. Persist validation result and a truncated response snippet.

WAF detection:

- Extend fingerprinting after `http-probe`/`security-headers` by adding a
  lightweight built-in adapter or helper in `security_headers.go`.
- Store WAF as `Technology{Name: "...", Category: "waf", SourceTool:
  "waf-detect"}`.
- Do not send malicious probes in the first version. Use passive header/status
  and known body patterns only.

## API And CLI

API endpoints:

- `POST /api/sessions/{id}/findings/{finding_id}/generate-payloads`
  - Body: `{ "force_regenerate": false }`
  - Requires API key when configured; generation requires configured LLM.
- `GET /api/sessions/{id}/findings/{finding_id}/payloads`
- `POST /api/sessions/{id}/payloads/{payload_id}/validate`
  - Requires configured API key because it sends traffic.
- `GET /api/sessions/{id}/payloads?type=&validated=`

CLI commands:

- `nox payloads generate <session-id> --finding <finding-id> [--force]`
- `nox payloads generate <session-id> --all [--force]`
- `nox payloads list <session-id> [--finding <id>] [--validated-only]`
- `nox payloads validate <session-id> --payload <payload-id>`

CLI output defaults to terminal table and supports `--format json`.

## Frontend

Update the Findings detail drawer:

- Add `Payloads` tab beside evidence/CVE/source detail tabs.
- Show empty state: "No generated payloads for this finding."
- Add `Generate Payloads` action, disabled when LLM is unconfigured.
- Show payload cards with:
  - rank, confidence, type, target WAF/DB, bypass technique,
  - copy button,
  - validation status and `Validate` button.
- Use optimistic loading states but do not mutate the finding list until API
  success.

Add API client methods and types for payloads. Keep generated payload strings in
`<pre><code>` style with wrapping and copy action.

## Implementation Order

1. Add migration, model, store methods, and tests.
2. Add passive WAF technology detection and tests.
3. Add `internal/payload` context assembly and deterministic JSON parser tests.
4. Add LLM generation service with fake client tests.
5. Add API endpoints and auth/session ownership tests.
6. Add CLI commands.
7. Add manual validator and scoped request tests.
8. Add UI tab and build/test.
9. Add report inclusion only as a compact appendix of generated/validated
   payload counts and validated evidence.

## Tests And Acceptance

Run:

```sh
go test ./...
cd web && npm run build
```

Add targeted tests:

- Migration creates `payloads`.
- Existing DB migrates cleanly.
- Generation rejects unsupported findings.
- Existing payloads are reused unless forced.
- Malformed LLM output is rejected with a clear error.
- Validation refuses out-of-scope URLs.
- API returns 404 for wrong session/finding/payload.
- UI builds and renders payload tab empty/populated states.

Acceptance scenario:

1. Create a fixture scan with an XSS or SQLi finding.
2. Configure a fake OpenAI-compatible LLM in tests.
3. Generate payloads.
4. Confirm payloads appear in API, CLI, UI, and session DB.
5. Validate a safe reflected payload against the local fixture.
