# Module 4 Implementation Plan: OSINT Expansion

Current repository state: an initial production-safe slice is implemented with
session DB OSINT records, local scope/domain seeding, API/CLI/UI visibility, and
API-key-gated collection. Remaining depth should add provider clients,
provider-status UX, strict seeding confirmation, and report summaries.

## Goal And Success Criteria

Add an explicit OSINT phase that collects public intelligence about an
authorized target and turns it into normalized OSINT records, scan seeds, and
operator context. OSINT should improve recon and credential testing without
making external API dependencies mandatory.

Done means:

- `osint` phase can run by itself or before recon when selected.
- OSINT findings are stored in session DB and exposed through API/CLI/UI.
- Optional providers degrade gracefully when API keys or tools are missing.
- OSINT seeds can create targets, technologies, usernames, and source hints.

Out of scope:

- Circumventing platform access controls.
- Scraping authenticated social networks.
- Storing large raw public datasets.

## Safety Constraints

- OSINT is opt-in and must respect configured target scope.
- API-triggered OSINT collection requires configured API-key auth.
- API keys for Shodan/GitHub/etc. must not be exposed in API responses.
- Provider requests should use conservative timeouts and identifiable user
  agent.
- Do not create new scan targets outside in-scope roots without explicit
  operator confirmation or scope match.

## Data Model And Migration

Add phase constant `osint`.

Add migration:

- `osint_findings`
  - id, session_id,
  - kind: employee, email, repo, secret_reference, technology, domain,
    endpoint, job_posting, shodan_service, dns_history,
  - value, source, confidence,
  - target_id nullable,
  - metadata JSON text,
  - created_at.
- Indexes on session, kind, source.

Add `models.OSINTFinding`.

Store methods:

- `InsertOSINTFinding`
- `ListOSINTFindings(sessionID, filter)`
- `OSINTFindingByID`

## Backend Architecture

Create `internal/osint`:

- `engine.go`: orchestrates selected providers.
- `providers/github.go`
- `providers/shodan.go`
- `providers/jobs.go`
- `providers/dns_history.go`
- `providers/employees.go`
- `seed.go`: converts OSINT records into targets/technologies/source hints.
- `redact.go`: hides API keys and sensitive tokens.

Configuration:

- `osint.enabled=false`
- `osint.providers`
- `osint.github_token`
- `osint.shodan_api_key`
- `osint.allowed_domains`
- `osint.max_results_per_provider`

Provider behavior:

- GitHub: search public code and org metadata when token is configured.
- Shodan: host/domain lookup when key is configured.
- Job postings: parse operator-provided URLs or configured search sources; do
  not scrape authenticated sites.
- DNS history: use configured passive source or local fixture parser first.
- Employees: parse public pages and configured files; no authenticated scraping.

Seeding:

- Domains/endpoints can become new targets only if in scope.
- Technologies can be inserted into `technologies`.
- Usernames/emails can later seed Module 3.

## API And CLI

API:

- `POST /api/sessions/{id}/osint/run`
- `GET /api/sessions/{id}/osint?kind=&source=`
- `POST /api/sessions/{id}/osint/{finding_id}/seed`

Run/seed endpoints require configured API-key auth.

CLI:

- `nox osint run <session-id> [--providers github,shodan]`
- `nox osint list <session-id> [--kind email] [--format json]`
- `nox osint export <session-id> --output osint.json`

## Frontend

Add OSINT page or session tab:

- Filters by kind/source/confidence.
- Cards for domains, employees/emails, repos, technologies, endpoints.
- Seed action for in-scope items.
- Provider status panel showing configured/missing providers without exposing
  secrets.

If route count should stay small, place OSINT under Source or Tools initially
and promote to sidebar later.

## Implementation Order

1. Add phase constant, model, migration, store methods, tests.
2. Add provider interfaces and fixture-based provider tests.
3. Add GitHub and Shodan clients with fake HTTP tests.
4. Add seed conversion and scope enforcement.
5. Add OSINT runner and scan integration.
6. Add API and CLI.
7. Add UI.
8. Add report summary section.

## Tests And Acceptance

Run:

```sh
go test ./...
cd web && npm run build
```

Targeted tests:

- Missing API keys produce skipped provider results, not scan failure.
- Provider fixtures normalize expected records.
- Out-of-scope seeds are rejected.
- API auth blocks OSINT run/seed without API key.
- UI renders provider missing/configured states.

Acceptance scenario:

1. Run OSINT against a local fixture/domain fixture.
2. Confirm records persist.
3. Seed an in-scope endpoint and verify it appears as a target or source hint.
