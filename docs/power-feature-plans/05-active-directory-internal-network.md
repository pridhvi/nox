# Module 5 Implementation Plan: Active Directory And Internal Network

Current repository state: an initial production-safe slice is implemented with
AD entity/relationship/artifact persistence, internal-scope enforcement for enum
requests, BloodHound JSON import/export, and API/CLI/UI visibility. Remaining
depth should add parser fixtures, optional tool wrappers, graph conversion, and
Kerberoast warning-gated execution.

## Goal And Success Criteria

Add an internal-network module for authorized AD and Windows environment
assessment. The module should enumerate LDAP/SMB signals, identify AD attack
paths, import/export BloodHound-compatible data, and normalize findings without
running against public internet targets by accident.

Done means:

- AD phases run only for internal/private scopes or explicit override.
- LDAP/SMB/NetExec/BloodHound outputs normalize into Nyx models.
- AD-specific entities and attack graph edges are visible in API/UI.
- Kerberoast and relay-risk checks are explicit, scoped, and logged.

Out of scope:

- Automated lateral movement.
- Credential dumping.
- Exploit execution beyond safe enumeration and explicit Kerberoast request.

## Safety Constraints

- AD module is disabled by default.
- Only private, link-local, loopback, or explicitly allowed CIDR scopes can run
  AD phases.
- API-triggered AD actions require configured API-key auth.
- Kerberoasting requires explicit command/API action and warning confirmation.
- No password capture, relay execution, or hash cracking in the first version.
- All subprocess tools are optional and degrade gracefully unless explicitly
  selected.

## Data Model And Migration

Reuse existing targets, findings, technologies, attack vectors, and graph edges
where possible.

Add AD tables only for graph/entity detail:

- `ad_entities`
  - id, session_id, entity_type, name, domain, sid, distinguished_name,
    metadata, created_at.
- `ad_relationships`
  - id, session_id, from_entity_id, to_entity_id, relation, metadata,
    created_at.
- `ad_artifacts`
  - id, session_id, artifact_type, path, summary, created_at.

Indexes:

- session/entity type/name.
- session/from/to relation.

Add `models.ADEntity`, `ADRelationship`, `ADArtifact`.

## Backend Architecture

Create `internal/activedirectory`:

- `scope.go`: internal scope detection and override validation.
- `ldap.go`: LDAP enumeration wrapper/parser.
- `smb.go`: SMB enumeration wrapper/parser.
- `kerberoast.go`: explicit Kerberoast wrapper.
- `bloodhound.go`: import/export BloodHound JSON.
- `netexec.go`: NetExec parser/wrapper.
- `relay.go`: relay-risk detection only.
- `graph.go`: converts AD relationships to attack graph edges.

Add adapter phases:

- `ad_discovery`
- `ad_enum`
- `ad_attack_paths`

External binaries:

- `ldapsearch`, `smbclient`, `netexec`, `bloodhound-python` are optional.
- Tool status should surface missing binaries through existing `/api/tools`
  patterns.

## API And CLI

API:

- `GET /api/sessions/{id}/ad/entities?type=`
- `GET /api/sessions/{id}/ad/relationships`
- `GET /api/sessions/{id}/ad/artifacts`
- `POST /api/sessions/{id}/ad/enum`
- `POST /api/sessions/{id}/ad/kerberoast`
- `POST /api/sessions/{id}/ad/bloodhound/import`
- `GET /api/sessions/{id}/ad/bloodhound/export`

Mutating/active endpoints require configured API-key auth.

CLI:

- `nyx ad enum <session-id> --domain ...`
- `nyx ad kerberoast <session-id> --spn ...`
- `nyx ad bloodhound import <session-id> --input data.json`
- `nyx ad bloodhound export <session-id> --output data.json`

## Frontend

Add an AD/Internal page:

- Domain summary.
- Entity tables for users, groups, computers, SPNs, shares.
- Relationship graph using existing graph styling where possible.
- Attack path list with relation labels.
- BloodHound import/export controls.
- Clear internal-scope warning and disabled state for public targets.

## Implementation Order

1. Add scope detection helpers and tests.
2. Add AD models/migration/store methods.
3. Add parser fixtures for LDAP, SMB, NetExec, BloodHound.
4. Add read-only enumeration adapters.
5. Add graph conversion into attack graph edges.
6. Add explicit Kerberoast wrapper with warning gate.
7. Add API and CLI.
8. Add UI.
9. Add docs and tool-version smoke entries.

## Tests And Acceptance

Run:

```sh
go test ./...
cd web && npm run build
```

Targeted tests:

- Public target rejects AD phases.
- Internal CIDR permits AD phases.
- BloodHound JSON import creates entities/relationships.
- NetExec/LDAP/SMB fixtures normalize findings.
- Kerberoast endpoint requires API key and explicit confirmation.
- UI shows disabled state for non-internal sessions.

Acceptance scenario:

1. Import BloodHound fixture JSON into a session.
2. Confirm AD entities/relationships persist.
3. Confirm attack graph shows AD edges.
