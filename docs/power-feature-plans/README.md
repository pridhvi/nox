# Nox Power Feature Implementation Plans

These plans expand `docs/nox-power-features-spec.md` into implementation-ready
work packages. Each file is intended to be handed to Codex or another engineer
as the starting point for one module. Do not implement a module directly from
the source spec when a detailed plan exists here.

## Module Plans

| # | Module | Plan |
|---|---|---|
| 1 | AI Payload Generation | [01-ai-payload-generation.md](01-ai-payload-generation.md) |
| 2 | Continuous Attack Surface Monitoring | [02-continuous-attack-surface-monitoring.md](02-continuous-attack-surface-monitoring.md) |
| 3 | Credential Testing | [03-credential-testing.md](03-credential-testing.md) |
| 4 | OSINT Expansion | [04-osint-expansion.md](04-osint-expansion.md) |
| 5 | Active Directory & Internal Network | [05-active-directory-internal-network.md](05-active-directory-internal-network.md) |
| 6 | Evasion & Stealth Mode | [06-evasion-stealth-mode.md](06-evasion-stealth-mode.md) |
| 7 | Automated PoC & Impact Demonstration | [07-automated-poc-impact.md](07-automated-poc-impact.md) |
| 8 | Burp Suite Bridge | [08-burp-suite-bridge.md](08-burp-suite-bridge.md) |

## Recommended Order

1. Implement [Evasion & Stealth Mode](06-evasion-stealth-mode.md) before any
   module that adds active request behavior.
2. Implement [OSINT Expansion](04-osint-expansion.md) before
   [Credential Testing](03-credential-testing.md) when both are selected.
3. Implement [AI Payload Generation](01-ai-payload-generation.md) before
   [Automated PoC & Impact Demonstration](07-automated-poc-impact.md) when both
   are selected.
4. Implement [Burp Suite Bridge](08-burp-suite-bridge.md) independently unless
   Module 7 is already in progress, in which case share callback/canary types.
5. Implement [Active Directory & Internal Network](05-active-directory-internal-network.md)
   independently, after the safety and scope-gating patterns are stable.

## Cross-Module Defaults

- Session evidence belongs in each `<session-id>/session.db`.
- Cross-session configuration and history belongs in a global state database
  under the existing Nox state directory, not in a single session database.
- Active, exploit-like, credential, AD, Burp sync, and validation actions are
  disabled unless explicitly requested by the operator.
- Host-privileged API endpoints require a configured API key.
- Scope validation must happen before any outbound network request.
- Missing external tools, API keys, and optional services degrade gracefully
  unless the operator explicitly selected a required tool/action.
- Every module must preserve the current CLI/API/UI behavior for existing
  dynamic, static, combined, lean, report, and sidecar-log workflows.

## Standard Verification

For each implemented module, run:

```sh
go test ./...
cd web && npm run build
```

Add module-specific fixture or integration checks from the relevant plan before
considering the module complete.
