# Codex Linux VM Validation Prompt

Copy this prompt into Codex CLI from the root of the Nox repository on the Kali
VM.

```text
Act as an autonomous QA/security validation agent for this Nox repo on this Kali VM.

Run the app and test it extensively end to end. You may install missing test dependencies if needed, but ask before installing large scanner suites. Do not scan any external targets. Use only the local vulnerable fixture and localhost.

Required work:
1. Run baseline checks:
   - go test ./...
   - cd web && npm ci && npm run build
   - scripts/tool-version-smoke.sh linux-full
2. Run integration suites:
   - NOX_RUN_INTEGRATION=1 make test-integration
   - NOX_RUN_LINUX_FULL=1 NOX_KEEP_LINUX_SMOKE_ARTIFACTS=1 make linux-full-smoke
3. Start the app:
   - make build
   - NOX_API_KEY=$(openssl rand -hex 24) ./bin/nox serve --host 127.0.0.1 --port 6767
4. Exercise the API with curl:
   - /api/health
   - /api/tools
   - authenticated scan start against the local vulnerable fixture
   - sessions, findings, tool runs, stats, reports, source findings, attack graph edges
   - tool-run stdout/stderr endpoints
5. Exercise the web UI. If browser automation is available, open http://127.0.0.1:6767, log in with the API key, navigate Dashboard, Scan Builder, Findings, Source, Attack Graph, Tool Runs, Reports, Settings, and verify no console errors or broken states. If browser automation is unavailable, use Playwright/headless Chromium if possible.
6. Inspect generated session databases under the test session dirs:
   - validate <session-id>/session.db layout
   - validate runs/*.log sidecars for normal scans
   - validate lean scans remove persisted log paths
7. If failures occur:
   - inspect /tmp/nox-*.log and /tmp/nox-linux-*.log
   - identify root cause
   - patch the repo
   - rerun the failed checks
8. At the end, produce a concise report with:
   - commands run
   - pass/fail results
   - tool availability gaps
   - bugs fixed
   - remaining risks
   - exact sessions/artifacts to inspect

If no desktop/browser-control tool is available, install/use Playwright headless Chromium and write a temporary smoke test that starts the app, logs in, clicks through the primary routes, captures screenshots, checks for console errors, and fails on HTTP 5xx or uncaught JS errors.

Do not commit unless I explicitly ask.
```

For an even stricter toolchain gate, ask Codex to include this command before
the full smoke:

```sh
NOX_TOOL_SMOKE_STRICT=1 scripts/tool-version-smoke.sh linux-full
```
