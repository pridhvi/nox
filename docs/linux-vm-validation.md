# Linux VM Validation

Use this checklist when validating Nox on a Linux VM with the external scanner
toolchain installed. The goal is to exercise subprocess adapters, sidecar logs,
directory-based sessions, reports, and source-aware correlation in an
authorized local environment before running against real targets.

## 1. Prepare The VM

Install Go, Node.js, SQLite, curl, and the scanner toolchain. The helper script
prints the intended commands by default:

```sh
scripts/install-linux-tools.sh
```

On a disposable VM, run the supported commands directly:

```sh
scripts/install-linux-tools.sh --execute
export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"
```

The helper covers baseline dynamic tools and common optional tools. Some
packages, especially SpotBugs, Grype, Syft, and distro-specific security tools,
may still need manual installation depending on the distribution.

## 2. Check Tool Availability

Run the version smoke first:

```sh
scripts/tool-version-smoke.sh linux-full
```

This fails when baseline scanner dependencies are missing and reports optional
scanner/audit tools when absent. For a strict all-tools gate:

```sh
NOX_TOOL_SMOKE_STRICT=1 scripts/tool-version-smoke.sh linux-full
```

## 3. Build And Run Local Acceptance

Run the regular suite first:

```sh
go test ./...
cd web && npm run build
```

Then run the Linux full smoke:

```sh
NOX_RUN_LINUX_FULL=1 make linux-full-smoke
```

The smoke script starts `scripts/vulnerable-fixture`, runs dynamic, lean,
static audit, and combined source-aware scans, and validates:

- sessions are stored at `<session-dir>/<session-id>/session.db`,
- normal scans retain `runs/*.log` sidecars,
- lean scans keep findings/tool runs while clearing sidecar paths,
- reports include tool coverage, source findings, and cross-confirmed findings,
- combined sessions generate confirmation graph edges.

Keep artifacts for debugging with:

```sh
NOX_RUN_LINUX_FULL=1 NOX_KEEP_LINUX_SMOKE_ARTIFACTS=1 make linux-full-smoke
```

Failure logs are written under `/tmp/nox-linux-*.log` and reports under
`/tmp/nox-linux-*report*`.

## 4. Optional Full-Tool Fixture Runs

The Linux smoke uses a local-safe default tool set. Override it to test a
specific adapter mix:

```sh
NOX_RUN_LINUX_FULL=1 \
NOX_LINUX_DYNAMIC_TOOLS=http-probe,security-headers,whatweb,nmap,ffuf,nuclei-vuln,sqlmap,dalfox,nikto \
make linux-full-smoke
```

For manual checks:

```sh
NOX_FIXTURE_ADDR=127.0.0.1:18082 go run ./scripts/vulnerable-fixture &
fixture_pid=$!
NOX_SESSION_DIR=/tmp/nox-linux-manual go run . scan --target http://127.0.0.1:18082 --no-llm
NOX_SESSION_DIR=/tmp/nox-linux-manual go run . audit scripts/vulnerable-fixture --no-llm --format sarif --output /tmp/nox-audit.sarif
NOX_SESSION_DIR=/tmp/nox-linux-manual go run . scan --target http://127.0.0.1:18082 --source scripts/vulnerable-fixture --no-llm
NOX_SESSION_DIR=/tmp/nox-linux-manual go run . scan --target http://127.0.0.1:18082 --lean --no-llm
kill "$fixture_pid"
```

## 5. Real Target Readiness

Before scanning a real target:

- confirm written authorization and scope,
- set explicit `--out-of-scope` values for excluded hosts/CIDRs,
- use `--rate-limit gentle` or conservative per-tool parameters for fragile
  environments,
- run `--no-llm` unless a local OpenAI-compatible endpoint is configured,
- export completed sessions with `nox sessions export <session-id> --output <file.zip>`.

ProjectDiscovery tools remain subprocess adapters in v1. Native Go-library
adapters are intentionally deferred until a focused future evaluation proves
the maintenance and in-process resource tradeoffs are worth it.
