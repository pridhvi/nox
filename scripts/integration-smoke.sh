#!/usr/bin/env sh
set -eu

if [ "${NOX_RUN_INTEGRATION:-}" != "1" ]; then
  echo "Integration smoke is opt-in. Set NOX_RUN_INTEGRATION=1 to run it."
  exit 0
fi

session_dir="$(mktemp -d)"
fixture_pid=""
cleanup() {
  if [ -n "$fixture_pid" ]; then
    kill "$fixture_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$session_dir"
}
trap cleanup EXIT INT TERM

target="${NOX_INTEGRATION_TARGET:-}"
if [ -z "$target" ]; then
  NOX_FIXTURE_ADDR="${NOX_FIXTURE_ADDR:-127.0.0.1:18081}" go run ./scripts/vulnerable-fixture >/tmp/nox-fixture.log 2>&1 &
  fixture_pid="$!"
  target="http://${NOX_FIXTURE_ADDR:-127.0.0.1:18081}"
  i=0
  until curl -fsS "$target" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 30 ]; then
      echo "Integration smoke failed: fixture did not become ready" >&2
      cat /tmp/nox-fixture.log >&2 || true
      exit 1
    fi
    sleep 1
  done
fi
NOX_SESSION_DIR="$session_dir" go run . scan --target "$target" --no-llm --config /dev/null >/tmp/nox-integration-scan.log
session_id="$(find "$session_dir" -name '*.db' -maxdepth 1 -type f -print 2>/dev/null | sed 's#.*/##; s#\.db$##' | tail -1)"
if [ -z "$session_id" ]; then
  echo "Integration smoke failed: no session database created" >&2
  cat /tmp/nox-integration-scan.log >&2 || true
  exit 1
fi
NOX_SESSION_DIR="$session_dir" go run . report "$session_id" --format md --mode executive >/tmp/nox-integration-report.md
grep -q "Executive Summary" /tmp/nox-integration-report.md
grep -Eq "Missing|CORS|finding|Findings" /tmp/nox-integration-report.md
echo "Integration smoke passed for session $session_id"
