#!/usr/bin/env sh
set -eu

if [ "${NOX_RUN_POWER_INTEGRATION:-}" != "1" ]; then
  echo "Power integration smoke is opt-in. Set NOX_RUN_POWER_INTEGRATION=1 to run it."
  exit 0
fi

root_dir="$(mktemp -d)"
fixture_log="/tmp/nox-power-fixture.log"
scan_log="/tmp/nox-power-scan.log"
payload_log="/tmp/nox-power-payloads.log"
creds_log="/tmp/nox-power-creds.log"
osint_log="/tmp/nox-power-osint.log"
poc_log="/tmp/nox-power-poc.log"
report_file="/tmp/nox-power-report.md"
fixture_pid=""

cleanup() {
  if [ -n "$fixture_pid" ]; then
    kill "$fixture_pid" >/dev/null 2>&1 || true
  fi
  if [ "${NOX_KEEP_INTEGRATION_ARTIFACTS:-}" != "1" ]; then
    rm -rf "$root_dir"
  else
    echo "Keeping power integration sessions under $root_dir"
  fi
}
trap cleanup EXIT INT TERM

fail() {
  echo "Power integration smoke failed: $*" >&2
  for artifact in "$fixture_log" "$scan_log" "$payload_log" "$creds_log" "$osint_log" "$poc_log" "$report_file"; do
    if [ -s "$artifact" ]; then
      echo "----- $artifact -----" >&2
      sed -n '1,220p' "$artifact" >&2 || true
    fi
  done
  exit 1
}

query() {
  sqlite3 "$1" "$2"
}

assert_count_at_least() {
  db="$1"
  sql="$2"
  min="$3"
  label="$4"
  count="$(query "$db" "$sql")"
  if [ "$count" -lt "$min" ]; then
    fail "$label: expected at least $min, got $count"
  fi
}

assert_file_contains() {
  file="$1"
  pattern="$2"
  label="$3"
  if ! grep -Eq "$pattern" "$file"; then
    fail "$label: $file did not contain pattern $pattern"
  fi
}

session_id_for() {
  dir="$1"
  found=""
  for db_path in "$dir"/*/session.db; do
    if [ -f "$db_path" ]; then
      found="$(basename "$(dirname "$db_path")")"
      break
    fi
  done
  if [ -z "$found" ]; then
    fail "no directory-based session database found under $dir"
  fi
  printf '%s' "$found"
}

fixture_addr="${NOX_FIXTURE_ADDR:-127.0.0.1:18082}"
target="http://$fixture_addr"
: >"$fixture_log"
NOX_FIXTURE_ADDR="$fixture_addr" go run ./scripts/vulnerable-fixture >"$fixture_log" 2>&1 &
fixture_pid="$!"
i=0
until curl -fsS "$target" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 30 ]; then
    fail "fixture did not become ready at $target"
  fi
  sleep 1
done

session_dir="$root_dir/sessions"
mkdir -p "$session_dir"
NOX_SESSION_DIR="$session_dir" go run . scan --target "$target" --tools security-headers --no-llm --config /dev/null >"$scan_log" 2>&1
session_id="$(session_id_for "$session_dir")"
db_path="$session_dir/$session_id/session.db"
target_id="$(query "$db_path" "SELECT id FROM targets LIMIT 1;")"
if [ -z "$target_id" ]; then
  fail "scan did not create a target"
fi

query "$db_path" "INSERT INTO findings (id, session_id, target_id, tool_id, type, severity, confidence, cvss_score, title, description, remediation, url, parameter, method, evidence_raw, evidence_normalized, code_context, flow_summary, status, notes, tags, created_at) VALUES ('power-xss-1', '$session_id', '$target_id', 'fixture', 'vulnerability', 'high', 0.9, 0, 'Reflected XSS marker', 'Fixture reflected input sink for safe validation.', 'Escape reflected output.', '$target/api/search?q=x', 'q', 'GET', '', '', '', '', 'pending', '', '[\"xss\"]', CURRENT_TIMESTAMP);"

NOX_SESSION_DIR="$session_dir" go run . payloads generate "$session_id" --finding power-xss-1 --force >"$payload_log" 2>&1
payload_id="$(query "$db_path" "SELECT id FROM payloads WHERE finding_id = 'power-xss-1' ORDER BY rank LIMIT 1;")"
if [ -z "$payload_id" ]; then
  fail "payload generation did not persist a payload"
fi
NOX_SESSION_DIR="$session_dir" NOX_POWER_ACTIVE_VALIDATION_ENABLED=true go run . payloads validate "$session_id" --payload "$payload_id" --confirm --enabled=true >>"$payload_log" 2>&1
assert_count_at_least "$db_path" "SELECT COUNT(*) FROM payloads WHERE id = '$payload_id' AND validated = 1;" 1 "validated payload"

NOX_SESSION_DIR="$session_dir" go run . creds test "$session_id" --mode defaults --url "$target/login" --username admin --password password --confirm --max-attempts 1 --delay-ms 0 >"$creds_log" 2>&1
assert_count_at_least "$db_path" "SELECT COUNT(*) FROM credential_findings WHERE valid = 1 AND password = '********';" 1 "redacted valid credential finding"

NOX_SESSION_DIR="$session_dir" go run . osint run "$session_id" --providers github,shodan,securitytrails >"$osint_log" 2>&1
assert_count_at_least "$db_path" "SELECT COUNT(*) FROM provider_statuses WHERE status = 'skipped';" 2 "skipped provider status records"

NOX_SESSION_DIR="$session_dir" NOX_POWER_ACTIVE_VALIDATION_ENABLED=true go run . poc run "$session_id" --finding power-xss-1 --confirm --active=true >"$poc_log" 2>&1
assert_count_at_least "$db_path" "SELECT COUNT(*) FROM poc_results WHERE finding_id = 'power-xss-1';" 1 "PoC result"

NOX_SESSION_DIR="$session_dir" go run . report "$session_id" --format md --mode technical --config /dev/null --output "$report_file" >>"$scan_log" 2>&1
assert_file_contains "$report_file" "Power Feature Evidence" "power report section"
assert_file_contains "$report_file" "Generated payloads|Credential findings|OSINT findings|PoC results|Provider statuses" "power report evidence"

echo "Power integration smoke passed"
echo "session: $session_id"
