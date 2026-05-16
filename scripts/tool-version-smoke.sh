#!/usr/bin/env sh
set -eu

mode="${1:-host}"
strict="${NOX_TOOL_SMOKE_STRICT:-0}"
missing_recommended=0

check_required() {
  name="$1"
  shift
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "missing required tool: $name" >&2
    return 1
  fi
  printf '%s: ' "$name"
  if "$@" 2>&1 | head -n 1; then
    return 0
  fi
  echo "available"
}

check_optional() {
  name="$1"
  shift
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "optional tool not installed: $name"
    return 0
  fi
  printf '%s: ' "$name"
  if "$@" 2>&1 | head -n 1; then
    return 0
  fi
  echo "available"
}

check_recommended() {
  name="$1"
  shift
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "recommended tool not installed: $name"
    missing_recommended=$((missing_recommended + 1))
    return 0
  fi
  printf '%s: ' "$name"
  if "$@" 2>&1 | head -n 1; then
    return 0
  fi
  echo "available"
}

check_required curl curl --version
check_required dig dig -v
check_required ffuf ffuf -V
check_required nikto nikto -Version
check_required nmap nmap --version
check_required python3 python3 --version
check_required sqlmap sqlmap --version
check_required whatweb whatweb --version
check_required whois whois --version

check_optional arjun arjun --version
check_optional dalfox dalfox version
check_optional dnsx dnsx -version
check_optional droopescan droopescan --version
check_optional gitleaks gitleaks version
check_optional httpx httpx -version
check_optional jwt_tool jwt_tool --version
check_optional linkfinder linkfinder --help
check_optional naabu naabu -version
check_optional nuclei nuclei -version
check_optional ssrfmap ssrfmap -h
check_optional subfinder subfinder -version
check_optional testssl.sh testssl.sh --version
check_optional waybackurls waybackurls -h
check_optional wpscan wpscan --version

if [ "$mode" = "linux-full" ]; then
  check_required git git --version
  check_required go go version
  check_required sqlite3 sqlite3 --version

  check_recommended semgrep semgrep --version
  check_recommended bandit bandit --version
  check_recommended gosec gosec -version
  check_recommended govulncheck govulncheck -version
  check_recommended npm npm --version
  check_recommended retire retire --version
  check_recommended safety safety --version
  check_recommended brakeman brakeman --version
  check_recommended spotbugs spotbugs -version
  check_recommended psalm psalm --version
  check_recommended trufflehog trufflehog --version
  check_recommended grype grype version
  check_recommended syft syft version

  if [ "$strict" = "1" ] && [ "$missing_recommended" -gt 0 ]; then
    echo "linux-full tool smoke failed: $missing_recommended recommended tools missing" >&2
    exit 1
  fi
fi

echo "tool version smoke passed (${mode})"
