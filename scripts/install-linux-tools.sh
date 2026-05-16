#!/usr/bin/env sh
set -eu

execute=0
with_optional=1

usage() {
  cat <<'USAGE'
Usage: scripts/install-linux-tools.sh [--execute] [--minimal]

Print a Linux VM tool installation plan for Nox. By default the script is
dry-run only. Pass --execute to run supported package-manager and Go install
commands on the current host.

Options:
  --execute   run commands instead of printing them
  --minimal   install only baseline dynamic scanner dependencies
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --execute)
      execute=1
      ;;
    --minimal)
      with_optional=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

run() {
  if [ "$execute" = "1" ]; then
    echo "+ $*"
    sh -c "$*"
  else
    echo "$*"
  fi
}

echo "# Nox Linux tool setup"
if [ "$execute" != "1" ]; then
  echo "# Dry run. Re-run with --execute to apply supported commands."
fi
echo

if command -v apt-get >/dev/null 2>&1; then
  packages="ca-certificates curl git jq sqlite3 build-essential dnsutils ffuf nikto nmap python3 python3-pip python3-venv sqlmap whatweb whois ruby-full default-jre npm golang-go pipx"
  run "sudo apt-get update"
  run "sudo apt-get install -y $packages"
elif command -v dnf >/dev/null 2>&1; then
  packages="ca-certificates curl git jq sqlite gcc gcc-c++ make bind-utils ffuf nmap python3 python3-pip pipx ruby java-latest-openjdk npm golang whois"
  run "sudo dnf install -y $packages"
  echo "# Install nikto, sqlmap, and whatweb from your distro/security repo if unavailable."
elif command -v pacman >/dev/null 2>&1; then
  packages="ca-certificates curl git jq sqlite base-devel bind ffuf nmap python python-pip python-pipx ruby jre-openjdk npm go whois"
  run "sudo pacman -Sy --needed $packages"
  echo "# Install nikto, sqlmap, and whatweb from your distro/security repo if unavailable."
else
  echo "# No supported package manager detected. Install baseline packages manually:"
  echo "# curl git jq sqlite3 dig ffuf nikto nmap python3 pip sqlmap whatweb whois ruby java npm go"
fi

echo
echo "# Go-installed dynamic scanners"
run "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
run "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
run "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
run "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
run "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
run "go install github.com/hahwul/dalfox/v2@latest"
run "go install github.com/gitleaks/gitleaks/v8@latest"
run "go install github.com/trufflesecurity/trufflehog/v3@latest"

if [ "$with_optional" = "1" ]; then
  echo
  echo "# Optional static/dependency audit tools"
  if command -v pipx >/dev/null 2>&1; then
    run "pipx install semgrep"
    run "pipx install bandit"
    run "pipx install safety"
    run "pipx install arjun"
    run "pipx install linkfinder"
    run "pipx install droopescan"
  else
    run "python3 -m pip install --user --upgrade semgrep bandit safety arjun linkfinder droopescan"
  fi
  run "go install github.com/securego/gosec/v2/cmd/gosec@latest"
  run "go install golang.org/x/vuln/cmd/govulncheck@latest"
  run "npm install -g retire"
  run "gem install --user-install brakeman"
  echo "# Psalm is a PHP Composer tool; install it through Composer when PHP audit coverage is needed."
  echo "# SpotBugs is Java-based; install it from your distro package manager or release archive."
  echo "# Grype and Syft can be installed from Anchore packages or release installers."
fi

cat <<'NEXT'

# Ensure Go/Python/Ruby user binary directories are on PATH, then validate:
export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"
scripts/tool-version-smoke.sh linux-full

# For a strict acceptance gate where recommended audit tools must be present:
NOX_TOOL_SMOKE_STRICT=1 scripts/tool-version-smoke.sh linux-full
NEXT
