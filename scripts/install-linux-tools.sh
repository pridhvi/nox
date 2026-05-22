#!/usr/bin/env sh
set -eu

execute=0
with_optional=1
user_path='$HOME/go/bin:$HOME/.local/bin:$HOME/.config/composer/vendor/bin:$(ruby -rrubygems -e '\''print Gem.user_dir'\'' 2>/dev/null)/bin'

usage() {
  cat <<'USAGE'
Usage: scripts/install-linux-tools.sh [--execute] [--minimal]

Print a Linux VM tool installation plan for Nyx. By default the script is
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

install_linkfinder() {
  linkfinder_ref="${NYX_LINKFINDER_REF:-master}"
  if command -v linkfinder >/dev/null 2>&1; then
    echo "# LinkFinder is already available; skipping source install."
    return 0
  fi
  if [ "$execute" = "1" ]; then
    echo "+ install LinkFinder $linkfinder_ref from source"
    tmp_dir="$(mktemp -d)"
    install_dir="$HOME/.local/share/nyx-linkfinder"
    git clone --depth 1 --branch "$linkfinder_ref" https://github.com/GerbenJavado/LinkFinder.git "$tmp_dir/LinkFinder"
    rm -rf "$install_dir/LinkFinder"
    mkdir -p "$install_dir" "$HOME/.local/bin"
    python3 -m venv "$install_dir/venv"
    "$install_dir/venv/bin/python" -m pip install --upgrade pip
    "$install_dir/venv/bin/python" -m pip install -r "$tmp_dir/LinkFinder/requirements.txt"
    cp -R "$tmp_dir/LinkFinder" "$install_dir/LinkFinder"
    cat >"$HOME/.local/bin/linkfinder" <<'SH'
#!/usr/bin/env sh
exec "$HOME/.local/share/nyx-linkfinder/venv/bin/python" "$HOME/.local/share/nyx-linkfinder/LinkFinder/linkfinder.py" "$@"
SH
    chmod 755 "$HOME/.local/bin/linkfinder"
    rm -rf "$tmp_dir"
  else
    echo "tmp_dir=\"\$(mktemp -d)\""
    echo "install_dir=\"\$HOME/.local/share/nyx-linkfinder\""
    echo "git clone --depth 1 --branch \"$linkfinder_ref\" https://github.com/GerbenJavado/LinkFinder.git \"\$tmp_dir/LinkFinder\""
    echo "python3 -m venv \"\$install_dir/venv\""
    echo "\"\$install_dir/venv/bin/python\" -m pip install --upgrade pip"
    echo "\"\$install_dir/venv/bin/python\" -m pip install -r \"\$tmp_dir/LinkFinder/requirements.txt\""
    echo "cp -R \"\$tmp_dir/LinkFinder\" \"\$install_dir/LinkFinder\""
    echo "cat >\"\$HOME/.local/bin/linkfinder\" <<'SH'"
    echo '#!/usr/bin/env sh'
    echo 'exec "$HOME/.local/share/nyx-linkfinder/venv/bin/python" "$HOME/.local/share/nyx-linkfinder/LinkFinder/linkfinder.py" "$@"'
    echo "SH"
    echo "chmod 755 \"\$HOME/.local/bin/linkfinder\""
    echo "rm -rf \"\$tmp_dir\""
  fi
}

echo "# Nyx Linux tool setup"
if [ "$execute" != "1" ]; then
  echo "# Dry run. Re-run with --execute to apply supported commands."
fi
echo "# Recommended PATH for user-installed tools:"
echo "# export PATH=\"$user_path:\$PATH\""
echo

if command -v apt-get >/dev/null 2>&1; then
  packages="ca-certificates curl git jq sqlite3 build-essential dnsutils ffuf nikto nmap python3 python3-pip python3-venv sqlmap whatweb whois default-jre golang-go pipx"
  if command -v npm >/dev/null 2>&1; then
    echo "# npm is already available; skipping distro npm package to avoid NodeSource/Kali package conflicts."
  else
    packages="$packages npm"
  fi
  if command -v ruby >/dev/null 2>&1 && command -v gem >/dev/null 2>&1; then
    echo "# ruby and gem are already available; skipping distro ruby-full package."
  else
    packages="$packages ruby-full"
  fi
  run "sudo apt-get update"
  run "sudo apt-get install -y $packages"
  if apt-cache show arjun >/dev/null 2>&1; then
    run "sudo apt-get install -y arjun"
  else
    echo "# arjun is not available from this apt repository; install it with pipx if needed."
  fi
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
run "mkdir -p \"\$HOME/go/bin\" \"\$HOME/.local/bin\""
run "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
run "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
run "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
run "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
run "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
run "go install github.com/hahwul/dalfox/v2@latest"
run "go install github.com/zricethezav/gitleaks/v8@latest"
trufflehog_version="${NYX_TRUFFLEHOG_VERSION:-v3.95.3}"
if command -v trufflehog >/dev/null 2>&1; then
  echo "# trufflehog is already available; skipping source install."
elif [ "$execute" = "1" ]; then
  echo "+ install trufflehog $trufflehog_version from source"
  tmp_dir="$(mktemp -d)"
  git clone --depth 1 --branch "$trufflehog_version" https://github.com/trufflesecurity/trufflehog.git "$tmp_dir/trufflehog"
  (cd "$tmp_dir/trufflehog" && GOBIN="$HOME/go/bin" go install .)
  rm -rf "$tmp_dir"
else
  echo "tmp_dir=\"\$(mktemp -d)\""
  echo "git clone --depth 1 --branch \"$trufflehog_version\" https://github.com/trufflesecurity/trufflehog.git \"\$tmp_dir/trufflehog\""
  echo "(cd \"\$tmp_dir/trufflehog\" && GOBIN=\"\$HOME/go/bin\" go install .)"
  echo "rm -rf \"\$tmp_dir\""
fi

if [ "$with_optional" = "1" ]; then
  echo
  echo "# Optional static/dependency audit tools"
  if command -v pipx >/dev/null 2>&1; then
    run "pipx ensurepath"
    run "pipx install semgrep"
    run "pipx install bandit"
    run "pipx install safety"
    install_linkfinder
    python_major_minor="$(python3 - <<'PY'
import sys
print(f"{sys.version_info.major}.{sys.version_info.minor}")
PY
)"
    case "$python_major_minor" in
      3.12|3.13|3.14|3.15|3.16|3.17|3.18|3.19)
        echo "# Skipping pipx droopescan on Python $python_major_minor; current releases depend on removed stdlib imp."
        echo "# Use a distro package or an older dedicated Python runtime if Drupal/WordPress droopescan coverage is required."
        ;;
      *)
        run "pipx install droopescan"
        ;;
    esac
  else
    run "python3 -m pip install --user --upgrade semgrep bandit safety"
    install_linkfinder
    echo "# Install arjun from your package manager when available; avoid pip-installed droopescan on Python 3.12+."
  fi
  run "go install github.com/securego/gosec/v2/cmd/gosec@latest"
  run "go install golang.org/x/vuln/cmd/govulncheck@latest"
  if command -v retire >/dev/null 2>&1; then
    echo "# retire is already available; skipping npm global install."
  else
    run "npm install -g --prefix \"\$HOME/.local\" retire"
  fi
  run "gem install --user-install brakeman"
  if command -v composer >/dev/null 2>&1; then
    run "composer global require vimeo/psalm"
    if [ "$execute" = "1" ]; then
      cat >"$HOME/.local/bin/psalm" <<'SH'
#!/usr/bin/env sh
exec "$HOME/.config/composer/vendor/bin/psalm" "$@"
SH
      chmod 755 "$HOME/.local/bin/psalm"
      echo "+ installed user-local Psalm shim at $HOME/.local/bin/psalm"
    else
      echo "cat >\"\$HOME/.local/bin/psalm\" <<'SH'"
      echo '#!/usr/bin/env sh'
      echo 'exec "$HOME/.config/composer/vendor/bin/psalm" "$@"'
      echo "SH"
      echo "chmod 755 \"\$HOME/.local/bin/psalm\""
    fi
  else
    echo "# Composer was not found; install Composer before enabling Psalm PHP audit coverage."
  fi
  echo "# SpotBugs is Java-based; install it from your distro package manager or release archive."
  echo "# Grype and Syft can be installed from Anchore packages or release installers:"
  echo "# curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b \"\$HOME/.local/bin\""
  echo "# curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b \"\$HOME/.local/bin\""
fi

cat <<'NEXT'

# Ensure Go/Python/Ruby user binary directories are on PATH before system shims, then validate:
export PATH="$HOME/go/bin:$HOME/.local/bin:$HOME/.config/composer/vendor/bin:$(ruby -rrubygems -e 'print Gem.user_dir' 2>/dev/null)/bin:$PATH"
scripts/tool-version-smoke.sh linux-full

# For a strict acceptance gate where recommended audit tools must be present:
NYX_TOOL_SMOKE_STRICT=1 scripts/tool-version-smoke.sh linux-full
NEXT
