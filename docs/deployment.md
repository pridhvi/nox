# Nox Deployment Notes

## Docker

Build and run the container locally:

```sh
docker build -t nox:local .
NOX_API_KEY=$(openssl rand -hex 24)
docker run --rm -p 127.0.0.1:8080:8080 -e NOX_API_KEY="$NOX_API_KEY" -v nox-data:/home/nox/.nox nox:local serve --host 0.0.0.0 --port 8080
curl -H "X-Nox-API-Key: $NOX_API_KEY" http://127.0.0.1:8080/api/health
```

The web console prompts for the same API key when auth is enabled and stores only an opaque HttpOnly session cookie. Do not put API keys in URLs; query-string API keys are rejected.

Run the packaged smoke check:

```sh
make docker-smoke
```

The smoke check builds the image, starts Nox, verifies `/api/health`, verifies
`/api/tools`, and runs `nox version` inside the container.

## Compose

`docker-compose.yml` starts Nox and Ollama with persistent volumes:

```sh
export NOX_API_KEY=$(openssl rand -hex 24)
docker compose up --build
```

Compose publishes Nox on `127.0.0.1:6767` and requires `NOX_API_KEY`. Nox refuses to bind to non-loopback interfaces without an API key.

For containerized custom config, create a config file and mount it at
`/home/nox/.nox/config.yaml`:

```sh
mkdir -p config
nox config init --path config/nox.yaml
docker run --rm -p 127.0.0.1:8080:8080 \
  -e NOX_API_KEY="$NOX_API_KEY" \
  -v nox-data:/home/nox/.nox \
  -v "$PWD/config/nox.yaml:/config/nox.yaml:ro" \
  nox:local serve --config /config/nox.yaml --host 0.0.0.0 --port 8080
```

LLM settings can be provided through the config file or environment variables:

```yaml
llm:
  enabled: true
  provider: openai-compatible
  base_url: http://ollama:11434/v1
  model: llama3:8b
```

For tighter host deployments, constrain source scans and LLM model probing:

```sh
export NOX_SOURCE_ROOTS=/srv/audits,/work/repos
export NOX_LLM_ALLOWED_HOSTS=127.0.0.1,localhost,ollama
```

Single-binary local mode remains supported. Optional external tools degrade
gracefully when they are not installed.

## Linux VM Scanner Validation

For a Linux VM intended to run the full external scanner toolchain, start with:

```sh
scripts/install-linux-tools.sh
scripts/tool-version-smoke.sh linux-full
NOX_RUN_LINUX_FULL=1 make linux-full-smoke
```

`scripts/install-linux-tools.sh` is dry-run by default and can be run with
`--execute` on a disposable VM. `scripts/linux-full-smoke.sh` starts the local
vulnerable fixture and validates dynamic, lean, audit, combined, sidecar-log,
and report paths. Use `NOX_TOOL_SMOKE_STRICT=1` with the tool-version smoke to
fail when recommended optional audit tools are missing.

See [linux-vm-validation.md](linux-vm-validation.md) for the complete checklist.

## Release Snapshots

Use:

```sh
make release-snapshot
```

The snapshot release runs the frontend build before compiling binaries so the
embedded UI is included in release artifacts.
