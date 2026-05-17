#!/usr/bin/env sh
set -eu

image="${NYX_DOCKER_IMAGE:-nyx:smoke}"
container="${NYX_DOCKER_CONTAINER:-nyx-smoke}"
port="${NYX_DOCKER_PORT:-16767}"
api_key="${NYX_API_KEY:-nyx-smoke-api-key}"

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker build -t "$image" .
cleanup
docker run -d --name "$container" -p "127.0.0.1:${port}:6767" -e "NYX_API_KEY=${api_key}" "$image" >/dev/null

deadline=$(($(date +%s) + 45))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if curl -fsS -H "X-Nyx-API-Key: ${api_key}" "http://127.0.0.1:${port}/api/health" >/dev/null; then
    docker exec "$container" nyx version
    docker exec "$container" nyx-tool-version-smoke docker
    curl -fsS -H "X-Nyx-API-Key: ${api_key}" "http://127.0.0.1:${port}/api/tools" >/dev/null
    echo "Docker smoke passed on http://127.0.0.1:${port}"
    exit 0
  fi
  sleep 1
done

docker logs "$container" >&2 || true
echo "Docker smoke failed: health endpoint did not become ready" >&2
exit 1
