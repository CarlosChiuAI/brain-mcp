#!/usr/bin/env bash
# Stops and removes the Brain MCP container. Keeps the vault untouched.
# Run as root on the Docker host. Reads deploy/local.env.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$HERE/local.env" ] && . "$HERE/local.env"
PROJECT="${PROJECT:-/opt/brain-mcp}"
: "${STATE_DIR:?set STATE_DIR in local.env}"
[ -f /.dockerenv ] && { echo "Run this on the host, not inside a container." >&2; exit 1; }
if [ -f "$PROJECT/docker-compose.yml" ]; then
  docker compose -f "$PROJECT/docker-compose.yml" down
fi
rm -f "$STATE_DIR/state.json"
echo "Brain MCP stopped and removed. Sign-in tokens deleted. Vault untouched."
echo "Config kept in $PROJECT (delete it with: rm -rf $PROJECT)."
echo "Also remove the connector in your AI app."
