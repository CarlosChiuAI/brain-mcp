#!/usr/bin/env bash
# Brain MCP installer. Run as root on the Docker HOST (not inside a container), behind Traefik.
#   bash install.sh            first install (asks for a password)
#   bash install.sh --password change the password only
# Settings come from deploy/local.env (copy deploy/local.env.example and edit it).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$HERE/local.env" ] || { echo "Missing $HERE/local.env. Copy local.env.example to local.env and edit it." >&2; exit 1; }
# shellcheck source=/dev/null
. "$HERE/local.env"
: "${DOMAIN:?set DOMAIN in local.env}" "${VAULT_DIR:?set VAULT_DIR in local.env}" "${STATE_DIR:?set STATE_DIR in local.env}"
APP_DIR="${APP_DIR:-$(dirname "$HERE")}"
RUN_UID="${RUN_UID:-1000}"
PROJECT="${PROJECT:-/opt/brain-mcp}"
IMAGE="${IMAGE:-node:22-alpine}"
ALLOW="${ALLOW:-*}"
DENY="${DENY:-}"
BRAIN_OWNER="${BRAIN_OWNER:-}"
BRAIN_WRITER="${BRAIN_WRITER:-}"
BRAIN_TZ="${BRAIN_TZ:-}"
CHANGE_PW=0

for arg in "$@"; do
  case "$arg" in
    --password) CHANGE_PW=1 ;;
    -h|--help) sed -n '2,4p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

say() { printf '\n==> %s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- checks
if [ -f /.dockerenv ]; then
  die "This looks like the inside of a container. Run it on the Docker host."
fi
[ "$(id -u)" -eq 0 ] || die "Run as root."
command -v docker >/dev/null || die "docker not found. Are you on the VPS host?"
docker compose version >/dev/null 2>&1 || die "'docker compose' plugin not found."
[ -f "$APP_DIR/src/server.mjs" ] || die "$APP_DIR/src/server.mjs not found."
[ -d "$APP_DIR/node_modules/@modelcontextprotocol/sdk" ] || die "node_modules missing. Run 'npm ci --omit=dev' in $APP_DIR first."
[ -d "$VAULT_DIR" ] || die "$VAULT_DIR not found."
[ -d "$STATE_DIR" ] || { mkdir -p "$STATE_DIR"; chown "$RUN_UID:$RUN_UID" "$STATE_DIR"; chmod 700 "$STATE_DIR"; }

mkdir -p "$PROJECT"; chmod 700 "$PROJECT"; cd "$PROJECT"

ask_password() {
  local pw1 pw2
  echo
  echo "Choose the Brain password. You type it on the Brain sign-in page when you connect an AI app."
  echo "Nothing shows while you type. At least 12 characters. Do not reuse another password."
  while :; do
    read -r -s -p "Password: " pw1; echo
    read -r -s -p "Type it again: " pw2; echo
    [ "$pw1" = "$pw2" ] || { echo "They don't match. Try again."; continue; }
    [ "${#pw1}" -ge 12 ] || { echo "Too short. Use at least 12 characters."; continue; }
    break
  done
  PW_HASH="$(printf '%s\n' "$pw1" | docker run --rm -i --network none -v "$APP_DIR:/app:ro" "$IMAGE" node /app/tools/hash-password.mjs)"
  unset pw1 pw2
  case "$PW_HASH" in scrypt\$*) ;; *) die "Hashing failed." ;; esac
}

write_env() {
  umask 077
  printf "BRAIN_PASSWORD_HASH='%s'\n" "$PW_HASH" > .env
  chmod 600 .env
}

if [ "$CHANGE_PW" -eq 1 ]; then
  [ -f docker-compose.yml ] || die "Not installed yet. Run install.sh without flags first."
  ask_password; write_env
  docker compose up -d --force-recreate
  echo "Password changed. Reconnect your AI app to sign in again."
  exit 0
fi

# ------------------------------------------------------------- traefik
say "Detecting Traefik"
TRAEFIK="$(docker ps --format '{{.Names}} {{.Image}}' | awk '$2 ~ /traefik/ {print $1; exit}')"
[ -n "$TRAEFIK" ] || die "No running Traefik container found."
NETMODE="$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$TRAEFIK")"
LABELS="$(docker ps -q | xargs -r docker inspect -f '{{range $k,$v := .Config.Labels}}{{$k}}={{$v}}{{"\n"}}{{end}}' 2>/dev/null || true)"
ENTRYPOINT="$(printf '%s\n' "$LABELS" | sed -n 's/^traefik\.http\.routers\.[^.]*\.entrypoints=\([^,]*\).*/\1/p' | grep -v '^web$' | sort | uniq -c | sort -rn | awk 'NR==1{print $2}')"
RESOLVER="$(printf '%s\n' "$LABELS" | sed -n 's/^traefik\.http\.routers\.[^.]*\.tls\.certresolver=\(.*\)/\1/p' | sort | uniq -c | sort -rn | awk 'NR==1{print $2}')"
ENTRYPOINT="${ENTRYPOINT:-websecure}"; RESOLVER="${RESOLVER:-letsencrypt}"
TRAEFIK_NET=""
if [ "$NETMODE" != "host" ]; then
  TRAEFIK_NET="$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' "$TRAEFIK" | grep -v '^$' | head -n1)"
fi
echo "Traefik: $TRAEFIK (network mode: $NETMODE${TRAEFIK_NET:+, network: $TRAEFIK_NET}), entrypoint: $ENTRYPOINT, resolver: $RESOLVER"

# ---------------------------------------------------------------- port
PORT=""
[ -f docker-compose.yml ] && PORT="$(sed -n 's/.*"127\.0\.0\.1:\([0-9]*\):8788".*/\1/p' docker-compose.yml | head -n1)"
if [ -z "$PORT" ]; then
  for p in $(seq 8788 8899); do
    [ -z "$(ss -ltnH "( sport = :$p )" 2>/dev/null)" ] && { PORT="$p"; break; }
  done
fi
[ -n "$PORT" ] || die "No free port between 8788 and 8899."
echo "Local port: 127.0.0.1:$PORT"

# ------------------------------------------------------------- secrets
if [ -f .env ] && grep -q '^BRAIN_PASSWORD_HASH=' .env; then
  echo "Keeping the existing password (change it with: bash install.sh --password)"
else
  ask_password; write_env
fi

# ------------------------------------------------------------- compose
say "Writing $PROJECT/docker-compose.yml"
[ -f docker-compose.yml ] && cp -p docker-compose.yml "docker-compose.yml.bak-$(date +%m%d%Y-%H%M%S)"
{
  cat <<YAML
services:
  brain-mcp:
    image: $IMAGE
    container_name: brain-mcp
    command: ["node", "/app/src/server.mjs"]
    restart: unless-stopped
    read_only: true
    user: "$RUN_UID:$RUN_UID"
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 160m
    pids_limit: 64
    tmpfs: ["/tmp:size=8m"]
    env_file: .env
    environment:
      NODE_ENV: production
      NODE_OPTIONS: "--max-old-space-size=64"
      PORT: "8788"
      BRAIN_PUBLIC_URL: "https://$DOMAIN"
      BRAIN_VAULT_DIR: /vault
      BRAIN_STATE_DIR: /state
      BRAIN_ALLOW: "$ALLOW"
      BRAIN_DENY: "$DENY"
      BRAIN_OWNER: "$BRAIN_OWNER"
      BRAIN_WRITER: "$BRAIN_WRITER"
      BRAIN_TZ: "$BRAIN_TZ"
    volumes:
      - $APP_DIR:/app:ro
      - $VAULT_DIR:/vault:ro
      - $STATE_DIR:/state:rw
    ports:
      - "127.0.0.1:$PORT:8788"
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8788/healthz"]
      interval: 30s
      timeout: 5s
      retries: 3
    labels:
      - traefik.enable=true
      - traefik.http.routers.brain-mcp.rule=Host(\`$DOMAIN\`)
      - traefik.http.routers.brain-mcp.entrypoints=$ENTRYPOINT
      - traefik.http.routers.brain-mcp.tls.certresolver=$RESOLVER
      - traefik.http.services.brain-mcp.loadbalancer.server.port=8788
YAML
  if [ -n "$TRAEFIK_NET" ]; then
    cat <<YAML
      - traefik.docker.network=$TRAEFIK_NET
    networks:
      - traefik
networks:
  traefik:
    external: true
    name: $TRAEFIK_NET
YAML
  fi
} > docker-compose.yml

say "Starting the container"
docker compose up -d
sleep 4
if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
  echo "Health check OK on 127.0.0.1:$PORT"
else
  echo "Health check did not answer yet. Check with: docker logs --tail 30 brain-mcp"
fi

cat <<DONE

==> Done.
  Connector URL:  https://$DOMAIN/mcp
  Logs:                      docker logs --tail 50 brain-mcp
  Change password:           bash install.sh --password
  Remove:                    bash uninstall.sh
DONE
