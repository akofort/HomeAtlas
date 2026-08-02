#!/usr/bin/env bash
# Deployt HomeAtlas nach 192.168.1.110 und baut die Container neu.
# Login per SSH-Key (falls eingerichtet) oder per Passwort.
set -euo pipefail

HOST="${HOMEATLAS_HOST:-192.168.1.110}"
REMOTE_USER="${HOMEATLAS_USER:-root}"
REMOTE_DIR="${HOMEATLAS_DIR:-/opt/homeatlas}"
PORT="${HOMEATLAS_PORT:-8280}"
API_PORT="${HOMEATLAS_API_PORT:-8281}"
LOCAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SSH_OPTS=(-o StrictHostKeyChecking=accept-new)

echo "==> Verbinde mit $HOST"
ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$HOST" "mkdir -p $REMOTE_DIR/backend $REMOTE_DIR/frontend"

# Beide Container laufen im Host-Netz -- die Ports sind also die des Docker-Hosts und kollidieren
# mit allem, was dort schon lauscht. Vorher prüfen, sonst scheitert erst `docker compose up`,
# nachdem alles hochgeladen und gebaut wurde.
#
# Die eigenen Container werden dabei ignoriert: beim Re-Deploy hält der noch laufende alte Stand
# die Ports selbst, das ist kein Konflikt.
check_port() {
  local port="$1" label="$2" var="$3"
  local holder
  holder="$(ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$HOST" \
    "ss -tlnpH 2>/dev/null | awk -v p=\":$port\$\" '\$4 ~ p {print \$6; exit}'" || true)"
  if [ -n "$holder" ] && ! echo "$holder" | grep -qE 'nginx|uvicorn|python'; then
    echo "!!! Port $port ($label) ist auf $HOST bereits belegt von: $holder"
    echo "    Anderen Port wählen: $var=$((port + 100)) ./deploy.sh"
    return 1
  fi
  return 0
}

check_port "$PORT" "Oberfläche" "HOMEATLAS_PORT" || exit 1
check_port "$API_PORT" "Backend-API" "HOMEATLAS_API_PORT" || exit 1

echo "==> Lade Backend hoch"
scp -rq "${SSH_OPTS[@]}" \
  "$LOCAL_DIR/backend/app" "$LOCAL_DIR/backend/requirements.txt" "$LOCAL_DIR/backend/Dockerfile" \
  "$REMOTE_USER@$HOST:$REMOTE_DIR/backend/"

echo "==> Lade Frontend hoch"
scp -rq "${SSH_OPTS[@]}" \
  "$LOCAL_DIR/frontend/src" "$LOCAL_DIR/frontend/index.html" \
  "$LOCAL_DIR/frontend/package.json" "$LOCAL_DIR/frontend/package-lock.json" \
  "$LOCAL_DIR/frontend/vite.config.ts" "$LOCAL_DIR/frontend/tsconfig.json" \
  "$LOCAL_DIR/frontend/nginx.conf.template" "$LOCAL_DIR/frontend/Dockerfile" \
  "$REMOTE_USER@$HOST:$REMOTE_DIR/frontend/"

scp -q "${SSH_OPTS[@]}" "$LOCAL_DIR/docker-compose.yml" "$REMOTE_USER@$HOST:$REMOTE_DIR/"

BUILD_SHA="$(git -C "$LOCAL_DIR" rev-parse --short HEAD 2>/dev/null || echo dev)"
if ! git -C "$LOCAL_DIR" diff --quiet HEAD 2>/dev/null; then
  BUILD_SHA="$BUILD_SHA-dirty"
fi
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "==> Baue und starte Container neu (Build $BUILD_SHA, UI $PORT, API $API_PORT)"
ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$HOST" \
  "cd $REMOTE_DIR && VITE_BUILD_SHA='$BUILD_SHA' VITE_BUILD_TIME='$BUILD_TIME' \
   HOMEATLAS_PORT='$PORT' HOMEATLAS_API_PORT='$API_PORT' \
   docker compose up -d --build backend frontend"

echo "==> Health-Check"
# Der erste Start legt die Datenbank an und kann ein paar Sekunden brauchen -- deshalb mehrere
# Versuche statt eines einzelnen sleep.
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$HOST" "curl -fsS http://127.0.0.1:$API_PORT/api/health"; then
    echo
    break
  fi
  if [ "$attempt" = 10 ]; then
    echo "!!! Backend antwortet nicht. Protokoll:"
    ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$HOST" "cd $REMOTE_DIR && docker compose logs --tail 40 backend"
    exit 1
  fi
  sleep 2
done

echo "==> Fertig. HomeAtlas läuft auf http://$HOST:$PORT"
echo
echo "    Beim allerersten Start steht das Anmeldepasswort einmalig im Protokoll:"
echo "      ssh $REMOTE_USER@$HOST 'cd $REMOTE_DIR && docker compose logs backend | grep -A4 Anmeldedaten'"
