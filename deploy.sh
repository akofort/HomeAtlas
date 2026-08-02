#!/usr/bin/env bash
# Deployt HomeAtlas nach 192.168.1.110 und baut die Container neu.
# Login per SSH-Key (falls eingerichtet) oder per Passwort.
set -euo pipefail

HOST="${HOMEATLAS_HOST:-192.168.1.110}"
REMOTE_USER="${HOMEATLAS_USER:-root}"
REMOTE_DIR="${HOMEATLAS_DIR:-/opt/homeatlas}"
PORT="${HOMEATLAS_PORT:-8280}"
LOCAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SSH_OPTS=(-o StrictHostKeyChecking=accept-new)

echo "==> Verbinde mit $HOST"
ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$HOST" "mkdir -p $REMOTE_DIR/backend $REMOTE_DIR/frontend"

# Warnen, wenn der Port schon belegt ist -- sonst scheitert erst `docker compose up` mit einer
# wenig sprechenden Meldung, nachdem alles hochgeladen und gebaut wurde.
if ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$HOST" "ss -tlnp 2>/dev/null | grep -q ':$PORT '"; then
  echo "!!! Port $PORT ist auf $HOST bereits belegt."
  echo "    Anderen Port wählen: HOMEATLAS_PORT=8380 ./deploy.sh"
  exit 1
fi

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

echo "==> Baue und starte Container neu (Build $BUILD_SHA, Port $PORT)"
ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$HOST" \
  "cd $REMOTE_DIR && VITE_BUILD_SHA='$BUILD_SHA' VITE_BUILD_TIME='$BUILD_TIME' HOMEATLAS_PORT='$PORT' \
   docker compose up -d --build backend frontend"

echo "==> Health-Check"
sleep 3
ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$HOST" "curl -fsS http://127.0.0.1:8000/api/health" || {
  echo "!!! Backend antwortet nicht. Protokoll:"
  ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$HOST" "cd $REMOTE_DIR && docker compose logs --tail 40 backend"
  exit 1
}
echo

echo "==> Fertig. HomeAtlas läuft auf http://$HOST:$PORT"
echo
echo "    Beim allerersten Start steht das Anmeldepasswort einmalig im Protokoll:"
echo "      ssh $REMOTE_USER@$HOST 'cd $REMOTE_DIR && docker compose logs backend | grep -A4 Anmeldedaten'"
