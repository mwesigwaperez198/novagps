#!/bin/sh
# Run NOVA GPS backend (native Python) + frontend (Node 24 in Docker) in ONE terminal.
# Backend:  http://127.0.0.1:8000   (FastAPI + built UI)
# Frontend: http://127.0.0.1:5173   (Vite dev server in a node:24 container)
# Press Ctrl+C to stop both.
#
# Why Docker: macOS Catalina cannot run Node >= 20 prebuilt binaries ("dyld:
# Symbol not found"). Running the frontend inside a node:24 container uses the
# LATEST LTS unchanged - nothing is downgraded.
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
VENV="$ROOT/build/venv"
NODE_IMG="node:24"
VOLUME="novagps_node_modules"
BE_PORT="${BE_PORT:-8000}"
FE_PORT="${FE_PORT:-5173}"

# ---- 0. Docker must be running ----
if ! docker info >/dev/null 2>&1; then
    printf '[NOVA] ERROR: Docker is not running.\n'
    printf '[NOVA]   Start Docker Desktop, wait for the whale icon to be steady, then re-run.\n'
    exit 1
fi

# ---- 1. Backend python env (create + install deps on first run) ----
if [ ! -x "$VENV/bin/python" ]; then
    printf '[NOVA] First run: creating Python env + installing backend deps...\n'
    rm -rf "$VENV"
    python3 -m venv "$VENV" || { printf '[NOVA] ERROR: could not create venv\n'; exit 1; }
    "$VENV/bin/pip" install --quiet -r "$ROOT/backend/requirements.txt" \
        || { printf '[NOVA] ERROR: backend deps failed to install. Fix and re-run.\n'; exit 1; }
fi

# ---- 2. Frontend deps, installed by Node 24 inside the container ----
# node_modules lives in a named Docker volume so Linux binaries never touch the
# host disk. npm's cache goes to a throwaway dir inside the volume too.
docker volume inspect "$VOLUME" >/dev/null 2>&1 || docker volume create "$VOLUME" >/dev/null

# Node fights Docker VMs unless it sees a sane CPU count: cap the container so
# it never spawns an absurd number of worker threads ("uv_thread_create"
# assertion / OOM on small Macs).
NODE_RUN_ARGS="--cpus=2 -e UV_THREADPOOL_SIZE=4 -e NODE_OPTIONS=--max-old-space-size=2048"

if ! docker run --rm -v "${VOLUME}:/nm" "$NODE_IMG" sh -c 'test -x /nm/.bin/vite' >/dev/null 2>&1; then
    printf '[NOVA] Installing frontend deps in %s container...\n' "$NODE_IMG"
    printf '[NOVA]   Container view -> '
    docker run --rm $NODE_RUN_ARGS "$NODE_IMG" node -e \
        "const os=require('os'); console.log('node', process.version, '| cpus', os.cpus().length, '| mem', Math.round(os.totalmem()/1048576)+'MB')" 2>&1 \
        || printf '(node probe failed - see above)\n'
    docker run --rm $NODE_RUN_ARGS \
        -v "$ROOT/frontend:/app" \
        -v "${VOLUME}:/app/node_modules" \
        -v "${VOLUME}:/cache" \
        -w /app \
        -e npm_config_cache=/cache/.npm \
        -e npm_config_fund=false \
        -e npm_config_audit=false \
        "$NODE_IMG" \
        sh -c 'test -f package-lock.json && npm ci || npm install' \
        || { printf '[NOVA] ERROR: frontend deps failed to install. Fix and re-run.\n'; exit 1; }
    printf '[NOVA]   ...frontend deps installed\n'
fi

# ---- 3. Start backend + frontend ----
NOVA_MODE=portable
ENVIRONMENT=development
DATA_DIR="$ROOT/backend/data"
DATABASE_URL="sqlite:///$DATA_DIR/nova.sqlite3"
export NOVA_MODE ENVIRONMENT DATA_DIR DATABASE_URL

trap 'printf "\n[NOVA] Stopping...\n"; kill 0 2>/dev/null' INT TERM

printf '[NOVA] Backend  -> http://127.0.0.1:%s\n' "$BE_PORT"
printf '[NOVA] Frontend -> http://127.0.0.1:%s   (Node %s in Docker)\n' "$FE_PORT" "$NODE_IMG"
printf '[NOVA] Ctrl+C to stop both\n'

(
    cd "$ROOT/backend"
    exec "$VENV/bin/python" -m uvicorn main:app --host 127.0.0.1 --port "$BE_PORT"
) &

(
    docker run --rm $NODE_RUN_ARGS \
        -p "${FE_PORT}:5173" \
        -v "$ROOT/frontend:/app" \
        -v "${VOLUME}:/app/node_modules" \
        -v "${VOLUME}:/cache" \
        -w /app \
        -e npm_config_cache=/cache/.npm \
        "$NODE_IMG" \
        npm run dev -- --host 0.0.0.0 --port 5173
) &

wait