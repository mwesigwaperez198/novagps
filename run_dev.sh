#!/bin/sh
# Run NOVA GPS backend + frontend together in ONE terminal (dev mode).
# Backend:  http://127.0.0.1:8000   (FastAPI + built UI)
# Frontend: http://127.0.0.1:5173   (Vite dev server - live reload)
# Press Ctrl+C to stop both.
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
VENV="$ROOT/build/venv"
BE_PORT="${BE_PORT:-8000}"
FE_PORT="${FE_PORT:-5173}"

# ---- 0. Prerequisite check (fail fast with a clear message) ----
# The frontend stack (vite, vitest, eslint, jsdom) requires Node >= 18.
# Node 16/npm 8 (2022-era) crashes with "edgesOut" / Z_DATA_ERROR. Python
# must be >= 3.9 for the backend venv.
NODE_MAJOR="$(node -v 2>/dev/null | sed 's/^v//' | cut -d. -f1)"
if [ -z "$NODE_MAJOR" ] || [ "$NODE_MAJOR" -lt 18 ]; then
    printf '[NOVA] ERROR: Node.js 18+ is required.\n'
    printf '[NOVA]   Found: %s\n' "$(node -v 2>/dev/null || echo 'none')"
    printf '[NOVA]   Install Node 20 LTS, e.g. via nvm:\n'
    printf '[NOVA]     curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash\n'
    printf '[NOVA]     nvm install 20 && nvm use 20\n'
    printf '[NOVA]   Then re-run this script.\n'
    exit 1
fi

PY_MAJOR="$(python3 -c 'import sys; print(sys.version_info[0])' 2>/dev/null || true)"
PY_MINOR="$(python3 -c 'import sys; print(sys.version_info[1])' 2>/dev/null || true)"
if [ -z "$PY_MAJOR" ] || [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 9 ]; }; then
    printf '[NOVA] ERROR: Python 3.9+ is required for the backend.\n'
    printf '[NOVA]   Install Python 3.12, then re-run.\n'
    exit 1
fi

printf '[NOVA] Node %s / Python %s.%s OK\n' "$(node -v 2>/dev/null)" "$PY_MAJOR" "$PY_MINOR"

# ---- 1. Backend python env (create + deps) ----
if [ ! -x "$VENV/bin/python" ]; then
    printf '[NOVA] First run: creating Python env + installing backend deps...\n'
    # A stale/empty venv dir (e.g. from an interrupted run) makes "venv" fail
    # with "File exists". Remove it if present so we always start clean.
    rm -rf "$VENV"
    python3 -m venv "$VENV" || { printf '[NOVA] ERROR: could not create venv\n'; exit 1; }
    "$VENV/bin/pip" install --quiet -r "$ROOT/backend/requirements.txt" \
        || { printf '[NOVA] ERROR: backend deps failed to install. Fix and re-run.\n'; exit 1; }
fi

# ---- 2. Frontend deps ----
# .npmrc (legacy-peer-deps=true) is committed alongside this script so npm
# 8's arborist peer-resolver bug ("edgesOut" crash) is always bypassed.
NEED_INSTALL=0
if [ ! -d "$ROOT/frontend/node_modules" ]; then
    NEED_INSTALL=1
else
    # Stale/mismatched node_modules can break rollup (missing platform binary,
    # e.g. "@rollup/rollup-darwin-x64"). Verify rollup actually runs; if not, refresh.
    if [ -x "$ROOT/frontend/node_modules/.bin/rollup" ] \
       && "$ROOT/frontend/node_modules/.bin/rollup" --version >/dev/null 2>&1; then
        :
    else
        NEED_INSTALL=1
    fi
fi

if [ "$NEED_INSTALL" = "1" ]; then
    printf '[NOVA] Installing frontend deps...\n'
    # One clean pass: drop npm cache locks that can poison a reinstall, then
    # wipe project artifacts so the graph is rebuilt from scratch.
    (cd "$ROOT/frontend" && npm cache clean --force >/dev/null 2>&1 || true)
    rm -rf "$ROOT/frontend/node_modules" \
           "$ROOT/frontend/package-lock.json" \
           "$ROOT/frontend/node_modules/.package-lock.json"
    npm --prefix "$ROOT/frontend" install \
        || { printf '[NOVA] ERROR: frontend deps failed to install.\n'; \
             printf '[NOVA] Tip: run "npm install -g npm@latest" then re-run.\n'; exit 1; }
fi

# ---- 3. Start backend + frontend ----
NOVA_MODE=portable
ENVIRONMENT=development
DATA_DIR="$ROOT/backend/data"
DATABASE_URL="sqlite:///$DATA_DIR/nova.sqlite3"
export NOVA_MODE ENVIRONMENT DATA_DIR DATABASE_URL

trap 'printf "\n[NOVA] Stopping...\n"; kill 0 2>/dev/null' INT TERM

printf '[NOVA] Backend  -> http://127.0.0.1:%s\n' "$BE_PORT"
printf '[NOVA] Frontend -> http://127.0.0.1:%s\n' "$FE_PORT"
printf '[NOVA] Ctrl+C to stop both\n'

(
    cd "$ROOT/backend"
    exec "$VENV/bin/python" -m uvicorn main:app --host 127.0.0.1 --port "$BE_PORT"
) &

(
    cd "$ROOT/frontend"
    exec npm run dev -- --port "$FE_PORT"
) &

wait
