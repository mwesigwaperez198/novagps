#!/bin/sh
# Run NOVA GPS backend ONLY. Serves the built frontend at the root URL.
#   http://127.0.0.1:8000   (FastAPI + built UI from frontend/dist)
# Press Ctrl+C to stop.
#
# When to use: machines whose Node/npm can't run the dev toolchain (e.g. macOS
# Catalina). No Node, npm or Docker needed -- the UI is prebuilt and committed
# to git, and FastAPI mounts it automatically (see backend/main.py).
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
VENV="$ROOT/build/venv"
BE_PORT="${BE_PORT:-8000}"
BIND_HOST="${HOST:-127.0.0.1}"

# ---- 0. The built UI must exist (backend serves it at the root) ----
if [ ! -f "$ROOT/frontend/dist/index.html" ]; then
    printf '[NOVA] ERROR: missing frontend/dist/index.html\n'
    printf '[NOVA]   This machine does not need Node -- the UI is committed to git.\n'
    printf '[NOVA]   Run "git pull" first, or build the UI on any Node 18+ machine\n'
    printf '[NOVA]   with "cd frontend && npm install && npm run build" and re-push.\n'
    exit 1
fi

# ---- 1. Backend python env (create + deps) ----
# Python must actually be able to import uvicorn, not just exist: an earlier
# interrupted install (e.g. the old cryptography source-build failure) leaves a
# venv with no deps while the python binary itself is present.
if ! "$VENV/bin/python" -c 'import uvicorn, fastapi' >/dev/null 2>&1; then
    printf '[NOVA] Preparing Python env + installing backend deps...\n'
    rm -rf "$VENV"
    python3 -m venv "$VENV" || { printf '[NOVA] ERROR: could not create venv\n'; exit 1; }
    "$VENV/bin/pip" install --quiet -r "$ROOT/backend/requirements.txt" \
        || { printf '[NOVA] ERROR: backend deps failed to install. Fix and re-run.\n'; exit 1; }
    printf '[NOVA]   ...backend deps installed\n'
fi

# ---- 2. Start backend ----
NOVA_MODE=portable
ENVIRONMENT=development
DATA_DIR="$ROOT/backend/data"
DATABASE_URL="sqlite:///$DATA_DIR/nova.sqlite3"
export NOVA_MODE ENVIRONMENT DATA_DIR DATABASE_URL

printf '[NOVA] NOVA GPS running at -> http://%s:%s\n' "$BIND_HOST" "$BE_PORT"
printf '[NOVA] Ctrl+C to stop\n'

cd "$ROOT/backend"
exec "$VENV/bin/python" -m uvicorn main:app --host "$BIND_HOST" --port "$BE_PORT"