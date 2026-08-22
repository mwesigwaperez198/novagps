#!/usr/bin/env bash
# Run NOVA directly on this PC - no Docker needed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$ROOT/build/venv"

if [ ! -x "$VENV/bin/python" ]; then
    echo "[NOVA] First run: creating local Python environment..."
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install --quiet -r "$ROOT/backend/requirements.txt"
fi

export NOVA_MODE=portable
export ENVIRONMENT=development
export DATA_DIR="$ROOT/backend/data"
export DATABASE_URL="sqlite:///$DATA_DIR/nova.sqlite3"

cd "$ROOT/backend"
echo "[NOVA] Dashboard: http://127.0.0.1:8000 (Ctrl+C to stop)"
exec "$VENV/bin/python" -m uvicorn main:app --host 127.0.0.1 --port "${1:-8000}"
