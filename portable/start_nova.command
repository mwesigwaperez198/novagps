#!/usr/bin/env bash
# NOVA portable launcher (macOS) - double-click or run from Terminal
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${1:-8000}"
ARCH="$(uname -m)"
case "$ARCH" in
  arm64) RUNTIME="macos-aarch64" ;;
  x86_64) RUNTIME="macos-x86_64" ;;
  *) echo "[NOVA] Unsupported arch: $ARCH"; exit 1 ;;
esac

PY="$ROOT/runtime/$RUNTIME/python/bin/python3"
if [ ! -x "$PY" ]; then
  echo "[NOVA] Missing runtime for $RUNTIME. Run build_portable.py first."
  exit 1
fi

DATA_DIR="$ROOT/data"
if [ -d "$ROOT/secure/data" ]; then DATA_DIR="$ROOT/secure/data";
else echo "[NOVA] WARNING: unencrypted data dir - mount VeraCrypt into secure/data for at-rest protection."; fi

export NOVA_MODE=portable
export ENVIRONMENT=development
export DATA_DIR
export DATABASE_URL="sqlite:///$DATA_DIR/nova.sqlite3"
export PYTHONPATH="$ROOT/app/backend"
export PATH="$ROOT/runtime/$RUNTIME/python/bin:$PATH"

# macOS gatekeeper: clear quarantine on first run
xattr -dr com.apple.quarantine "$ROOT/runtime/$RUNTIME/python" >/dev/null 2>&1 || true

cd "$ROOT/app/backend"
echo "[NOVA] Bootstrapping portable database..."
"$PY" bootstrap_portable.py

( sleep 2; open "http://127.0.0.1:$PORT/" >/dev/null 2>&1 || true ) &
echo "[NOVA] Starting NOVA on http://127.0.0.1:$PORT/ (Ctrl+C to stop)"
exec "$PY" -m uvicorn main:app --host 127.0.0.1 --port "$PORT"
