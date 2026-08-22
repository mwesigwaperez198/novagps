#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) RUNTIME="linux-x86_64" ;;
  aarch64|arm64) RUNTIME="linux-aarch64" ;;
  *) RUNTIME="macos-$ARCH" ;;
esac
PY="$ROOT/runtime/$RUNTIME/python/bin/python3"
export NOVA_MODE=portable ENVIRONMENT=development
export DATA_DIR="$ROOT/data"; [ -d "$ROOT/secure/data" ] && DATA_DIR="$ROOT/secure/data"
export DATABASE_URL="sqlite:///$DATA_DIR/nova.sqlite3"
export PYTHONPATH="$ROOT/app/backend"
echo "=== NOVA doctor: bootstrap check ==="
"$PY" bootstrap_portable.py
echo "=== NOVA doctor: security tools on PATH ==="
PYTHONPATH="$ROOT/app/backend:$PYTHONPATH" "$PY" "$ROOT/app/backend/doctor_tools.py" 2>/dev/null || PYTHONPATH="$ROOT/app/backend" "$PY" doctor_tools.py
