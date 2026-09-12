#!/bin/sh
# LAU chat launcher — run from anywhere, keeps LAU's memory next to the repo in ./data
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"

export NOVA_DATA_DIR="$ROOT/data"
export NOVA_VAULT_DIR="$ROOT/data/nova_vault"
export NOVA_PROJECT_ROOT="$ROOT"
export NOVA_BACKEND_DIR="$ROOT/backend"
export NOVA_LOG_FILE="$NOVA_VAULT_DIR/agent.log"
export NOVA_MEMORY_DB="$NOVA_VAULT_DIR/local_memory.db"
export NOVA_ESCROW_BIN="$NOVA_VAULT_DIR/secure_escrow.bin"
export NOVA_ALERT_FILE="$NOVA_VAULT_DIR/alerts.json"
export NOVA_BACKEND_URL="${NOVA_BACKEND_URL:-https://novagps.onrender.com}"

# Auto-start the local Ollama server if it isn't already running, so the
# only thing you ever have to type is ./lau.sh
if command -v ollama >/dev/null 2>&1 && ! curl -fsS --max-time 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
  echo "waking LAU's reasoning engine (starting ollama serve)…"
  nohup ollama serve >/tmp/ollama.log 2>&1 &
  sleep 4
fi

# Prefer the bigger brain when it's already been pulled, else keep the default.
if [ -z "${OLLAMA_MODEL:-}" ] && curl -fsS --max-time 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && ollama list 2>/dev/null | grep -q "llama3:8b"; then
  export OLLAMA_MODEL="llama3:8b"
fi

if [ -x "$ROOT/.venv/bin/python" ]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="${PYTHON:-python3}"
fi

if ! "$PY" -c "import fastapi, pydantic, httpx" >/dev/null 2>&1; then
  echo ""
  echo "LAU needs 3 Python packages. One-time setup (in $ROOT):"
  echo ""
  echo "  python3 -m venv .venv"
  echo "  .venv/bin/pip install fastapi pydantic httpx"
  echo ""
  echo "Then run ./lau.sh again."
  echo ""
  exit 1
fi

exec "$PY" -m nova_core "$@"