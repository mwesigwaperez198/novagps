#!/usr/bin/env bash
set -u
PORT="${1:-8000}"
echo "[NOVA] Stopping uvicorn on port $PORT..."
pkill -f "uvicorn main:app --host 127.0.0.1 --port $PORT" 2>/dev/null && echo "[NOVA] Stopped." || echo "[NOVA] No process found."
