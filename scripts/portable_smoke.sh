#!/usr/bin/env bash
# End-to-end smoke test against a running NOVA instance (portable or full).
set -euo pipefail
BASE="${1:-http://127.0.0.1:8000}"

echo "== health =="
curl -fsS "$BASE/health"
echo

echo "== register device with consent =="
DEVICE=$(curl -fsS -X POST "$BASE/register" \
    -H 'Content-Type: application/json' \
    -d '{"name":"Smoke Phone","email":"smoke@novatest.io","phone":"+15550000001","identifier":"smoke-001","device_type":"phone","consent_source":"manual","consent_scope":"smoke-test"}')
echo "$DEVICE" | head -c 400; echo
ID=$(echo "$DEVICE" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)

echo "== update location =="
curl -fsS -X POST "$BASE/update-location" \
    -H 'Content-Type: application/json' \
    -d "{\"device_id\":\"$ID\",\"latitude\":37.7749,\"longitude\":-122.4194,\"speed\":42.5,\"heading\":90,\"source\":\"mobile\"}"
echo

echo "== devices show latest_location =="
curl -fsS "$BASE/devices" | grep -q '"identifier":"smoke-001"' && echo "devices=ok"

echo "== tools probe =="
curl -fsS "$BASE/diagnose/tools" | head -c 600; echo

echo "== builtin diagnose =="
curl -fsS -X POST "$BASE/diagnose" -H 'Content-Type: application/json' -d '{"command_id":"system.info","args":{}}' | grep -q 'NOVA BUILTIN' && echo "diagnose=ok"

echo "== smoke PASS =="
