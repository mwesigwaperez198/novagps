#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-http://localhost:8000}"

echo "[nova] health"
curl -sS "$API_URL/health" | jq .

echo "[nova] register device with consent"
DEVICE_ID="$(
  curl -sS -X POST "$API_URL/register" \
    -H 'Content-Type: application/json' \
    -d '{
      "name": "Perez Demo Phone",
      "email": "perez@example.com",
      "phone": "+15550101010",
      "identifier": "android-demo-001",
      "device_type": "phone",
      "consent_source": "manual-admin",
      "consent_scope": "live-location,history,alerts"
    }' | jq -r .id
)"

echo "[nova] update location"
curl -sS -X POST "$API_URL/update-location" \
  -H 'Content-Type: application/json' \
  -d "{
    \"device_id\": \"$DEVICE_ID\",
    \"latitude\": 37.7785,
    \"longitude\": -122.4156,
    \"speed\": 4.2,
    \"heading\": 91,
    \"accuracy\": 8,
    \"source\": \"mobile\"
  }" | jq .

echo "[nova] list devices"
curl -sS "$API_URL/devices" | jq .

echo "[nova] run safe diagnosis"
curl -sS -X POST "$API_URL/diagnose" \
  -H 'Content-Type: application/json' \
  -d '{"command_id":"echo.hash","args":{"label":"demo-trace"}}' | jq .
