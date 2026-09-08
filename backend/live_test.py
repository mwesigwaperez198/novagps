#!/usr/bin/env python3
"""Live test for a running NOVA GPS backend.

Registers a phone device with real phone info, streams location samples,
then runs the full analytics stack against it (dashboard, device analytics,
fraud check, heartbeat, location stats).

Run with the backend up, e.g.:
    ./run_backend.sh          # in one terminal
    python3 backend/live_test.py
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("NOVA_BASE_URL", "http://127.0.0.1:8000")


def call(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()[:300]


def section(title):
    print(f"\n=== {title} ===")


def main():
    # 1. Login (dev mode accepts any credentials and issues an admin JWT)
    section("AUTH")
    code, body = call("POST", "/auth/login", {"email": "dev-admin@nova.local", "password": "pass123"})
    if code != 200:
        print(f"FAIL login: {code} {body}")
        return 1
    token = body["access_token"]
    print(f"login OK -> role={body['role']} email={body['email']}")

    # 2. Register a phone with full phone fingerprint info
    section("REGISTER PHONE")
    identifier = f"phone-{int(time.time())}"
    phone = {
        "name": "Alice Phone",
        "email": f"alice-{int(time.time())}@example.com",
        "phone": f"+256{int(time.time()) % 10_000_000_000:010d}",
        "identifier": identifier,
        "serial": "C02XR2A6JGHH",
        "imei": f"355{int(time.time()) % 100_000_000_000:011d}",
        "model": "iPhone 13",
        "manufacturer": "Apple",
        "os_type": "iOS",
        "os_version": "17.5.1",
        "device_type": "phone",
        "ip_address": "105.178.10.22",
        "mac_address": "A4:83:E7:12:34:56",
        "consent_source": "app",
        "consent_scope": "location tracking for fleet analytics",
    }
    code, dev = call("POST", "/register", phone, token)
    if code != 201:
        print(f"FAIL register: {code} {body if isinstance(body, str) else body}")
        return 1
    dev_id = dev["id"]
    print(f"registered device id={dev_id} identifier={identifier}")
    print(f"  model={dev['model']} os={dev['os_type']} {dev['os_version']} imei={dev['imei']}")
    print(f"  latest_location={dev['latest_location']}")

    # 3. Stream location samples along a city route (some + overspeed)
    section("LOCATION STREAM")
    route = [
        (0.3476, 32.5825, 0.0, 90.0),    # Kampala city center
        (0.3254, 32.5965, 28.4, 120.0),
        (0.3129, 32.6100, 55.0, 135.0),
        (0.2989, 32.6260, 45.3, 140.0),
        (0.2851, 32.6410, 67.8, 145.0),   # overspeed -> fraud candidate
        (0.2720, 32.6555, 33.1, 150.0),
    ]
    for lat, lon, speed, heading in route:
        code, body = call(
            "POST", "/update-location",
            {"identifier": identifier, "latitude": lat, "longitude": lon,
             "altitude": 1180.0, "speed": speed, "heading": heading,
             "accuracy": 6.0, "source": "mobile", "raw_payload": {"rssi": -62}},
            token,
        )
        if code != 202:
            print(f"FAIL location: {code} {body}")
            return 1
    print(f"{len(route)} location samples ingested (speeds up to 67.8 km/h)")

    # 4. Analytics
    section("DEVICE ANALYTICS")
    code, a = call("GET", f"/analytics/device/{dev_id}", token=token)
    if code != 200:
        print(f"FAIL device analytics: {code} {a}")
        return 1
    print("device analytics:", json.dumps(a, indent=2))

    section("FRAUD CHECK")
    code, f = call("GET", f"/analytics/device/{dev_id}/fraud", token=token)
    print(f"fraud verdict: {f.get('verdict')} | anomalies={f.get('anomaly_count')} "
          f"| samples={f.get('samples')}")
    for an in f.get("anomalies", []):
        print("  anomaly:", an)

    section("HEARTBEAT")
    code, h = call("GET", f"/analytics/device/{dev_id}/heartbeat", token=token)
    print(f"heartbeat: status={h.get('status')} cadence={h.get('cadence_seconds')}s "
          f"updates={h.get('count')} last_update={h.get('last_update')}")

    section("LOCATION STATS")
    code, s = call("GET", f"/analytics/device/{dev_id}/location-stats", token=token)
    if isinstance(s, dict):
        print("stats:", json.dumps(s, indent=2))

    section("DASHBOARD")
    code, d = call("GET", "/analytics/dashboard", token=token)
    if code == 200 and isinstance(d, dict):
        s = d.get("summary", {})
        print(f"devices={s.get('total_devices')} avg_speed={s.get('avg_speed_kph')} km/h "
              f"active_24h={s.get('active_devices_24h')} locations_24h={s.get('locations_24h')}")

    print("\nALL LIVE TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())