import pathlib
import subprocess
import sys
import textwrap

"""Recovery-plane regression guard (Phase 2).

Covers the endpoints that turn a match into an investigation: the self-locate
watchlist hook, the last-seen trail, the heartbeat/stale view, and the one-scan
pairing token the Android agent consumes via QR.
"""

BACKEND = str(pathlib.Path(__file__).resolve().parents[1])


def test_recovery_plane_end_to_end():
    scenario = textwrap.dedent(
        """
        import os, sys, tempfile
        sys.path.insert(0, %r)
        tmp = tempfile.mkdtemp(prefix="nova_recovery_")
        os.environ["NOVA_MODE"] = "portable"
        os.environ["DATABASE_URL"] = f"sqlite:///{tmp}/recovery.sqlite3"
        os.environ["ENVIRONMENT"] = "development"
        os.environ["SECRET_KEY"] = "recovery-test-secret-0000"
        os.environ["DEV_OWNER_EMAIL"] = "owner@example.com"
        from fastapi.testclient import TestClient
        from db import init_db
        init_db()
        from main import app
        client = TestClient(app)
        login = client.post("/auth/login", json={"email": "owner@example.com", "password": "x"})
        assert login.status_code == 200, login.text
        auth = {"Authorization": f"Bearer {login.json()['access_token']}"}

        phone = client.post("/register", json={
            "name": "Recovery Phone",
            "email": "client@example.com",
            "phone": "+256770000000",
            "identifier": "RECOVERY-PHONE",
            "imei": "3557585300012301",
            "device_type": "phone",
        }, headers=auth)
        assert phone.status_code == 201, phone.text
        phone_id = phone.json()["id"]

        consent = client.post("/consent", json={
            "device_id": phone_id,
            "source": "test",
            "scope": "location,tracking,security",
            "granted": True,
        }, headers=auth)
        assert consent.status_code in (200, 201), consent.text

        idle = client.post("/register", json={
            "name": "Idle Laptop",
            "email": "client@example.com",
            "phone": "+256770000001",
            "identifier": "IDLE-LAPTOP",
            "device_type": "laptop",
        }, headers=auth)
        assert idle.status_code == 201, idle.text

        created = client.post("/watchlist", params={
            "imei": "3557585300012301",
            "phone": "+256770000000",
            "email": "client@example.com",
            "label": "Stolen phone",
        }, headers=auth)
        assert created.status_code == 201, created.text
        watch_id = created.json()["watchlist_id"]

        located = client.post("/device/locate", params={
            "identifier": "RECOVERY-PHONE",
            "latitude": 0.3476,
            "longitude": 32.5825,
        })
        assert located.status_code == 202, located.text
        body = located.json()
        assert body["watchlist"]["watchlist_id"] == watch_id, body
        assert body["watchlist"]["first_sighting"] is True, body

        trail = client.get(f"/watchlist/{watch_id}/sightings", headers=auth)
        assert trail.status_code == 200, trail.text
        payload = trail.json()
        assert payload["status"] == "sighted", payload
        assert len(payload["sightings"]) >= 1, payload
        assert payload["sightings"][0]["latitude"] == 0.3476, payload
        assert payload["alerts"] and payload["alerts"][0]["severity"] == "critical", payload

        health = client.get("/devices/health", headers=auth)
        assert health.status_code == 200, health.text
        rows = {row["device_id"]: row for row in health.json()["devices"]}
        assert rows[phone_id]["watchlisted"] is True, rows
        assert rows[phone_id]["stale"] is False, rows
        idle_rows = [r for r in health.json()["devices"] if r["identifier"] == "IDLE-LAPTOP"]
        assert idle_rows and idle_rows[0]["stale"] is True, health.json()

        paired = client.post("/device/pairing", params={"identifier": "RECOVERY-PHONE"}, headers=auth)
        assert paired.status_code == 201, paired.text
        pairing = paired.json()
        assert pairing["identifier"] == "RECOVERY-PHONE", pairing
        assert pairing["scope"], pairing
        wanted = {"server_url", "pair_token", "scope", "expires_in_minutes"}
        assert wanted.issubset(pairing), pairing

        verified = client.post(
            "/device/pairing/verify",
            params={"token": pairing["pair_token"]},
            headers=auth,
        )
        assert verified.status_code == 200, verified.text
        assert verified.json()["valid"] is True, verified.json()

        bad = client.post("/device/pairing/verify", params={"token": "not.a.real.token"}, headers=auth)
        assert bad.status_code == 401, bad.text

        missing = client.post("/device/pairing", params={"identifier": "NOPE"}, headers=auth)
        assert missing.status_code == 404, missing.text
        print("RECOVERY_OK")
        """
    ) % (BACKEND,)
    result = subprocess.run(
        [sys.executable, "-c", scenario],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "RECOVERY_OK" in result.stdout
