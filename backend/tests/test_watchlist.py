import pathlib
import subprocess
import sys
import textwrap

"""Stolen-device watchlist regression guard.

Covers the full recovery lane: IMEISV -> IMEI normalization, TAC/carrier
enrichment, the ingest sighting hook on `/traccar`, the critical alert, the
recovered state and deletion. Subprocess-isolated because `main`/`db` bind
config at import time.
"""

BACKEND = str(pathlib.Path(__file__).resolve().parents[1])


def test_watchlist_sighting_end_to_end():
    scenario = textwrap.dedent(
        """
        import os, sys, tempfile
        sys.path.insert(0, %r)
        tmp = tempfile.mkdtemp(prefix="nova_watchlist_")
        os.environ["NOVA_MODE"] = "portable"
        os.environ["DATABASE_URL"] = f"sqlite:///{tmp}/watchlist.sqlite3"
        os.environ["ENVIRONMENT"] = "development"
        os.environ["SECRET_KEY"] = "watchlist-test-secret-0000"
        os.environ["DEV_OWNER_EMAIL"] = "owner@example.com"
        from fastapi.testclient import TestClient
        from db import init_db
        init_db()
        import main as app_module
        from main import app
        client = TestClient(app)
        login = client.post("/auth/login", json={"email": "owner@example.com", "password": "x"})
        assert login.status_code == 200, login.text
        auth = {"Authorization": f"Bearer {login.json()['access_token']}"}

        created = client.post("/watchlist", params={
            "imei": "3557585300012301",
            "phone": "+256770000000",
            "email": "client@example.com",
            "label": "Stolen Samsung A06",
        }, headers=auth)
        assert created.status_code == 201, created.text
        entry = created.json()
        assert entry["imei"] == "355758530001233", entry
        assert entry["imeisv"] == "3557585300012301", entry
        assert entry["imei_luhn_valid"] is True, entry
        assert entry["manufacturer"] == "Samsung", entry
        assert "Galaxy A06" in (entry["model"] or ""), entry
        assert entry["carrier"] == "MTN Uganda", entry
        watch_id = entry["watchlist_id"]

        listed = client.get("/watchlist", headers=auth).json()
        assert len(listed) == 1 and listed[0]["status"] == "watching", listed

        sight = client.get("/traccar", params={
            "id": "STOLEN-A06",
            "lat": 0.3476,
            "lon": 32.5825,
            "imei": "3557585300012301",
        })
        assert sight.status_code == 202, sight.text
        body = sight.json()
        assert body.get("watchlist", {}).get("watchlist_id") == watch_id, body
        assert body["watchlist"]["first_sighting"] is True, body
        assert body["watchlist"]["latitude"] == 0.3476, body

        listed = client.get("/watchlist", headers=auth).json()
        assert listed[0]["status"] == "sighted", listed
        assert listed[0]["first_sighted_at"], listed
        sighted_device = listed[0]["first_sighted_device_id"]
        assert sighted_device, listed

        alerts = client.get("/alerts", headers=auth).json()
        hits = [a for a in alerts["alerts"] if a.get("alert_type") == "watchlist_sighting"]
        assert hits, alerts
        assert hits[0]["severity"] == "critical", hits
        assert hits[0]["device_id"] == sighted_device, hits

        again = client.get("/traccar", params={
            "id": "STOLEN-A06",
            "lat": 0.3480,
            "lon": 32.5830,
            "imei": "3557585300012301",
        }).json()
        assert again["watchlist"]["first_sighting"] is False, again

        recovered = client.post(f"/watchlist/{watch_id}/recover", headers=auth)
        assert recovered.status_code == 200, recovered.text
        after = client.get("/watchlist", headers=auth).json()
        assert after[0]["status"] == "recovered", after

        quiet = client.get("/traccar", params={
            "id": "STOLEN-A06",
            "lat": 0.35,
            "lon": 32.59,
            "imei": "3557585300012301",
        }).json()
        assert "watchlist" not in quiet, quiet

        removed = client.delete(f"/watchlist/{watch_id}", headers=auth)
        assert removed.status_code == 200, removed.text
        assert client.get("/watchlist", headers=auth).json() == []

        bad = client.post("/watchlist", params={"imei": "12345"}, headers=auth)
        assert bad.status_code == 400, bad.text
        print("WATCHLIST_OK")
        """
    ) % (BACKEND,)
    result = subprocess.run(
        [sys.executable, "-c", scenario],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "WATCHLIST_OK" in result.stdout
