import subprocess
import sys
import textwrap

"""Regression guard for the Traccar self-enrol path.

The endpoint must transparently provision an unknown Traccar identifier
(device + active consent) and persist the location, so the dashboard can
list it. This runs in a subprocess because `main`/`db` bind config at import
time (module-level engine + cached settings); an isolated interpreter keeps
the suite hermetic.
"""


def test_traccar_ingest_enrolls_device_with_active_consent():
    scenario = textwrap.dedent(
        """
        import os, sys, tempfile
        sys.path.insert(0, %r)
        tmp = tempfile.mkdtemp(prefix="nova_ingest_")
        os.environ["NOVA_MODE"] = "portable"
        os.environ["DATABASE_URL"] = f"sqlite:///{tmp}/ingest.sqlite3"
        os.environ["ENVIRONMENT"] = "development"
        os.environ["SECRET_KEY"] = "ingest-test-secret-0000"
        os.environ["DEV_OWNER_EMAIL"] = "owner@example.com"
        from fastapi.testclient import TestClient
        from db import init_db
        init_db()
        import main as app_module
        from main import app
        client = TestClient(app)
        login = client.post("/auth/login", json={"email": "owner@example.com", "password": "x"})
        assert login.status_code == 200, login.text
        token = login.json()["access_token"]
        auth = {"Authorization": f"Bearer {token}"}
        before = client.get("/devices", headers=auth).json()
        assert before == [], before
        r = client.get(
            "/traccar",
            params={
                "id": "NOVA-IPHONE-0765866555",
                "lat": 0.3476,
                "lon": 32.5825,
                "speed": 0,
                "battery": 84,
            },
        )
        assert r.status_code == 202, r.text
        after = client.get("/devices", headers=auth).json()
        hits = [d for d in after if d.get("identifier") == "NOVA-IPHONE-0765866555"]
        assert hits, f"device not listed after ingest: {after}"
        dev = hits[0]
        assert dev.get("is_active") is not False
        assert dev.get("latest_location", {}).get("latitude") == 0.3476
        r2 = client.get(
            "/traccar",
            params={"id": "NOVA-IPHONE-0765866555", "lat": 0.4, "lon": 32.6, "event": "sos"},
        )
        assert r2.status_code == 202, r2.text
        locs = client.get(f"/devices/{dev['id']}/locations", headers=auth).json()
        assert len(locs) >= 2, locs
        print("TRAECAR_INGEST_OK")
        """
    ) % ("/workspace/backend",)
    result = subprocess.run(
        [sys.executable, "-c", scenario],
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "TRAECAR_INGEST_OK" in result.stdout