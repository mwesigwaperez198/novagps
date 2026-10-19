"""Guard for the /nova-core surface.

FastAPI 0.148 lists mounted routers as _IncludedRouter nodes with no `.path`,
which crashed prometheus-fastapi-instrumentator while labelling a request and
returned 500 for every nova-core route. This asserts the whole surface answers
under a production-shaped app (the exact conditions that regressed).
"""

import pathlib
import subprocess
import sys
import textwrap

BACKEND = str(pathlib.Path(__file__).resolve().parents[1])


def test_nova_core_surface_responds():
    scenario = textwrap.dedent(
        """
        import os, sys, tempfile
        sys.path.insert(0, %r)
        tmp = tempfile.mkdtemp(prefix="nova_core_routes_")
        os.environ["NOVA_MODE"] = "portable"
        os.environ["DATABASE_URL"] = f"sqlite:///{tmp}/routes.sqlite3"
        os.environ["ENVIRONMENT"] = "production"
        os.environ["SECRET_KEY"] = "nova-core-routes-secret"
        os.environ["DEV_OWNER_EMAIL"] = "owner@example.com"
        os.environ["OWNER_PASSWORD"] = "pw"
        os.environ["NOVA_EMBEDDED"] = "0"
        from fastapi.testclient import TestClient
        from db import init_db
        init_db()
        import main as app_module
        from main import app
        client = TestClient(app)
        login = client.post("/auth/login", json={"email": "owner@example.com", "password": "pw"})
        assert login.status_code == 200, login.text
        auth = {"Authorization": f"Bearer {login.json()['access_token']}"}

        for path in ("/nova-core/health", "/nova-core/status", "/nova-core/skills", "/nova-core/config"):
            resp = client.get(path, headers=auth)
            assert resp.status_code == 200, f"{path} -> {resp.status_code} {resp.text[:200]}"

        skills = client.get("/nova-core/skills", headers=auth).json()
        assert skills["count"] >= 18, skills

        reply = client.post("/nova-core/agent/dispatch", json={"command": "hi", "device_id": ""}, headers=auth)
        assert reply.status_code == 200, reply.text
        assert reply.json().get("intent"), reply.json()
        print("NOVA_CORE_SURFACE_OK")
        """
    ) % (BACKEND,)
    result = subprocess.run(
        [sys.executable, "-c", scenario],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "NOVA_CORE_SURFACE_OK" in result.stdout
