"""Gate for the streaming LAU endpoint.

The conversational UI depends on a well-formed event stream, so this asserts the
real production-shaped app emits status/thought/tool/token/done frames rather
than buffering a single JSON blob.
"""

import pathlib
import subprocess
import sys
import textwrap

BACKEND = str(pathlib.Path(__file__).resolve().parents[1])


def test_agent_stream_emits_sse_frames():
    scenario = textwrap.dedent(
        """
        import os, sys, tempfile
        sys.path.insert(0, %r)
        tmp = tempfile.mkdtemp(prefix="nova_stream_")
        os.environ["NOVA_MODE"] = "portable"
        os.environ["DATABASE_URL"] = f"sqlite:///{tmp}/stream.sqlite3"
        os.environ["ENVIRONMENT"] = "production"
        os.environ["SECRET_KEY"] = "nova-stream-secret"
        os.environ["DEV_OWNER_EMAIL"] = "owner@example.com"
        os.environ["OWNER_PASSWORD"] = "pw"
        os.environ["NOVA_EMBEDDED"] = "0"
        os.environ.pop("NOVA_LLM_API_KEY", None)
        from fastapi.testclient import TestClient
        from db import init_db
        init_db()
        from main import app

        client = TestClient(app)
        login = client.post("/auth/login", json={"email": "owner@example.com", "password": "pw"})
        assert login.status_code == 200, login.text
        auth = {"Authorization": f"Bearer {login.json()['access_token']}"}

        frames = []
        with client.stream(
            "POST",
            "/nova-core/agent/stream",
            json={"command": "scan open ports on 127.0.0.1", "device_id": ""},
            headers=auth,
        ) as resp:
            assert resp.status_code == 200, resp.read()
            assert resp.headers["content-type"].startswith("text/event-stream")
            for line in resp.iter_lines():
                if line.startswith("event:"):
                    frames.append(line.split(":", 1)[1].strip())

        assert frames[0] == "status", frames
        assert "thought" in frames, frames
        assert "tool" in frames, frames
        assert frames.count("token") > 0, frames
        assert frames[-1] == "done", frames
        print("AGENT_STREAM_OK")
        """
    ) % (BACKEND,)
    result = subprocess.run(
        [sys.executable, "-c", scenario],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "AGENT_STREAM_OK" in result.stdout
