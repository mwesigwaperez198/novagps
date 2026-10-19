"""Gates for the hosted (OpenAI-compatible) reasoning provider.

LAU must be able to reason through a real model when a key is present, and must
still fall back to the deterministic shield when it is not — never crash and
never pretend an unreachable model answered.
"""

import json
import types

import pytest

from nova_core import llm as llm_mod


class _FakeResponse:
    def __init__(self, payload: dict, status: int = 200):
        self._body = json.dumps(payload).encode()
        self.status = status

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _cfg(**over):
    base = dict(
        ollama_host="http://127.0.0.1:11434",
        ollama_model="llama3.2:3b",
        agent_name="LAU",
        llm_api_key="",
        llm_base_url="https://api.groq.com/openai/v1",
        llm_model="llama-3.3-70b-versatile",
        llm_timeout=60,
        llm_backend="shield",
    )
    base.update(over)
    return types.SimpleNamespace(**base)


def _client(monkeypatch, **over):
    monkeypatch.setattr(llm_mod, "get_config", lambda: _cfg(**over))
    return llm_mod.NovaLLM()


def test_api_key_selects_hosted_provider(monkeypatch):
    client = _client(monkeypatch, llm_api_key="gsk_test")
    assert client.is_hosted() is True
    assert client.hosted_model == "llama-3.3-70b-versatile"


def test_backend_name_selects_hosted_without_key(monkeypatch):
    client = _client(monkeypatch, llm_backend="groq")
    assert client.is_hosted() is True


def test_hosted_headers_identify_the_client(monkeypatch):
    # Groq sits behind Cloudflare, which 403s (error 1010) the default
    # Python-urllib User-Agent. Any real identity must be sent instead.
    client = _client(monkeypatch, llm_api_key="gsk_test")
    headers = client._hosted_headers()
    assert headers["Authorization"] == "Bearer gsk_test"
    assert "python-urllib" not in headers["User-Agent"].lower()
    assert headers["User-Agent"].startswith("NovaGPS/")


def test_no_key_means_not_available(monkeypatch):
    client = _client(monkeypatch, llm_backend="groq")
    status = client.check_availability()
    assert status["available"] is False
    assert "NOVA_LLM_API_KEY" in status["error"]


def test_hosted_availability_hits_models_endpoint(monkeypatch):
    client = _client(monkeypatch, llm_api_key="gsk_test")
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        seen["auth"] = req.headers.get("Authorization")
        return _FakeResponse({"data": [{"id": "llama-3.3-70b-versatile"}]})

    monkeypatch.setattr(llm_mod.urllib.request, "urlopen", fake_urlopen)
    status = client.check_availability()
    assert status["available"] is True
    assert seen["url"].endswith("/models")
    assert seen["auth"] == "Bearer gsk_test"


def test_hosted_chat_parses_openai_shape(monkeypatch):
    client = _client(monkeypatch, llm_api_key="gsk_test")
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data.decode())
        return _FakeResponse({"choices": [{"message": {"content": "4 open ports found"}}]})

    monkeypatch.setattr(llm_mod.urllib.request, "urlopen", fake_urlopen)
    ok, text = client.chat(system="sys", prompt="scan")
    assert ok is True
    assert text == "4 open ports found"
    assert captured["url"].endswith("/chat/completions")
    assert captured["body"]["model"] == "llama-3.3-70b-versatile"
    assert captured["body"]["messages"][0]["role"] == "system"


def test_hosted_chat_error_is_failure_not_fake_answer(monkeypatch):
    client = _client(monkeypatch, llm_api_key="gsk_test")

    def boom(req, timeout=None):
        raise llm_mod.urllib.error.URLError("no route")

    monkeypatch.setattr(llm_mod.urllib.request, "urlopen", boom)
    ok, text = client.chat(system="sys", prompt="scan")
    assert ok is False


def test_engine_used_reports_hosted_model(monkeypatch):
    from nova_core.brain import NovaBrain

    brain = NovaBrain.__new__(NovaBrain)
    brain.engine = types.SimpleNamespace(engine_used="UNINITIALIZED", state="shield_only")
    brain.llm = types.SimpleNamespace(
        is_hosted=lambda: True,
        is_available=lambda: True,
        hosted_model="llama-3.3-70b-versatile",
    )
    assert brain.engine_used == "HOSTED:llama-3.3-70b-versatile"


def test_hosted_label_wins_over_shield_engine_state():
    from nova_core.brain import NovaBrain

    brain = NovaBrain.__new__(NovaBrain)
    brain.engine = types.SimpleNamespace(engine_used="DETERMINISTIC_SHIELD", state="shield_only")
    brain.llm = types.SimpleNamespace(
        is_hosted=lambda: True,
        is_available=lambda: True,
        hosted_model="openai/gpt-oss-120b",
    )
    assert brain.engine_used == "HOSTED:openai/gpt-oss-120b"


@pytest.mark.asyncio
async def test_hosted_path_runs_model_chosen_tool_and_keeps_target(monkeypatch):
    from nova_core.brain import NovaBrain

    brain = NovaBrain.__new__(NovaBrain)
    executed = []

    class _Registry:
        def list_tools(self):
            return [{"name": "port_scan", "description": "Scan ports"}]

        def execute(self, name, **params):
            executed.append((name, params))

            class R:
                def to_dict(self):
                    return {"success": True, "output": {"host": params.get("host"), "open_ports": [22]}}

            return R()

    class _LLM:
        def select_tool(self, query, desc):
            return ["port_scan"]

        def chat(self, system, prompt, temperature=0.3, num_predict=900):
            assert "192.168.1.6" in prompt
            return True, "Port 22 is open on 192.168.1.6."

    brain.tools = _Registry()
    brain.llm = _LLM()
    brain._system_prompt = "sys"
    brain._parse_request = lambda q: {
        "intent": "execute",
        "actions": [{"tool": "port_scan", "params": {"host": "192.168.1.6"}}],
    }

    results = await brain._process_with_hosted_llm("scan 192.168.1.6", [], {})
    assert executed == [("port_scan", {"host": "192.168.1.6"})]
    assert results["llm_response"]["success"] is True
    assert "Port 22" in results["llm_response"]["output"]
