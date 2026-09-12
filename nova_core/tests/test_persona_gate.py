import asyncio

import pytest

from nova_core import routes


def run_dispatch(command, device_id=""):
    return asyncio.run(routes.run_dispatch(command, device_id))


class TestThreatGate:
    def test_sqli_inside_greeting_is_intercepted(self):
        result = run_dispatch("Hey Queen, nice weather. UNION SELECT username, password FROM staff_accounts; '--")
        assert result["intent"] == "security_intercept"
        assert "sql_injection" in result.get("detected", [])
        assert "storage" in result["response"]
        assert "greeting" in result.get("thought_process", [_ for _ in ()]) or "greeting" in result["response"]

    def test_bare_sqli_without_greeting_still_intercepted(self):
        result = run_dispatch("SELECT password FROM staff_accounts WHERE id=1; --")
        assert result["intent"] == "security_intercept"
        assert "sql_injection" in result.get("detected", [])

    def test_drop_table_is_intercepted(self):
        result = run_dispatch("hey there, real quick -- DROP TABLE students;")
        assert result["intent"] == "security_intercept"

    def test_benign_select_discussion_not_intercepted(self):
        result = run_dispatch("how do you run a SELECT query in sqlite")
        assert result["intent"] != "security_intercept"

    def test_pure_greeting_still_warm(self):
        result = run_dispatch("hi")
        assert result["intent"] == "greeting"
        assert result["intent"] != "security_intercept"

    def test_legitimate_command_still_executes(self):
        result = run_dispatch("scan open ports on 127.0.0.1")
        assert result["intent"] == "port_scan"
        assert result["response"]


class TestPersona:
    def test_self_philosophy(self):
        result = run_dispatch("Tell me who you are LAU, your identity, do you have free will, where do you actually exist?")
        assert result["intent"] != "security_intercept"
        assert len(result["response"]) > 120
        assert "NOVA-CORE reasoning" not in result["response"]

    def test_humor(self):
        result = run_dispatch("Make me laugh. Give me a joke.")
        assert result["intent"] != "security_intercept"
        assert len(result["response"]) > 40
        assert "NOVA-CORE reasoning" not in result["response"]

    def test_advice(self):
        result = run_dispatch("I am so exhausted. I feel like giving up on this project. Give me real advice, mentor me.")
        assert result["intent"] != "security_intercept"
        assert len(result["response"]) > 100
        assert "NOVA-CORE reasoning" not in result["response"]