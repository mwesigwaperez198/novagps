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


class TestThreatPanel:
    def test_threat_scan_parses_target_and_host(self):
        from nova_core.brain import NovaBrain
        parsed = NovaBrain()._parse_request(
            "can you analyse threats from https://novagps.onrender.com"
        )
        tools = [a["tool"] for a in parsed["actions"]]
        assert tools == ["vuln_scan", "dns_resolve", "connectivity_probe", "port_scan"]
        vuln = parsed["actions"][0]["params"]
        assert vuln["base_url"] == "https://novagps.onrender.com"
        assert parsed["actions"][2]["params"]["port"] == 443

    def test_threat_scan_honors_explicit_port(self):
        from nova_core.brain import NovaBrain
        parsed = NovaBrain()._parse_request("analyze threats from http://example.com:8080")
        conv = parsed["actions"][2]["params"]
        assert conv["host"] == "example.com"
        assert conv["port"] == 8080

    def test_verdict_note_appended_for_scan(self):
        from nova_core.brain import NovaBrain
        results = {"vuln_scan": {
            "success": True,
            "output": {
                "target": "https://novagps.onrender.com",
                "findings": [
                    {"severity": "medium", "fix": "Add 'x-frame-options' header to responses"},
                    {"severity": "high", "fix": "Disable /admin in production"},
                ],
                "finding_count": 2,
                "risk_level": "high",
            },
        }}
        note = NovaBrain()._threat_verdict(results)
        assert "Threat summary" in note
        assert "risk **HIGH**" in note
        assert "1 high, 1 medium" in note
        assert "Quick wins" in note

    def test_no_verdict_without_scan(self):
        from nova_core.brain import NovaBrain
        assert NovaBrain()._threat_verdict({"system_info": {"success": True}}) == ""