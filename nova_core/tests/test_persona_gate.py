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


class TestPacketCapture:
    def test_parse_routes_sniff_with_proto_and_count(self):
        from nova_core.brain import NovaBrain
        parsed = NovaBrain()._parse_request("sniff 50 packets tcp")
        caps = [a for a in parsed["actions"] if a["tool"] == "packet_capture"]
        assert caps
        assert caps[0]["params"]["protocol"] == "tcp"
        assert caps[0]["params"]["count"] == 50

    def test_parse_routes_dns_traffic(self):
        from nova_core.brain import NovaBrain
        parsed = NovaBrain()._parse_request("capture dns traffic")
        caps = [a for a in parsed["actions"] if a["tool"] == "packet_capture"]
        assert caps[0]["params"]["protocol"] == "dns"

    def test_parse_routes_pcap_file(self):
        from nova_core.brain import NovaBrain
        parsed = NovaBrain()._parse_request("analyze packets from trace.pcap")
        caps = [a for a in parsed["actions"] if a["tool"] == "packet_capture"]
        assert caps[0]["params"]["pcap_file"] == "trace.pcap"

    def test_tshark_fields_parsed(self):
        from nova_core.tools.packet import PacketCapture
        out = PacketCapture()._parse_tshark_fields([
            "frame.time_relative|ip.src|ip.dst|tcp.srcport|tcp.dstport|udp.srcport|udp.dstport|dns.qry.name|dns.a|tcp.flags.str|_ws.col.Protocol|frame.len",
            "0.000000|192.168.1.5|8.8.8.8|||||example.com|93.184.216.34||DNS|60",
            "1.000000|93.184.216.34|192.168.1.5|443|53000|||||SA|TCP|1500",
        ]).output
        assert out["total_packets"] == 2
        assert out["dns_queries"][0]["query"] == "example.com"
        assert out["tcp_connections"][0]["flags"] == "SA"

    def test_tcpdump_text_parsed_ports(self):
        from nova_core.tools.packet import PacketCapture
        out = PacketCapture()._parse_tcpdump_text([
            "2026-09-12 15:40:01.234567 IP 192.168.1.5.53000 > 8.8.8.8.53: 12345+ A? novagps.onrender.com. (42)",
            "2026-09-12 15:40:01.240000 IP 192.168.1.5.53001 > 142.250.1.1.443: Flags [S], seq 1",
        ]).output
        assert out["dns_queries"][0]["query"] == "novagps.onrender.com"
        conn = [c for c in out["tcp_connections"] if c.get("dst_port") == "443"][0]
        assert conn["src_port"] == "53001"
        assert conn["flags"] == "S"

    def test_missing_engine_returns_graceful_error(self):
        from nova_core.tools.packet import PacketCapture
        import shutil
        if not shutil.which("tshark") and not shutil.which("tcpdump"):
            r = PacketCapture().execute(duration=1, count=5, protocol="all")
            assert r.success is False
            assert "shark" in r.error or "tcpdump" in r.error or "raw socket" in r.error


class TestDeviceLookup:
    def test_parse_imei(self):
        from nova_core.brain import NovaBrain
        parsed = NovaBrain()._parse_request("locate device with imei 355985051234567")
        acts = [a for a in parsed["actions"] if a["tool"] == "device_lookup"]
        assert len(acts) == 1
        assert acts[0]["params"]["query"] == "355985051234567"
        assert acts[0]["params"]["trigger_locate"] is True

    def test_parse_serial(self):
        from nova_core.brain import NovaBrain
        parsed = NovaBrain()._parse_request("track device serial SN-0942")
        acts = [a for a in parsed["actions"] if a["tool"] == "device_lookup"]
        assert acts[0]["params"]["query"] == "sn-0942"

    def test_parse_generic_name(self):
        from nova_core.brain import NovaBrain
        parsed = NovaBrain()._parse_request("show device info for test-phone")
        acts = [a for a in parsed["actions"] if a["tool"] == "device_lookup"]
        assert acts[0]["params"]["query"] == "test-phone"
        assert acts[0]["params"]["trigger_locate"] is False

    def test_parse_trigger_no_trigger_for_info(self):
        from nova_core.brain import NovaBrain
        parsed = NovaBrain()._parse_request("show device info for test-phone")
        assert all(a["params"].get("trigger_locate") is False for a in parsed["actions"])

    def test_parse_imei_number_phrase(self):
        from nova_core.brain import NovaBrain
        parsed = NovaBrain()._parse_request(
            "track my device on IMEI number 358638090685186 , SN FCDZ70W3HG00"
        )
        acts = [a for a in parsed["actions"] if a["tool"] == "device_lookup"]
        assert parsed["actions"]
        assert acts[0]["params"]["query"] == "358638090685186"
        assert acts[0]["params"]["trigger_locate"] is True

    def test_parse_imei_only_digits(self):
        from nova_core.brain import NovaBrain
        parsed = NovaBrain()._parse_request("IMEI: 355985051234567 show device info")
        acts = [a for a in parsed["actions"] if a["tool"] == "device_lookup"]
        assert acts and acts[0]["params"]["query"] == "355985051234567"

    def test_parse_serial_sn_phrase(self):
        from nova_core.brain import NovaBrain
        parsed = NovaBrain()._parse_request("find device serial SN FCDZ70W3HG00")
        acts = [a for a in parsed["actions"] if a["tool"] == "device_lookup"]
        assert acts and acts[0]["params"]["query"] == "fcdz70w3hg00"

    def test_format_no_match_diagnosis(self):
        from nova_core.brain import format_device_lookup
        s = format_device_lookup({
            "query": "358638090685186",
            "device_count": 0,
            "message": "No device matches '358638090685186'.",
            "backend_status": "healthy",
            "total_devices": 3,
            "analysis": [
                "3 device(s) are registered on the backend.",
                "No registered device matches that IMEI/serial on the backend.",
                "If the device phones home via the Traccar app, it is enrolled under its",
                "Traccar device id (the /traccar 'id' param) — NOT necessarily the IMEI.",
            ],
        })
        assert "0 devices for" in s
        assert "3 device(s) are registered" in s
        assert "Traccar device id" in s
        assert "backend: healthy" in s

    def test_format_backend_down_diagnosis(self):
        from nova_core.brain import format_device_lookup
        s = format_device_lookup({
            "query": "358638090685186",
            "device_count": 0,
            "message": "Backend returned HTTP 502.",
            "backend_status": "unreachable",
            "healthy": False,
            "analysis": [
                "Backend unreachable (unreachable); Render spins the free tier down after idle. "
                "Wait ~60s or use a paid instance."
            ],
        })
        assert "Backend returned HTTP 502" in s
        assert "Render spins the free tier down" in s

    def test_tool_returns_diagnosis_on_no_match(self, monkeypatch):
        import nova_core.tools.backend as be

        class FakeResp:
            status_code = 200
            headers = {"content-type": "application/json"}

            def json(self):
                return []

        seen = []

        def fake_get(url, params=None, headers=None, timeout=None):
            seen.append(url)
            if url.endswith("/search"):
                return FakeResp()
            if url.endswith("/devices"):
                class DR:
                    status_code = 200
                    headers = {"content-type": "application/json"}

                    def json(self):
                        return [
                            {"id": "a", "identifier": "T8812", "imei": "", "serial": ""},
                            {"id": "b", "identifier": "s21-phone", "imei": "35598505",
                             "serial": "SN-09"},
                        ]
                return DR()
            if url.endswith("/health"):
                class HR:
                    status_code = 200
                    headers = {"content-type": "application/json"}

                    def json(self):
                        return {"status": "ok"}
                return HR()
            raise AssertionError(f"unexpected url {url}")

        monkeypatch.setattr(be.httpx, "get", fake_get)
        tool = be.DeviceLookup()
        r = tool.execute(query="999999", trigger_locate=False)
        assert r.success
        out = r.output
        assert out["device_count"] == 0
        assert out["healthy"] is True
        assert out["total_devices"] == 2
        assert any("Traccar" in a for a in out["analysis"])

    def test_tool_returns_diagnosis_on_unreachable(self, monkeypatch):
        import nova_core.tools.backend as be
        import httpx as real_httpx

        def fake_get(url, params=None, headers=None, timeout=None):
            raise real_httpx.ConnectError("conn refused")

        monkeypatch.setattr(be.httpx, "get", fake_get)
        tool = be.DeviceLookup()
        r = tool.execute(query="358638090685186", trigger_locate=False)
        assert r.success
        out = r.output
        assert out["device_count"] == 0
        assert out["healthy"] is False
        assert "unreachable" in out["backend_status"].lower()

    def test_format_live_locate_queued(self):
        from nova_core.brain import format_device_lookup
        s = format_device_lookup({
            "query": "355985051234567",
            "device_count": 1,
            "devices": [{
                "id": "d1", "name": "S21", "identifier": "phone-1",
                "imei": "355985051234567", "serial": None,
            }],
            "locate": {"ok": True, "status_code": 200, "result": {"command_id": "abc123", "status": "pending"}},
        })
        assert "LIVE LOCATE → queued (pending)" in s

    def test_format_live_locate_failed(self):
        from nova_core.brain import format_device_lookup
        s = format_device_lookup({
            "query": "x",
            "device_count": 1,
            "devices": [{"id": "d1", "name": "X", "identifier": "x"}],
            "locate": {"ok": False, "error": "boom"},
        })
        assert "LIVE LOCATE → failed" in s


class TestLANDiscovery:
    def test_parse_human_phrasing(self):
        from nova_core.brain import NovaBrain
        q = ("can scan for nearby ip addresses to the system and those connected "
             "to the same internet connection")
        parsed = NovaBrain()._parse_request(q)
        tools = [a["tool"] for a in parsed["actions"]]
        assert parsed["intent"] == "execute"
        assert "network_discovery" in tools
        assert "port_scan" not in tools

    def test_parse_same_network(self):
        from nova_core.brain import NovaBrain
        parsed = NovaBrain()._parse_request("scan for devices on the same network as this computer")
        assert "network_discovery" in [a["tool"] for a in parsed["actions"]]

    def test_parse_router_wifi(self):
        from nova_core.brain import NovaBrain
        for q in ("what devices are on my router", "list hosts connected to my wifi"):
            parsed = NovaBrain()._parse_request(q)
            assert "network_discovery" in [a["tool"] for a in parsed["actions"]]

    def test_tool_lists_self_host(self):
        from nova_core.tools.network import LANDiscovery
        out = LANDiscovery().execute().output
        assert out["own_ips"]
        assert out["self_count"] >= 1
        assert any(h["is_self"] for h in out["hosts"])

    def test_format_panel(self):
        from nova_core.brain import format_network_discovery
        s = format_network_discovery({
            "own_ips": ["192.168.1.10"],
            "gateway": "192.168.1.1",
            "host_count": 2,
            "hosts": [
                {"ip": "192.168.1.10", "mac": "", "is_self": True, "is_gateway": False, "ports": [], "kind": "self"},
                {"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff", "is_self": False, "is_gateway": False,
                 "ports": [80, 443], "kind": "web-ui"},
            ],
        })
        assert "THIS MACHINE" in s
        assert "192.168.1.1" in s
        assert "192.168.1.5" in s
        assert "web-ui" in s

    def test_rejects_bad_subnet(self):
        from nova_core.tools.network import LANDiscovery
        r = LANDiscovery().execute(subnets="not-a-subnet")
        assert r.success is False
        assert "Bad subnet" in r.error

    def test_tool_registered(self):
        from nova_core.tools import get_registry
        reg = get_registry()
        assert "device_lookup" in reg._tools

    def test_format_device_card(self):
        from nova_core.brain import format_device_lookup
        s = format_device_lookup({
            "query": "355985051234567",
            "device_count": 1,
            "devices": [{
                "id": "d1", "name": "S21", "identifier": "phone-1",
                "imei": "355985051234567", "serial": None,
                "model": "Galaxy S21", "manufacturer": "Samsung",
                "os_type": "android", "os_version": "14",
                "ip_address": "94.1.2.3", "local_ip": "192.168.1.42",
                "carrier": "MTN", "active": True, "lost_mode": False,
                "last_lat": 0.347596, "last_lon": 32.582520,
                "last_speed": 1.2, "last_place": "Kampala",
                "last_seen": "2026-09-12T10:00:00",
            }],
        })
        assert "S21" in s
        assert "imei=355985051234567" in s
        assert "0.347596,32.58252" in s
        assert "ACTIVE" in s
        assert "MTN" in s