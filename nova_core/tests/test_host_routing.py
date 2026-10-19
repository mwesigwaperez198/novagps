"""Gates for IP/host-aware routing in the LAU brain.

An operator naming a target must actually reach that target. A private LAN
address must never be reported as if the cloud could scan it, and a sentence
must never be shipped to device lookup as though it were an IMEI/serial.
"""

from nova_core.brain import NovaBrain
from nova_core.tools.backend import HostIdentifier


def _brain():
    return NovaBrain.__new__(NovaBrain)


def test_backend_url_override_wins(monkeypatch):
    from nova_core import config

    monkeypatch.setenv("NOVA_BACKEND_URL", "https://novagps.onrender.com/")
    assert config._default_backend_url() == "https://novagps.onrender.com"


def test_backend_url_resolves_render_public_url(monkeypatch):
    from nova_core import config

    monkeypatch.delenv("NOVA_BACKEND_URL", raising=False)
    monkeypatch.setenv("RENDER_EXTERNAL_URL", "https://novagps.onrender.com")
    assert config._default_backend_url() == "https://novagps.onrender.com"


def test_backend_url_uses_bound_port(monkeypatch):
    from nova_core import config

    monkeypatch.delenv("NOVA_BACKEND_URL", raising=False)
    monkeypatch.delenv("RENDER_EXTERNAL_URL", raising=False)
    monkeypatch.delenv("PUBLIC_BASE_URL", raising=False)
    monkeypatch.setenv("PORT", "9000")
    assert config._default_backend_url() == "http://127.0.0.1:9000"


def test_host_extracted_from_url_and_ip():
    brain = _brain()
    assert brain._extract_host("scan ports on https://example.test/path") == "example.test"
    assert brain._extract_host("check 192.168.1.6 for open ports") == "192.168.1.6"
    assert brain._extract_host("999.1.1.1 is not an address") == ""


def test_ip_question_routes_to_host_identify_and_scans_that_host():
    brain = _brain()
    query = (
        "can you track ip device on router id 192.168.1.6, "
        "which device is that and does it have open ports"
    )
    parsed = brain._parse_request(query)
    actions = parsed["actions"]
    assert {"tool": "host_identify", "params": {"target": "192.168.1.6"}} in actions
    assert {"tool": "port_scan", "params": {"host": "192.168.1.6"}} in actions
    # The whole sentence must not be treated as a device name.
    assert all(a["tool"] != "device_lookup" for a in actions)


def test_port_scan_without_host_keeps_default_behavior():
    brain = _brain()
    parsed = brain._parse_request("port scan ports 22,80")
    action = next(a for a in parsed["actions"] if a["tool"] == "port_scan")
    assert action["params"]["ports"] == "22,80"
    assert "host" not in action["params"]


def test_private_ip_is_reported_as_unreachable_lan():
    result = HostIdentifier().execute(target="192.168.1.6")
    assert result.success is True
    assert result.output["scope"] == "private"
    assert result.output["matched_devices"] == []
    joined = " ".join(result.output["analysis"])
    assert "cloud" in joined.lower()
    assert "local network" in joined.lower()


def test_public_ip_without_registry_match_is_honest(monkeypatch):
    import socket

    def _no_reverse(*args, **kwargs):
        raise OSError("no resolver in test")

    monkeypatch.setattr(socket, "gethostbyaddr", _no_reverse)
    result = HostIdentifier().execute(target="8.8.8.8")
    assert result.success is True
    assert result.output["scope"] == "public"
    assert "No registered device" in result.output["message"]


def test_empty_target_fails_cleanly():
    result = HostIdentifier().execute(target="")
    assert result.success is False
