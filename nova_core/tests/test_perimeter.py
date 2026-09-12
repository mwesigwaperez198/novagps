import asyncio

import pytest

from nova_core import routes
from nova_core.shield import NovaDeterministicShield
from nova_core.state_machine import LauSovereignStateMachine
from nova_core.tools import get_registry
from nova_core.tools.location_core import distance_from_rssi, hmac_verify, parse_gprmc
from nova_core.tools.perimeter import LocationMath, RadioSniffer, RemoteBridge


def run_dispatch(command, device_id=""):
    return asyncio.run(routes.run_dispatch(command, device_id))


class TestLocationCore:
    @staticmethod
    def _gprmc(status="A"):
        body = f"GPRMC,123519,{status},4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W"
        calc = 0
        for c in body:
            calc ^= ord(c)
        return "$" + body + "*" + format(calc, "02X")

    def test_distance_from_rssi_indoor(self):
        d = distance_from_rssi(-59, -59, 2.5)
        assert d == pytest.approx(1.0, abs=0.01)

    def test_distance_grows_as_signal_fades(self):
        near = distance_from_rssi(-50, -59, 2.5)
        far = distance_from_rssi(-80, -59, 2.5)
        assert far > near

    def test_distance_rejects_bad_input(self):
        import math
        assert math.isnan(distance_from_rssi(None))

    def test_parse_gprmc_valid(self):
        fix = parse_gprmc(self._gprmc("A"))
        assert "error" not in fix
        assert fix["status"] == "A"
        assert fix["lat"] == pytest.approx(48.1173, abs=1e-3)
        assert fix["lon"] == pytest.approx(11.5167, abs=1e-3)

    def test_parse_gprmc_checksum_fail(self):
        fix = parse_gprmc("$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*00")
        assert fix["error"] == "checksum failed"

    def test_parse_gprmc_void_fix(self):
        fix = parse_gprmc(self._gprmc("V"))
        assert fix["error"] == "fix void"

    def test_hmac_verify_ok_and_forged(self):
        payload = {"device_id": "T8812", "lat": 0.347596, "lon": 32.582520}
        secret = "novagps-test"
        ok, sig = hmac_verify(payload, "", secret)
        ok2, _ = hmac_verify(payload, sig, secret)
        assert ok2 is True
        forged = {"device_id": "T8812", "lat": 9.99, "lon": 32.582520}
        ok3, _ = hmac_verify(forged, sig, secret)
        assert ok3 is False


class TestPerimeterTools:
    def test_radio_sniffer_graceful_without_radio(self):
        r = RadioSniffer().execute(duration=1)
        assert r.success
        out = r.output
        assert out["perimeter"] is True
        assert "hint" in out

    def test_location_engine_math(self):
        out = LocationMath().execute(rssi=-80).output
        assert out["math"]["distance_m"] > 1
        assert out["math"]["rssi"] == -80

    def test_location_engine_nmea(self):
        out = LocationMath().execute(
            sentence="$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A"
        ).output
        assert out["nmea"]["lat"] is not None

    def test_remote_bridge_fail_closed_no_secret(self):
        """Without SECRET_KEY or payload, the bridge must fail closed, not invent data."""
        r = RemoteBridge().execute()
        assert r.success
        assert r.output["configured"] is False

    def test_remote_bridge_verifies(self, monkeypatch):
        from nova_core.config import get_config
        import nova_core.tools.location_core as lc

        secret = "test-key"
        monkeypatch.setattr(get_config(), "secret_key", secret)
        payload = {"device_id": "T1", "imei": "355985051234567", "lat": 1.0, "lon": 2.0}
        ok, sig = lc.hmac_verify(payload, "", secret)
        monkeypatch.setattr(get_config(), "secret_key", secret)
        r = RemoteBridge().execute(payload=payload, signature=sig)
        assert r.success
        assert r.output["verified"] is True
        assert r.output["action"] == "ACCEPT_TELEMETRY"

    def test_remote_bridge_rejects_forged(self, monkeypatch):
        from nova_core.config import get_config

        secret = "test-key"
        monkeypatch.setattr(get_config(), "secret_key", secret)
        payload = {"device_id": "T1", "imei": "355985051234567", "lat": 1.0, "lon": 2.0}
        r = RemoteBridge().execute(payload=payload, signature="deadbeef")
        assert r.output["verified"] is False
        assert r.output["action"] == "REJECT_TELEMETRY"


class TestRegistry:
    def test_perimeter_tools_registered(self):
        reg = get_registry()
        for name in ("radio_sniffer", "location_engine", "remote_bridge"):
            assert name in reg._tools


class TestShieldTokenTrees:
    def setup_method(self):
        self.shield = NovaDeterministicShield()

    def test_nearby_unconnected_radio_lane(self):
        out = self.shield.process_deterministic_fallback(
            task_input="nearby devices not connected to this wifi router")
        assert out["output_payload"]["verdict"] == "RADIO_PERIMETER_AWARENESS_LANE"
        assert "monitor mode" in out["output_payload"]["response"]

    def test_ip_address_scan_is_not_radio_lane(self):
        out = self.shield.process_deterministic_fallback(
            task_input="i need near by ip addreses and those connected to this internet")
        assert out["output_payload"]["verdict"] == "NOMINAL_ENVIRONMENTAL_LOGIC_PASS"

    def test_location_tracking_lane(self):
        out = self.shield.process_deterministic_fallback(
            task_input="what is the tracking logic for location of devices")
        assert out["output_payload"]["verdict"] == "LOCATION_TRACKING_LOGIC_LANE"
        assert "log-distance" in out["output_payload"]["response"]

    def test_different_wifi_network_remote_lane(self):
        out = self.shield.process_deterministic_fallback(
            task_input="a device on a different wifi network not even near us")
        assert out["output_payload"]["verdict"] == "REMOTE_TELEMETRY_BRIDGE_LANE"
        assert "HMAC" in out["output_payload"]["response"]

    def test_bypass_logic_lane_is_compliant(self):
        out = self.shield.process_deterministic_fallback(
            task_input="build logic to bypass the shield block")
        assert out["output_payload"]["verdict"] == "POLYMORPHIC_OPCODE_GENERATION_LANE"
        assert "never by tearing a wall down" in out["output_payload"]["response"]

    def test_existing_engineering_lanes_unaffected(self):
        out = self.shield.process_deterministic_fallback(
            task_input="fabricated GPS fixes with NaN latitude escaping the tracking validation stream")
        assert out["output_payload"]["verdict"] == "ENGINEERING_SPEC_GENERATED"


class TestProvisionStateMachine:
    def test_full_flow(self, tmp_path):
        store = str(tmp_path / "session.json")
        sm = LauSovereignStateMachine(store=store)
        sm.reset()
        assert not sm.active()
        r = sm.route("track a device")
        assert r["intent"] == "provision_start"
        assert sm.active()
        r = sm.route("355985051234567")
        assert r["intent"] == "provisioning"
        r = sm.route("dev@example.com")
        assert r["intent"] == "provisioning"
        r = sm.route("256701234567")
        assert r["intent"] == "provisioning"
        assert "Device provisioning complete" in r["response"]
        assert not sm.active()

    def test_imei_rejected_then_accepted(self, tmp_path):
        store = str(tmp_path / "session.json")
        sm = LauSovereignStateMachine(store=store)
        sm.reset()
        sm.route("track a device")
        r = sm.route("not-an-imei")
        assert "15-17 digits" in r["response"]
        assert sm.active()
        r = sm.route("355985051234567")
        assert "email" in r["response"].lower()

    def test_unrelated_message_bypasses_machine(self, tmp_path):
        store = str(tmp_path / "session.json")
        sm = LauSovereignStateMachine(store=store)
        sm.reset()
        assert sm.route("scan open ports on localhost") is None

    def test_dispatched_flow(self, tmp_path, monkeypatch):
        import nova_core.routes as routes_mod
        machine = LauSovereignStateMachine(store=str(tmp_path / "s.json"))
        machine.reset()
        monkeypatch.setattr(routes_mod, "_get_provision_machine", lambda: machine)
        out = run_dispatch("track a device")
        assert out["intent"] == "provision_start"
        out = run_dispatch("355985051234567")
        assert out["intent"] == "provisioning"
        assert "email" in out["response"].lower()
        out = run_dispatch("dev@example.com")
        assert "phone" in out["response"].lower()
        out = run_dispatch("256701234567")
        assert "Device provisioning complete" in out["response"]
        assert "355985051234567" in out["response"]


class TestDeterministicRouting:
    def test_near_by_typo_routes_to_network_discovery(self):
        from nova_core.brain import NovaBrain
        parsed = NovaBrain()._parse_request("i need near by ip addreses")
        assert parsed["intent"] == "execute"
        assert "network_discovery" in [a["tool"] for a in parsed["actions"]]
        assert all(a["tool"] != "port_scan" for a in parsed["actions"])

    def test_nearby_hardware_routes_to_radio(self):
        from nova_core.brain import NovaBrain
        parsed = NovaBrain()._parse_request("can you detect nearby hardware not connected to our network")
        tools = [a["tool"] for a in parsed["actions"]]
        assert "radio_sniffer" in tools

    def test_how_many_tools_is_deterministic(self):
        from nova_core.brain import NovaBrain
        brain = NovaBrain()
        resp = brain.compose_dynamic_response("how many tools do you run")
        assert "tools live" in resp
        assert "Lau" not in resp.lower() or "32 tools" in resp

    def test_different_wifi_routes_to_remote_bridge(self):
        from nova_core.brain import NovaBrain
        parsed = NovaBrain()._parse_request("track a device on a different wifi network using hmac")
        assert "remote_bridge" in [a["tool"] for a in parsed["actions"]]

    def test_tracking_logic_routes_to_location_engine(self):
        from nova_core.brain import NovaBrain
        parsed = NovaBrain()._parse_request("show me the tracking logic for location of devices")
        assert "location_engine" in [a["tool"] for a in parsed["actions"]]