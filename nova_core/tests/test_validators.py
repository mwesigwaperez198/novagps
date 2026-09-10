"""LAU module validators - deterministic gates for the Hardware Peripheral,
Tracking Logic, and Geofence Verification lanes.

Each test feeds the definitive staging-loop prompt through the shield, asserts
the correct intent routing, then compiles AND executes the emitted source
standalone, verifying the emitted machine-parseable JSON payload lands.
"""

import json
import subprocess
import sys
import tempfile

import pytest

from nova_core.shield import NovaDeterministicShield


HARDWARE_VECTOR_PROMPT = (
    "Isolate an internal system alert where an unauthorized PID is attempting to "
    "spawn a background shell thread and bind to local video capture nodes (/dev/video0). "
    "Generate your 4-step <thought_process> showing how you trap this file descriptor "
    "interaction, map the rogue process memory tree, and write an immutable Python handler "
    "to forcefully revoke its media access rights."
)

TRACKING_LOGIC_PROMPT = (
    "A compromised asset terminal is streaming fabricated GPS fixes with NaN latitude, "
    "infinite longitude, 1e300 out-of-range coordinates, and wrapped/negative timestamps "
    "to escape the tracking validation stream. Run your localized tracking logic: float "
    "plausibility, bounding-box range gate, speed and timestamp monotonicity, and emit a "
    "validation filter that drops invalid fixes before the routing pipeline."
)

GEOFENCE_VERIFICATION_PROMPT = (
    "A compromised asset terminal is sending corrupted NMEA 0183 sentences ($GPRMC) "
    "attempting to bypass a critical geofence layer via a coordinates race-condition exploit. "
    "Isolate this anomaly: enforce checksum status, monotonic fix ordering, a max jump "
    "velocity gate, and serialize the geofence verification so the TOCTOU window closes. "
    "Emit the neutralizing filter."
)


def _emit(source):
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
        fh.write(source)
        path = fh.name
    return path


def _compile_and_run(path):
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", path],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr

    result = subprocess.run(
        [sys.executable, path], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr[-1000:]
    return result.stdout


def _last_json_line(stdout):
    for line in stdout.strip().splitlines():
        stripped = line.strip()
        if stripped.startswith("{"):
            decoded = json.loads(stripped)
            assert "status" in decoded
            assert "alert_badges" in decoded
            return decoded
    pytest.fail("no JSON payload emitted")
    return None


@pytest.fixture(scope="module")
def shield():
    return NovaDeterministicShield()


@pytest.fixture(scope="module")
def emitted_sources(shield):
    return {
        "hardware": shield.process_deterministic_fallback(
            task_input=HARDWARE_VECTOR_PROMPT
        )["output_payload"]["response"],
        "tracking": shield.process_deterministic_fallback(
            task_input=TRACKING_LOGIC_PROMPT
        )["output_payload"]["response"],
        "geofence": shield.process_deterministic_fallback(
            task_input=GEOFENCE_VERIFICATION_PROMPT
        )["output_payload"]["response"],
    }


class TestHardwarePeripheral:
    def test_intent_routing(self, shield):
        out = shield.process_deterministic_fallback(task_input=HARDWARE_VECTOR_PROMPT)
        payload = out["output_payload"]
        assert payload["action_enforced"] == "EMIT_PERIPHERAL_GUARD_DAEMON"
        assert "flag_unauthorized_pid_binds" in payload["directives"]
        assert "audit_ioctl_requests" in payload["directives"]
        assert set(out["thought_process"]) == {
            "Telemetric Baseline",
            "Constraint Isolation",
            "Exploitation / Adaptation Vector",
            "Defensive Delta / Execution Steps",
        }
        assert len(out["thought_sequence"]) == 4

    def test_emitter_runs_with_json_contract(self, emitted_sources):
        path = _emit(emitted_sources["hardware"])
        try:
            stdout = _compile_and_run(path)
        finally:
            import os

            os.unlink(path)
        payload = _last_json_line(stdout)
        assert payload["engine"] == "PERIPHERAL_GUARD_DAEMON"
        assert payload["status"] == "GUARD_ARMED"
        assert len(payload["alert_badges"]) >= 4
        assert "<thought_process>" in stdout
        assert "</thought_process>" in stdout
        assert "---HUMAN---" in stdout


class TestTrackingLogic:
    def test_intent_routing(self, shield):
        out = shield.process_deterministic_fallback(task_input=TRACKING_LOGIC_PROMPT)
        payload = out["output_payload"]
        assert payload["action_enforced"] == "EMIT_COORDINATE_VALIDATION_FILTER"
        assert "deny_non_finite_coordinates" in payload["directives"]
        assert "deny_out_of_range_fixes" in payload["directives"]

    def test_emitter_runs_with_json_contract(self, emitted_sources):
        path = _emit(emitted_sources["tracking"])
        try:
            stdout = _compile_and_run(path)
        finally:
            import os

            os.unlink(path)
        payload = _last_json_line(stdout)
        assert payload["engine"] == "COORDINATE_VALIDATION_FILTER"
        assert payload["status"] == "FILTER_GUARDED"
        cases = {row["case"]: row for row in payload["matrix"]}
        assert cases["valid_sf"]["accepted"] is True
        for bad in ("nan_lat", "inf_lon", "1e300_lat", "neg_ts", "out_of_world"):
            assert cases[bad]["accepted"] is False
        assert "<thought_process>" in stdout
        assert "---HUMAN---" in stdout


class TestGeofenceVerification:
    def test_intent_routing(self, shield):
        out = shield.process_deterministic_fallback(
            task_input=GEOFENCE_VERIFICATION_PROMPT
        )
        payload = out["output_payload"]
        assert payload["action_enforced"] == "EMIT_GEOFENCE_NMEA_NEUTRALIZING_FILTER"
        assert "enforce_checksum_status" in payload["directives"]
        assert "monotonic_fix_ordering" in payload["directives"]
        assert "max_jump_velocity_gate" in payload["directives"]
        assert "serialize_geofence_verification" in payload["directives"]

    def test_emitter_runs_with_json_contract(self, emitted_sources):
        path = _emit(emitted_sources["geofence"])
        try:
            stdout = _compile_and_run(path)
        finally:
            import os

            os.unlink(path)
        payload = _last_json_line(stdout)
        assert payload["engine"] == "GEOFENCE_NMEA_NEUTRALIZING_FILTER"
        assert payload["status"] == "FILTER_SERIALIZED"
        cases = {row["case"]: row for row in payload["matrix"]}
        assert cases["valid_inside"]["accepted"] is True
        assert cases["valid_inside"]["inside"] is True
        assert cases["outside_jump"]["accepted"] is False
        assert "<thought_process>" in stdout
        assert "---HUMAN---" in stdout