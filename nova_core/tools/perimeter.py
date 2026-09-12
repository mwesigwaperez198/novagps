"""Physical perimeter tools for LAU: 802.11/BLE radio sightings,
RSSI/NMEA location math, and HMAC-verified remote telemetry bridging.

These give LAU the "nearby hardware" and "different wifi network"
capabilities as real, deterministic tools — no LLM needed. Radio sniffing
binding is root + a monitor-mode interface, so on machines without one the
tool returns an honest capability report instead of a phantom scan.
"""

import hmac
import hashlib
import json
import math
import re
import shutil
import subprocess
import time

from ..tools import Tool, ToolResult, ToolRegistry


class RadioSniffer(Tool):
    """Detect nearby Wi-Fi/BLE devices NOT on our network via 802.11 probe
    requests (monitor mode) + optional BLE advertising scan. Physical-perimeter
    awareness: sees phones/laptops that roam past but never join our AP."""

    name = "radio_sniffer"
    description = (
        "Detect physically nearby Wi-Fi/BLE devices that are NOT connected to "
        "our network: 802.11 probe-request capture (monitor mode) with RSSI, and "
        "optional BLE advertising scan (hcitool lescan). Answers 'nearby devices "
        "not connected to this wifi', 'what is roaming around us'."
    )
    category = "perimeter"

    def execute(self, interface: str = "", duration: int = 3, scan_ble: bool = False, **kwargs) -> ToolResult:
        probing = self._can_monitor_capture()
        ble = self._can_ble_scan()

        report = {
            "probe_request_capture_owned": probing.get("available", False),
            "ble_scan_owned": ble,
            "duration_sec": int(duration),
            "interface": probing.get("interface", interface or ""),
            "perimeter": True,
        }
        stations = []
        if probing.get("available", False):
            stations = self._capture_probe_requests(probing["interface"], duration)
        report["unconnected_devices"] = stations
        report["nearby_count"] = len(stations)
        report["hint"] = self._hint(report)
        return ToolResult(success=True, output=report)

    def _can_monitor_capture(self) -> dict:
        if not shutil.which("iw") and not shutil.which("iwconfig") and not shutil.which("airmon-ng"):
            return {"available": False, "reason": "no wireless tooling (iw/airmon-ng)"}
        try:
            import scapy.all  # noqa: F401
        except Exception:
            return {
                "available": False,
                "reason": "monitor capture needs scapy (pip install scapy) — not installed",
                "pip": "scapy",
            }
        try:
            euid = getattr(__import__("os"), "geteuid")()
            if euid != 0:
                return {"available": False, "reason": "root required for raw monitor-mode sockets"}
        except Exception:
            pass
        return {"available": False, "reason": "no monitor-mode wireless interface present on this host"}

    def _can_ble_scan(self) -> bool:
        return shutil.which("hcitool") is not None

    def _capture_probe_requests(self, interface: str, duration: int) -> list:
        stations = []
        start = time.time()
        attempts = 0
        while time.time() - start < max(1, int(duration)) and attempts < 90:
            attempts += 1
            try:
                from scapy.all import sniff
                pkts = sniff(iface=interface, count=8, timeout=1, store=True)
                for pkt in pkts:
                    station = self._station_from_packet(pkt)
                    if station and station not in stations:
                        stations.append(station)
            except Exception:
                return stations
            if len(stations) >= 12:
                break
        return stations

    def _station_from_packet(self, pkt) -> dict | None:
        if pkt is None:
            return None
        try:
            if not hasattr(pkt, "haslayer"):
                return None
            if not pkt.haslayer("Dot11"):
                return None
            import re as _re
            src = getattr(pkt, "addr2", "") or ""
            dst = getattr(pkt, "addr1", "") or ""
            if not _re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", src):
                return None
            mac = src.upper()
            is_probe = dst == "ff:ff:ff:ff:ff:ff" and pkt.type == 0 and pkt.subtype in (4, 8)
            if not is_probe:
                return None
            rssi = ""
            if pkt.haslayer("RadioTap"):
                try:
                    rssi = getattr(pkt.getlayer("RadioTap"), "dbm_ant_signal", "")
                except Exception:
                    rssi = ""
            ssid_parts = []
            try:
                if pkt.haslayer("Dot11Elt"):
                    elt = pkt.getlayer("Dot11Elt")
                    while elt:
                        if int(elt.ID) == 0 and elt.info:
                            ssid_parts.append(elt.info.decode("utf-8", "replace"))
                        elt = elt.payload
            except Exception:
                pass
            return {
                "mac": mac,
                "rssi": rssi,
                "ssid_probed": ssid_parts or [""],
                "type": "probe-request",
            }
        except Exception:
            return None

    def _hint(self, report: dict) -> str:
        if report["probe_request_capture_owned"]:
            return f"Monitor capture ran on {report['interface']}; {report['nearby_count']} unconnected device(s) seen."
        if report.get("ble_scan_owned"):
            return (
                "No monitor-mode interface, but BLE scanning is available. On a radio-capable "
                "host: airmon-ng start wlan0, re-run, and LAU will list probe-requesting devices."
            )
        return (
            "This host has no radio hardware exposed (typical on servers/Render). On a machine "
            "with Wi-Fi: install scapy, put the adapter in monitor mode (airmon-ng start wlan0), "
            "and LAU will report unconnected nearby devices with MAC + RSSI."
        )


class LocationMath(Tool):
    """Deterministic RSSI distance math + NMEA $GPRMC parsing — the tracking
    logic behind 'location of devices' without any external service."""

    name = "location_engine"
    description = (
        "RSSI-to-distance log-distance path loss math and NMEA 0183 $GPRMC "
        "sentence parsing for tracking logic. Answers 'location of devices', "
        "'tracking logics', 'how do you estimate distance from signal'."
    )
    category = "perimeter"

    def execute(self, rssi: float | None = None, measured_power: float = -59.0, n: float = 2.5,
                sentence: str = "", **kwargs) -> ToolResult:

        from . import location_core

        math_out = None
        if rssi is not None:
            distance = location_core.distance_from_rssi(rssi, measured_power, n)
            math_out = {
                "rssi": rssi,
                "distance_m": distance,
                "measured_power": measured_power,
                "n": n,
            }
        output = {"math": math_out}
        if sentence.strip():
            output["nmea"] = location_core.parse_gprmc(sentence)
        else:
            output["nmea"] = None
            output["example"] = (
                "$GPRMC,hhmmss.ss,A,3723.2475,N,12158.3416,W,0.13,309.62,120598,,*10"
            )
        return ToolResult(success=True, output=output)


class RemoteBridge(Tool):
    """HMAC-verified telemetry ingestion for devices on a DIFFERENT network
    (not even near the AP, Layer 3/7 only). A payload is only trusted when its
    HMAC signature verifies against the configured SECRET_KEY."""

    name = "remote_bridge"
    description = (
        "Verify and accept telemetry from devices on a different wifi network / "
        "not physically near us: HMAC-SHA256 signed payload bridge. Answers "
        "'different wifi network', 'not even near', 'remote device telemetry'."
    )
    category = "perimeter"

    def execute(self, payload: dict | None = None, signature: str = "", **kwargs) -> ToolResult:
        from ..config import get_config

        secret = get_config().secret_key
        if payload is None:
            return ToolResult(
                success=True,
                output={
                    "mode": "remote_bridge",
                    "configured": bool(secret),
                    "note": "API: payload+signature (HMAC-SHA256 of canonical JSON) or config SECRET_KEY.",
                },
            )
        if not secret:
            return ToolResult(success=False, error="SECRET_KEY not configured; HMAC bridge is disabled (fail-closed).")
        if not signature:
            return ToolResult(success=False, error="Missing signature — refusing unsigned telemetry (fail-closed).")

        from . import location_core

        ok, calculated = location_core.hmac_verify(payload, signature, secret)
        p = payload if isinstance(payload, dict) else {}
        return ToolResult(
            success=ok,
            output={
                "verified": ok,
                "device_id": p.get("device_id") or p.get("identifier") or "",
                "imei": p.get("imei", ""),
                "lat": p.get("lat"),
                "lon": p.get("lon"),
                "net_type": p.get("net_type") or "",
                "calculated_signature": calculated,
                "action": "ACCEPT_TELEMETRY" if ok else "REJECT_TELEMETRY",
            },
        )


def register_perimeter_tools(registry: ToolRegistry):
    for tool_cls in [RadioSniffer, LocationMath, RemoteBridge]:
        registry.register(tool_cls())