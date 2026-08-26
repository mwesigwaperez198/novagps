"""Firmware diagnosis module.

Probes devices for firmware version, serial numbers, and checks
against known vulnerability databases.
"""

import logging
import re
from typing import Any

import requests as http_requests

logger = logging.getLogger("nova.firmware")


def lookup_cve(keyword: str, limit: int = 10) -> dict[str, Any]:
    """Search the NIST NVD API for CVEs matching a keyword."""
    try:
        resp = http_requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": limit},
            timeout=15,
        )
        if resp.status_code != 200:
            return {"error": f"NVD API returned status {resp.status_code}"}
        data = resp.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cves.append({
                "id": cve_data.get("id", ""),
                "description": (cve_data.get("descriptions", [{}])[0].get("value", ""))[:200],
                "published": cve_data.get("published", ""),
                "severity": _extract_severity(cve_data),
            })
        return {"keyword": keyword, "cves": cves, "count": len(cves)}
    except Exception as exc:
        return {"keyword": keyword, "error": str(exc)}


def _extract_severity(cve_data: dict) -> str:
    """Extract severity from CVE metrics."""
    metrics = cve_data.get("metrics", {})
    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version in metrics and metrics[version]:
            cvss = metrics[version][0].get("cvssData", {})
            return cvss.get("baseSeverity", "UNKNOWN")
    return "UNKNOWN"


def diagnose_firmware(ip: str, manufacturer: str = "", model: str = "", firmware_version: str = "") -> dict[str, Any]:
    """Diagnose device firmware and check for known vulnerabilities."""
    result: dict[str, Any] = {"ip": ip}
    result["manufacturer"] = manufacturer
    result["model"] = model
    result["firmware_version"] = firmware_version
    keywords = []
    if manufacturer:
        keywords.append(manufacturer)
    if model:
        keywords.append(model)
    if firmware_version:
        keywords.append(firmware_version)
    if keywords:
        search_term = " ".join(keywords[:3])
        cve_result = lookup_cve(search_term)
        result["cve_search"] = cve_result
    else:
        result["cve_search"] = {"note": "No manufacturer/model/version provided for CVE lookup"}
    result["recommendations"] = _generate_recommendations(manufacturer, model, firmware_version)
    return result


def _generate_recommendations(manufacturer: str, model: str, firmware: str) -> list[str]:
    recs = []
    if not manufacturer:
        recs.append("Could not identify manufacturer — check ONVIF or SNMP for device info")
    if not firmware:
        recs.append("Firmware version unknown — check device web interface for updates")
    if manufacturer.lower() in ("hikvision", "dahua", "axis", "amcrest"):
        recs.append(f"{manufacturer} devices require regular firmware updates for security")
        recs.append("Check manufacturer website for latest firmware")
    if "hikvision" in manufacturer.lower():
        recs.append("Hikvision devices have known CVE-2021-36260 — ensure firmware >= 4.30")
    if "dahua" in manufacturer.lower():
        recs.append("Dahua devices have known backdoor vulnerabilities — update immediately")
    recs.append("Disable UPnP if not needed to reduce attack surface")
    recs.append("Use SNMPv3 instead of v2c for secure device management")
    return recs


def check_device_health(ip: str) -> dict[str, Any]:
    """Quick health check of a network device."""
    import subprocess
    ping_output = subprocess.run(
        ["ping", "-c", "3", "-W", "2", ip],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=10,
        check=False,
    ).stdout.decode("utf-8", errors="replace")
    latency_match = re.search(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", ping_output)
    avg_latency = float(latency_match.group(2)) if latency_match else None
    return {
        "ip": ip,
        "reachable": "3 packets transmitted, 3 received" in ping_output or "3 received" in ping_output,
        "avg_latency_ms": avg_latency,
        "packet_loss": "100% packet loss" in ping_output,
    }
