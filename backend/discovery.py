"""Auto-detection of connected devices.

Discovers devices on the local network via ARP, mDNS, LLDP, and USB.
"""

import logging
import subprocess
import re
from typing import Any

logger = logging.getLogger("nova.discovery")


def _run(cmd: list[str], timeout: int = 15) -> str:
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        return completed.stdout.decode("utf-8", errors="replace")
    except FileNotFoundError:
        return f"ERROR: {cmd[0]} not installed"
    except subprocess.TimeoutExpired:
        return f"ERROR: command timed out after {timeout}s"


def arp_scan() -> list[dict[str, str]]:
    """Parse the system ARP table for discovered devices."""
    output = _run(["arp", "-a"], timeout=5)
    if output.startswith("ERROR:"):
        return [{"error": output}]
    devices: list[dict[str, str]] = []
    for line in output.splitlines():
        ip_match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
        mac_match = re.search(r"at\s+([0-9A-Fa-f:]{17})", line)
        if ip_match and mac_match:
            devices.append({
                "ip": ip_match.group(1),
                "mac": mac_match.group(1),
                "method": "arp",
            })
    if not devices:
        output = _run(["ip", "neigh"], timeout=5)
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[3] == "REACHABLE":
                mac_match = re.search(r"([0-9A-Fa-f:]{17})", line)
                if mac_match:
                    devices.append({
                        "ip": parts[0],
                        "mac": mac_match.group(1),
                        "method": "ip_neigh",
                    })
    return devices


def mdns_discover() -> list[dict[str, str]]:
    """Discover devices via mDNS/Avahi/Bonjour."""
    devices: list[dict[str, str]] = []
    output = _run(["avahi-browse", "-alrp", "-t"], timeout=10)
    if not output.startswith("ERROR:") and output.strip():
        current: dict[str, str] = {}
        for line in output.splitlines():
            if line.startswith("="):
                if current:
                    devices.append(current)
                current = {"method": "mdns"}
            elif line.startswith("address"):
                parts = line.split("[")
                if len(parts) > 1:
                    current["ip"] = parts[1].rstrip("]")
            elif "hostname" in line:
                current["hostname"] = line.split("=", 1)[1].strip().rstrip(".local") if "=" in line else ""
            elif "txt" in line and "model" in line.lower():
                current["model"] = line.split("=", 1)[1].strip() if "=" in line else ""
        if current:
            devices.append(current)
    if not devices:
        output = _run(["dns-sd", "-B", "_http._tcp", "local."], timeout=8)
        if not output.startswith("ERROR:"):
            for line in output.splitlines():
                if ".local" in line:
                    parts = line.split()
                    if parts:
                        devices.append({
                            "method": "mdns",
                            "hostname": parts[-1].rstrip("."),
                        })
    return devices


def usb_enumerate() -> list[dict[str, str]]:
    """Enumerate connected USB devices."""
    devices: list[dict[str, str]] = []
    output = _run(["lsusb"], timeout=5)
    if output.startswith("ERROR:"):
        return [{"error": output}]
    for line in output.splitlines():
        if not line.strip():
            continue
        id_match = re.search(r"ID\s+([0-9A-Fa-f]{4}:[0-9A-Fa-f]{4})", line)
        desc = line.split("ID")[1].strip() if "ID" in line else line
        parts = desc.split(None, 1)
        vendor_product = parts[0] if parts else ""
        description = parts[1] if len(parts) > 1 else ""
        devices.append({
            "id": vendor_product,
            "description": description.strip(),
            "method": "usb",
            "raw": line.strip(),
        })
    return devices


def scan_network(subnet: str = "192.168.1.0/24") -> dict[str, Any]:
    """Comprehensive network scan using nmap for host discovery."""
    output = _run(["nmap", "-sn", "--min-rate", "1000", subnet], timeout=30)
    if output.startswith("ERROR:"):
        return {"error": output}
    hosts: list[dict[str, str]] = []
    current_ip = ""
    current_mac = ""
    current_vendor = ""
    for line in output.splitlines():
        if "Nmap scan report for" in line:
            if current_ip:
                hosts.append({"ip": current_ip, "mac": current_mac, "vendor": current_vendor})
            parts = line.split()
            host_part = parts[-1].strip("()")
            if "(" in host_part and ")" in host_part:
                ip = host_part.split("(")[1].rstrip(")")
                name = host_part.split("(")[0]
                current_ip = ip
                current_mac = ""
                current_vendor = ""
            else:
                current_ip = host_part
                current_mac = ""
                current_vendor = ""
        elif "MAC Address" in line:
            mac_match = re.search(r"([0-9A-Fa-f:]{17})", line)
            if mac_match:
                current_mac = mac_match.group(1)
            if "(" in line:
                vendor = line.split("(")[1].rstrip(")")
                current_vendor = vendor
    if current_ip:
        hosts.append({"ip": current_ip, "mac": current_mac, "vendor": current_vendor})
    return {"subnet": subnet, "hosts": hosts, "count": len(hosts)}


def discover_usb_devices() -> dict[str, Any]:
    """Return all connected USB devices."""
    return {"devices": usb_enumerate()}
