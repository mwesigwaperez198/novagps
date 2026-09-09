"""Auto-detection of connected devices.

Discovers devices on the local network via ARP, mDNS, LLDP, and USB.
"""

import concurrent.futures
import ipaddress
import logging
import re
import socket
import subprocess
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


# Ports that hint at a camera / IP webcam when open.
CAMERA_PORTS = (554, 80, 443, 8080)
# Small "is anything alive here?" probe set for the binary-free sweep.
PROBE_PORTS = (22, 80, 443, 554)


def _tcp_open(ip: str, port: int, timeout: float = 0.5) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((str(ip), port)) == 0
    except socket.error:
        return False
    finally:
        sock.close()


def _open_ports(ip: str, ports, timeout: float = 0.5) -> list[int]:
    return [port for port in ports if _tcp_open(ip, port, timeout)]


def _classify_kind(ports: list[int]) -> str:
    if 554 in ports:
        return "rtsp-camera"
    if any(port in ports for port in (80, 443, 8080)):
        return "web-ui"
    return "host"


def _tcp_host_discovery(subnet: str) -> tuple[list[dict[str, Any]], bool]:
    """Host discovery without any external binary.

    Uses a bounded concurrent TCP connect sweep on a small probe set. Wide
    ranges are truncated to 1024 addresses so an accidental /8 never hangs.
    """
    network = ipaddress.ip_network(subnet, strict=False)
    candidates = list(network.hosts())
    truncated = len(candidates) > 1024
    candidates = candidates[:1024]

    def probe(ip):
        alive = _open_ports(str(ip), PROBE_PORTS, 0.35)
        if not alive:
            return None
        camera = _open_ports(str(ip), CAMERA_PORTS, 0.35)
        return {
            "ip": str(ip),
            "mac": "",
            "vendor": "",
            "ports": sorted(set(alive) | set(camera)),
            "is_camera": 554 in camera,
            "kind": _classify_kind(camera),
            "method": "tcp",
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        found = [host for host in pool.map(probe, candidates) if host is not None]

    macs = {}
    for entry in arp_scan():
        if isinstance(entry, dict) and entry.get("ip") and entry.get("mac"):
            macs[entry["ip"]] = entry["mac"]
    for host in found:
        if host["ip"] in macs:
            host["mac"] = macs[host["ip"]]
    return found, truncated


def _classify_nmap_hosts(hosts: list[dict[str, Any]]) -> None:
    for host in hosts:
        camera = _open_ports(host["ip"], CAMERA_PORTS, 0.35)
        host["ports"] = sorted(camera)
        host["is_camera"] = 554 in camera
        host["kind"] = _classify_kind(camera)
        host["method"] = "nmap"


def scan_network(subnet: str = "192.168.1.0/24") -> dict[str, Any]:
    """Comprehensive network scan with nmap, falling back to a built-in
    TCP sweep when the host binary is missing.

    Every live host is probed for camera ports (554/80/443/8080) so the
    frontend can filter out / highlight nearby cameras and street cams.
    """
    output = _run(["nmap", "-sn", "--min-rate", "1000", subnet], timeout=30)
    if output.startswith("ERROR:"):
        hosts, truncated = _tcp_host_discovery(subnet)
        return {
            "subnet": subnet,
            "hosts": hosts,
            "count": len(hosts),
            "engine": "tcp-fallback",
            "truncated": truncated,
            "note": "nmap not installed - used built-in TCP sweep (ports 22/80/443/554)",
        }
    hosts: list[dict[str, Any]] = []
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
                current_ip = host_part.split("(")[1].rstrip(")")
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
    _classify_nmap_hosts(hosts)
    return {"subnet": subnet, "hosts": hosts, "count": len(hosts), "engine": "nmap"}


def discover_usb_devices() -> dict[str, Any]:
    """Return all connected USB devices."""
    return {"devices": usb_enumerate()}
