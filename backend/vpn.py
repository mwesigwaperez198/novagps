import logging
import subprocess
import re
from pathlib import Path

logger = logging.getLogger("nova.vpn")

WG_INTERFACE_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,15}$")


def get_vpn_status() -> dict:
    status = {"wireguard": {}, "openvpn": {}}
    try:
        completed = subprocess.run(
            ["wg", "show"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=5,
            check=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        interfaces = []
        current_iface = None
        for line in output.splitlines():
            if line.startswith("interface:"):
                current_iface = line.split(":", 1)[1].strip()
                interfaces.append({"name": current_iface, "peers": []})
            elif line.strip().startswith("peer:") and interfaces:
                peer_id = line.split(":", 1)[1].strip()
                interfaces[-1]["peers"].append({"public_key": peer_id})
            elif current_iface and "latest handshake" in line.lower():
                if interfaces and interfaces[-1]["peers"]:
                    interfaces[-1]["peers"][-1]["last_handshake"] = line.split(":", 1)[1].strip()
        status["wireguard"] = {"interfaces": interfaces, "active": len(interfaces) > 0}
    except FileNotFoundError:
        status["wireguard"] = {"error": "wireguard-tools not installed"}
    except subprocess.TimeoutExpired:
        status["wireguard"] = {"error": "wg show timed out"}

    try:
        completed = subprocess.run(
            ["pgrep", "-a", "openvpn"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=5,
            check=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace").strip()
        processes = []
        for line in output.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                processes.append({"pid": parts[0], "command": parts[1]})
        status["openvpn"] = {"processes": processes, "active": len(processes) > 0}
    except FileNotFoundError:
        status["openvpn"] = {"error": "openvpn not installed"}

    return status


def connect_vpn(config_path: str, vpn_type: str = "wireguard") -> dict:
    if not Path(config_path).exists():
        return {"error": "config file not found"}
    if vpn_type == "wireguard":
        interface_name = Path(config_path).stem
        if not WG_INTERFACE_PATTERN.fullmatch(interface_name):
            return {"error": "invalid interface name"}
        try:
            completed = subprocess.run(
                ["wg-quick", "up", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=15,
                check=False,
            )
            if completed.returncode == 0:
                return {"status": "connected", "interface": interface_name, "type": "wireguard"}
            return {"error": "connection failed", "detail": completed.stdout.decode("utf-8", errors="replace")[:500]}
        except FileNotFoundError:
            return {"error": "wg-quick not installed"}
    elif vpn_type == "openvpn":
        try:
            proc = subprocess.Popen(
                ["openvpn", "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return {"status": "connecting", "pid": proc.pid, "type": "openvpn"}
        except FileNotFoundError:
            return {"error": "openvpn not installed"}
    return {"error": "unsupported vpn type"}


def disconnect_vpn(interface_name: str = "", vpn_type: str = "wireguard") -> dict:
    if vpn_type == "wireguard":
        if not interface_name:
            return {"error": "interface name required"}
        if not WG_INTERFACE_PATTERN.fullmatch(interface_name):
            return {"error": "invalid interface name"}
        try:
            completed = subprocess.run(
                ["wg-quick", "down", interface_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=10,
                check=False,
            )
            if completed.returncode == 0:
                return {"status": "disconnected", "interface": interface_name}
            return {"error": "disconnect failed", "detail": completed.stdout.decode("utf-8", errors="replace")[:500]}
        except FileNotFoundError:
            return {"error": "wg-quick not installed"}
    elif vpn_type == "openvpn":
        try:
            subprocess.run(["killall", "openvpn"], timeout=5, check=False)
            return {"status": "disconnected", "type": "openvpn"}
        except FileNotFoundError:
            return {"error": "killall not available"}
    return {"error": "unsupported vpn type"}
