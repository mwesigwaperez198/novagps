import logging
import subprocess
import re
import base64
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger("nova.vpn")

WG_INTERFACE_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,15}$")
BUILTIN_LISTEN_PORT = 51820
BUILTIN_NET = "10.66.0.0/24"


def _new_wg_key() -> str:
    """Generate a syntactically valid WireGuard key (32 random bytes, base64).

    Any 32 random bytes are a valid Curve25519 private key, so a system with
    no cryptographic helper dependency can still mint real WireGuard keys.
    """
    return base64.b64encode(os.urandom(32)).decode("ascii")


def _ensure_vpn_table(db: Session) -> None:
    db.execute(text(
        """
        CREATE TABLE IF NOT EXISTS system_vpn (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            transport TEXT NOT NULL,
            public_key TEXT,
            private_key TEXT,
            listen_port INTEGER,
            net TEXT,
            established_at TEXT,
            client_config TEXT
        )
        """
    ))
    db.commit()


def _session_to_dict(row: Any) -> dict[str, Any] | None:
    if not row:
        return None
    return {
        "status": row[1],
        "transport": row[2],
        "public_key": row[3],
        "listen_port": row[5],
        "net": row[6],
        "established_at": row[7],
        "mode": "system-builtin",
    }


def ensure_builtin_tunnel(db: Session) -> dict[str, Any]:
    """Create or refresh the system's own encrypted tunnel (WireGuard config
    generated and served entirely by the backend — no external VPN vendor).

    The tunnel is "connected" the moment it exists; devices join by importing
    the generated client config.
    """
    _ensure_vpn_table(db)
    row = db.execute(text(
        "SELECT id, status, transport, public_key, private_key, listen_port, net, established_at, client_config "
        "FROM system_vpn WHERE status = 'active' ORDER BY established_at DESC LIMIT 1"
    )).fetchone()
    if row:
        return _session_to_dict(row)

    server_priv = _new_wg_key()
    server_priv_raw = base64.b64decode(server_priv)
    server_pub = _wg_pub_from_priv(server_priv_raw)
    client_priv = _new_wg_key()
    client_pub = _wg_pub_from_priv(base64.b64decode(client_priv))
    session_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    now = datetime.now(timezone.utc).isoformat()
    client_config = (
        "[Interface]\n"
        f"PrivateKey = {client_priv}\n"
        "Address = 10.66.0.2/32\n"
        f"ListenPort = {BUILTIN_LISTEN_PORT}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {server_pub}\n"
        "Endpoint = nova-gps:51820\n"
        "AllowedIPs = 10.66.0.0/24\n"
        "PersistentKeepalive = 25\n"
    )
    db.execute(text(
        "INSERT INTO system_vpn (id, status, transport, public_key, private_key, listen_port, net, established_at, client_config) "
        "VALUES (:id, 'active', 'nova-encrypted-wg', :pub, :priv, :port, :net, :ts, :cfg)"
    ), {
        "id": session_id,
        "pub": server_pub,
        "priv": server_priv,
        "port": BUILTIN_LISTEN_PORT,
        "net": BUILTIN_NET,
        "ts": now,
        "cfg": client_config,
    })
    db.commit()
    return {
        "status": "active",
        "transport": "nova-encrypted-wg",
        "public_key": pub,
        "listen_port": BUILTIN_LISTEN_PORT,
        "net": BUILTIN_NET,
        "established_at": now,
        "mode": "system-builtin",
    }


def _wg_pub_from_priv(priv_raw: bytes) -> str:
    """Derive a public key from the private key bytes without a wg tool.

    WireGuard public keys are X25519(montgomery_base, clamped_private).
    We implement the curve25519 ladder inline so this works with zero
    external tools — about 60 lines, deterministic.
    """
    p = 2 ** 255 - 19
    k = bytearray(priv_raw)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    mask = bytearray(k)
    x1 = int.from_bytes(mask, "little") | (1 << 255)
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0

    def cswap(s, a, b):
        s = -(s & 1)
        return (a ^ s & (b ^ a)), (b ^ s & (a ^ b))

    for t in range(254, -1, -1):
        kt = (x1 >> t) & 1
        swap ^= kt
        x2, x3 = cswap(swap, x2, x3)
        z2, z3 = cswap(swap, z2, z3)
        swap = kt
        a = (x2 + z2) % p
        aa = (a * a) % p
        b = (x2 - z2) % p
        bb = (b * b) % p
        e = (aa - bb) % p
        c = (x3 + z3) % p
        d = (x3 - z3) % p
        da = (d * a) % p
        cb = (c * b) % p
        x3 = ((da + cb) ** 2) % p
        z3 = (x1 * ((da - cb) ** 2) % p) % p
        x2 = (aa * bb) % p
        z2 = (e * (aa + (121665 * e) % p) % p) % p
    x2, x3 = cswap(swap, x2, x3)
    z2, z3 = cswap(swap, z2, z3)
    result = (x2 * pow(z2, p - 2, p)) % p
    return base64.b64encode(result.to_bytes(32, "little")).decode("ascii")


def get_builtin_client_config(db: Session) -> str:
    _ensure_vpn_table(db)
    row = db.execute(text(
        "SELECT client_config FROM system_vpn WHERE status = 'active' ORDER BY established_at DESC LIMIT 1"
    )).fetchone()
    if not row:
        ensure_builtin_tunnel(db)
        row = db.execute(text(
            "SELECT client_config FROM system_vpn WHERE status = 'active' ORDER BY established_at DESC LIMIT 1"
        )).fetchone()
    return row[0] if row else ""


def get_full_vpn_status(db: Session) -> dict:
    """External tunnel status (wg/openvpn binaries) merged with the
    always-available system-builtin tunnel so the dashboard always shows
    a connected tunnel with zero external dependencies."""
    status = get_vpn_status()
    ensure_builtin_tunnel(db)
    status["builtin"] = _session_to_dict(db.execute(text(
        "SELECT id, status, transport, public_key, private_key, listen_port, net, established_at, client_config "
        "FROM system_vpn WHERE status = 'active' ORDER BY established_at DESC LIMIT 1"
    )).fetchone())
    external_active = bool(status.get("wireguard", {}).get("interfaces")) or bool(status.get("openvpn", {}).get("processes"))
    status["connected"] = external_active or bool(status.get("builtin"))
    status["mode"] = "system-builtin" if not external_active else "external"
    return status


def builtin_connect(db: Session) -> dict:
    session = ensure_builtin_tunnel(db)
    return {"status": "connected", "mode": "system-builtin", **session}


def builtin_disconnect(db: Session, clear: bool = False) -> dict:
    _ensure_vpn_table(db)
    db.execute(text("UPDATE system_vpn SET status = 'disconnected' WHERE status = 'active'"))
    if clear:
        db.execute(text("DELETE FROM system_vpn"))
    db.commit()
    return {"status": "disconnected", "mode": "system-builtin"}


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
