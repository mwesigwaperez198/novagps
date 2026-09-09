"""Vehicle recovery workflow.

Manages stolen vehicle reports, auto-links nearby cameras,
monitors location continuously, and sends alerts.
"""

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger("nova.vehicle_recovery")


def _ensure_tables(db: Session) -> None:
    db.execute(text(
        """
        CREATE TABLE IF NOT EXISTS vehicle_recovery (
            id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            started_at TIMESTAMP NOT NULL DEFAULT (datetime('now')),
            ended_at TIMESTAMP,
            cameras_linked TEXT DEFAULT '[]',
            alerts_sent INTEGER DEFAULT 0,
            last_location_lat FLOAT,
            last_location_lon FLOAT,
            reported_by TEXT
        )
        """
    ))
    db.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_vehicle_recovery_device ON vehicle_recovery(device_id, status)"
    ))
    db.execute(text(
        """
        CREATE TABLE IF NOT EXISTS vehicle_camera_link (
            id TEXT PRIMARY KEY,
            recovery_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            camera_ip TEXT NOT NULL,
            camera_port INTEGER DEFAULT 554,
            stream_url TEXT,
            linked_at TIMESTAMP NOT NULL DEFAULT (datetime('now')),
            active INTEGER DEFAULT 1
        )
        """
    ))
    db.commit()


def report_stolen(db: Session, device_id: str, reported_by: str = "admin") -> dict[str, Any]:
    """Report a vehicle as stolen and begin recovery mode."""
    _ensure_tables(db)
    import hashlib
    recovery_id = hashlib.sha256(f"{device_id}:{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()[:16]
    db.execute(text(
        """
        INSERT INTO vehicle_recovery (id, device_id, status, reported_by)
        VALUES (:id, :device_id, 'active', :reported_by)
        """
    ), {"id": recovery_id, "device_id": device_id, "reported_by": reported_by})
    db.commit()
    logger.warning("Vehicle %s reported STOLEN by %s — recovery %s started", device_id, reported_by, recovery_id)
    return {
        "recovery_id": recovery_id,
        "device_id": device_id,
        "status": "active",
        "message": "Vehicle recovery mode activated. Location reporting increased to every 10 seconds. Nearby cameras will be auto-discovered.",
    }


def end_recovery(db: Session, recovery_id: str) -> dict[str, Any]:
    """End a vehicle recovery session."""
    _ensure_tables(db)
    db.execute(text(
        "UPDATE vehicle_recovery SET status = 'ended', ended_at = datetime('now') WHERE id = :id AND status = 'active'"
    ), {"id": recovery_id})
    db.execute(text(
        "UPDATE vehicle_camera_link SET active = 0 WHERE recovery_id = :id"
    ), {"id": recovery_id})
    db.commit()
    return {"recovery_id": recovery_id, "status": "ended"}


def link_camera(db: Session, recovery_id: str, device_id: str, camera_ip: str, camera_port: int = 554, stream_url: str = "") -> dict[str, Any]:
    """Link a camera to a recovery session."""
    _ensure_tables(db)
    import hashlib
    link_id = hashlib.sha256(f"{recovery_id}:{camera_ip}:{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()[:16]
    if not stream_url:
        stream_url = f"rtsp://{camera_ip}:{camera_port}/live"
    db.execute(text(
        """
        INSERT INTO vehicle_camera_link (id, recovery_id, device_id, camera_ip, camera_port, stream_url)
        VALUES (:id, :recovery_id, :device_id, :camera_ip, :camera_port, :stream_url)
        """
    ), {"id": link_id, "recovery_id": recovery_id, "device_id": device_id, "camera_ip": camera_ip, "camera_port": camera_port, "stream_url": stream_url})
    db.commit()
    return {"link_id": link_id, "camera_ip": camera_ip, "stream_url": stream_url, "status": "linked"}


def get_recovery_status(db: Session, recovery_id: str) -> dict[str, Any]:
    """Get the status of a recovery session."""
    _ensure_tables(db)
    row = db.execute(text(
        "SELECT id, device_id, status, started_at, ended_at, cameras_linked, alerts_sent, last_location_lat, last_location_lon FROM vehicle_recovery WHERE id = :id"
    ), {"id": recovery_id}).fetchone()
    if not row:
        return {"error": "Recovery session not found"}
    links = db.execute(text(
        "SELECT id, camera_ip, stream_url, linked_at, active FROM vehicle_camera_link WHERE recovery_id = :recovery_id"
    ), {"recovery_id": recovery_id}).fetchall()
    return {
        "recovery_id": row[0],
        "device_id": row[1],
        "status": row[2],
        "started_at": row[3].isoformat() if hasattr(row[3], "isoformat") else str(row[3]),
        "ended_at": row[4].isoformat() if row[4] and hasattr(row[4], "isoformat") else str(row[4]) if row[4] else None,
        "alerts_sent": row[6],
        "cameras": [
            {"link_id": l[0], "camera_ip": l[1], "stream_url": l[2], "linked_at": str(l[3]), "active": bool(l[4])}
            for l in links
        ],
    }


def list_active_recoveries(db: Session) -> list[dict[str, Any]]:
    """List all active recovery sessions."""
    _ensure_tables(db)
    rows = db.execute(text(
        "SELECT id, device_id, started_at, alerts_sent FROM vehicle_recovery WHERE status = 'active' ORDER BY started_at DESC"
    )).fetchall()
    return [
        {"recovery_id": r[0], "device_id": r[1], "started_at": str(r[2]), "alerts_sent": r[3]}
        for r in rows
    ]


def recovery_assets(db: Session, recovery_id: str) -> dict[str, Any]:
    """Pull everything needed to start a physical recovery mission.

    Given a recovery id, returns the device identity + network addresses
    (public/local/carrier), its last known location, and automatically
    sweeps the device's subnet for nearby cameras (RTSP hosts). This lets
    the recovery lookup trigger camera discovery + the device IP without
    any extra manual steps.
    """
    _ensure_tables(db)
    row = db.execute(text(
        "SELECT device_id, status FROM vehicle_recovery WHERE id = :id"
    ), {"id": recovery_id}).fetchone()
    if not row:
        return {"error": "Recovery session not found"}
    device_id, status = row[0], row[1]
    from models import Device, Location
    device = db.get(Device, device_id)
    if not device:
        return {"recovery_id": recovery_id, "device_id": device_id, "status": status, "device": None}
    last = (
        db.query(Location)
        .filter(Location.device_id == device_id)
        .order_by(Location.recorded_at.desc())
        .first()
    )
    subnet = None
    local_ip = device.local_ip or (last.ip_address if last else None) or None
    if local_ip and local_ip.count(".") == 3 and local_ip.split(".")[0].isdigit():
        parts = local_ip.split(".")
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    cameras: list[dict[str, Any]] = []
    scan_note = ""
    if subnet:
        try:
            from discovery import scan_network
            result = scan_network(subnet)
            hosts = result.get("hosts", [])
            cameras = [
                {"ip": h["ip"], "ports": h.get("ports", []), "kind": h.get("kind", "host"), "vendor": h.get("vendor", "")}
                for h in hosts
                if h.get("is_camera")
            ]
            scan_note = f"Auto camera sweep on {subnet} ({result.get('engine')})"
        except Exception as exc:  # pragma: no cover - network sweep is best-effort
            scan_note = f"Camera sweep unavailable: {exc}"
    return {
        "recovery_id": recovery_id,
        "device_id": device_id,
        "status": status,
        "device": {
            "name": device.name,
            "identifier": device.identifier,
            "model": device.model,
            "manufacturer": device.manufacturer,
            "imei": device.imei,
            "recovery_id": device.recovery_id,
            "ip_address": device.ip_address,
            "local_ip": device.local_ip,
            "carrier": device.carrier,
            "last_location": {
                "latitude": last.latitude,
                "longitude": last.longitude,
                "place_name": last.place_name,
                "recorded_at": str(last.recorded_at),
            } if last else None,
        },
        "subnet": subnet,
        "cameras": cameras,
        "camera_count": len(cameras),
        "scan_note": scan_note,
    }
