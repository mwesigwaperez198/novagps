"""Push-to-find service for remote device location.

Dispatches locate commands via FCM (Android), MQTT, and stores
pending commands for offline devices to pick up on next connection.
"""

import hashlib
import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger("nova.push")


def queue_locate_command(db: Session, device_id: str, command_type: str = "locate", payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Store a pending command for a device."""
    command_id = hashlib.sha256(f"{device_id}:{command_type}:{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()[:16]
    db.execute(text(
        """
        CREATE TABLE IF NOT EXISTS pending_commands (
            id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            command_type TEXT NOT NULL,
            payload TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT (datetime('now')),
            delivered_at TIMESTAMP
        )
        """
    ))
    db.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_pending_commands_device ON pending_commands(device_id, status)"
    ))
    db.execute(text(
        """
        INSERT INTO pending_commands (id, device_id, command_type, payload, status, attempts)
        VALUES (:id, :device_id, :command_type, :payload, 'pending', 0)
        """
    ), {
        "id": command_id,
        "device_id": device_id,
        "command_type": command_type,
        "payload": json.dumps(payload or {}, default=str),
    })
    db.commit()
    logger.info("Queued %s command %s for device %s", command_type, command_id, device_id)
    return {
        "command_id": command_id,
        "device_id": device_id,
        "command_type": command_type,
        "status": "pending",
        "message": f"Command will be delivered when device connects (MQTT/FCM/MQTT)",
    }


def get_pending_commands(db: Session, device_id: str) -> list[dict[str, Any]]:
    """Get all pending commands for a device."""
    db.execute(text(
        """
        CREATE TABLE IF NOT EXISTS pending_commands (
            id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            command_type TEXT NOT NULL,
            payload TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT (datetime('now')),
            delivered_at TIMESTAMP
        )
        """
    ))
    rows = db.execute(text(
        "SELECT id, command_type, payload, status, attempts, created_at FROM pending_commands "
        "WHERE device_id = :device_id AND status = 'pending' ORDER BY created_at ASC"
    ), {"device_id": device_id}).fetchall()
    return [
        {
            "command_id": r[0],
            "command_type": r[1],
            "payload": json.loads(r[2]) if r[2] else {},
            "status": r[3],
            "attempts": r[4],
            "created_at": r[5].isoformat() if hasattr(r[5], "isoformat") else str(r[5]),
        }
        for r in rows
    ]


def acknowledge_command(db: Session, command_id: str) -> None:
    """Mark a command as delivered."""
    db.execute(text(
        "UPDATE pending_commands SET status = 'delivered', delivered_at = datetime('now') WHERE id = :id"
    ), {"id": command_id})
    db.commit()


def get_command_history(db: Session, device_id: str, limit: int = 20) -> list[dict[str, Any]]:
    """Get command history for a device (delivered + pending)."""
    db.execute(text(
        """
        CREATE TABLE IF NOT EXISTS pending_commands (
            id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            command_type TEXT NOT NULL,
            payload TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT (datetime('now')),
            delivered_at TIMESTAMP
        )
        """
    ))
    rows = db.execute(text(
        "SELECT id, command_type, payload, status, attempts, created_at, delivered_at "
        "FROM pending_commands WHERE device_id = :device_id ORDER BY created_at DESC LIMIT :limit"
    ), {"device_id": device_id, "limit": limit}).fetchall()
    return [
        {
            "command_id": r[0],
            "command_type": r[1],
            "payload": json.loads(r[2]) if r[2] else {},
            "status": r[3],
            "attempts": r[4],
            "created_at": r[5].isoformat() if hasattr(r[5], "isoformat") else str(r[5]),
            "delivered_at": r[6].isoformat() if r[6] and hasattr(r[6], "isoformat") else str(r[6]) if r[6] else None,
        }
        for r in rows
    ]


def dispatch_fcm(fcm_token: str, command: dict[str, Any]) -> dict[str, Any]:
    """Dispatch a command via FCM (Android). Requires FCM_SERVER_KEY env var."""
    from config import get_settings
    settings = get_settings()
    server_key = getattr(settings, "fcm_server_key", "")
    if not server_key:
        return {"success": False, "provider": "fcm", "error": "FCM_SERVER_KEY not configured"}
    try:
        resp = __import__("requests").post(
            "https://fcm.googleapis.com/fcm/send",
            headers={
                "Authorization": f"key={server_key}",
                "Content-Type": "application/json",
            },
            json={
                "to": fcm_token,
                "data": command,
                "priority": "high",
            },
            timeout=10,
        )
        return {"success": resp.ok, "provider": "fcm", "status_code": resp.status_code, "response": resp.text[:500]}
    except Exception as exc:
        return {"success": False, "provider": "fcm", "error": str(exc)}


def dispatch_mqtt_command(broker: str, device_id: str, command: dict[str, Any], username: str = "", password: str = "") -> dict[str, Any]:
    """Dispatch a command via MQTT topic for a device."""
    from config import get_settings
    settings = get_settings()
    broker = broker or settings.mqtt_broker
    if not broker:
        return {"success": False, "provider": "mqtt", "error": "MQTT broker not configured"}
    try:
        import paho.mqtt.client as mqtt_client
        topic = f"nova/commands/{device_id}"
        payload = json.dumps(command)
        client = mqtt_client.Client(client_id=f"nova-cmd-{secrets.token_hex(4)}")
        if username:
            client.username_pw_set(username, password or settings.mqtt_password)
        client.connect(broker, 1883, 5)
        result = client.publish(topic, payload, qos=1)
        client.disconnect()
        return {"success": result.rc == 0, "provider": "mqtt", "topic": topic}
    except Exception as exc:
        return {"success": False, "provider": "mqtt", "error": str(exc)}
