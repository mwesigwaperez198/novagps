"""Webhook system for event notifications.

Registers webhook endpoints, fires events with HMAC signatures,
and manages delivery with exponential backoff retry.
"""

import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Any

import requests as http_requests
from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger("nova.webhooks")


def _ensure_tables(db: Session) -> None:
    db.execute(text(
        """
        CREATE TABLE IF NOT EXISTS webhook_endpoints (
            id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            secret TEXT NOT NULL,
            events TEXT NOT NULL DEFAULT '[]',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP NOT NULL DEFAULT (datetime('now'))
        )
        """
    ))
    db.execute(text(
        """
        CREATE TABLE IF NOT EXISTS webhook_deliveries (
            id TEXT PRIMARY KEY,
            endpoint_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            created_at TIMESTAMP NOT NULL DEFAULT (datetime('now')),
            delivered_at TIMESTAMP
        )
        """
    ))
    db.commit()


def register_endpoint(db: Session, url: str, events: list[str], secret: str = "") -> dict[str, Any]:
    """Register a new webhook endpoint."""
    _ensure_tables(db)
    endpoint_id = secrets.token_hex(8)
    if not secret:
        secret = secrets.token_urlsafe(32)
    db.execute(text(
        """
        INSERT INTO webhook_endpoints (id, url, secret, events, active)
        VALUES (:id, :url, :secret, :events, 1)
        """
    ), {"id": endpoint_id, "url": url, "secret": secret, "events": json.dumps(events)})
    db.commit()
    return {"endpoint_id": endpoint_id, "url": url, "events": events, "secret": secret}


def list_endpoints(db: Session) -> list[dict[str, Any]]:
    """List all webhook endpoints."""
    _ensure_tables(db)
    rows = db.execute(text(
        "SELECT id, url, events, active, created_at FROM webhook_endpoints ORDER BY created_at DESC"
    )).fetchall()
    return [
        {
            "endpoint_id": r[0], "url": r[1],
            "events": json.loads(r[2]) if r[2] else [],
            "active": bool(r[3]), "created_at": str(r[4]),
        }
        for r in rows
    ]


def delete_endpoint(db: Session, endpoint_id: str) -> dict[str, Any]:
    """Delete a webhook endpoint."""
    _ensure_tables(db)
    db.execute(text("DELETE FROM webhook_endpoints WHERE id = :id"), {"id": endpoint_id})
    db.execute(text("DELETE FROM webhook_deliveries WHERE endpoint_id = :id"), {"id": endpoint_id})
    db.commit()
    return {"endpoint_id": endpoint_id, "deleted": True}


def fire_event(db: Session, event_type: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Fire an event to all matching webhook endpoints."""
    _ensure_tables(db)
    rows = db.execute(text(
        "SELECT id, url, secret, events FROM webhook_endpoints WHERE active = 1"
    )).fetchall()
    results: list[dict[str, Any]] = []
    for endpoint_id, url, secret, events_json in rows:
        events = json.loads(events_json) if events_json else []
        if event_type in events or "*" in events:
            delivery_id = secrets.token_hex(8)
            db.execute(text(
                """
                INSERT INTO webhook_deliveries (id, endpoint_id, event_type, payload, status, attempts)
                VALUES (:id, :endpoint_id, :event_type, :payload, 'pending', 0)
                """
            ), {"id": delivery_id, "endpoint_id": endpoint_id, "event_type": event_type, "payload": json.dumps(payload, default=str)})
            threading.Thread(
                target=_deliver_webhook,
                args=(delivery_id, url, secret, event_type, payload),
                daemon=True,
            ).start()
            results.append({"delivery_id": delivery_id, "endpoint_id": endpoint_id, "url": url, "status": "dispatched"})
    db.commit()
    return results


def _deliver_webhook(delivery_id: str, url: str, secret: str, event_type: str, payload: dict[str, Any], max_retries: int = 3) -> None:
    """Deliver a webhook with HMAC signature and retry."""
    body = json.dumps({"event": event_type, "payload": payload, "timestamp": datetime.now(timezone.utc).isoformat()}, default=str)
    signature = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "X-NOVA-Signature": f"sha256={signature}",
        "X-NOVA-Event": event_type,
    }
    for attempt in range(max_retries):
        try:
            resp = http_requests.post(url, data=body, headers=headers, timeout=15)
            if resp.ok:
                logger.info("Webhook %s delivered to %s (attempt %d)", delivery_id, url, attempt + 1)
                return
        except Exception as exc:
            logger.warning("Webhook %s attempt %d failed: %s", delivery_id, attempt + 1, exc)
        backoff = 2 ** attempt
        time.sleep(backoff)
    logger.error("Webhook %s failed after %d attempts", delivery_id, max_retries)


def list_deliveries(db: Session, endpoint_id: str = "", limit: int = 50) -> list[dict[str, Any]]:
    """List webhook deliveries."""
    _ensure_tables(db)
    if endpoint_id:
        rows = db.execute(text(
            "SELECT id, endpoint_id, event_type, status, attempts, last_error, created_at, delivered_at "
            "FROM webhook_deliveries WHERE endpoint_id = :endpoint_id ORDER BY created_at DESC LIMIT :limit"
        ), {"endpoint_id": endpoint_id, "limit": limit}).fetchall()
    else:
        rows = db.execute(text(
            "SELECT id, endpoint_id, event_type, status, attempts, last_error, created_at, delivered_at "
            "FROM webhook_deliveries ORDER BY created_at DESC LIMIT :limit"
        ), {"limit": limit}).fetchall()
    return [
        {
            "delivery_id": r[0], "endpoint_id": r[1], "event_type": r[2],
            "status": r[3], "attempts": r[4], "last_error": r[5],
            "created_at": str(r[6]),
            "delivered_at": str(r[7]) if r[7] else None,
        }
        for r in rows
    ]
