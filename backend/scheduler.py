"""Task scheduler for automated operations.

Manages recurring tasks like device health checks, retention cleanup,
geofence evaluation, and camera health monitoring.
"""

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger("nova.scheduler")


def _ensure_tables(db: Session) -> None:
    db.execute(text(
        """
        CREATE TABLE IF NOT EXISTS scheduled_tasks (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            cron_expr TEXT NOT NULL,
            command_id TEXT,
            args TEXT DEFAULT '{}',
            enabled INTEGER NOT NULL DEFAULT 1,
            last_run TIMESTAMP,
            next_run TIMESTAMP,
            last_result TEXT,
            created_at TIMESTAMP NOT NULL DEFAULT (datetime('now'))
        )
        """
    ))
    db.commit()


def create_task(db: Session, name: str, cron_expr: str, command_id: str = "", args: dict | None = None) -> dict[str, Any]:
    """Create a new scheduled task."""
    _ensure_tables(db)
    task_id = hashlib.sha256(f"{name}:{cron_expr}:{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()[:16]
    db.execute(text(
        """
        INSERT INTO scheduled_tasks (id, name, cron_expr, command_id, args, enabled)
        VALUES (:id, :name, :cron_expr, :command_id, :args, 1)
        """
    ), {"id": task_id, "name": name, "cron_expr": cron_expr, "command_id": command_id, "args": json.dumps(args or {})})
    db.commit()
    return {"task_id": task_id, "name": name, "cron_expr": cron_expr, "enabled": True}


def list_tasks(db: Session) -> list[dict[str, Any]]:
    """List all scheduled tasks."""
    _ensure_tables(db)
    rows = db.execute(text(
        "SELECT id, name, cron_expr, command_id, args, enabled, last_run, next_run, last_result, created_at "
        "FROM scheduled_tasks ORDER BY created_at DESC"
    )).fetchall()
    return [
        {
            "task_id": r[0], "name": r[1], "cron_expr": r[2], "command_id": r[3],
            "args": json.loads(r[4]) if r[4] else {}, "enabled": bool(r[5]),
            "last_run": str(r[6]) if r[6] else None,
            "next_run": str(r[7]) if r[7] else None,
            "last_result": json.loads(r[8]) if r[8] else None,
            "created_at": str(r[9]),
        }
        for r in rows
    ]


def toggle_task(db: Session, task_id: str, enabled: bool) -> dict[str, Any]:
    """Enable or disable a scheduled task."""
    _ensure_tables(db)
    db.execute(text(
        "UPDATE scheduled_tasks SET enabled = :enabled WHERE id = :id"
    ), {"id": task_id, "enabled": int(enabled)})
    db.commit()
    return {"task_id": task_id, "enabled": enabled}


def delete_task(db: Session, task_id: str) -> dict[str, Any]:
    """Delete a scheduled task."""
    _ensure_tables(db)
    db.execute(text("DELETE FROM scheduled_tasks WHERE id = :id"), {"id": task_id})
    db.commit()
    return {"task_id": task_id, "deleted": True}


def record_execution(db: Session, task_id: str, result: dict[str, Any]) -> None:
    """Record the result of a task execution."""
    _ensure_tables(db)
    db.execute(text(
        "UPDATE scheduled_tasks SET last_run = datetime('now'), last_result = :result WHERE id = :id"
    ), {"id": task_id, "result": json.dumps(result, default=str)})
    db.commit()
