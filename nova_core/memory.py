"""NOVA-CORE persistent memory system.

SQLite-backed write-ahead log for lessons learned, system state,
and crash recovery. Survives container restarts on persistent disk.
"""

import json
import time
import sqlite3
import hashlib
import threading
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from typing import Optional, List, Generator

from .config import get_config


@dataclass
class MemoryEntry:
    timestamp: float
    category: str
    obstacle: str
    maneuver: str
    delta: str
    severity: str = "info"
    tags: str = ""
    hash_chain: str = ""


class NovaMemory:
    def __init__(self, db_path: Optional[str] = None):
        cfg = get_config()
        self.db_path = db_path or str(cfg.memory_db)
        self.max_entries = cfg.max_memory_entries
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, timeout=10)
            self._local.conn.isolation_level = None
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS lessons (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                category TEXT NOT NULL,
                obstacle TEXT NOT NULL,
                maneuver TEXT NOT NULL,
                delta TEXT NOT NULL,
                severity TEXT DEFAULT 'info',
                tags TEXT DEFAULT '',
                engine_used TEXT DEFAULT '',
                hash_chain TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_lessons_category ON lessons(category);
            CREATE INDEX IF NOT EXISTS idx_lessons_severity ON lessons(severity);
            CREATE INDEX IF NOT EXISTS idx_lessons_timestamp ON lessons(timestamp);

            CREATE TABLE IF NOT EXISTS system_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                results TEXT NOT NULL,
                risk_level TEXT DEFAULT 'low',
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_scans_type ON scan_results(scan_type);

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                alert_type TEXT NOT NULL,
                message TEXT NOT NULL,
                source TEXT DEFAULT 'nova_core',
                acknowledged INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now'))
            );
        """)
        self._migrate_lessons_engine_column(conn)
        conn.commit()

    def _migrate_lessons_engine_column(self, conn: sqlite3.Connection):
        conn.execute("BEGIN IMMEDIATE")
        try:
            cols = [r["name"] for r in conn.execute("PRAGMA table_info(lessons)").fetchall()]
            if "engine_used" not in cols:
                conn.execute("ALTER TABLE lessons ADD COLUMN engine_used TEXT DEFAULT ''")
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    @contextmanager
    def transaction(self):
        conn = self._get_conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def record_lesson(self, category: str, obstacle: str, maneuver: str, delta: str, severity: str = "info", tags: str = "", engine_used: str = "") -> int:
        entry = MemoryEntry(
            timestamp=time.time(),
            category=category,
            obstacle=obstacle,
            maneuver=maneuver,
            delta=delta,
            severity=severity,
            tags=tags,
        )
        with self.transaction() as conn:
            prev = conn.execute(
                "SELECT hash_chain FROM lessons ORDER BY id DESC LIMIT 1"
            ).fetchone()
            parent_hash = prev["hash_chain"] if prev else "genesis"
            entry.hash_chain = hashlib.sha256(
                f"{parent_hash}:{entry.obstacle}:{entry.maneuver}".encode()
            ).hexdigest()[:16]
            cursor = conn.execute(
                """INSERT INTO lessons (timestamp, category, obstacle, maneuver, delta, severity, tags, engine_used, hash_chain)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (entry.timestamp, entry.category, entry.obstacle, entry.maneuver,
                 entry.delta, entry.severity, entry.tags, engine_used, entry.hash_chain),
            )
            self._enforce_retention(conn)
            return cursor.lastrowid

    def log_lesson(self, engine: str, obstacle: str, maneuver: str, delta: str) -> int:
        """Dual-core ledger: tags the lesson with the engine that produced it."""
        return self.record_lesson(
            category="system_lesson",
            obstacle=obstacle,
            maneuver=maneuver,
            delta=delta,
            engine_used=engine,
        )

    def get_recent_lessons(self, limit: int = 20, category: Optional[str] = None) -> List[dict]:
        conn = self._get_conn()
        if category:
            rows = conn.execute(
                "SELECT * FROM lessons WHERE category = ? ORDER BY timestamp DESC LIMIT ?",
                (category, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM lessons ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_lessons_by_severity(self, severity: str, limit: int = 50) -> List[dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM lessons WHERE severity = ? ORDER BY timestamp DESC LIMIT ?",
            (severity, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def search_lessons(self, query: str, limit: int = 20) -> List[dict]:
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT * FROM lessons
               WHERE obstacle LIKE ? OR maneuver LIKE ? OR delta LIKE ? OR tags LIKE ?
               ORDER BY timestamp DESC LIMIT ?""",
            (f"%{query}%",) * 4 + (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def set_state(self, key: str, value: str):
        with self.transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO system_state (key, value, updated_at) VALUES (?, ?, ?)",
                (key, value, time.time()),
            )

    def get_state(self, key: str, default: str = "") -> str:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT value FROM system_state WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def record_scan(self, scan_type: str, target: str, results: dict, risk_level: str = "low") -> int:
        with self.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO scan_results (timestamp, scan_type, target, results, risk_level) VALUES (?, ?, ?, ?, ?)",
                (time.time(), scan_type, target, json.dumps(results), risk_level),
            )
            return cursor.lastrowid

    def get_recent_scans(self, scan_type: Optional[str] = None, limit: int = 10) -> List[dict]:
        conn = self._get_conn()
        if scan_type:
            rows = conn.execute(
                "SELECT * FROM scan_results WHERE scan_type = ? ORDER BY timestamp DESC LIMIT ?",
                (scan_type, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scan_results ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def create_alert(self, alert_type: str, message: str, source: str = "nova_core") -> int:
        with self.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO alerts (timestamp, alert_type, message, source) VALUES (?, ?, ?, ?)",
                (time.time(), alert_type, message, source),
            )
            return cursor.lastrowid

    def get_alerts(self, acknowledged: bool = False, limit: int = 20) -> List[dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM alerts WHERE acknowledged = ? ORDER BY timestamp DESC LIMIT ?",
            (1 if acknowledged else 0, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def acknowledge_alert(self, alert_id: int):
        with self.transaction() as conn:
            conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))

    def _get_last_hash(self) -> str:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT hash_chain FROM lessons ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row["hash_chain"] if row else "genesis"

    def _enforce_retention(self, conn: sqlite3.Connection):
        count = conn.execute("SELECT COUNT(*) as c FROM lessons").fetchone()["c"]
        if count > self.max_entries:
            delete_count = count - self.max_entries
            conn.execute(
                "DELETE FROM lessons WHERE id IN (SELECT id FROM lessons ORDER BY timestamp ASC LIMIT ?)",
                (delete_count,),
            )

    def get_memory_stats(self) -> dict:
        conn = self._get_conn()
        return {
            "total_lessons": conn.execute("SELECT COUNT(*) as c FROM lessons").fetchone()["c"],
            "total_scans": conn.execute("SELECT COUNT(*) as c FROM scan_results").fetchone()["c"],
            "total_alerts": conn.execute("SELECT COUNT(*) as c FROM alerts").fetchone()["c"],
            "unacknowledged_alerts": conn.execute(
                "SELECT COUNT(*) as c FROM alerts WHERE acknowledged = 0"
            ).fetchone()["c"],
            "categories": [
                dict(r) for r in conn.execute(
                    "SELECT category, COUNT(*) as count FROM lessons GROUP BY category ORDER BY count DESC"
                ).fetchall()
            ],
            "recent_severity_breakdown": [
                dict(r) for r in conn.execute(
                    "SELECT severity, COUNT(*) as count FROM lessons GROUP BY severity"
                ).fetchall()
            ],
        }
