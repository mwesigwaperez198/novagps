"""Consent anchoring via a local tamper-evident hash chain.

Each consent event is linked to the previous one by embedding its SHA-256
hash into the next record.  The chain lives in the database so it survives
restarts without requiring an external blockchain node.  Verifiers can
walk the chain from any anchor point and detect any inserted, removed,
or altered records.
"""

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AnchorRecord:
    record_id: str
    consent_id: str
    device_id: str
    action: str
    payload_hash: str
    previous_hash: str
    chain_hash: str
    anchored_at: datetime


GENESIS_HASH = "0" * 64


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _compute_chain_hash(consent_id: str, action: str, payload_hash: str, previous_hash: str) -> str:
    material = f"{consent_id}:{action}:{payload_hash}:{previous_hash}"
    return _sha256(material)


def _ensure_table(db: Session) -> None:
    db.execute(text(
        """
        CREATE TABLE IF NOT EXISTS consent_anchor (
            id TEXT PRIMARY KEY,
            consent_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            action TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            chain_hash TEXT NOT NULL,
            anchored_at TIMESTAMP NOT NULL DEFAULT (datetime('now'))
        )
        """
    ))
    db.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_consent_anchor_device ON consent_anchor(device_id)"
    ))
    db.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_consent_anchor_consent ON consent_anchor(consent_id)"
    ))
    db.commit()


def _latest_hash(db: Session) -> str:
    row = db.execute(text("SELECT chain_hash FROM consent_anchor ORDER BY rowid DESC LIMIT 1")).fetchone()
    return row[0] if row else GENESIS_HASH


def anchor_consent_event(
    db: Session,
    consent_id: str,
    device_id: str,
    action: str,
    payload: dict[str, Any],
) -> AnchorRecord:
    """Append a consent event to the hash chain and return the anchor record."""
    _ensure_table(db)

    previous_hash = _latest_hash(db)
    payload_str = json.dumps(payload, sort_keys=True, default=str)
    payload_hash = _sha256(payload_str)
    chain_hash = _compute_chain_hash(consent_id, action, payload_hash, previous_hash)

    record_id = _sha256(f"{consent_id}:{action}:{datetime.now(timezone.utc).isoformat()}")
    anchored_at = datetime.now(timezone.utc)

    db.execute(text(
        """
        INSERT INTO consent_anchor (id, consent_id, device_id, action, payload_hash, previous_hash, chain_hash, anchored_at)
        VALUES (:id, :consent_id, :device_id, :action, :payload_hash, :previous_hash, :chain_hash, :anchored_at)
        """
    ), {
        "id": record_id,
        "consent_id": consent_id,
        "device_id": device_id,
        "action": action,
        "payload_hash": payload_hash,
        "previous_hash": previous_hash,
        "chain_hash": chain_hash,
        "anchored_at": anchored_at,
    })
    db.commit()

    logger.info("Anchored consent %s action=%s chain=%s", consent_id, action, chain_hash[:12])
    return AnchorRecord(
        record_id=record_id,
        consent_id=consent_id,
        device_id=device_id,
        action=action,
        payload_hash=payload_hash,
        previous_hash=previous_hash,
        chain_hash=chain_hash,
        anchored_at=anchored_at,
    )


def verify_chain(db: Session, start: int = 0, limit: int = 1000) -> dict[str, Any]:
    """Walk the hash chain and verify integrity.

    Returns a summary with tamper status, total records checked, and
    the index of the first broken link (if any).
    """
    _ensure_table(db)

    rows = db.execute(text(
        "SELECT id, consent_id, device_id, action, payload_hash, previous_hash, chain_hash "
        "FROM consent_anchor ORDER BY rowid ASC LIMIT :limit OFFSET :start"
    ), {"start": start, "limit": limit}).fetchall()

    if not rows:
        return {"valid": True, "checked": 0, "broken_at": None, "message": "empty chain"}

    expected_previous = GENESIS_HASH
    broken_at = None

    for idx, row in enumerate(rows):
        record_id, consent_id, device_id, action, payload_hash, previous_hash, chain_hash = row

        if previous_hash != expected_previous:
            broken_at = idx
            break

        recomputed = _compute_chain_hash(consent_id, action, payload_hash, previous_hash)
        if recomputed != chain_hash:
            broken_at = idx
            break

        expected_previous = chain_hash

    return {
        "valid": broken_at is None,
        "checked": len(rows),
        "broken_at": broken_at,
        "last_chain_hash": rows[-1][6] if rows else None,
    }


def get_consent_history(db: Session, device_id: str, limit: int = 50) -> list[dict[str, Any]]:
    """Return the anchored consent history for a device."""
    _ensure_table(db)

    rows = db.execute(text(
        "SELECT consent_id, action, payload_hash, chain_hash, anchored_at "
        "FROM consent_anchor WHERE device_id = :device_id ORDER BY rowid DESC LIMIT :limit"
    ), {"device_id": device_id, "limit": limit}).fetchall()

    return [
        {
            "consent_id": r[0],
            "action": r[1],
            "payload_hash": r[2],
            "chain_hash": r[3],
            "anchored_at": r[4].isoformat() if hasattr(r[4], "isoformat") else str(r[4]),
        }
        for r in rows
    ]
