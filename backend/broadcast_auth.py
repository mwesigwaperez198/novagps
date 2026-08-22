import hashlib
from datetime import datetime, timezone

from db import SessionLocal
from models import BroadcastSession


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_allowed(token: str | None, channel: str) -> bool:
    from config import get_settings

    settings = get_settings()
    if settings.environment == "development" and not token:
        return True
    if not token:
        return False
    with SessionLocal() as db:
        session = (
            db.query(BroadcastSession)
            .filter(
                BroadcastSession.token_hash == token_hash(token),
                BroadcastSession.channel == channel,
                BroadcastSession.active.is_(True),
                BroadcastSession.expires_at > datetime.now(timezone.utc),
            )
            .first()
        )
        return bool(session)
