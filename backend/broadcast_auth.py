import hashlib
from datetime import datetime, timezone

from db import SessionLocal
from models import BroadcastSession


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_allowed(token: str | None, channel: str) -> bool:
    from config import get_settings

    settings = get_settings()
    if not token:
        # Anonymous listeners are a development convenience only.
        return settings.environment == "development"

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
        if session:
            return True

    # A signed-in operator/admin holds a login JWT, not a broadcast session.
    # Accept it so the dashboard's live map and LAU notifications actually work
    # in production instead of silently closing the socket.
    try:
        from jose import JWTError, jwt

        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        return payload.get("role") in {"viewer", "auditor", "operator", "admin"}
    except Exception:
        return False
