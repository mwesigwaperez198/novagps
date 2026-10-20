"""Owner confirmation — a conversational step-up on top of the JWT.

Flow (in-session, keyed by the authenticated principal's subject):
  1. "I am Perez"            -> LAU asks: "Are you my king?"
  2. "yes"                   -> LAU asks for the phrase only the owner knows
  3. "<NOVA_OWNER_PHRASE>"   -> verified for the session TTL; LAU treats the
                               operator as owner/admin from that point.

Security posture:
- This is *ceremonial*, not authentication. The request must already carry a
  valid JWT; the owner role gates it exactly like every other /nova-core call.
  An unauthenticated caller can never reach this code at all.
- The phrase is normalised on both sides (case, punctuation, ordinal suffix)
  so "23rd December" and "23 december" are the same answer, but it is never
  echoed back, never written to logs, and never included in an error message.
- Sessions live in process memory only: nothing about ownership is persisted
  to disk, exported, or shipped anywhere.
"""

from __future__ import annotations

import re
import threading
import time
from typing import Optional

try:  # type: ignore
    from .config import get_config
except Exception:  # pragma: no cover
    from config import get_config

_LOCK = threading.RLock()
_SESSIONS: dict[str, dict] = {}
_MAX_ATTEMPTS = 3
_ADMIN_ROLES = {"admin", "superadmin", "owner"}

_YES_RE = re.compile(r"^(yes|yeah|yep|yup|sure|indeed|correct|right|i am|i'm|of course)[.! ]*$", re.I)
_NO_RE = re.compile(r"^(no|nope|nah|not really|never)[.! ]*$", re.I)
_CANCEL_RE = re.compile(r"^(cancel|stop|nevermind|never mind|abort)[.! ]*$", re.I)
_CLAIM_RE = re.compile(
    r"\b(i am|i'm|it's me|its me|this is|call me|the owner is)\b",
    re.I,
)
_ORDINAL_RE = re.compile(r"(\d+)(?:st|nd|rd|th)\b", re.I)
_COMMAND_HINT_RE = re.compile(
    r"(?i)\b(scan|ports?|find|check|list|run|what|how|help|open|read|grep|logs?|"
    r"devices?|locate|lock|wipe|dns|status|health|whois|search|research|nmap|"
    r"register|show|give|execute|start|stop|test|update|report|engine|skills?)\b"
    r"|https?://|\b\d{1,3}(?:\.\d{1,3}){3}\b"
)


def normalise(text: str) -> str:
    """Lowercase, strip ordinal suffixes and punctuation, collapse whitespace."""
    value = (text or "").strip().lower()
    value = _ORDINAL_RE.sub(r"\1", value)
    value = re.sub(r"[^\w\s]", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def _subject_key(subject: Optional[str]) -> str:
    return (subject or "anonymous").strip().lower() or "anonymous"


def _is_admin(role: Optional[str]) -> bool:
    # When no role is supplied (isolated tests / local REPL) we treat the
    # caller as privileged; in production the router dependency always supplies
    # a real role, and non-admins are refused here.
    if role is None:
        return True
    return str(role).strip().lower() in _ADMIN_ROLES


def _prune_locked(now: float) -> None:
    cfg = get_config()
    ttl = max(60, int(cfg.owner_session_ttl or 43200))
    dead = [k for k, v in _SESSIONS.items() if now - v.get("updated", 0) > ttl]
    for k in dead:
        _SESSIONS.pop(k, None)


def status(subject: Optional[str] = None, role: Optional[str] = None) -> dict:
    cfg = get_config()
    now = time.time()
    with _LOCK:
        _prune_locked(now)
        session = _SESSIONS.get(_subject_key(subject))
        verified = bool(session and session.get("verified"))
    return {
        "verified": verified,
        "mode": "admin" if verified else "operator",
        "session": bool(session),
        "stage": (session or {}).get("stage") if session else "none",
        "owner_name": cfg.owner_name,
        "ttl_seconds": int(cfg.owner_session_ttl or 43200),
    }


def reset(subject: Optional[str] = None) -> None:
    with _LOCK:
        _SESSIONS.pop(_subject_key(subject), None)


def reset_all() -> None:
    with _LOCK:
        _SESSIONS.clear()


def handle_turn(
    command: str,
    subject: Optional[str] = None,
    role: Optional[str] = None,
) -> Optional[dict]:
    """Handle one owner-confirmation turn. Returns None when the normal
    dispatch chain should continue untouched (the common case)."""
    cfg = get_config()
    text = (command or "").strip()
    if not text:
        return None

    key = _subject_key(subject)
    now = time.time()
    with _LOCK:
        _prune_locked(now)
        session = _SESSIONS.get(key)

    # Non-admin principals can never claim ownership, and we say so plainly
    # rather than running the ritual.
    if not _is_admin(role) and _mentions_claim(text, cfg.owner_name):
        return _reply(
            "owner_identity",
            "Ownership is confirmed on the admin account only. Sign in as the "
            "owner, then say your claim again.",
            subject,
            verified=False,
            note="role_gate",
        )

    if _CANCEL_RE.match(text):
        if session:
            reset(subject)
        return _reply(
            "owner_identity",
            "Cancelled — back to normal operator mode." if session
            else "Nothing was in progress. Still on normal operator mode.",
            subject,
            verified=False,
            note="cancelled",
        )

    if _mentions_claim(text, cfg.owner_name):
        if session and session.get("verified"):
            return _reply(
                "owner_identity",
                f"You are already verified as {cfg.owner_name}, my king. "
                "Owner mode is active for this session.",
                subject,
                verified=True,
                note="already_verified",
            )
        with _LOCK:
            _SESSIONS[key] = {
                "stage": "confirm",
                "verified": False,
                "attempts": 0,
                "updated": now,
            }
        return _reply(
            "owner_identity",
            f"You say you are {cfg.owner_name}. Are you my king?",
            subject,
            verified=False,
            note="confirm",
        )

    if not session:
        return None

    stage = session.get("stage")
    if stage == "confirm":
        if _YES_RE.match(text):
            with _LOCK:
                session["stage"] = "verify"
                session["updated"] = now
            return _reply(
                "owner_identity",
                "Then prove it. What is our phrase?",
                subject,
                verified=False,
                note="verify",
            )
        if _NO_RE.match(text):
            reset(subject)
            return _reply(
                "owner_identity",
                "Understood. I will not treat this session as the owner's.",
                subject,
                verified=False,
                note="denied",
            )
        # Not an answer to my question — leave the ritual parked and let the
        # normal brain answer, so mid-flow small talk never gets hijacked.
        return None

    if stage == "verify":
        if _looks_like_command(text):
            # A tool request during the ritual is not a verification attempt.
            # Park the session, let the brain answer, and keep the phrase slot
            # open for a real reply.
            return None
        expected = normalise(cfg.owner_phrase)
        if expected and normalise(text) == expected:
            with _LOCK:
                _SESSIONS[key] = {
                    "stage": "verified",
                    "verified": True,
                    "attempts": 0,
                    "updated": time.time(),
                }
            return _reply(
                "owner_identity",
                f"Identity confirmed. Welcome back, my king. {cfg.owner_name} "
                "acknowledged — I am treating you as the owner/admin of NOVARA "
                "for this session.",
                subject,
                verified=True,
                note="verified",
            )
        attempts = int(session.get("attempts", 0)) + 1
        if attempts >= _MAX_ATTEMPTS:
            reset(subject)
            return _reply(
                "owner_identity",
                "That is not the phrase, and that was your last attempt. "
                "Session reset — normal operator mode. Say your claim again if "
                "you want to retry.",
                subject,
                verified=False,
                note="reset",
            )
        left = _MAX_ATTEMPTS - attempts
        with _LOCK:
            session["attempts"] = attempts
            session["updated"] = now
        return _reply(
            "owner_identity",
            f"That is not our phrase. {left} attempt(s) left, then I reset to "
            "normal operator mode. Say 'cancel' to stop.",
            subject,
            verified=False,
            note="retry",
        )

    return None


def _mentions_claim(text: str, name: str) -> bool:
    """Only short, claim-shaped messages start the ritual."""
    if not name or len(text) > 80:
        return False
    if not _CLAIM_RE.search(text):
        return False
    return bool(re.search(rf"\b{re.escape(name)}\b", text, re.I))


def _looks_like_command(text: str) -> bool:
    return bool(_COMMAND_HINT_RE.search(text or ""))


def _reply(intent: str, response: str, subject: Optional[str], verified: bool, note: str) -> dict:
    state = status(subject)
    return {
        "intent": intent,
        "response": response,
        "owner": {**state, "verified": verified, "note": note},
        "engine": "owner_gate",
        "thought_process": [
            "Owner-confirmation gate handled this turn before tool dispatch.",
            f"Stage marker: {note}.",
            "JWT authentication still applies to every following call.",
        ],
    }
