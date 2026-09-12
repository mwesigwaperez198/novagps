"""LAU sovereign provisioning state machine.

Turns "track a device" into a grounded multi-turn conversation:
READY -> COLLECTING_IMEI -> COLLECTING_EMAIL -> COLLECTING_TEL -> DONE.

Each accepted answer is validated before the next question is asked, the
finished provision is anchored into the memory ledger, and the state is
persisted so the flow survives across HTTP dispatches.

Dispatch contract shared with routes.run_dispatch:
    route(text) -> dict | None
None means "not in a provisioning flow" so normal routing proceeds.
"""

import hashlib
import hmac
import json
import os
import re
import time

from .config import get_config

SESSION_FILE = "/tmp/lau_queen_session.json"

_MONOLOGUE_ENABLED = True


def _log_monologue(text: str, detail: dict | None = None) -> None:
    """Append a silent monologue line to the private debug ledger.

    Never surfaces raw reasoning in chat output; only the operator can read
    /tmp/lau_internal_monologue.log. Silence with LAU_MONOLOGUE=0.
    """
    global _MONOLOGUE_ENABLED
    if _MONOLOGUE_ENABLED and os.environ.get("LAU_MONOLOGUE") == "0":
        _MONOLOGUE_ENABLED = False
    if not _MONOLOGUE_ENABLED:
        return
    try:
        from .config import get_config as _cfg

        target = _cfg().monologue_file
        target.parent.mkdir(parents=True, exist_ok=True)
        entry = {"ts": time.time(), "step": text}
        if detail:
            entry.update(detail)
        with open(target, "a") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception:
        pass


_START_PHRASES = (
    "track a device",
    "track this device",
    "track that device",
    "provision a device",
    "provision device",
    "provision this device",
    "add a device to track",
    "i want to track a device",
    "i want to track this device",
    "setup tracking",
    "set up tracking",
    "set up tracking for a device",
    "onboard a device",
)
_IMEI_RE = re.compile(r"^\d{15,17}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_TEL_RE = re.compile(r"^\d{9,15}$")
_TREE = "├──"
_TREE_LAST = "└──"


class LauSovereignStateMachine:
    def __init__(self, store: str = SESSION_FILE):
        self.store = store
        self._session = None
        self._load()

    def _load(self):
        import json
        import os

        if os.path.exists(self.store):
            try:
                with open(self.store) as fh:
                    self._session = json.load(fh)
            except (OSError, ValueError):
                self._session = None

    def _save(self):
        import json
        import os

        try:
            os.makedirs(os.path.dirname(self.store) or ".", exist_ok=True)
            with open(self.store, "w") as fh:
                json.dump(self._session, fh)
        except OSError:
            pass

    def active(self) -> bool:
        return bool(self._session and self._session.get("state") in (
            "COLLECTING_IMEI", "COLLECTING_EMAIL", "COLLECTING_TEL"
        ))

    def is_start(self, text: str) -> bool:
        return any(p in text.lower() for p in _START_PHRASES)

    def reset(self):
        self._session = None
        self._save()

    def _phase_intent(self):
        return "provisioning"

    def route(self, text: str) -> dict | None:
        text = (text or "").strip()
        if not text:
            return None
        if self.active():
            return self.accept(text)
        if self.is_start(text):
            self._session = {
                "state": "COLLECTING_IMEI",
                "imei": "",
                "email": "",
                "tel": "",
                "token": "",
                "started": time.time(),
            }
            self._save()
            _log_monologue("provision_start", {"text": text})
            return self._freeze("provision_start", _COLLECT_IMEI_MSG)
        return None

    def accept(self, text: str) -> dict:
        s = self._session
        state = s.get("state")
        if state == "COLLECTING_IMEI" and _IMEI_RE.match(text.strip()):
            s["imei"] = text.strip()
            s["state"] = "COLLECTING_EMAIL"
            self._save()
            _log_monologue("step_imei", {"imei": s["imei"]})
            return self._freeze("provisioning", _COLLECT_EMAIL_MSG)
        if state == "COLLECTING_EMAIL" and _EMAIL_RE.match(text.strip()):
            s["email"] = text.strip().lower()
            s["state"] = "COLLECTING_TEL"
            self._save()
            _log_monologue("step_email", {"email": s["email"]})
            return self._freeze("provisioning", _COLLECT_TEL_MSG)
        if state == "COLLECTING_TEL" and _TEL_RE.match(text.strip()):
            s["tel"] = text.strip()
            s["token"] = self._make_token(s)
            s["state"] = "DONE"
            provision = self._commit(s)
            self.reset()
            _log_monologue("provision_done", {"token": s["token"], "ledger": provision.get("ok")})
            return self._freeze("provisioning", _done_message(s, provision))

        if state not in ("COLLECTING_IMEI", "COLLECTING_EMAIL", "COLLECTING_TEL"):
            return self.route(text)

        expectation = {
            "COLLECTING_IMEI": _COLLECT_IMEI_MSG,
            "COLLECTING_EMAIL": _COLLECT_EMAIL_MSG,
            "COLLECTING_TEL": _COLLECT_TEL_MSG,
        }[state]
        valid = {
            "COLLECTING_IMEI": "IMEI must be 15-17 digits (numbers only).",
            "COLLECTING_EMAIL": "That doesn't look like an email — it needs an '@' and a domain.",
            "COLLECTING_TEL": "That doesn't look like a phone number — digits only, 9-15 characters.",
        }[state]
        self._save()
        return self._freeze(
            "provisioning",
            f"{valid}\n\nPlease try again:\n{_TREE} {expectation}",
        )

    def status(self) -> dict:
        return {
            "active": self.active(),
            "state": (self._session or {}).get("state", "READY"),
            "imei": (self._session or {}).get("imei", ""),
        }

    def _make_token(self, s: dict) -> str:
        cfg = get_config()
        secret = cfg.secret_key or "novagps-provision-local"
        payload = f"{s['imei']}|{s['email']}|{s['tel']}"
        return hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()[:16].upper()

    def _commit(self, s: dict) -> dict:
        try:
            from .memory import NovaMemory

            memory = NovaMemory()
            memory.record_lesson(
                "provisioning",
                f"Device provisioned: IMEI {s['imei']}",
                "Multi-turn sovereign flow collected IMEI/email/tel and generated an anchored token",
                f"token={s['token']} email={s['email']} tel={s['tel']}",
                severity="info",
                tags="lau,sovereign,provision",
                engine_used="LAU_SOVEREIGN_STATE",
            )
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def _freeze(self, intent: str, message: str) -> dict:
        state = (self._session or {}).get("state", "READY")
        s = self._session or {}
        return {
            "thought_process": [
                "Sovereign provisioning lane engaged before generic routing.",
                f"Collecting field {state}: validating as the operator answers.",
                "Each value is validated before the next question is asked.",
                "Finished provisions are anchored in the memory ledger.",
            ],
            "intent": intent,
            "response": message,
            "engine": "DETERMINISTIC_SOVEREIGN",
            "provision": s,
        }


_COLLECT_IMEI_MSG = (
    "Got it — I'll set up live tracking for the device. "
    "First, the device IMEI (15-17 digits, numbers only)."
)
_COLLECT_EMAIL_MSG = (
    "IMEI locked in. Now the owner email (must be a valid email)."
)
_COLLECT_TEL_MSG = (
    "Email locked in. Last field — the owner phone number (digits only, 9-15 characters)."
)


def _done_message(s: dict, provision: dict) -> str:
    tree = [
        "Device provisioning complete:",
        f"{_TREE} IMEI .......... {s['imei']}",
        f"{_TREE} Owner email ... {s['email']}",
        f"{_TREE} Owner phone ... {s['tel']}",
        f"{_TREE} Provision token {s['token']} (anchored to SECRET_KEY)",
        _TREE_LAST + " Ledger ........ anchored" if provision.get("ok") else
        _TREE_LAST + f" Ledger ........ failed ({provision.get('error')})",
    ]
    if provision.get("ok"):
        tree.append(
            "\nThe device is now wired for live GPS ingestion. If it phones home via "
            "the Traccar app, make sure its /traccar id matches this IMEI and it will "
            "map straight to the dashboard."
        )
    else:
        tree.append("\nProvision captured but the memory ledger is unavailable here.")
    return "\n".join(tree)