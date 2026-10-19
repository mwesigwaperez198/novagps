"""LAU skill adapters.

Thin, guarded wrappers that turn a registry entry into an actual subprocess
call. Every run is scope-checked (lab-only tools refuse unless NOVA_LAB_MODE=1)
and recorded in LAU's memory so there is always an audit trail of what was
executed, against what target, and with what result.
"""

from __future__ import annotations

import logging
import os
import shlex
import subprocess

from .registry import get_skill, is_available, lab_enabled, resolve_binary

logger = logging.getLogger("nova_core.skills")

MAX_OUTPUT = 8000


class SkillRefused(Exception):
    """Raised when a skill is blocked by scope policy rather than failing."""


def _audit(category: str, obstacle: str, maneuver: str, delta: str, severity: str = "info") -> None:
    try:
        from ..memory import NovaMemory

        NovaMemory().record_lesson(category, obstacle, maneuver, delta, severity=severity)
    except Exception as exc:  # pragma: no cover - memory must never break a run
        logger.debug("skill audit skipped: %s", exc)


def run_skill(
    key: str,
    target: str | None = None,
    args: list[str] | None = None,
    timeout: int | None = None,
) -> dict:
    """Execute a registered skill. Returns a structured, JSON-safe result."""
    skill = get_skill(key)
    if skill is None:
        return {"status": "unknown_skill", "skill": key}

    if skill.lab_only and not lab_enabled():
        _audit(
            "skill_refused",
            f"{skill.key} requires lab scope",
            "refused execution",
            f"target={target or '-'}",
            severity="warning",
        )
        raise SkillRefused(
            f"{skill.name} is lab-only. Set NOVA_LAB_MODE=1 on an authorised network to enable it."
        )

    if not is_available(skill):
        return {
            "status": "missing",
            "skill": skill.key,
            "name": skill.name,
            "install": skill.install,
        }

    binary = resolve_binary(skill) or (skill.bins[0] if skill.bins else skill.key)
    argv: list[str] = [binary]
    if skill.default_args:
        argv.extend(shlex.split(skill.default_args))
    if args:
        argv.extend(args)
    if target and skill.needs_target:
        argv.append(target)

    limit = timeout or int(os.environ.get("NOVA_SKILL_TIMEOUT", "180"))
    _audit(
        "skill_run",
        f"run {skill.key}",
        " ".join(shlex.quote(part) for part in argv),
        f"target={target or '-'}",
    )

    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=limit,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "skill": skill.key,
            "command": argv,
            "timeout": limit,
        }
    except (OSError, ValueError) as exc:
        return {"status": "error", "skill": skill.key, "command": argv, "error": str(exc)}

    return {
        "status": "ok" if completed.returncode == 0 else "failed",
        "skill": skill.key,
        "name": skill.name,
        "command": argv,
        "returncode": completed.returncode,
        "stdout": (completed.stdout or "")[:MAX_OUTPUT],
        "stderr": (completed.stderr or "")[:MAX_OUTPUT],
    }


def install_hint(key: str) -> str:
    skill = get_skill(key)
    if skill is None:
        return f"unknown skill: {key}"
    return skill.install
