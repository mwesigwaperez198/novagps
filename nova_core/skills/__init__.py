"""LAU skills package — registry, adapters and documentation.

`list_skills()` powers `lau skills`. `run_skill()` is the guarded execution path
used by the CLI and the web HUD.
"""

from .adapters import SkillRefused, install_hint, run_skill
from .registry import (
    SKILLS,
    SkillSpec,
    get_skill,
    is_available,
    lab_enabled,
    list_skills,
    resolve_binary,
)

__all__ = [
    "SKILLS",
    "SkillSpec",
    "SkillRefused",
    "get_skill",
    "is_available",
    "install_hint",
    "lab_enabled",
    "list_skills",
    "resolve_binary",
    "run_skill",
]
