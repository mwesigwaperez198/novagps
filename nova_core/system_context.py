"""Live, bounded system knowledge for LAU.

The Queen does not need to guess what was changed: this module keeps a compact
manifest of the NOVA codebase and records meaningful deltas in her lesson
ledger.  It deliberately stores metadata and hashes, never source or secrets.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .config import get_config
from .memory import NovaMemory


WATCHED_AREAS = ("backend", "nova_core", "frontend/src", "agent", "docs", "k8s", "iac", "scripts")
SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".kt", ".md", ".yaml", ".yml", ".tf", ".sh"}


class SystemContext:
    def __init__(self, memory: NovaMemory | None = None):
        self.cfg = get_config()
        self.memory = memory or NovaMemory()

    def manifest(self) -> dict[str, str]:
        root = self.cfg.project_root
        entries: dict[str, str] = {}
        for area in WATCHED_AREAS:
            base = root / area
            if not base.exists():
                continue
            for path in base.rglob("*"):
                if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
                    continue
                if any(part in {"node_modules", "dist", "__pycache__", ".pytest_cache"} for part in path.parts):
                    continue
                try:
                    relative = str(path.relative_to(root))
                    entries[relative] = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
                except OSError:
                    continue
        # The production image intentionally flattens backend/ into /app.
        # Preserve that code in LAU's map under the same logical namespace.
        if not (root / "backend").exists():
            for path in root.glob("*.py"):
                try:
                    entries[f"backend/{path.name}"] = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
                except OSError:
                    continue
        return entries

    def observe(self) -> dict:
        current = self.manifest()
        raw_previous = self.memory.get_state("codebase_manifest", "")
        previous = json.loads(raw_previous) if raw_previous else {}
        added = sorted(set(current) - set(previous))
        removed = sorted(set(previous) - set(current))
        modified = sorted(key for key in set(current) & set(previous) if current[key] != previous[key])
        changed = {"added": added, "modified": modified, "removed": removed}
        self.memory.set_state("codebase_manifest", json.dumps(current, sort_keys=True))
        if not raw_previous:
            self.memory.record_lesson("codebase_baseline", "LAU mapped the NOVA codebase", f"{len(current)} tracked source files", "Initial manifest captured; future changes will be learned.", tags="codebase,queen")
        elif added or modified or removed:
            summary = {key: values[:30] for key, values in changed.items() if values}
            self.memory.record_lesson("codebase_change", f"Codebase changed: +{len(added)} ~{len(modified)} -{len(removed)}", "LAU refreshed her system map", json.dumps(summary), severity="info", tags="codebase,queen")
        return {"tracked_files": len(current), "changes": changed}

    def overview(self) -> dict:
        last = self.memory.get_state("last_codebase_observation", "")
        return {
            "identity": "LAU",
            "role": "supervised NOVA operations orchestrator",
            "storage": str(self.cfg.vault_dir),
            "backend_url": self.cfg.backend_url,
            "watched_areas": list(WATCHED_AREAS),
            "last_observation": json.loads(last) if last else None,
            "active_goals": len(self.memory.list_goals("active")),
            "authority": {
                "observe": "automatic",
                "diagnose_and_plan": "automatic for authenticated requests",
                "execute_read_only": "automatic only through allowlisted tools",
                "execute_state_change": "explicit operator approval required",
                "destructive_actions": "typed confirmation required in every UI",
            },
        }
