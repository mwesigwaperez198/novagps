"""NOVA-CORE enforcement and state resilience module.

Handles code patching, file integrity monitoring, crash recovery,
and persistent state management via memory-mapped binary escrow.
"""

import hashlib
import json
import mmap
import os
import shutil
import tempfile
import time
import logging
from pathlib import Path
from typing import Optional, List, Tuple
from contextlib import contextmanager

from .config import get_config
from .memory import NovaMemory

logger = logging.getLogger("nova_core.enforcer")


class StateEscrow:
    def __init__(self, bin_path: Optional[str] = None, size: int = 4096):
        cfg = get_config()
        self.bin_path = bin_path or str(cfg.escrow_bin)
        self.size = size
        self._ensure_file()

    def _ensure_file(self):
        path = Path(self.bin_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(b"\x00" * self.size)

    def write(self, data: str):
        encoded = data.encode("utf-8")[:self.size]
        encoded = encoded.ljust(self.size, b"\x00")
        with open(self.bin_path, "r+b") as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
                mm.seek(0)
                mm.write(encoded)
                mm.flush()

    def read(self) -> str:
        with open(self.bin_path, "rb") as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                data = mm[:self.size]
                return data.decode("utf-8", errors="replace").rstrip("\x00")

    def write_json(self, obj: dict):
        self.write(json.dumps(obj, default=str))

    def read_json(self) -> dict:
        raw = self.read()
        if raw:
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return {}
        return {}


class FilePatcher:
    def __init__(self, memory: Optional[NovaMemory] = None):
        self.memory = memory or NovaMemory()

    def create_backup(self, file_path: str) -> Optional[str]:
        path = Path(file_path)
        if not path.exists():
            return None

        backup_dir = path.parent / ".nova_backups"
        backup_dir.mkdir(exist_ok=True)

        ts = int(time.time())
        backup_path = backup_dir / f"{path.name}.{ts}.bak"
        shutil.copy2(path, backup_path)

        self.memory.record_lesson(
            "file_backup",
            f"Backup created for {file_path}",
            f"Copied to {backup_path}",
            f"backup_size={backup_path.stat().st_size}",
        )

        return str(backup_path)

    def apply_patch(self, file_path: str, new_content: str, dry_run: bool = False) -> dict:
        path = Path(file_path)

        if not path.exists():
            return {"success": False, "error": f"File not found: {file_path}"}

        original = path.read_text(errors="replace")
        original_hash = hashlib.sha256(original.encode()).hexdigest()

        if original == new_content:
            return {"success": True, "unchanged": True, "message": "No changes needed"}

        diff_stats = self._compute_diff_stats(original, new_content)

        if dry_run:
            return {
                "success": True,
                "dry_run": True,
                "original_hash": original_hash,
                "new_hash": hashlib.sha256(new_content.encode()).hexdigest(),
                "diff": diff_stats,
            }

        backup = self.create_backup(file_path)

        try:
            path.write_text(new_content)
            new_hash = hashlib.sha256(new_content.encode()).hexdigest()

            self.memory.record_lesson(
                "file_patch",
                f"Patched {file_path}",
                f"Applied {diff_stats['lines_added']} additions, {diff_stats['lines_removed']} removals",
                f"from={original_hash[:12]} to={new_hash[:12]}",
                severity="info",
            )

            return {
                "success": True,
                "file": file_path,
                "backup": backup,
                "original_hash": original_hash,
                "new_hash": new_hash,
                "diff": diff_stats,
            }
        except Exception as e:
            if backup:
                shutil.copy2(backup, file_path)
            return {"success": False, "error": str(e), "rolled_back": bool(backup)}

    def _compute_diff_stats(self, original: str, modified: str) -> dict:
        orig_lines = original.splitlines()
        mod_lines = modified.splitlines()
        return {
            "original_lines": len(orig_lines),
            "new_lines": len(mod_lines),
            "lines_added": max(0, len(mod_lines) - len(orig_lines)),
            "lines_removed": max(0, len(orig_lines) - len(mod_lines)),
            "percent_changed": round(
                abs(len(mod_lines) - len(orig_lines)) / max(len(orig_lines), 1) * 100, 1
            ),
        }

    def cleanup_backups(self, max_age_hours: int = 72):
        cfg = get_config()
        for backup_dir in [cfg.backend_dir, cfg.project_root]:
            bak_dir = backup_dir / ".nova_backups"
            if not bak_dir.exists():
                continue
            cutoff = time.time() - (max_age_hours * 3600)
            for f in bak_dir.iterdir():
                if f.stat().st_mtime < cutoff:
                    f.unlink()


class IntegrityMonitor:
    def __init__(self, memory: Optional[NovaMemory] = None):
        self.memory = memory or NovaMemory()
        self.cfg = get_config()

    def snapshot(self) -> dict:
        files = [
            self.cfg.backend_dir / "main.py",
            self.cfg.backend_dir / "config.py",
            self.cfg.backend_dir / "auth.py",
            self.cfg.backend_dir / "models.py",
            self.cfg.backend_dir / "schemas.py",
            self.cfg.project_root / "Dockerfile",
        ]

        hashes = {}
        for fpath in files:
            if fpath.exists():
                sha = hashlib.sha256(fpath.read_bytes()).hexdigest()
                hashes[str(fpath.relative_to(self.cfg.project_root))] = sha

        state_key = f"integrity_snapshot_{int(time.time())}"
        self.memory.set_state("last_integrity_snapshot", json.dumps(hashes))
        return hashes

    def verify(self) -> dict:
        stored = self.memory.get_state("last_integrity_snapshot")
        if not stored:
            return {"verified": False, "reason": "no previous snapshot found"}

        previous = json.loads(stored)
        current = self.snapshot()

        changes = []
        for fpath, current_hash in current.items():
            prev_hash = previous.get(fpath)
            if prev_hash is None:
                changes.append({"file": fpath, "status": "new"})
            elif prev_hash != current_hash:
                changes.append({"file": fpath, "status": "modified", "from": prev_hash[:12], "to": current_hash[:12]})

        for fpath in previous:
            if fpath not in current:
                changes.append({"file": fpath, "status": "deleted"})

        if changes:
            self.memory.record_lesson(
                "integrity_check",
                f"File changes detected: {len(changes)} files",
                json.dumps(changes),
                "integrity_violation" if any(c["status"] == "modified" for c in changes) else "new_files",
                severity="warning",
            )

        return {
            "verified": len(changes) == 0,
            "changes": changes,
            "files_checked": len(current),
            "snapshot_time": time.time(),
        }


class NovaEnforcer:
    def __init__(self, memory: Optional[NovaMemory] = None):
        self.memory = memory or NovaMemory()
        self.escrow = StateEscrow()
        self.patcher = FilePatcher(self.memory)
        self.integrity = IntegrityMonitor(self.memory)

    def save_task_state(self, task_id: str, thought: str, progress: float = 0.0):
        self.escrow.write_json({
            "task_id": task_id,
            "thought": thought,
            "progress": progress,
            "timestamp": time.time(),
        })

    def recover_task_state(self) -> dict:
        return self.escrow.read_json()

    def patch_file(self, file_path: str, new_content: str, dry_run: bool = False) -> dict:
        return self.patcher.apply_patch(file_path, new_content, dry_run=dry_run)

    def take_integrity_snapshot(self) -> dict:
        return self.integrity.snapshot()

    def verify_integrity(self) -> dict:
        return self.integrity.verify()

    def cleanup(self, max_age_hours: int = 72):
        self.patcher.cleanup_backups(max_age_hours)

    def force_memory_flush(self):
        stats = self.memory.get_memory_stats()
        self.escrow.write_json({
            "memory_stats": stats,
            "last_flush": time.time(),
        })
        logger.info("Memory flushed: %s", json.dumps(stats))
