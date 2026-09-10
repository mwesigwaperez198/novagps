"""NOVA-CORE Embedded Cognitive Engine.

Downloads a small GGUF model into the persistent disk on first boot via
huggingface_hub, loads it natively in-process with llama-cpp-python, and
guarantees uninterrupted reasoning via the NovaDeterministicShield fallback.

No Ollama daemon, no external API keys, no open ports.
"""

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Optional

from .config import get_config

logger = logging.getLogger("nova_core.engine")

# Candidate small CPU-friendly models: (repo_id, [filenames], approx_size_bytes)
MODEL_CANDIDATES = [
    {
        "repo": "Qwen/Qwen2.5-1.5B-Instruct-GGUF",
        "files": ["qwen2.5-1.5b-instruct-q4_k_m.gguf"],
        "size_bytes": 1_050_000_000,
        "label": "qwen2.5-1.5b-instruct-Q4_K_M",
    },
    {
        "repo": "unsloth/Llama-3.2-1B-Instruct-GGUF",
        "files": ["Llama-3.2-1B-Instruct.Q4_K_M.gguf"],
        "size_bytes": 750_000_000,
        "label": "llama-3.2-1b-instruct-Q4_K_M",
    },
    {
        "repo": "Qwen/Qwen2.5-0.5B-Instruct-GGUF",
        "files": ["qwen2.5-0.5b-instruct-q4_k_m.gguf"],
        "size_bytes": 400_000_000,
        "label": "qwen2.5-0.5b-instruct-Q4_K_M",
    },
]


class NovaCognitiveEngine:
    def __init__(self):
        self.cfg = get_config()
        self.agent_name = self.cfg.agent_name
        self.shield = None
        self.llm = None
        self.model_path: Optional[str] = None
        self.model_label: Optional[str] = None
        self.engine_used = "UNINITIALIZED"
        self.state = "idle"  # idle | downloading | loading | ready | shield_only | failed
        self.init_error: Optional[str] = None
        self._lock = threading.Lock()
        self._init_thread: Optional[threading.Thread] = None
        self._last_latency_ms = 0.0

        self._model_dir = Path(self.cfg.vault_dir) / "models"
        try:
            self._model_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error("Model dir creation failed: %s", e)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def status(self) -> dict:
        return {
            "agent": self.agent_name,
            "state": self.state,
            "engine_used": self.engine_used,
            "model": self.model_label,
            "model_path": self.model_path,
            "latency_ms": round(self._last_latency_ms, 2),
            "init_error": self.init_error,
            "available_ram_mb": round(self._available_ram_mb(), 1),
            "model_dir": str(self._model_dir),
        }

    def start_async(self):
        if self._init_thread and self._init_thread.is_alive():
            return
        self._init_thread = threading.Thread(
            target=self.initialize, name="nova-engine-init", daemon=True
        )
        self._init_thread.start()
        logger.info("Engine initialization started on background thread.")

    def initialize(self, force: bool = False) -> bool:
        with self._lock:
            if self.llm is not None and not force:
                return True
            if self.state in ("downloading", "loading"):
                return False

            self.model_path = self._resolve_model()
            if not self.model_path:
                self.state = "shield_only"
                self.engine_used = "DETERMINISTIC_SHIELD"
                self._log_lesson(
                    "No model fits available RAM; deterministic shield engaged.",
                    f"available_ram_mb={round(self._available_ram_mb(), 1)}",
                    engine="DETERMINISTIC_SHIELD",
                )
                return False

            self.state = "loading"
            try:
                from llama_cpp import Llama
            except Exception as e:
                self.state = "shield_only"
                self.engine_used = "DETERMINISTIC_SHIELD"
                self.init_error = f"llama_cpp import failed: {e}"
                logger.error(self.init_error)
                self._log_lesson(self.init_error, "Fell back to deterministic shield.")
                return False

            try:
                logger.info("Binding model weights natively (n_ctx=%d, n_threads=%d)...",
                            self.cfg.embedded_max_ctx, self.cfg.embedded_threads)
                self.llm = Llama(
                    model_path=self.model_path,
                    n_ctx=self.cfg.embedded_max_ctx,
                    n_threads=self.cfg.embedded_threads,
                    verbose=False,
                    seed=-1,
                )
                self.state = "ready"
                self.engine_used = "EMBEDDED_LLM"
                logger.info("NOVA-CORE LLM status: ONLINE (single-process, no external deps).")
                self._log_lesson(
                    "Embedded LLM loaded successfully.",
                    f"model={self.model_label} ctx={self.cfg.embedded_max_ctx}",
                    engine="EMBEDDED_LLM",
                )
                return True
            except Exception as e:
                self.llm = None
                self.state = "shield_only"
                self.engine_used = "DETERMINISTIC_SHIELD"
                self.init_error = f"llama_cpp load failed (OOM/compile): {e}"
                logger.error(self.init_error)
                self._log_lesson(self.init_error, "Fell back to deterministic shield.")
                return False

    def execute_reasoning_loop(self, system_prompt: str, task_input: str) -> dict:
        if self.engine_used == "DETERMINISTIC_SHIELD" or self.llm is None:
            self._ensure_shield()
            result = self.shield.process_deterministic_fallback(system_prompt, task_input)
            self._capture_shield_event(system_prompt, task_input, result)
            return result

        formatted_prompt = (
            f"<|im_start|>system\n{system_prompt}\n"
            f"<|im_end|>\n<|im_start|>user\n{task_input}\n<|im_end|>\n<|im_start|>assistant\n"
        )

        try:
            start = time.time()
            output = self.llm(
                formatted_prompt,
                max_tokens=self.cfg.embedded_max_tokens,
                temperature=0.2,
                stop=["<|im_end|>", "<|end|>"],
                echo=False,
            )
            self._last_latency_ms = (time.time() - start) * 1000
            text = output["choices"][0]["text"].strip()

            return {
                "engine": "EMBEDDED_LLM",
                "latency_ms": round(self._last_latency_ms, 3),
                "thought_process": {
                    "Telemetric Baseline": "Embedded llama-cpp core, local execution.",
                    "Constraint Isolation": "None — native process binding.",
                    "Exploitation / Adaptation Vector": "In-process reasoning, no external calls.",
                    "Defensive Delta / Execution Steps": "LLM_CORE_EXECUTED",
                },
                "output_payload": {
                    "verdict": "LLM_PROCESSED",
                    "action_enforced": "EXECUTE_LLM_OUTPUT",
                    "directives": [],
                    "response": text or "No output generated.",
                },
            }
        except Exception as e:
            logger.error("Live engine exception: %s — hot-swapping to shield.", e)
            self.engine_used = "DETERMINISTIC_SHIELD"
            self.llm = None
            self.state = "shield_only"
            self.init_error = f"Live engine crashed: {e}"
            self._log_lesson(f"Live engine crashed: {e}", "Hot-swapped to shield.", engine="DETERMINISTIC_SHIELD")
            self._ensure_shield()
            return self.shield.process_deterministic_fallback(system_prompt, task_input)

    def telemetry_verify(self, packet: dict) -> dict:
        if self.engine_used == "DETERMINISTIC_SHIELD" or self.llm is None:
            self._ensure_shield()
            return self.shield.telemetry_verify(packet)

        raw = json.dumps(packet, default=str)
        result = self.execute_reasoning_loop(
            f"You are {self.agent_name}, the NOVA-CORE telemetry guard. Verify this GPS/device packet for anomalies.",
            f"Packet: {raw[:800]}",
        )
        detected = self.shield.scan_input(raw) if self._shield_available() else []
        if detected:
            result["output_payload"]["verdict"] = f"SHIELD_OVERRIDE: {detected}"
            result["output_payload"]["directives"] = ["ISOLATE_AND_BLOCK", "alert_operator"]
        return result

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _ensure_shield(self):
        if self.shield is None:
            from .shield import NovaDeterministicShield
            self.shield = NovaDeterministicShield()

    def _shield_available(self) -> bool:
        self._ensure_shield()
        return self.shield is not None

    def _resolve_model(self) -> Optional[str]:
        override = os.environ.get("NOVA_EMBEDDED_MODEL", "").strip()
        if override:
            p = Path(override)
            if p.exists():
                logger.info("Using explicit model path: %s", p)
                self.model_label = override
                return str(p)
            return self._download(override, None)

        usable = self._usable_ram_mb()
        for candidate in MODEL_CANDIDATES:
            size_mb = candidate["size_bytes"] / (1024 * 1024)
            if size_mb <= usable:
                self.model_label = candidate["label"]
                return self._download(candidate["repo"], candidate["files"])

        logger.warning("No candidate model fits. Usable RAM: %.1f MB", usable)
        return None

    def _download(self, repo_id: str, filenames: Optional[list]) -> Optional[str]:
        self.state = "downloading"
        for filename in (filenames or []):
            dest = self._model_dir / filename
            if dest.exists() and dest.stat().st_size > 100_000:
                logger.info("Model already present: %s", dest)
                self.state = "idle"
                return str(dest)

        try:
            from huggingface_hub import hf_hub_download
        except Exception as e:
            self.state = "shield_only"
            self.init_error = f"huggingface_hub unavailable: {e}"
            logger.error(self.init_error)
            return None

        try:
            logger.info("[NOVA-CORE] Downloading model %s into %s ...", repo_id, self._model_dir)
            if filenames:
                local = hf_hub_download(
                    repo_id=repo_id,
                    filename=filenames[0],
                    local_dir=str(self._model_dir),
                )
                return str(local)
            else:
                snapshot = self._hf_snapshot(repo_id, hf_hub_download)
                if snapshot:
                    return snapshot
        except Exception as e:
            self.init_error = f"Model download failed: {e}"
            logger.error(self.init_error)

        found = self._find_existing_gguf()
        if found:
            logger.info("Using pre-existing GGUF: %s", found)
            return found
        return None

    def _hf_snapshot(self, repo_id: str, hf_hub_download) -> Optional[str]:
        try:
            from huggingface_hub import list_repo_files
            files = list_repo_files(repo_id)
            gguf = [f for f in files if f.endswith(".gguf") and "Q4_K_M" in f.upper()]
            if not gguf:
                gguf = [f for f in files if f.endswith(".gguf")]
        except Exception:
            gguf = []

        if gguf:
            local = hf_hub_download(repo_id=repo_id, filename=gguf[0], local_dir=str(self._model_dir))
            return str(local)
        return None

    def _find_existing_gguf(self) -> Optional[str]:
        try:
            candidates = sorted(self._model_dir.rglob("*.gguf"), key=lambda p: p.stat().st_size, reverse=True)
            if candidates:
                self.model_label = candidates[0].stem
                return str(candidates[0])
        except Exception:
            pass
        return None

    def _available_ram_mb(self) -> float:
        try:
            with open("/proc/meminfo") as f:
                lines = f.readlines()
            mem = {}
            for line in lines:
                parts = line.split(":")
                if len(parts) == 2:
                    mem[parts[0].strip()] = int(parts[1].strip().split()[0])  # kB
            return mem.get("MemAvailable", mem.get("MemFree", 0)) / 1024
        except Exception:
            return 1024.0

    def _usable_ram_mb(self) -> float:
        reserve_mb = int(os.environ.get("NOVA_MEM_RESERVE_MB", "512"))
        return max(0.0, self._available_ram_mb() - reserve_mb)

    def _capture_shield_event(self, system_prompt: str, task_input: str, result: dict):
        """Commit notable shield responses (threat block / engineering spec) to the
        lesson ledger so LAU retains every adversarial probe it sees."""
        try:
            payload = result.get("output_payload", {}) or {}
            verdict = payload.get("verdict", "")
            if "ENGINEERING_SPEC_GENERATED" in verdict or "CRITICAL_MITIGATION_TRIGGERED" in verdict:
                from .memory import NovaMemory
                NovaMemory().record_lesson(
                    "shield_deployment",
                    f"Probe seen: {str(task_input)[:140]}",
                    f"{verdict} ({result.get('engine', 'DETERMINISTIC_SHIELD')})",
                    str(payload.get("response", ""))[:400],
                    severity="high" if "CRITICAL" in verdict else "info",
                    tags=self.agent_name,
                    engine_used="DETERMINISTIC_SHIELD",
                )
        except Exception as e:
            logger.debug("Shield event capture skipped: %s", e)

    def _log_lesson(self, obstacle: str, maneuver: str, engine: str = "ENGINE"):
        try:
            from .memory import NovaMemory
            memory = NovaMemory()
            memory.record_lesson(
                "engine",
                obstacle,
                maneuver,
                f"engine={engine}",
                severity="info",
                tags=engine,
                engine_used=engine,
            )
        except Exception as e:
            logger.debug("Lesson log skipped: %s", e)


_engine: Optional[NovaCognitiveEngine] = None


def get_engine() -> NovaCognitiveEngine:
    global _engine
    if _engine is None:
        _engine = NovaCognitiveEngine()
    return _engine