"""NOVA-CORE LLM client — connects to a local Ollama/llama.cpp server.

Provides chat, reasoning, and tool-selection capabilities with
automatic fallback to rule-based dispatch when no LLM is available.
"""

import json
import logging
import time
import urllib.request
import urllib.error
from typing import Optional, List, Tuple

from .config import get_config

logger = logging.getLogger("nova_core.llm")


class NovaLLM:
    def __init__(self, host: Optional[str] = None, model: Optional[str] = None):
        cfg = get_config()
        self.host = host or cfg.ollama_host
        self.model = model or cfg.ollama_model
        self.agent_name = cfg.agent_name
        self._available: Optional[bool] = None
        self._latency_ms = 0.0
        self._checked_at = 0.0
        self._availability_ttl = 20.0

    def check_availability(self) -> dict:
        if self._available is not None and time.time() - self._checked_at < self._availability_ttl:
            return {
                "available": self._available,
                "host": self.host,
                "model": self.model,
                "latency_ms": self._latency_ms,
            }

        try:
            start = time.time()
            req = urllib.request.Request(
                f"{self.host}/api/tags",
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read())
            self._latency_ms = (time.time() - start) * 1000

            models = [m.get("name", "") for m in data.get("models", [])]
            self._available = True
            self._checked_at = time.time()

            if not any(self.model in m for m in models):
                chosen = self._pick_best_model(models)
                if chosen:
                    logger.info(
                        "Configured model '%s' not installed — auto-selected '%s'",
                        self.model, chosen,
                    )
                    self.model = chosen
                else:
                    logger.warning(
                        "Requested model '%s' not in Ollama. Available: %s",
                        self.model, ", ".join(models) if models else "none",
                    )

            return {
                "available": True,
                "host": self.host,
                "model": self.model,
                "latency_ms": round(self._latency_ms, 2),
                "models_installed": models,
            }
        except Exception as e:
            self._available = False
            self._checked_at = time.time()
            logger.info("Ollama not reachable at %s: %s", self.host, e)
            return {"available": False, "host": self.host, "error": str(e)}

    def _pick_best_model(self, installed: list) -> str:
        """Choose the most capable installed model when the configured one is
        missing — prefers larger, newer models, else first installed."""
        if not installed:
            return ""
        preference = [
            "llama3.1:8b", "llama3:8b", "llama3", "llama3.2", "qwen2.5:7b",
            "qwen3:8b", "mistral", "gemma3", "phi4", "deepseek-r1",
        ]
        for pref in preference:
            for m in installed:
                if pref in m:
                    return m
        return installed[0]

    def is_available(self) -> bool:
        return self.check_availability().get("available", False)

    def chat(
        self,
        system: str,
        prompt: str,
        history: Optional[List[dict]] = None,
        temperature: float = 0.2,
        num_predict: int = 2048,
        timeout: int = 600,
    ) -> Tuple[bool, str]:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        for h in (history or []):
            messages.append(h)
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": num_predict,
            },
        }

        req = urllib.request.Request(
            f"{self.host}/api/chat",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            start = time.time()
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
            self._latency_ms = (time.time() - start) * 1000
            return True, data.get("message", {}).get("content", "")
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode()
            except Exception:
                pass
            logger.error("Ollama HTTP %s: %s", e.code, body[:300])
            return False, f"Ollama error {e.code}: {body[:200]}"
        except Exception as e:
            logger.error("Ollama chat failed: %s", e)
            return False, str(e)

    def generate(self, prompt: str, stream: bool = False, system: str = "") -> Tuple[bool, str]:
        return self.chat(system=system, prompt=prompt)

    def select_tool(self, query: str, tool_descriptions: list) -> list:
        """Ask the LLM which tools to use for a query.
        Returns list of tool names; falls back to [].
        """
        desc_text = "\n".join(
            f"- {t['name']}: {t['description']}" for t in tool_descriptions
        )

        prompt = f"""You are {self.agent_name}, the NOVA-CORE agent. Based on the user request, list which tools to call.
Return ONLY a JSON array of tool names. Example: ["port_scan", "system_info"]
If no tools are relevant, return [].

User request: {query}

Available tools:
{desc_text}

Response:"""

        ok, response = self.chat(
            system="You are a tool selection engine. Return only valid JSON arrays.",
            prompt=prompt,
            temperature=0.0,
            num_predict=256,
            timeout=30,
        )

        if not ok:
            return []

        try:
            cleaned = response.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.split("\n", 1)[1].rsplit("```", 1)[0].strip()
            result = json.loads(cleaned)
            if isinstance(result, list):
                return [t for t in result if any(desc["name"] == t for desc in tool_descriptions)]
        except json.JSONDecodeError:
            import re
            names = re.findall(r'"([a-z_]+)"', response)
            return [n for n in names if any(desc["name"] == n for desc in tool_descriptions)]

        return []

    def reason(self, state_summary: str, task: str) -> str:
        """Ask the LLM to reason about the current state and task.
        Returns the reasoning text; falls back to a local analysis."""
        prompt = f"""You are {self.agent_name}, the security agent of NOVA-CORE for NovaGPS. Analyze the current system state and plan the next action.

CURRENT SYSTEM STATE:
{state_summary}

ASSIGNED TASK:
{task}

Think step-by-step:
1. [System State]: What is the current state?
2. [Obstacle]: What is blocking or what needs fixing?
3. [Vector]: How should we adapt or exploit locally?
4. [Action]: Concrete next action to execute.

Keep it concise and actionable:"""

        ok, response = self.chat(
            system=self.reasoning_system_prompt(),
            prompt=prompt,
            temperature=0.4,
            num_predict=1024,
            timeout=600,
        )

        if ok:
            return response

        return (
            "[LLM unavailable] Falling back to local analysis.\n"
            f"State: {state_summary[:300]}\n"
            f"Task: {task[:300]}\n"
            "Suggested: run full security scan + integrity check."
        )

    def reasoning_system_prompt(self) -> str:
        try:
            from pathlib import Path
            prompts_dir = Path(__file__).resolve().parent / "prompts"
            prompt_file = prompts_dir / "system_prompt.md"
            if prompt_file.exists():
                return prompt_file.read_text()
        except Exception:
            pass
        return f"You are {self.agent_name}, an autonomous security agent of NOVA-CORE for NovaGPS."

    def get_latency(self) -> float:
        return self._latency_ms