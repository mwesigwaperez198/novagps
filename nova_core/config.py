"""NOVA-CORE agent configuration."""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


def _default_backend_dir() -> Path:
    root = Path(os.environ.get("NOVA_PROJECT_ROOT", "/app"))
    nested = root / "backend"
    # Render's production image flattens backend/ into /app, while source and
    # portable layouts retain backend/.  Support both without stale settings.
    return nested if nested.exists() else root


def _default_backend_url() -> str:
    """Where LAU's own backend tools should call.

    LAU runs inside the same service that serves the API, so on a host like
    Render the loopback default is wrong and every backend tool reports
    "unreachable". Prefer an explicit override, then the platform's own public
    URL, then the bound port, and only fall back to the classic dev default.
    """
    explicit = os.environ.get("NOVA_BACKEND_URL")
    if explicit:
        return explicit.rstrip("/")
    public = os.environ.get("RENDER_EXTERNAL_URL") or os.environ.get("PUBLIC_BASE_URL")
    if public:
        return public.rstrip("/")
    port = os.environ.get("PORT")
    if port:
        return f"http://127.0.0.1:{port}"
    return "http://127.0.0.1:8000"


@dataclass
class NovaCoreConfig:
    agent_name: str = field(default_factory=lambda: os.environ.get("NOVA_AGENT_NAME", "LAU"))
    # DATA_DIR is the platform-wide storage contract.  Older launchers only set
    # DATA_DIR, so derive every LAU path from it unless an explicit NOVA_* value
    # is supplied.  This keeps local, portable, and hosted memory in one place.
    base_dir: Path = field(default_factory=lambda: Path(os.environ.get("NOVA_DATA_DIR") or os.environ.get("DATA_DIR") or "data"))
    vault_dir: Path = field(default_factory=lambda: Path(os.environ.get("NOVA_VAULT_DIR") or os.environ.get("NOVA_DATA_DIR") or os.environ.get("DATA_DIR") or "data") / "nova_vault")
    project_root: Path = field(default_factory=lambda: Path(os.environ.get("NOVA_PROJECT_ROOT", "/app")))
    backend_dir: Path = field(default_factory=lambda: Path(os.environ["NOVA_BACKEND_DIR"]) if os.environ.get("NOVA_BACKEND_DIR") else _default_backend_dir())
    log_file: Path = field(default_factory=lambda: Path(os.environ.get("NOVA_LOG_FILE") or (Path(os.environ.get("NOVA_VAULT_DIR") or os.environ.get("NOVA_DATA_DIR") or os.environ.get("DATA_DIR") or "data") / "nova_vault/agent.log")))
    memory_db: Path = field(default_factory=lambda: Path(os.environ.get("NOVA_MEMORY_DB") or (Path(os.environ.get("NOVA_VAULT_DIR") or os.environ.get("NOVA_DATA_DIR") or os.environ.get("DATA_DIR") or "data") / "nova_vault/local_memory.db")))
    escrow_bin: Path = field(default_factory=lambda: Path(os.environ.get("NOVA_ESCROW_BIN") or (Path(os.environ.get("NOVA_VAULT_DIR") or os.environ.get("NOVA_DATA_DIR") or os.environ.get("DATA_DIR") or "data") / "nova_vault/secure_escrow.bin")))
    alert_file: Path = field(default_factory=lambda: Path(os.environ.get("NOVA_ALERT_FILE") or (Path(os.environ.get("NOVA_VAULT_DIR") or os.environ.get("NOVA_DATA_DIR") or os.environ.get("DATA_DIR") or "data") / "nova_vault/alerts.json")))
    monologue_file: Path = field(default_factory=lambda: Path(os.environ.get("NOVA_MONOLOGUE_FILE", "/tmp/lau_internal_monologue.log")))

    backend_url: str = field(default_factory=_default_backend_url)
    backend_token: str = field(default_factory=lambda: os.environ.get("NOVA_TOKEN", ""))
    environment: str = field(default_factory=lambda: os.environ.get("ENVIRONMENT", "development"))
    auto_enroll: bool = field(default_factory=lambda: os.environ.get("AUTO_ENROLL", "0") == "1")
    secret_key: str = field(default_factory=lambda: os.environ.get("SECRET_KEY", ""))

    watch_interval: int = field(default_factory=lambda: int(os.environ.get("NOVA_WATCH_INTERVAL", "60")))
    watch_enabled: bool = field(default_factory=lambda: os.environ.get("NOVA_WATCH_ENABLED", "1") == "1")
    scan_interval: int = field(default_factory=lambda: int(os.environ.get("NOVA_SCAN_INTERVAL", "300")))
    fuzz_interval: int = field(default_factory=lambda: int(os.environ.get("NOVA_FUZZ_INTERVAL", "3600")))

    max_memory_entries: int = 5000
    escrow_size: int = 4096

    ollama_host: str = field(default_factory=lambda: os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434"))
    ollama_model: str = field(default_factory=lambda: os.environ.get("OLLAMA_MODEL", "llama3.2:3b"))
    llm_backend: str = field(default_factory=lambda: os.environ.get("NOVA_LLM_BACKEND", "embedded"))
    llm_model_override: str = field(default_factory=lambda: os.environ.get("NOVA_MODEL", ""))

    # OpenAI-compatible hosted reasoning (Groq, OpenRouter, OpenAI, together...).
    # One key is enough to give LAU a real reasoning model; when it is absent the
    # deterministic shield remains the fallback so the app never hard-fails.
    llm_api_key: str = field(default_factory=lambda: os.environ.get("NOVA_LLM_API_KEY", ""))
    llm_base_url: str = field(
        default_factory=lambda: os.environ.get("NOVA_LLM_BASE_URL", "https://api.groq.com/openai/v1")
    )
    llm_model: str = field(
        default_factory=lambda: os.environ.get("NOVA_LLM_MODEL", "llama-3.3-70b-versatile")
    )
    llm_timeout: int = field(default_factory=lambda: int(os.environ.get("NOVA_LLM_TIMEOUT", "60")))

    embedded_enabled: bool = field(default_factory=lambda: os.environ.get("NOVA_EMBEDDED", "0") == "1")
    embedded_max_ctx: int = field(default_factory=lambda: int(os.environ.get("NOVA_EMBEDDED_CTX", "512")))
    embedded_max_tokens: int = field(default_factory=lambda: int(os.environ.get("NOVA_EMBEDDED_TOKENS", "128")))
    embedded_threads: int = field(default_factory=lambda: int(os.environ.get("NOVA_EMBEDDED_THREADS", "1")))
    mem_reserve_mb: int = field(default_factory=lambda: int(os.environ.get("NOVA_MEM_RESERVE_MB", "128")))

    def ensure_dirs(self):
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        for d in [self.base_dir, self.project_root, self.backend_dir]:
            d.mkdir(parents=True, exist_ok=True)

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


_config: Optional[NovaCoreConfig] = None


def get_config() -> NovaCoreConfig:
    global _config
    if _config is None:
        _config = NovaCoreConfig()
        _config.ensure_dirs()
    return _config
