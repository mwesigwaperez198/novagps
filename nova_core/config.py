"""NOVA-CORE agent configuration."""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NovaCoreConfig:
    agent_name: str = field(default_factory=lambda: os.environ.get("NOVA_AGENT_NAME", "LAU"))
    base_dir: Path = field(default_factory=lambda: Path(os.environ.get("NOVA_DATA_DIR", "/var/data")))
    vault_dir: Path = field(default_factory=lambda: Path(os.environ.get("NOVA_VAULT_DIR", "/var/data/nova_vault")))
    project_root: Path = field(default_factory=lambda: Path(os.environ.get("NOVA_PROJECT_ROOT", "/app")))
    backend_dir: Path = field(default_factory=lambda: Path(os.environ.get("NOVA_BACKEND_DIR", "/app/backend")))
    log_file: Path = field(default_factory=lambda: Path(os.environ.get("NOVA_LOG_FILE", "/var/data/nova_vault/agent.log")))
    memory_db: Path = field(default_factory=lambda: Path(os.environ.get("NOVA_MEMORY_DB", "/var/data/nova_vault/local_memory.db")))
    escrow_bin: Path = field(default_factory=lambda: Path(os.environ.get("NOVA_ESCROW_BIN", "/var/data/nova_vault/secure_escrow.bin")))
    alert_file: Path = field(default_factory=lambda: Path(os.environ.get("NOVA_ALERT_FILE", "/var/data/nova_vault/alerts.json")))
    monologue_file: Path = field(default_factory=lambda: Path(os.environ.get("NOVA_MONOLOGUE_FILE", "/tmp/lau_internal_monologue.log")))

    backend_url: str = field(default_factory=lambda: os.environ.get("NOVA_BACKEND_URL", "http://127.0.0.1:8000"))
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

    embedded_enabled: bool = field(default_factory=lambda: os.environ.get("NOVA_EMBEDDED", "1") == "1")
    embedded_max_ctx: int = field(default_factory=lambda: int(os.environ.get("NOVA_EMBEDDED_CTX", "2048")))
    embedded_max_tokens: int = field(default_factory=lambda: int(os.environ.get("NOVA_EMBEDDED_TOKENS", "256")))
    embedded_threads: int = field(default_factory=lambda: int(os.environ.get("NOVA_EMBEDDED_THREADS", "1")))
    mem_reserve_mb: int = field(default_factory=lambda: int(os.environ.get("NOVA_MEM_RESERVE_MB", "512")))

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
