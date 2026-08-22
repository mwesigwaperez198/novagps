from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    nova_mode: str = Field("full", alias="NOVA_MODE")
    data_dir: str = Field("", alias="DATA_DIR")
    database_url: str = Field("", alias="DATABASE_URL")
    postgres_user: str = Field("", alias="POSTGRES_USER")
    postgres_password: str = Field("", alias="POSTGRES_PASSWORD")
    postgres_db: str = Field("", alias="POSTGRES_DB")
    kafka_broker: str = Field("", alias="KAFKA_BROKER")
    kafka_topic: str = Field("nova.locations", alias="KAFKA_TOPIC")
    mqtt_broker: str = Field("", alias="MQTT_BROKER")
    secret_key: str = Field("replace_with_secure_random", alias="SECRET_KEY")
    jwt_algorithm: str = Field("HS256", alias="JWT_ALGORITHM")
    oauth_client_id: str = Field("", alias="OAUTH_CLIENT_ID")
    oauth_client_secret: str = Field("", alias="OAUTH_CLIENT_SECRET")
    vault_addr: str = Field("", alias="VAULT_ADDR")
    vault_token: str = Field("", alias="VAULT_TOKEN")
    sentry_dsn: str = Field("", alias="SENTRY_DSN")
    letsencrypt_email: str = Field("", alias="LETSENCRYPT_EMAIL")
    environment: str = Field("development", alias="ENVIRONMENT")
    cors_origins: str = Field("http://localhost:5173,http://127.0.0.1:5173", alias="CORS_ORIGINS")
    sandbox_executor_mode: str = Field("mock", alias="SANDBOX_EXECUTOR_MODE")
    retention_days: int = Field(365, alias="RETENTION_DAYS")
    rate_limit_per_minute: int = Field(120, alias="RATE_LIMIT_PER_MINUTE")

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    @model_validator(mode="after")
    def apply_portable_defaults(self) -> "Settings":
        if self.nova_mode not in {"portable", "full"}:
            raise ValueError("NOVA_MODE must be 'portable' or 'full'")
        if not self.database_url:
            base = Path(self.data_dir) if self.data_dir else Path("data")
            base.mkdir(parents=True, exist_ok=True)
            db_path = (base / "nova.sqlite3").resolve()
            self.database_url = f"sqlite:///{db_path.as_posix()}"
        return self

    @property
    def database_is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def kafka_enabled(self) -> bool:
        return bool(self.kafka_broker)

    @property
    def mqtt_enabled(self) -> bool:
        return bool(self.mqtt_broker)

    @property
    def cors_origin_list(self) -> List[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
