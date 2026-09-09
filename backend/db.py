from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from config import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()

if settings.database_is_sqlite:
    db_file = settings.database_url.replace("sqlite:///", "", 1)
    if db_file not in {":memory:", ""}:
        Path(db_file).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        settings.database_url,
        connect_args={"check_same_thread": False},
        pool_pre_ping=True,
        future=True,
    )
else:
    engine = create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        future=True,
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)


def init_db() -> None:
    # Portable/SQLite mode bootstraps the schema directly from the models.
    # Postgres deployments are managed by Alembic migrations because
    # Base.metadata.create_all() cannot create PostGIS geometry columns.
    if settings.database_is_sqlite:
        import models  # noqa: F401

        Base.metadata.create_all(bind=engine)
        _ensure_column("devices", "local_ip", "VARCHAR(45)")
        _ensure_column("devices", "carrier", "VARCHAR(128)")
        _ensure_column("devices", "recovery_id", "VARCHAR(32)")
    return


def _ensure_column(table: str, column: str, ddl: str) -> None:
    # create_all() only creates new tables; it never alters existing ones.
    # For the small additive columns we ship here, a guarded ALTER keeps
    # pre-existing SQLite databases working without a full migration flow.
    try:
        with engine.connect() as conn:
            has = conn.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
            if column in {row[1] for row in has}:
                return
            conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
            conn.commit()
    except Exception:  # pragma: no cover - non-critical schema helper
        pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
