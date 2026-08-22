"""Portable-mode bootstrap: verify layout and create the SQLite schema."""
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent


def main() -> int:
    try:
        import config  # noqa: F401
    except ImportError:
        print("nova-bootstrap=error backend code not found next to this script")
        return 1

    from config import get_settings
    from db import init_db

    settings = get_settings()
    if not settings.database_is_sqlite:
        print("nova-bootstrap=error portable mode requires a sqlite:// DATABASE_URL")
        return 1

    init_db()
    db_file = settings.database_url.replace("sqlite:///", "", 1)
    size = Path(db_file).stat().st_size if Path(db_file).exists() else 0
    print(f"nova-bootstrap=ok mode={settings.nova_mode} db={db_file} bytes={size}")
    print(f"python={sys.version.split()[0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
