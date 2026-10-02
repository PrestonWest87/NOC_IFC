"""Filesystem locations that follow the configured SQLite data volume."""

from pathlib import Path

from sqlalchemy.engine import make_url

from src.core.config import settings

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def sqlite_database_path(database_url: str | None = None) -> Path | None:
    """Return the configured SQLite file path, or None for an in-memory DB."""
    url = make_url(database_url or settings.database_url)
    if url.get_backend_name() != "sqlite":
        raise RuntimeError("Only SQLite databases are supported.")
    database = url.database
    if not database or database == ":memory:":
        return None
    path = Path(database).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve()


def application_data_dir(database_url: str | None = None) -> Path:
    """Use the database directory as the durable application-data root."""
    db_path = sqlite_database_path(database_url)
    return db_path.parent if db_path else PROJECT_ROOT / "data"


def ml_model_path(database_url: str | None = None) -> Path:
    """Return the shared, persistent location of the trained scorer artifact."""
    db_path = sqlite_database_path(database_url)
    if db_path is None:
        # Preserve the repository-local location for in-memory development/tests.
        return PROJECT_ROOT / "src" / "ml_model.pkl"
    return db_path.parent / "models" / "ml_model.pkl"
