"""Run pending SQLite schema revisions under a cross-process startup lock."""

from contextlib import contextmanager
import fcntl
import logging
import os
from pathlib import Path
import threading

from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)
_memory_lock = threading.RLock()
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


@contextmanager
def _migration_lock(engine: Engine):
    database_path = engine.url.database
    if not database_path or database_path == ":memory:":
        with _memory_lock:
            yield
        return

    database_file = Path(database_path).expanduser().resolve()
    database_file.parent.mkdir(parents=True, exist_ok=True)
    lock_file = database_file.with_name(database_file.name + ".migration.lock")
    descriptor = os.open(lock_file, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        with os.fdopen(descriptor, "r+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except Exception:
        # fdopen owns descriptor after successful construction; close only if
        # fdopen itself failed before taking ownership.
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def run_migrations(engine: Engine) -> None:
    """Upgrade to the latest packaged revision, or perform a version-only no-op."""
    if engine.dialect.name != "sqlite":
        raise RuntimeError("Only SQLite databases are supported; configure DATABASE_URL with a sqlite:/// URL.")

    config = Config(str(_REPOSITORY_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(_REPOSITORY_ROOT / "migrations"))

    with _migration_lock(engine):
        with engine.connect() as connection:
            config.attributes["connection"] = connection
            logger.info("Checking SQLite schema revision before application startup.")
            command.upgrade(config, "head")
            logger.info("SQLite schema is at the packaged Alembic head.")
