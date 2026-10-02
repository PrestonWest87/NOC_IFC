import logging
import time
import weakref

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from src.core.config import DATABASE_URL, settings
from src.models import Base

logger = logging.getLogger(__name__)


def validate_database_url(database_url: str):
    url = make_url(database_url)
    if url.get_backend_name() != "sqlite":
        raise RuntimeError(
            "Only SQLite databases are supported; configure DATABASE_URL with a sqlite:/// URL."
        )
    return url


validate_database_url(DATABASE_URL)
engine = create_engine(
    DATABASE_URL,
    poolclass=NullPool,
    connect_args={"check_same_thread": False, "timeout": 30},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
_sqlite_connection_pragmas_configured = weakref.WeakSet()
_sqlite_wal_configured = weakref.WeakSet()


def _apply_sqlite_connection_pragmas(dbapi_connection, _connection_record):
    """Apply connection-local SQLite tuning on every NullPool connection."""
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA cache_size=-16000")
        cursor.execute("PRAGMA temp_store=MEMORY")
        cursor.execute("PRAGMA mmap_size=67108864")
    finally:
        cursor.close()


def _set_sqlite_pragmas(bind=engine):
    """Enable persistent WAL and connection-local pragmas after migrations."""
    if bind not in _sqlite_connection_pragmas_configured:
        event.listen(bind, "connect", _apply_sqlite_connection_pragmas)
        _sqlite_connection_pragmas_configured.add(bind)
    if bind in _sqlite_wal_configured:
        return

    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            with bind.connect() as connection:
                journal_mode = connection.execute(text("PRAGMA journal_mode")).scalar_one()
                if str(journal_mode).lower() != "wal":
                    connection.execute(text("PRAGMA journal_mode=WAL"))
            _sqlite_wal_configured.add(bind)
            return
        except Exception as exc:
            wait = 0.5 * (attempt + 1)
            logger.warning(
                "SQLite WAL setup attempt %d/%d failed: %s; retrying in %.1fs",
                attempt + 1, max_attempts, exc, wait,
            )
            time.sleep(wait)
    logger.warning("SQLite WAL setup failed after %d attempts.", max_attempts)


def get_db():
    """FastAPI dependency yielding a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Run pending schema migrations before pragmas or bootstrap data."""
    from src.core.migration_runner import run_migrations

    run_migrations(engine)
    _set_sqlite_pragmas(engine)

    from src.core.bootstrap import ensure_bootstrap_data

    ensure_bootstrap_data(SessionLocal)
