"""Create and seed a fresh dev-c SQLite database using the host Alembic runner."""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DATABASE_DIRECTORY = REPOSITORY_ROOT / "data-dev-c"
DATABASE_PATH = DATABASE_DIRECTORY / "noc_fusion.db"
EXPECTED_REVISION = "20261125_0025"  # Keep aligned with SqliteReadinessProbe.ExpectedSchemaRevision.


def main() -> None:
    os.chdir(REPOSITORY_ROOT)
    sys.path.insert(0, str(REPOSITORY_ROOT))

    from dotenv import load_dotenv

    load_dotenv(REPOSITORY_ROOT / ".env")
    if not os.environ.get("DEFAULT_ADMIN_PASSWORD", "").strip():
        raise SystemExit("Set DEFAULT_ADMIN_PASSWORD in .env or the environment before preparing dev-c data.")

    artifacts = (
        DATABASE_PATH,
        Path(f"{DATABASE_PATH}-wal"),
        Path(f"{DATABASE_PATH}-shm"),
        Path(f"{DATABASE_PATH}-journal"),
        DATABASE_PATH.with_name(f"{DATABASE_PATH.name}.migration.lock"),
    )
    if DATABASE_DIRECTORY.is_symlink() or any(path.exists() or path.is_symlink() for path in artifacts):
        raise SystemExit(f"Refusing to overwrite existing dev-c database artifacts under {DATABASE_DIRECTORY}.")

    created_directory = not DATABASE_DIRECTORY.exists()
    DATABASE_DIRECTORY.mkdir(mode=0o700, parents=True, exist_ok=True)
    if created_directory and os.name != "nt":
        DATABASE_DIRECTORY.chmod(0o700)

    os.environ["DATABASE_URL"] = f"sqlite:///{DATABASE_PATH.as_posix()}"
    os.environ["DEMO_SEED_DATA"] = "false"
    os.environ["RESCORE_ON_STARTUP"] = "false"

    from src.core.db import init_db

    init_db()

    with sqlite3.connect(DATABASE_PATH) as connection:
        revisions = connection.execute("SELECT version_num FROM alembic_version").fetchall()
        admin = connection.execute("SELECT 1 FROM users WHERE username = 'admin'").fetchone()
    if revisions != [(EXPECTED_REVISION,)]:
        raise RuntimeError(f"Expected Alembic revision {EXPECTED_REVISION}; found {revisions!r}.")
    if admin is None:
        raise RuntimeError("Bootstrap completed without creating the initial admin account.")

    if os.name != "nt":
        DATABASE_PATH.chmod(0o600)
    print(f"Prepared {DATABASE_PATH} at Alembic revision {EXPECTED_REVISION} with bootstrap defaults.")


if __name__ == "__main__":
    main()
