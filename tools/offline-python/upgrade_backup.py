"""Migrate an encrypted SQLite backup offline and write a current-head package."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_REVISION = "20261125_0025"


def upgrade_backup(source: Path, destination: Path) -> dict[str, object]:
    """Migrate a package in a temporary database and create a new encrypted package.

    The source package and active database are never modified. Restored credentials
    are invalidated by the existing restore routine, as they are during installation.
    """
    if source.is_symlink():
        raise ValueError("Source must be a regular .nocbackup file.")
    source = source.resolve(strict=True)
    if not source.is_file() or source.suffix != ".nocbackup":
        raise ValueError("Source must be a regular .nocbackup file.")

    destination_parent = destination.parent.resolve(strict=True)
    if destination.is_symlink():
        raise ValueError("Destination must not be a symbolic link.")
    destination = destination_parent / destination.name
    if destination.suffix != ".nocbackup":
        raise ValueError("Destination must end in .nocbackup.")
    if destination == source or destination.exists() or destination.is_symlink():
        raise ValueError("Destination must be a new path distinct from the source backup.")

    sys.path.insert(0, str(REPOSITORY_ROOT))
    os.chdir(REPOSITORY_ROOT)

    from src.core.backup_manager import create_backup, restore_backup, validate_backup

    with tempfile.TemporaryDirectory(prefix="noc-ifc-upgrade-", dir=destination_parent) as temporary:
        workspace = Path(temporary)
        database_path = workspace / "upgraded.sqlite"
        safety_dir = workspace / "restore-backups"
        package_dir = workspace / "converted-backups"

        restore_backup(
            source,
            maintenance_confirmed=True,
            database_path=database_path,
            backup_dir=safety_dir,
        )
        with sqlite3.connect(database_path) as connection:
            revisions = connection.execute("SELECT version_num FROM alembic_version").fetchall()
        if revisions != [(EXPECTED_REVISION,)]:
            raise RuntimeError(f"Expected schema revision {EXPECTED_REVISION}; found {revisions!r}.")

        package = create_backup(
            "manual",
            reason="offline schema upgrade",
            created_by="offline-backup-upgrade",
            database_path=database_path,
            backup_dir=package_dir,
        )
        package_path = package_dir / str(package["id"])
        validate_backup(package_path)

        try:
            with package_path.open("rb") as source_stream, destination.open("xb") as output_stream:
                if os.name != "nt":
                    os.chmod(destination, 0o600)
                shutil.copyfileobj(source_stream, output_stream, length=1024 * 1024)
                output_stream.flush()
                os.fsync(output_stream.fileno())
            if os.name != "nt":
                directory_fd = os.open(destination_parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        return {
            "status": "upgraded",
            "source": source.name,
            "output": destination.name,
            "schema_revision": EXPECTED_REVISION,
            "table_count": package["table_count"],
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Encrypted .nocbackup package to migrate")
    parser.add_argument("destination", type=Path, help="New current-head .nocbackup package path")
    args = parser.parse_args()
    try:
        source = args.source.absolute()
        destination = args.destination.absolute()
        os.chdir(REPOSITORY_ROOT)
        from dotenv import load_dotenv

        load_dotenv(REPOSITORY_ROOT / ".env")
        result = upgrade_backup(source, destination)
    except Exception as exception:
        parser.exit(1, f"Backup upgrade failed: {exception}\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
