# Core Package

**Directory:** `src/core/`

Contains foundational infrastructure modules for the NOC Fusion Center application:

- **`config.py`** — Environment-based configuration via Pydantic `BaseSettings` and standardized logging setup.
- **`db.py`** — SQLAlchemy engine, session factory, database initialization (schema, migrations, seeding), and FastAPI dependency injection.
- **`migration_runner.py`** — Cross-process SQLite startup lock and Alembic upgrade runner.
- **`bootstrap.py`** — Idempotent role/admin/feed/keyword/default-data seeding after migrations.
- **`permissions.py`** — Canonical page, action, and tab permission catalogs.
- **`scheduler_registry.py`** — Scheduler job defaults, safe bounds, and schedule validation.
- **`paths.py`** — SQLite-relative application-data and ML model artifact locations.
- **`backup_manager.py`** — Authenticated encrypted full-database/model snapshots and validation.
- **`restore_control.py` / `ui_restore.py`** — Cross-container writer quiescence, restore progress, and UI restore orchestration.

See the adjacent module references and `docs/MIGRATION_COMPATIBILITY.md` for detailed behavior and operational boundaries.
