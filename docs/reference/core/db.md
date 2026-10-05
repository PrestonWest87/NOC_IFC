# Core Database Module

**File:** `src/core/db.py`

Provides the SQLite engine/session factory, startup migration integration, post-migration connection tuning, bootstrap data setup, and the FastAPI database dependency.

## Database URL and engine

`DATABASE_URL` must use a SQLite URL. Non-SQLite backends fail during configuration with a clear error. The engine uses `NullPool`, `check_same_thread=False`, and a 30-second SQLite connection timeout.

## Startup sequence

`init_db()` performs these steps before a process serves work:

1. Calls `src.core.migration_runner.run_migrations(engine)`.
2. Enables persistent WAL mode and registers connection-local SQLite pragmas.
3. Calls `ensure_bootstrap_data(SessionLocal)` for conditional application defaults.

The API calls `init_db()` before starting its WebSocket broadcaster. The scheduler calls it before schedule registration or startup jobs. The webhook calls it before constructing its FastAPI app, and the standalone crime worker calls it before fetching data.

### Migration runner

`src/core/migration_runner.py` uses Alembic's `alembic_version` table and `migrations/versions/`. It acquires a cross-process lock file next to a file-backed SQLite database, then invokes `alembic upgrade head`. Startup at head performs a version check without schema DDL. Migration failures propagate and prevent that process from becoming ready.

Revision `20261002_0001` adopts databases created before Alembic using the frozen `migrations/schema_v1.py` snapshot: it creates missing baseline tables, adds absent columns in the explicit legacy compatibility map, creates missing indexes, and performs the documented one-time user/invitation/priority backfills. Revision `20261002_0002` adds `registration_invites.revoked_at` if absent. The upgrade path is additive and preserves existing rows; it does not drop or rename tables or columns.

Compatibility is intentionally bounded to known application schemas. If an existing table lacks an unlisted baseline column, or duplicate normalized emails prevent the unique index, validation fails before Alembic records success. Startup stops and the database may contain additive objects already completed by the attempted revision; those objects are checked before retry. This is not an automatic repair for arbitrary manual schema changes. Back up first and see [Migration Compatibility](../../MIGRATION_COMPATIBILITY.md) for supported cases and recovery guidance.

Future schema or deterministic data changes must be added as new forward-only revisions. Do not put recurring `ALTER TABLE` logic or production `create_all()` in startup code. SQLite DDL can leave partial work if a process is interrupted, so future revision operations should inspect existing objects and be safe to retry.

### SQLite connection tuning

After migrations, `_set_sqlite_pragmas()` enables persistent WAL mode. The SQLAlchemy `connect` event sets `synchronous=NORMAL`, `cache_size=-16000`, `temp_store=MEMORY`, and `mmap_size=67108864` on every new NullPool connection.

## Bootstrap data

`src/core/bootstrap.py` keeps application data initialization separate from schema migration:

- Starter roles and `SystemConfig` are created if missing.
- The `permission_catalog_version` field gates the one-time role-grant conversion; later startup does not broaden edited roles.
- `DEFAULT_ADMIN_PASSWORD` creates the first admin only when no user exists.
- A trusted `DEFAULT_ADMIN_EMAIL` may verify an existing email-less bootstrap admin and resolve a matching pending recovery-email request.
- Default RSS feeds and keywords are queried in batches and inserted only when absent; existing feed state and keyword weights are preserved.
- `DEMO_SEED_DATA` seeds sample assets only when the corresponding table is empty.
- Full article rescoring remains opt-in through `RESCORE_ON_STARTUP=true`.

## Operational notes

- Back up the SQLite database before a release that adds migrations.
- Do not manually edit `alembic_version` or drop columns to recover from a migration failure.
- The hourly scheduler maintenance job, not startup, handles retention deletion and orphan IOC cleanup.
- Tests may use in-memory SQLite engines; file-backed production startup uses the migration lock.
