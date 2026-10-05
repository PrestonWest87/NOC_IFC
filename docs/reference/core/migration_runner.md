# Module: `src.core.migration_runner`

`run_migrations(engine)` serializes SQLite startup upgrades and invokes `alembic upgrade head` from the packaged `migrations/` directory.

## Locking and execution

- Rejects engines whose dialect is not SQLite.
- For a file-backed database, creates a mode-`0600` sibling lock file named `<database filename>.migration.lock` and acquires an exclusive POSIX `flock` before checking/upgrading the revision.
- In-memory databases use a process-local reentrant thread lock; it is not a cross-process lock.
- Passes one connection to Alembic. Waiting processes acquire the lock and re-check the database revision after the prior process finishes.
- Errors propagate to `init_db()` and prevent the affected API, worker, or webhook process from starting its work.

The migration head is `20261002_0002`. The legacy adoption and failure guarantees are detailed in [Migration Compatibility](../../MIGRATION_COMPATIBILITY.md). Do not stamp `alembic_version` manually; restore a verified backup for rollback.
