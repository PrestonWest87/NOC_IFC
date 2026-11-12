# Module: `src.core.migration_runner`

`run_migrations(engine)` serializes SQLite startup upgrades and invokes `alembic upgrade head` from the packaged `migrations/` directory.

## Locking and execution

- Rejects engines whose dialect is not SQLite.
- For a file-backed database, creates a mode-`0600` sibling lock file named `<database filename>.migration.lock` and acquires an exclusive POSIX `flock` before checking/upgrading the revision.
- In-memory databases use a process-local reentrant thread lock; it is not a cross-process lock.
- Passes one connection to Alembic. Waiting processes acquire the lock and re-check the database revision after the prior process finishes.
- Errors propagate to `init_db()` and prevent the affected API, worker, or webhook process from starting its work.

The migration head is `20261112_0014`; revision `20261110_0009` creates the initial Operational Email tables, `20261110_0010` adds administrator-managed signatures/signature snapshots, `20261111_0011` creates the Fiber/ONPAGE email contacts and network-order/circuit directories, and `20261111_0012` conditionally refreshes shipped compose defaults while preserving administrator-customized text. Revision `20261112_0013` adds sender selection and Microsoft 365 public-feed freshness; revision `20261112_0014` adds Gmail OAuth fields, clears the retired App Password value, and falls back to the existing SMTP profile for password-only Gmail configurations. These revisions preserve existing records and add no destructive schema changes. Revision `20261105_0008` adds nullable environment-overridable alert/Elastic configuration and a legacy-compatible LLM provider field. Revision `20261103_0007` adds NWS CAP lifecycle fields and provider-fetch metadata while preserving cached GeoJSON; legacy unverified alert rows are marked `unknown`. The legacy adoption and failure guarantees are detailed in [Migration Compatibility](../../MIGRATION_COMPATIBILITY.md). Do not stamp `alembic_version` manually; restore a verified backup for rollback.
