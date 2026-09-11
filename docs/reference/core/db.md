# Core Database Module

**File:** `src/core/db.py`

Provides the SQLAlchemy engine, session factory, SQLite startup tuning, additive schema migration, default-data seeding, and the FastAPI database dependency.

## Module Objects

### `engine`

Created with `create_engine(DATABASE_URL, poolclass=NullPool, connect_args=...)`.

- SQLite uses `check_same_thread=False` and a 30-second timeout.
- PostgreSQL/other URLs use empty `connect_args`.
- `NullPool` is used for the current configuration to avoid long-lived SQLite connection contention.

### `SessionLocal`

`sessionmaker(autocommit=False, autoflush=False, bind=engine)`. Callers must close sessions; most service code uses `with SessionLocal() as session`.

## `_set_sqlite_pragmas()`

Called once at import when `engine.dialect.name == "sqlite"`. It opens a connection and applies:

| PRAGMA | Value | Purpose |
|---|---|---|
| `journal_mode` | `WAL` | Better read concurrency during writes. |
| `synchronous` | `NORMAL` | Balanced durability/performance under WAL. |
| `cache_size` | `-16000` | 16,000 KiB page cache. |
| `temp_store` | `MEMORY` | In-memory temporary tables. |
| `mmap_size` | `67108864` | 64 MiB memory mapping. |

It retries up to three times with waits of 0.5, 1.0, and 1.5 seconds. A final failure is logged as a warning because another process may already have enabled WAL.

## `get_db()`

Generator dependency:

1. Creates a `SessionLocal` instance.
2. Yields it to FastAPI.
3. Closes it in `finally`, including when the route raises.

## `init_db()`

Runs during API and worker startup. It is additive and intended to be idempotent.

### Schema creation

Calls `Base.metadata.create_all(bind=engine)`. Existing tables and columns are not dropped. A failure at this stage is logged and raised because the application cannot safely continue without a base schema.

### Additive migrations and indexes

The function executes guarded `ALTER TABLE` operations for fields introduced over time, including:

- `system_config`: alert tracking, wildfire state, enrichment/brief fields, risk tracking, scoring overrides, offsets, LLM context, and public app URL.
- `articles`: ingestion/enrichment state, attempts, error timestamps, and full content.
- `roles`: `allowed_site_types`.
- `solarwinds_alerts`: dispatch/ticket/acknowledgment fields.
- `monitored_locations`: district, maintenance, status tracking, and automatic/escalation timestamps.
- `shift_logs`: author role and soft-delete state.
- `crime_incidents`: alert-dispatched state.
- `users`: theme and default shift.
- `user_weather_prefs`: table and username index.

It creates indexes for article score/published/pinned queries, risk snapshots, SolarWinds status/node queries, cloud status, crime filtering, shift-log deletion, and weather preferences. Each migration is attempted with autocommit and an error is logged or debug-logged so an already-existing column does not prevent later migrations from running.

### Role and user seeds

The function creates or updates `admin` and `analyst` roles with the current page/action permission arrays and site-type support. It creates the first `admin` user only when no user exists and `DEFAULT_ADMIN_PASSWORD` is non-empty. The password is bcrypt-hashed; there is no guaranteed hard-coded password.

### Feed and keyword seeds

It inserts missing default RSS feed URLs and missing scoring keywords without replacing existing operator changes. The keyword list is maintained in the source seed array; the application uses the persisted `Keyword.weight` values at scoring time.

### System configuration and demo assets

If no `SystemConfig` exists, it creates an inactive default row. When `DEMO_SEED_DATA` is true, it adds synthetic hardware/software assets only when the relevant tables are empty.

### Optional article rescoring

The final stage checks `RESCORE_ON_STARTUP` directly from the process environment. Values `1`, `true`, and `yes` trigger `src.services.rescore_all_articles()`. The default is false, so normal startup does not rescore the complete corpus.

## Operational Notes

- Run `init_db()` manually only after creating a backup.
- Schema migration failures should be investigated rather than hidden by repeated restarts.
- The hourly scheduler maintenance job, not `init_db()`, handles normal retention deletion and orphan IOC cleanup.
- SQLite is suitable for a single-node deployment; use PostgreSQL for multiple writers or replicas.
