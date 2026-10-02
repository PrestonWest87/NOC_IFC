# Implementation Plan: Startup Migrations, Dependency Pruning, and Efficiency

**Status:** Complete
**Database:** SQLite only
**Migration behavior:** Check and apply pending revisions at startup, before application work begins.

## 1. Goals

- Track the database schema revision in the database and apply only migrations that are pending.
- Run migrations before API readiness, scheduled jobs, webhook processing, and bootstrap data updates.
- Remove PostgreSQL database-backend support.
- Prune unused dependencies and reduce install/build work while preserving active features.
- Improve database access patterns that load too much data or issue repeated per-record queries.

## 2. Versioned startup migrations

Use Alembic as an ongoing migration system. Each schema or deterministic data change gets a new, committed revision. Every process checks the database at startup; a database already at the application revision performs no schema changes. Alembic's `alembic_version` table records the successful revision. A failed migration stops startup and must not advance the database beyond its prior successful revision.

### Initial adoption of existing databases

The initial migration must support both an empty database and databases created by earlier releases:

- **Empty database:** create baseline tables and indexes from the frozen `migrations/schema_v1.py` snapshot.
- **Existing database:** inspect its actual tables, columns, and indexes; apply only missing baseline objects and one-time transformations; validate before recording the baseline revision.
- **Partial or inconsistent database:** stop with an actionable error rather than silently treating arbitrary DDL errors as “already exists.”

Do not blindly stamp an existing database as current. The adoption revision uses its frozen snapshot to create missing baseline tables, compares legacy tables against that snapshot, and records the revision only after successful validation. After the baseline, every schema/data change is a forward migration committed with the application-code change. Released revisions and the baseline snapshot are immutable.

### Startup order and concurrency

Create a shared database startup routine and call it from the API, scheduler, webhook, and standalone worker entrypoints. The order is:

1. Load settings and construct the SQLite engine without opening an application session.
2. Acquire a cross-process migration lock for the shared SQLite file.
3. Read the stored revision and apply pending revisions.
4. Validate the expected revision.
5. Configure SQLite runtime pragmas and run conditional bootstrap seeds.
6. Start serving requests or background work.

Move SQLite pragma setup out of module import so migration is the first database operation. Waiting processes must acquire the lock and recheck the revision; if another process already upgraded the file, they should no-op. Migration errors must fail startup before API readiness, scheduler registration, or webhook handling.

Remove production schema changes from `init_db()`: no recurring raw `ALTER TABLE` attempts or `create_all()` calls. `create_all()` is confined to the one-time Alembic adoption revision and isolated tests.

### Existing schema and data changes to migrate

Move the current DDL and one-time transformations in `src/core/db.py` into the baseline adoption migration, including:

- Additive columns across users, invites, roles, system configuration, articles, alerts, monitored locations, shift logs, timeline events, and crime incidents.
- `user_weather_prefs` creation and custom indexes.
- User timestamp and legacy-invitation backfills.
- Monitored-location priority conversion.
- The permission-catalog role migration currently guarded by `permission_catalog_version`.

Keep seed/bootstrap behavior separate from schema migrations. Default feeds, keywords, roles, system config, bootstrap-admin setup, and optional demo assets must be conditional and preserve operator changes. Batch seed checks or use SQLite conflict-safe inserts. Keep full article rescoring as a separate opt-in maintenance operation.

## 3. SQLite-only support

- Remove `psycopg2-binary` and `libpq-dev`.
- Reject non-SQLite `DATABASE_URL` values at startup with a clear error.
- Remove PostgreSQL-specific `SERIAL PRIMARY KEY` handling and update active deployment/configuration docs to SQLite-only.
- Retain SQLite's current `NullPool` behavior and WAL/performance settings.
- Retain the `PostgreSQL 16` demo software asset as inventory data; it is not database-backend support.
- A clean Python 3.11 container build verified prebuilt wheels for all runtime dependencies; remove `gcc` and keep `gosu`, which the entrypoint requires.

## 4. Dependency audit

### Remove unused Python packages

These declared packages had no corresponding source imports and were removed:

- `beautifulsoup4`
- `aiofiles`
- `openai`
- `google-generativeai`

The LLM code calls a configurable chat-completions endpoint using `requests`; it does not import either provider SDK. Correct documentation that currently describes these packages as active.

Add `httpx` to test-only requirements because the API tests use FastAPI's `TestClient`; do not rely on a removed SDK to install it transitively.

### Preserve production integrations

- **Elasticsearch:** Keep `elasticsearch` in normal requirements and preserve the current client/import behavior. Production uses the integration. Tests can leave `ELASTIC_URL` blank or mock the client; `tests/test_elastic_integration.py` covers both without a live service.
- **ML:** Keep `scikit-learn` and `joblib` in normal requirements and retain scheduled model training and scoring, even though retraining is infrequent.
- **Pandas:** Removed after the active regional, AIOps, settings, and training paths were converted to record lists, dictionaries, and `Counter`. ML training remains enabled through scikit-learn/joblib.
- Keep other active packages, including SQLAlchemy, FastAPI, `python-multipart`, Uvicorn, `pydantic-settings`, `python-dotenv`, bcrypt, Shapely, trafilatura, feedparser, schedule, requests, and aiohttp.

### RapidFuzz title matching

Article deduplication now uses `rapidfuzz.fuzz.ratio` with the existing strict `>85` threshold in place of Python `SequenceMatcher`. Representative title pairs were checked against the prior ratio.

### Frontend dependency pruning

- Replace the dual Mapbox/MapLibre React wrapper with `@vis.gl/react-maplibre`; the frontend uses only MapLibre and no Mapbox adapter.
- Remove the `deck.gl` umbrella package. It installs unused ArcGIS, CARTO, Google Maps, geo, mesh, aggregation, and Mapbox modules.
- Declare the actual imported packages directly: `@deck.gl/react`, `@deck.gl/layers`, and `@deck.gl/core`, plus required peers such as `@deck.gl/widgets`. Align versions and validate with a clean install.
- Update Axios, React Router, MapLibre, Vite, and the React Vite plugin to patched compatible versions; keep `npm audit` clear.
- Keep other frontend dependencies; they are imported by the application. Defer replacing Axios with browser `fetch` because many pages depend on Axios interceptors and response/error shapes.

## 5. Runtime efficiency improvements

### Bound article analytics reads

Several endpoints in `src/api/routes/keyword_analysis.py` load every article, and `/keyword-articles` applies its limit only after fetching the rows.

- Select only columns needed by each endpoint.
- Use SQL aggregation where appropriate.
- Apply limits and pagination in database queries.
- Recategorize in bounded batches.
- Preserve existing API response shapes.

### Batch ingestion lookups

Reduce per-record existence queries in `cloud_worker.py`, `infra_worker.py`, and `crime_worker.py`. In `cve_worker.py`, query only IDs from the current CISA response rather than loading every stored CVE ID. Batch-fetch existing keys or use SQLite upserts where semantics permit. Validate index changes with SQLite query plans.

### Remove DataFrame work from application paths

The DataFrame-heavy paths were converted to lists, dictionaries, and `Counter`, preserving output contracts:

- Regional map filtering and analytics.
- Location updates.
- AIOps chronic-alert summaries.
- Training-data loading in `src/train_model.py` (scikit-learn accepts Python lists and does not require pandas).

Pandas has been removed from runtime requirements after the active imports were eliminated. Do not substitute Polars as a presumed lightweight drop-in.

### Confirm legacy PyDeck helpers

The unused PyDeck rendering helpers had no in-repository callers and PyDeck was not a declared dependency. The helpers and stale reference documentation have been removed rather than adding PyDeck.

## 6. Build efficiency

- `web-dev` now uses a persistent `/app/node_modules` volume and lockfile fingerprint so `npm ci` runs only when dependencies change.
- An npm BuildKit cache mount speeds repeated clean installs.
- A hash-pinned Python 3.11 runtime lock is generated with `uv pip compile` and installed with hash checking.
- A BuildKit pip cache mount speeds installs while preserving the requirements-first Docker layer ordering.
- `.dockerignore` excludes the runtime `data/` directory and generated `src/ml_model.pkl` weights so local databases, backups, or training artifacts cannot change image size or content.
- Record current image/build measurements and compare them to a baseline when one was captured. Preserve route-level lazy loading; inspect bundle output before adding manual chunk rules.

## 7. Expected files

- `src/core/db.py` and new Alembic configuration/revision files.
- Startup code in `src/api/main.py`, `src/scheduler.py`, `src/webhook_listener.py`, and standalone worker startup.
- Python requirements/lock, test-only requirements, `Dockerfile`, and SQLite URL validation.
- `src/api/routes/keyword_analysis.py`, ingestion workers, and record-based regional/AIOps analytics.
- `web/package.json`, `web/package-lock.json`, web build files, and `docker-compose.yml`.
- Active dependency, database, deployment, architecture, and reference documentation.

## 8. Verification and acceptance criteria

- Fresh, legacy, and partially upgraded SQLite databases migrate successfully.
- A second startup at the current revision performs no schema or one-time data migration work.
- Concurrent process startup cannot run a migration twice.
- Migration failure prevents readiness and background work.
- User data, custom permissions, and operator-customized seed values are preserved.
- Non-SQLite URLs fail clearly.
- Elasticsearch support remains installed and unchanged; tests do not contact a live endpoint.
- ML training/scoring remain available in the normal image.
- Clean Python/npm installs pass; run backend tests, compilation checks, and the frontend production build.
- Validate reduced query work and migration behavior with focused tests; record image/build measurements where a comparable baseline exists. No baseline cold/warm timing was captured before this implementation.

Implementation must be done on `main`, then verified and synchronized to `architecture/monolith-to-decoupled` per `AGENTS.md`.
