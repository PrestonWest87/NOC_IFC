# Operational Runtime Settings

**File:** `src/core/runtime_settings.py`

`resolve_operational_settings(db=None)` returns `(values, sources)` for alert destinations and Elastic settings. A non-`NULL` `SystemConfig` override takes precedence; a `NULL` column uses the corresponding typed `src.core.config.settings` environment value. An explicitly saved empty string remains an override and disables an optional destination or Elastic URL. `sources` reports `database` or `environment` per field.

When passed a caller-owned SQLAlchemy session, the helper uses it and does not close it. Without a session it opens and closes `SessionLocal`. The function intentionally performs a database read for each operation so API and worker processes observe UI changes without relying on process-local cache invalidation.

The `elastic_api_key` value is available only to runtime callers that need to create the client. The Application Settings API uses the effective source to return only a configured flag and never serializes the key.
