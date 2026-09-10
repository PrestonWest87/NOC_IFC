# Elastic Worker Module

**File:** `src/workers/elastic_worker.py`

## Overview

Connects to an Elasticsearch cluster (using URL + API key authentication), queries for high-severity log events from the past N hours, and synchronises them into the local `ElasticEvent` table for unified alerting. Also provides an ad-hoc query interface and a data purging utility for lifecycle management.

---

## Module-Level State

### `es` (`elasticsearch.Elasticsearch | None`)

Module-level Elasticsearch client instance. Initialised once at import time from `ELASTIC_URL` and `ELASTIC_API_KEY`. Set to `None` if connection fails.

---

## Functions

### `sync_elastic_telemetry(hours_back: int = 24) -> None`

- **Purpose:** Query the Elasticsearch cluster for high-severity events from the last N hours and ingest new records into the `ElasticEvent` table.
- **Parameters:**
  - `hours_back` (`int`, optional): Look-back window in hours. Defaults to `24`.
- **Returns:** `None`
- **Raises:** None (all exceptions are caught and logged).
- **Flow:**
  1. Return immediately if `es` client is `None`.
  2. Build Elasticsearch query:
     - `range` filter on `@timestamp` >= `(UTC now - hours_back)`.
     - `should` clause: match `log.level` in `[emergency, alert, critical, error, severe]` **OR** `event.severity` <= 3.
     - `minimum_should_match: 1`.
     - Size: 500 results, sorted by `@timestamp` descending.
  3. Execute search against all non-hidden indices (`*,-.*`).
  4. For each hit:
     a. Skip if `id` already exists in `ElasticEvent`.
     b. Resolve severity:
        - Use `log.level` if present, uppercased.
        - Else map `event.severity` numeric: <=2 -> `CRITICAL`, 3 -> `HIGH`, else `WARNING`.
        - Fallback: `UNKNOWN`.
     c. Extract `message` from `message` or `event.original`.
     d. Extract `source_ip` from `source.ip` or `log.source.address`.
     e. Extract `event_category` from `event.category` (list or scalar).
     f. Build `ElasticEvent` row and add to session.
  5. Commit session.
  6. On failure, log error.
- **Dependencies:**
  - `elasticsearch.Elasticsearch` - Elasticsearch client
  - `src.core.db.SessionLocal` - SQLAlchemy session factory
  - `src.core.config.ELASTIC_URL`, `ELASTIC_API_KEY` - connection settings
  - `src.models.schema.ElasticEvent` - ORM model
  - `urllib3` - certificate warning suppression
  - `datetime`

### `execute_live_query(index_pattern: str = "*", query_body: dict = None, size: int = 100) -> dict | list`

- **Purpose:** Execute an ad-hoc Elasticsearch query and return raw hit results. Intended for interactive use or API-driven investigation.
- **Parameters:**
  - `index_pattern` (`str`, optional): Index pattern to search. Defaults to `"*"`.
  - `query_body` (`dict`, optional): Elasticsearch query DSL body. Defaults to `{"query": {"match_all": {}}}` sorted by `@timestamp` descending.
  - `size` (`int`, optional): Maximum number of hits to return. Clamped to `500`. Defaults to `100`.
- **Returns:** `list` of hit documents on success, or `dict` with an `"error"` key on failure or when `es` is `None`.
- **Raises:** None (exceptions are caught and returned as error dicts).
- **Flow:**
  1. Return `{"error": "Elasticsearch client is not connected."}` if `es` is `None`.
  2. Apply default query body if none provided.
  3. Clamp `size` to `min(size, 500)`.
  4. Execute `es.search()` with `ignore_unavailable=True`.
  5. Return `hits['hits']` on success, or `{"error": str(e)}` on failure.
- **Dependencies:**
  - `elasticsearch.Elasticsearch` (module-level `es` instance)

### `purge_stale_elastic_data(hours_to_keep: int = 72) -> None`

- **Purpose:** Delete `ElasticEvent` records older than the specified retention window.
- **Parameters:**
  - `hours_to_keep` (`int`, optional): Retention window in hours. Records older than this are deleted. Defaults to `72` (3 days).
- **Returns:** `None`
- **Raises:** None.
- **Flow:**
  1. Compute cutoff: `UTC now - hours_to_keep`.
  2. Execute `DELETE` query on `ElasticEvent` where `timestamp < cutoff`.
  3. Commit.
- **Dependencies:**
  - `src.core.db.SessionLocal` - SQLAlchemy session factory
  - `src.models.schema.ElasticEvent` - ORM model
  - `datetime`
