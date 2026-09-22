# Elastic Worker Module

**File:** `src/workers/elastic_worker.py`

## Overview

Connects to an Elasticsearch cluster (using URL + API key authentication), queries for high-severity log events from the past N hours, and synchronises them into the local `ElasticEvent` table for unified alerting. Also provides an ad-hoc query interface and a data purging utility for lifecycle management.

---

## Module-Level State

### `es` (`elasticsearch.Elasticsearch | None`)

Module-level client cache. The Elasticsearch client is created lazily on first use so API startup does not depend on Elasticsearch being reachable.

---

## Functions

### `sync_elastic_telemetry(hours_back: int = 24) -> dict`

- **Purpose:** Query the Elasticsearch cluster for high-severity events from the last N hours and ingest new records into the `ElasticEvent` table.
- **Parameters:**
  - `hours_back` (`int`, optional): Look-back window in hours. Defaults to `24`.
- **Returns:** `{"status": "ok", "imported": N}` or a controlled error result.
- **Raises:** `ValueError` for a non-positive/non-integer look-back value; request and database failures are returned as controlled errors.
- **Flow:**
   1. Lazily create the client with API-key authentication and configured TLS/request timeout.
  2. Build Elasticsearch query:
     - `range` filter on `@timestamp` >= `(UTC now - hours_back)`.
     - `should` clause: match `log.level` in `[emergency, alert, critical, error, severe]` **OR** `event.severity` <= 3.
     - `minimum_should_match: 1`.
      - Size: configured maximum results per page, sorted by `@timestamp` descending.
   3. Execute search-after pages against all non-hidden indices (`*,-.*`) with a bounded page count.
  4. For each hit:
      a. Use an index-qualified document ID and skip existing legacy or composite IDs.
     b. Resolve severity:
        - Use `log.level` if present, uppercased.
         - Else map numeric or numeric-string `event.severity`: <=2 -> `CRITICAL`, <=3 -> `HIGH`, else `WARNING`.
        - Fallback: `UNKNOWN`.
     c. Extract `message` from `message` or `event.original`.
     d. Extract `source_ip` from `source.ip` or `log.source.address`.
     e. Extract `event_category` from `event.category` (list or scalar).
     f. Build `ElasticEvent` row and add to session.
  5. Commit session.
   6. On failure, log the internal error and return a generic error result.
- **Dependencies:**
  - `elasticsearch.Elasticsearch` - Elasticsearch client
  - `src.core.db.SessionLocal` - SQLAlchemy session factory
  - `src.core.config.ELASTIC_URL`, `ELASTIC_API_KEY` - connection settings
  - `src.models.schema.ElasticEvent` - ORM model
   - `datetime`

### `execute_live_query(index_pattern: str = "*", query_body: dict = None, size: int = 100) -> dict | list`

- **Purpose:** Execute an ad-hoc Elasticsearch query and return raw hit results. Intended for interactive use or API-driven investigation.
- **Parameters:**
  - `index_pattern` (`str`, optional): Index pattern to search. Defaults to `"*"`.
  - `query_body` (`dict`, optional): Elasticsearch query DSL body. Defaults to `{"query": {"match_all": {}}}` sorted by `@timestamp` descending.
  - `size` (`int`, optional): Maximum number of hits to return. Clamped to `500`. Defaults to `100`.
- **Returns:** `list` of hit documents on success, or `dict` with an `"error"` key on validation, connection, or request failure.
- **Raises:** None (exceptions are caught and returned as error dicts).
- **Flow:**
  1. Validate the index pattern, query body, and bounded result size.
  2. Lazily create the client when needed.
  3. Apply default query body if none provided without mutating caller input.
  4. Execute `es.search()` with `ignore_unavailable=True`.
  5. Return `hits['hits']` on success, or a generic error result on failure.
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
