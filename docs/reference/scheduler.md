# Module: `src.scheduler`

The worker entrypoint and scheduled-job implementation. It is started by Docker as `python -u src/scheduler.py`.

## Startup

Import time configures logging and calls `init_db()`. The `__main__` block starts the report scheduler thread, registers jobs with the `schedule` library, fires a staggered boot sequence, then runs `schedule.run_pending()` once per second.

Jobs execute through a module-level `ThreadPoolExecutor(max_workers=2)`. `_running_jobs` and `_running_jobs_lock` prevent overlapping executions of the same function name.

## Utility Functions

### `log(message, source="SYSTEM", level=None)`

Writes a source-prefixed message through the module logger. It defaults to `logging.INFO` and is intended for Docker log collection.

### `log_memory_usage(tag="")`

Reads `VmRSS` from `/proc/self/status` and logs resident memory. On systems without that file it logs a warning rather than raising.

### `_ensure_scorer()`

Lazy-loads `src.services.logic.get_scorer()` into `_global_scorer`. ML retraining clears the global and reloads it after training.

## RSS Ingestion Functions

### `fetch_single_feed(session, f_name, f_url)`

Async HTTP fetch with browser-like headers and a 15-second timeout. It returns `(feed_name, response_text)` or `(feed_name, None)` after logging an error.

### `fetch_all_feeds_chunked(feed_data, chunk_size=5)`

Creates one `aiohttp.ClientSession`, divides `(id, name, url)` rows into chunks, fetches each chunk concurrently with `asyncio.gather`, pauses briefly between chunks, and returns results in chunk order. Chunking limits concurrent connections and memory use.

### `_fetch_full_content(url, timeout=10)`

Uses `requests` and `trafilatura` when available to extract article content. It returns `None` for missing dependency, HTTP failure, empty content, or extraction failure.

### `_entry_published_at(entry)`

Uses the feed’s `published_parsed` or `updated_parsed` timestamp, converts it with `calendar.timegm`, and falls back to `datetime.utcnow()` when unavailable or invalid.

### `parse_and_score_feed(f_name, content, known_links)`

Parses RSS/Atom content, skips empty links, links already in `known_links`, and duplicates within the current batch. It scores title plus summary with `HybridScorer`, categorizes with `categorize_text`, and extracts IOCs for articles scoring at least 50 and categorized as cyber. It returns article dictionaries with source, published date, score, category, keyword reasons, bubble state, and optional IOC data.

### `bulk_save_to_db(db_session, arts_data)`

Creates `Article` rows and nested transactions for IOC rows. Each article is isolated so an integrity error for one duplicate does not discard the rest of the batch. It commits once at the end, expunges objects, and returns the number added.

### `enrich_pending_articles(limit=25)`

Claims pending or failed articles with score at least 40, fewer than three attempts, and status `pending`/`failed`. It marks them `content_pending`, uses two concurrent extraction threads, stores at most 200,000 characters, and records success/failure metadata.

### `fetch_feeds(source="Scheduled")`

Main RSS cycle. It loads active feeds, builds a seven-day known-link set, downloads in chunks of five, parses/scores/saves each feed, runs article deduplication, and logs totals. One feed error is isolated from other feeds.

## Brief and Risk Jobs

| Function | Behavior |
|---|---|
| `job_unified_brief()` | Builds physical/cyber/internal context, generates and saves the Unified Brief, then evaluates risk alerts. |
| `job_global_brief()` | Calls `trigger_global_brief()` for the US critical-infrastructure threat brief. |
| `job_rolling_summary()` | Calls `trigger_rolling_summary()` for the shift handoff summary. |
| `job_internal_brief()` | Calls `trigger_internal_brief()` for asset-focused risk analysis. |
| `job_internal_risk()` | Saves a current internal risk snapshot and checks internal risk alerts. |
| `job_daily_email_unified_brief()` | Reads the saved brief, builds current risk context, formats HTML, and sends to `RISK_ALERT_RECIPIENTS`. |

Each wrapper catches and logs its own exception so one AI or email failure does not terminate the scheduler loop.

## `run_database_maintenance()`

Runs hourly retention deletion, orphan IOC cleanup, transaction commit/rollback, and SQLite `PRAGMA optimize` plus passive WAL checkpoint. Retention windows are documented in `docs/MAINTENANCE.md` and must be changed in source and reviewed together.

## `job_clear_expired_maintenance()`

Calls `auto_clear_expired_maintenance()`. If sites are cleared, it attempts to broadcast `RCA_UPDATE` to the API WebSocket manager.

## `job_tiered_alert_escalation()`

The 24/7 escalation loop:

1. Determines Central-time day shift or after-hours rules.
2. Requires `REMEDYFORCE_TICKET_EMAIL`.
3. Loads unresolved alerts from the last 12 hours plus weather/cloud/BGP context.
4. Clusters alerts with `EnterpriseAIOpsEngine`.
5. Chooses the oldest undispatched alert, then promotes to a higher-weight sibling tier when a cascade exists.
6. Applies wait windows, node cooldown, site mute, and SWF/ITNETWORK routing.
7. Sends ticket, notification, and optional on-page email.
8. Marks the cluster ticketed only when at least one dispatch succeeds.

See `docs/ESCALATION.md` for the exact SLA dictionaries and destinations.

## `job_retrain_ml()`

Calls `src.train_model.train()`, clears the global scorer, then reloads it. The model artifact is `src/ml_model.pkl` relative to the worker process working directory. Training requires at least 10 labeled articles.

## `run_threaded(job_func, *args, **kwargs) -> bool`

Rejects a function when the same name is already queued/running, submits a wrapper to the two-thread executor, logs pre/post memory, catches crashes, and removes the running marker in `finally`. Returns `True` when submitted and `False` when skipped.
