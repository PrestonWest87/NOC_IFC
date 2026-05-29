# Module: `src/scheduler.py`

## Overview

NOC Intelligence Fusion Center Background Scheduler. Orchestrates all background tasks including RSS feed ingestion, weather/telemetry data fetching, ML model retraining, automated reporting, 24/7 tiered alert escalation with Remedyforce ticketing, and database maintenance. Uses the `schedule` library with threaded execution to prevent blocking.

---

## Function: `log(message, source="SYSTEM")`

**Purpose:** Logs timestamped, prefixed messages formatted for Docker log capture.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `message` | `str` | The log message content. |
| `source` | `str` | Source identifier, default `"SYSTEM"`. Uppercased in output. |

**Returns:** None

**Raises:** None

**Flow:**
1. Calls `logger.info("[SOURCE] message")` with the uppercase source prefix.

**Dependencies:** `logging.getLogger(__name__)`

---

## Function: `fetch_single_feed(session, f_name, f_url)`

**Purpose:** Fetches a single RSS feed using an asynchronous HTTP GET request.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `session` | `aiohttp.ClientSession` | The shared aiohttp client session. |
| `f_name` | `str` | Human-readable feed name for logging. |
| `f_url` | `str` | The RSS feed URL to fetch. |

**Returns:**
| Type | Description |
|------|-------------|
| `tuple[str, str \| None]` | Tuple of `(feed_name, content_string)` on success, or `(feed_name, None)` on failure. |

**Raises:** None (all exceptions are caught and logged).

**Flow:**
1. Sets browser-like User-Agent and Accept headers.
2. Issues `session.get(f_url, headers=headers, timeout=15)`.
3. Calls `response.raise_for_status()`.
4. Reads response body via `await response.text()`.
5. Returns `(f_name, content)`.
6. On any `Exception`, logs a warning and returns `(f_name, None)`.

**Dependencies:** `aiohttp`

---

## Function: `fetch_all_feeds_chunked(feed_data, chunk_size=5)`

**Purpose:** Fetches multiple RSS feeds in parallel chunks to prevent memory spikes.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `feed_data` | `list[tuple[int, str, str]]` | List of tuples `(id, name, url)` for each feed source. |
| `chunk_size` | `int` | Number of feeds to fetch concurrently per chunk, default `5`. |

**Returns:**
| Type | Description |
|------|-------------|
| `list[tuple[str, str \| None]]` | List of `(name, content)` tuples from all feeds. |

**Raises:** None

**Flow:**
1. Iterates over `feed_data` in chunks of `chunk_size`.
2. For each chunk, creates a list of `fetch_single_feed` tasks.
3. Runs tasks concurrently with `asyncio.gather(*tasks)`.
4. Sleeps 0.1 seconds between chunks.
5. Aggregates and returns all results.

**Dependencies:** `aiohttp`, `asyncio`, `fetch_single_feed`

---

## Function: `parse_and_score_feed(f_name, content, known_links)`

**Purpose:** Parses RSS feed XML content and scores each article for relevance.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `f_name` | `str` | Feed source name for logging. |
| `content` | `str \| None` | Raw RSS XML content. |
| `known_links` | `set[str]` | Set of already-known article URLs for deduplication. |

**Returns:**
| Type | Description |
|------|-------------|
| `tuple[str, list[dict]]` | Tuple of `(feed_name, list_of_article_dicts)`. Each dict contains title, link, summary, source, score, category, keywords_found, is_bubbled, iocs. |

**Raises:** None

**Flow:**
1. If `content` is falsy, returns `(f_name, [])`.
2. Parses content with `feedparser.parse(content)`.
3. For each entry: deduplicates by link (using `known_links` and `seen_in_batch`).
4. Scores the article text using the pre-loaded `_global_scorer.score()`.
5. Categorizes via `categorize_text()`.
6. If score >= 50 and category starts with "Cyber", runs IOC extraction.
7. Appends article data dict to results.
8. Returns `(f_name, new_articles_data)`.

**Dependencies:** `feedparser`, `src.services.logic.get_scorer` (pre-loaded `_global_scorer`), `src.services.ioc_extractor.ioc_engine`, `src.services.categorizer.categorize_text`

---

## Function: `bulk_save_to_db(db_session, arts_data)`

**Purpose:** Saves scored article data to the database in batches for memory efficiency.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `db_session` | `Session` | SQLAlchemy database session. |
| `arts_data` | `list[dict]` | List of article data dicts from `parse_and_score_feed`. |

**Returns:**
| Type | Description |
|------|-------------|
| `int` | Total number of articles successfully saved. |

**Raises:** None (IntegrityError is caught and rolled back per batch)

**Flow:**
1. If no data, returns 0.
2. Iterates articles in batches of 100.
3. Creates `Article` ORM instances.
4. Flushes batch to get IDs.
5. If the article has extracted IOCs, creates `ExtractedIOC` records linked by `article_id`.
6. Commits batch.
7. On `IntegrityError`, rolls back the batch.
8. After all batches, calls `db_session.expunge_all()` to free memory.
9. Returns total added count.

**Dependencies:** `Article`, `ExtractedIOC` models, `sqlalchemy.exc.IntegrityError`

---

## Function: `fetch_feeds(source="Scheduled")`

**Purpose:** Main entry point for the scheduled RSS feed fetching and scoring cycle.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `source` | `str` | Source identifier for logging, default `"Scheduled"`. |

**Returns:** None

**Raises:** None (exceptions caught per-feed)

**Flow:**
1. Opens a DB session and queries all active `FeedSource` records.
2. Builds `feed_data` list and queries known article links from the last 7 days.
3. Phase 1: Downloads all feeds concurrently via `fetch_all_feeds_chunked`.
4. Phase 2: Processes each feed sequentially:
   - Calls `parse_and_score_feed` to get extracted articles.
   - Calls `bulk_save_to_db` to persist them.
   - Sleeps 0.1s between feeds.
5. Logs total added articles.
6. Runs `deduplicate_articles()` on a fresh session to clean near-duplicate titles.
7. Closes session and runs garbage collection.

**Dependencies:** `fetch_all_feeds_chunked`, `parse_and_score_feed`, `bulk_save_to_db`, `deduplicate_articles`, `FeedSource`, `Article`, `gc`

---

## Function: `job_unified_brief()`

**Purpose:** Auto-generates the Executive Unified Risk Brief by synthesizing global telemetry with internal risk data using the LLM.

**Parameters:** None

**Returns:** None

**Raises:** None (exceptions caught and logged)

**Flow:**
1. Gathers internal risk snapshot, active NWS hazard count, crime data, and executive grid intel.
2. Calls `generate_unified_risk_brief()` with the combined telemetry.
3. If successful and non-empty, saves the brief text and timestamp to `SystemConfig`.
4. Runs `check_and_alert()` to evaluate if notification is warranted.

**Dependencies:** `src.utils.llm.generate_unified_risk_brief`, `src.services.get_executive_grid_intel`, `src.services.get_recent_crimes`, `src.utils.risk_alert.check_and_alert`, `InternalRiskSnapshot`, `SystemConfig`

---

## Function: `job_internal_risk()`

**Purpose:** Generates and saves the internal risk snapshot, correlating internal assets against OSINT feeds.

**Parameters:** None

**Returns:** None

**Raises:** None (exceptions caught and logged)

**Flow:**
1. Calls `generate_and_save_internal_risk_snapshot()`.
2. If successful and `cis_data` returned, calls `check_and_alert()` with the internal risk level.

**Dependencies:** `src.services.generate_and_save_internal_risk_snapshot`, `src.utils.risk_alert.check_and_alert`

---

## Function: `job_daily_email_unified_brief()`

**Purpose:** Sends the latest Executive Unified Risk Brief via email at 07:00 daily.

**Parameters:** None

**Returns:** None

**Raises:** None (exceptions caught and logged)

**Flow:**
1. Checks for `RISK_ALERT_RECIPIENTS` env var; skips if not set.
2. Formats the current time in `America/Chicago` timezone.
3. Loads the latest `unified_brief` from `SystemConfig`.
4. Gathers current global and internal risk levels.
5. Calls `generate_unified_brief_email_html()` to produce formatted HTML.
6. Calls `send_alert_email()` to dispatch.
7. Logs success or failure.

**Dependencies:** `src.utils.mailer.send_alert_email`, `src.services.generate_unified_brief_email_html`, `src.services.get_executive_grid_intel`, `src.services.get_recent_crimes`, `InternalRiskSnapshot`, `SystemConfig`, `zoneinfo`

---

## Function: `run_database_maintenance()`

**Purpose:** Performs comprehensive database cleanup: deduplicates articles, purges stale records across all tables, and runs SQLite optimization pragmas.

**Parameters:** None

**Returns:** None

**Raises:** None (exceptions caught and logged)

**Flow:**
1. Opens a database session.
2. Runs `deduplicate_articles()`.
3. Deletes stale records:
   - `Article`: score <= 0, or published > 14 days ago (not pinned).
   - `SolarWindsAlert`: received > 60 days ago.
   - `RegionalHazard`: updated > 48 hours ago.
   - `RegionalOutage`: detected > 12 hours ago.
   - `BgpAnomaly`: detected > 12 hours ago.
   - `CveItem`: added > 7 days ago.
   - `CloudOutage`: resolved + updated > 24 hours, or unresolved + updated > 14 days.
   - `CrimeIncident`: older than 7 days.
4. Runs SQL to delete orphaned `ExtractedIOC` records (no matching article).
5. Commits the transaction.
6. Executes `PRAGMA optimize` and `PRAGMA wal_checkpoint(TRUNCATE)` on the SQLite engine.

**Dependencies:** All model classes, `deduplicate_articles`

---

## Function: `job_tiered_alert_escalation()`

**Purpose:** Comprehensive 24/7 Tiered Alert and RCA Ticketing Manager. Evaluates unfiltered SolarWinds alerts from the last 12 hours, clusters them by site using the AIOps engine, and dispatches prioritized tickets via email according to SLA rules. Supports day-shift (Remedyforce-only) and after-hours (full escalation with NOC notifications and smart on-page) modes.

**Parameters:** None

**Returns:** None

**Raises:** None (all exceptions caught and logged)

**Flow:**
1. Defines business hours detection: Mon-Fri 06:00-20:00 CT.
2. Reads SMTP destination addresses from environment variables:
   - `REMEDYFORCE_TICKET_EMAIL` (required)
   - `NOC_NOTIFY_EMAIL`
   - `NOC_ONPAGE_EMAIL`
   - `ITNETWORK_ONPAGE_EMAIL`
3. Defines dual SLA dictionaries for AFTER_HOURS_RULES and DAY_SHIFT_RULES with per-tier wait times, SLA targets, weights, on-page requirements, and cooldowns.
4. **Data Acquisition**: Queries unresolved SolarWindsAlerts from the last 12 hours, plus active weather, cloud, and BGP anomalies.
5. Initializes `EnterpriseAIOpsEngine` and calls `analyze_and_cluster()` to group alerts by site.
6. For each site/alerts cluster:
   - Filters to undispatched alerts (`is_ticketed == False`).
   - Checks site-level on-page mute (1-hour cooldown since last escalation ticket).
   - Calls `calculate_root_cause()` for root cause analysis.
   - Determines the highest-priority alert (handles cascade detection).
   - Evaluates against SLA wait times.
   - If threshold met, dispatches ticket email to Remedyforce.
   - If after-hours, sends NOC notification email and, if required, on-page email to NOC or ITNETWORK (based on SWF device detection).
   - On successful dispatch, marks all alerts in the cluster as `is_ticketed = True`.
   - Updates `last_escalation_ticket` on the MonitoredLocation for on-page mute.

**Dependencies:**
- `src.utils.mailer.send_alert_email`
- `src.services.aiops_engine.EnterpriseAIOpsEngine`
- `src.services.generate_rca_ticket_text`
- `SolarWindsAlert`, `RegionalHazard`, `CloudOutage`, `BgpAnomaly`, `MonitoredLocation`
- `datetime`, `zoneinfo`, `os`, `re`

---

## Function: `job_retrain_ml()`

**Purpose:** Automated weekly ML model retraining pipeline. Retrains the NLP scorer using human feedback data and hot-reloads the scorer in memory.

**Parameters:** None

**Returns:** None

**Raises:** None (exceptions caught and logged)

**Flow:**
1. Calls `train()` to retrain the scikit-learn pipeline on labeled articles.
2. On success, calls `get_scorer()` to hot-reload the model weights into `_global_scorer`.

**Dependencies:** `src.train_model.train`, `src.services.logic.get_scorer`

---

## Function: `run_threaded(job_func, *args, **kwargs)`

**Purpose:** Runs a scheduled job function in a separate daemon thread to prevent slow APIs from blocking the master schedule loop.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `job_func` | `callable` | The function to execute in a background thread. |
| `*args` | `tuple` | Positional arguments to pass to the function. |
| `**kwargs` | `dict` | Keyword arguments to pass to the function. |

**Returns:** None

**Raises:** None

**Flow:**
1. Creates a `threading.Thread` targeting `job_func` with the given args/kwargs.
2. Sets `daemon = True` so the thread exits when the main process exits.
3. Starts the thread.

**Dependencies:** `threading`

---

## Module-Level Execution (if `__name__ == "__main__"`)

**Purpose:** Bootstrap sequence when the scheduler is run as the main process.

**Flow:**
1. Calls `setup_logging()` from `src.core.config`.
2. Starts the automated email reporter in a daemon thread.
3. Registers all scheduled jobs with their intervals:
   - `job_retrain_ml`: Every Sunday at 02:00
   - `run_database_maintenance`: Every 60 minutes
   - `job_unified_brief`: Every 30 minutes
   - `fetch_feeds`: Every 15 minutes
   - `fetch_live_crimes`: Every 3 minutes
   - `fetch_cisa_kev`: Every 6 hours
   - `job_internal_risk`: Every 1 hour
   - `fetch_regional_hazards`: Every 2 minutes
   - `fetch_cloud_outages`: Every 5 minutes
   - `run_telemetry_sync`: Every 5 minutes
   - `job_tiered_alert_escalation`: Every 1 minute
   - `job_daily_email_unified_brief`: Daily at 07:00 CT
4. Fires a boot sequence running all critical jobs once on startup.
5. Enters master event loop: `while True: schedule.run_pending(); time.sleep(1)`.
6. On `KeyboardInterrupt`, logs shutdown and exits.

**Dependencies:** `schedule`, `threading`, all job functions, worker modules
