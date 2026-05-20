# Enterprise Architecture & Functional Specification: `src/scheduler.py`

## 1. Executive Overview

The `src/scheduler.py` module operates as the **Master Orchestration Daemon** for the Intelligence Fusion Center (IFC). Running entirely headlessly within the `worker` Docker container, this module is the heartbeat of the application's automated intelligence gathering, synthesis, and maintenance pipelines.

It employs a **Hybrid Concurrency Model** to ensure that high-volume network I/O (like polling hundreds of RSS feeds) does not block CPU-heavy computational tasks (like Scikit-Learn NLP vectorization or complex geospatial bounding-box math). Furthermore, it manages the automated generation schedules for the AI Shift Logbook, the Internal Asset Risk matrices, and a **24/7 Tiered Alert Escalation Engine** that routes alerts based on business hours and priority.

---

## 2. Core Architecture: The Hybrid Concurrency Engine

### 2.1 Asynchronous I/O (`asyncio` & `aiohttp`)
* **Target:** High-latency, low-CPU network requests.
* **Execution:** RSS feed fetching (`fetch_all_feeds_chunked`) is executed concurrently in the async event loop in chunks of 5 to prevent memory spikes.

### 2.2 Threaded Execution (`run_threaded`)
All scheduled jobs are wrapped in `run_threaded()`, which executes the job function in a separate daemon thread. This prevents slow API calls from blocking the master schedule loop.

### 2.3 Boot Sequence
On startup, the scheduler fires an immediate asynchronous boot sequence executing all critical data ingestion jobs in parallel: CISA KEV sync, regional hazards, cloud outages, telemetry sync, crime data, RSS feeds, internal risk, and unified brief generation.

---

## 3. Intelligence Ingestion Pipelines

### 3.1 RSS Feed Engine
The feed ingestion pipeline operates in three phases:
1. **Phase 1 (Concurrent Download):** `fetch_all_feeds_chunked` uses `aiohttp` to download all active feed URLs concurrently in chunks of 5
2. **Phase 2 (Sequential Processing):** `parse_and_score_feed` parses RSS XML via `feedparser`, scores articles using the `HybridScorer`, categorizes via `categorize_text`, and extracts IOCs via the `EnterpriseIOCExtractor`
3. **Phase 3 (Bulk Save):** `bulk_save_to_db` inserts articles in batches of 100 with IOC foreign key relationships

### 3.2 Background Workers
The scheduler routes raw telemetry fetching across distinct temporal frequencies:

| Worker | Interval | Function |
|--------|----------|----------|
| Crime Data | 3 min | `crime_worker.fetch_live_crimes` |
| Regional Hazards | 2 min | `infra_worker.fetch_regional_hazards` |
| Cloud Outages | 5 min | `cloud_worker.fetch_cloud_outages` |
| Telemetry Sync | 5 min | `telemetry_worker.run_telemetry_sync` |
| CISA KEV | 6 hours | `cve_worker.fetch_cisa_kev` |

---

## 4. Tiered Alert Escalation Engine

### `job_tiered_alert_escalation()` (Every 1 Minute)
A comprehensive 24/7 ticketing and escalation manager that evaluates active SolarWinds alerts against business hours and priority rules.

**Business Hours Detection:** DAY SHIFT (Mon-Fri 0600-2000 CST) vs. AFTER HOURS

**Dual SLA Dictionaries:**
- **Day Shift Rules:** P1-high immediate, P2-P5 with 10-minute wait. No onpage requirements.
- **After Hours Rules:** P1-high immediate with onpage, P1-low 45-min wait with onpage, P2-P5 with 30-120 min waits, tiered onpage routing.

**Dispatch Routing:**
- **Standard Ticket:** Always sent to `REMEDYFORCE_TICKET_EMAIL`
- **NOC Notification:** After-hours only, sent to `NOC_NOTIFY_EMAIL`
- **Smart Onpage:** After-hours only. SWF (Statewide Fiber) devices route to `NOC_ONPAGE_EMAIL`, all other devices to `ITNETWORK_ONPAGE_EMAIL`

**Flapping Node Protection:** Cooldown timers per tier prevent alert storms from repeatedly dispatching the same failing node.

**Site-Level Muting:** After-hours onpage has a 1-hour site-level cooldown to prevent major outage flooding.

---

## 5. AI Synthesis & Matrix Generation

### 5.1 Unified Risk Brief (`job_unified_brief`) — Every 30 Minutes
Generates an executive risk brief merging global OSINT telemetry with internal hardware/software vulnerabilities. Uses `generate_unified_risk_brief()` from `src.llm`.

### 5.2 Internal Risk Snapshot (`job_internal_risk`) — Every 1 Hour
Runs `generate_and_save_internal_risk_snapshot()` to calculate point-in-time risk scores for all tracked hardware and software assets against active OSINT threats.

### 5.3 ML Retraining (`job_retrain_ml`) — Sunday 02:00
Retrains the Scikit-Learn model from human feedback data. Hot-reloads the scorer in memory so new neural weights take effect immediately.

---

## 6. Database Maintenance

### `run_database_maintenance()` (Every 60 Minutes)
Executes aggressive cleanup routines:

| Entity | Retention | Condition |
|--------|-----------|-----------|
| Articles | 14 days | Score <= 0 OR unpinned and older than 14 days |
| SolarWinds Alerts | 60 days | Received before 60-day cutoff |
| Regional Hazards | 48 hours | Updated before 48-hour cutoff |
| Regional Outages | 12 hours | Detected before 12-hour cutoff |
| BGP Anomalies | 12 hours | Detected before 12-hour cutoff |
| CVE Items | 7 days | Date added before 7-day cutoff |
| Cloud Outages | 24 hours | Updated before 24-hour cutoff |
| Crime Incidents | 7 days | Timestamp before 7-day cutoff |
| Orphaned IOCs | N/A | Cleaned via SQL DELETE |

**SQLite Optimization:** Runs `PRAGMA optimize` and `PRAGMA wal_checkpoint(TRUNCATE)` after data deletion.

---

## 7. Complete Function Reference

| Function | Signature | Purpose |
|----------|-----------|---------|
| `log` | `(message, source) -> None` | Timestamped logging to stdout |
| `fetch_single_feed` | `(session, f_name, f_url) -> tuple` | Async single RSS feed fetch |
| `fetch_all_feeds_chunked` | `(feed_data, chunk_size) -> list` | Async chunked feed fetching |
| `parse_and_score_feed` | `(f_name, content, known_links) -> tuple` | Parse RSS, score, categorize, extract IOCs |
| `bulk_save_to_db` | `(db_session, arts_data) -> int` | Batch insert articles with IOC relationships |
| `fetch_feeds` | `(source) -> None` | Main RSS fetch entry point |
| `job_unified_brief` | `() -> None` | Generate unified brief (30 min) |
| `job_internal_risk` | `() -> None` | Generate internal risk snapshot (1 hour) |
| `job_tiered_alert_escalation` | `() -> None` | 24/7 ticketing and escalation engine (1 min) |
| `run_database_maintenance` | `() -> None` | Database cleanup with retention policies (60 min) |
| `job_retrain_ml` | `() -> None` | ML model retrain with hot-reload (Sunday 02:00) |
| `run_threaded` | `(job_func, *args, **kwargs) -> None` | Thread wrapper for background execution |

---

## 8. Scheduler Job Matrix

| Job | Interval | Function | Target |
|-----|----------|-----------|--------|
| RSS Feed Fetch | 15 min | `fetch_feeds` | Worker |
| Crime Fetch | 3 min | `crime_worker.fetch_live_crimes` | Worker |
| Regional Hazards | 2 min | `infra_worker.fetch_regional_hazards` | Worker |
| Cloud Outages | 5 min | `cloud_worker.fetch_cloud_outages` | Worker |
| Telemetry Sync | 5 min | `telemetry_worker.run_telemetry_sync` | Worker |
| CISA KEV | 6 hours | `cve_worker.fetch_cisa_kev` | Worker |
| Unified Brief | 30 min | `llm.generate_unified_risk_brief` | Worker |
| Internal Risk | 1 hour | `services.generate_and_save_internal_risk_snapshot` | Worker |
| Alert Escalation | 1 min | `job_tiered_alert_escalation` | Worker |
| DB Maintenance | 60 min | `run_database_maintenance` | Worker |
| ML Retrain | Sunday 02:00 | `job_retrain_ml` | Worker |

---

## 9. Environment Variables

| Variable | Purpose |
|----------|---------|
| `REMEDYFORCE_TICKET_EMAIL` | ITSM ticket destination |
| `NOC_NOTIFY_EMAIL` | NOC notification destination |
| `NOC_ONPAGE_EMAIL` | NOC onpage destination (SWF devices) |
| `ITNETWORK_ONPAGE_EMAIL` | IT Network onpage destination |

---

## 10. API Citations

| API / Service | Purpose | Documentation |
|---------------|---------|---------------|
| schedule | Cron scheduling | https://schedule.readthedocs.io/ |
| aiohttp | Async HTTP | https://docs.aiohttp.org/ |
| feedparser | RSS parsing | https://feedparser.readthedocs.io/ |
| asyncio | Async I/O | https://docs.python.org/3/library/asyncio.html |
