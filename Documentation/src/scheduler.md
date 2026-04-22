# Enterprise Architecture & Functional Specification: `src/scheduler.py`

## 1. Executive Overview

The `src/scheduler.py` module operates as the **Master Orchestration Daemon** for the Intelligence Fusion Center (IFC). Running entirely headlessly within the `worker` Docker container, this module is the heartbeat of the application's automated intelligence gathering, synthesis, and maintenance pipelines.

In its latest architectural iteration, the scheduler has been heavily optimized to bypass Python's Global Interpreter Lock (GIL) limitations. It employs a **Hybrid Concurrency Model** to ensure that high-volume network I/O (like polling hundreds of RSS feeds) does not block CPU-heavy computational tasks (like Scikit-Learn NLP vectorization or complex geospatial bounding-box math). Furthermore, it manages the automated generation schedules for the new AI Shift Logbook and the Internal Asset Risk matrices.

---

## 2. Core Architecture: The Hybrid Concurrency Engine

To maintain high throughput on low-power edge compute devices, the scheduler dynamically routes tasks based on their resource utilization profiles.

### 2.1 Asynchronous I/O (`asyncio` & `aiohttp`)
* **Target:** High-latency, low-CPU network requests.
* **Execution:** Polling operations such as `fetch_feeds()` (RSS scraping), `fetch_cloud_outages()`, and external API requests are executed concurrently in the async event loop. This prevents the worker daemon from stalling while waiting for slow, third-party government or municipal APIs to respond.

### 2.2 Multiprocessing (`ProcessPoolExecutor`)
* **Target:** Heavy CPU-bound analytical tasks.
* **Execution:** Complex math operations—such as calculating Haversine distances for `crime_worker.py`, running TF-IDF matrix predictions via `train_model.py`, or compiling the massive Shapely geometry intersections for the Regional Grid—are offloaded to separate CPU cores. This ensures the primary scheduler loop never misses a tick.

### 2.3 Fault Tolerance & The `try...except` Wrapper
Because the daemon runs indefinitely (`while True`), it is imperative that a single failed task does not crash the container. Every scheduled job is wrapped in a robust execution decorator that catches exceptions, logs the traceback to the Docker console, and allows the `schedule.run_pending()` loop to seamlessly continue.

---

## 3. Intelligence Ingestion Pipelines

The scheduler routes raw telemetry fetching across distinct temporal frequencies based on the volatility of the operational domain.

### 3.1 High-Frequency Tactical Polling (Every 5–15 Minutes)
* **`crime_worker.fetch_live_crimes()`:** Polls local municipal CAD APIs to track active law enforcement dispatches within the geofenced NOC perimeter.
* **`infra_worker.fetch_regional_hazards()`:** Connects to NOAA/NWS APIs to pull live severe weather polygons, Red Flag fire warnings, and NIFC active wildfires.
* **`telemetry_worker.fetch_feeds()`:** Rapidly scrapes targeted cyber threat intelligence RSS endpoints, passing new articles directly to the regex categorizer and ML scoring engine.

### 3.2 Mid-Frequency Strategic Polling (Hourly)
* **`cve_worker.fetch_cisa_kev()`:** Syncs the localized SQLite database with the federal Known Exploited Vulnerabilities catalog.
* **`cloud_worker.fetch_cloud_outages()`:** Scrapes AWS, Azure, GCP, and other Tier-1 SaaS provider status pages for upstream dependencies.

---

## 4. Automated AI Synthesis & Matrix Generation

The scheduler dictates exactly when the `src/llm.py` engine and `src/services.py` data access layer trigger their heavy map-reduce pipelines.

### 4.1 Executive Briefings & Handoffs
* **The Unified Risk Brief (Every 2 Hours):** Triggers `generate_unified_risk_brief()`, merging live global OSINT telemetry with the organization's internal hardware/software vulnerabilities to produce a macroscopic, boardroom-ready narrative.
* **The Rolling Summary (Every 6 Hours):** Generates a fast-paced, tactical 2-paragraph context brief summarizing the immediate shift's operational status.
* **The Daily Fusion SitRep (06:00 AM Daily):** Executes the massive, 4-tier LLM Map-Reduce pipeline spanning Cyber, KEVs, Hazards, and Cloud infrastructure. It autonomously saves the Markdown output and dispatches the HTML-converted version to executive distribution lists via SMTP.

### 4.2 Internal Asset Risk Matrix Calculations
* **`generate_and_save_internal_risk_snapshot()` (Every 6 Hours):** Rather than forcing the UI to calculate millions of data points on load, the scheduler autonomously runs the complex point-in-time calculation evaluating the `HardwareAsset` and `SoftwareAsset` footprint against active OSINT threats. It saves the resulting `InternalRiskSnapshot`, enabling the Streamlit UI to instantly render the 14-day deviation trend graph.

---

## 5. Database Failsafes & The Master Garbage Collector

To guarantee the SQLite database remains lightweight, performant, and resistant to disk-bloat during continuous 24/7 operations, the scheduler executes aggressive maintenance routines.

### `run_database_maintenance()` (Hourly)
* **The Zero-Score Purge:** Deletes any un-pinned `Article` objects that the hybrid ML/Regex engine scored as `0`, ruthlessly cutting through generic marketing noise and geopolitics unrelated to the Bulk Electric System (BES).
* **The 30-Day Expiration:** Permanently drops un-pinned intelligence older than 30 days to free up SQLite indexing space. 
* **Kinetic Expiration:** Drops any `CrimeIncident` or `RegionalHazard` object older than 7 days, as severe weather and law enforcement dispatches are only relevant in the immediate tactical timeframe.
* **`VACUUM` Execution:** After data is deleted, the scheduler executes an implicit database vacuum to physically release the storage bytes back to the host machine's disk drive.

---

## 6. Complete Function Reference

| Function | Signature | Purpose |
|----------|----------|---------|
| `log` | `(message, source) -> None` | Timestamped logging |
| `fetch_single_feed` | `(session, f_name, f_url) -> list` | Async single RSS feed fetch |
| `fetch_all_feeds_chunked` | `(feed_data, chunk_size) -> list` | Async chunked feed fetching |
| `parse_and_score_feed` | `(f_name, content, known_links) -> list` | Parse RSS and apply scoring |
| `bulk_save_to_db` | `(db_session, arts_data) -> int` | Bulk insert articles |
| `fetch_feeds` | `(source) -> int` | Main RSS fetch entry point |
| `job_unified_brief` | `() -> None` | Generate unified brief (2hr) |
| `job_internal_risk` | `() -> None` | Generate internal risk (6hr) |
| `run_database_maintenance` | `() -> None` | Database cleanup (60min) |
| `job_retrain_ml` | `() -> None` | ML model retrain (Sunday 02:00) |
| `run_threaded` | `(job_func, *args, **kwargs) -> None` | Thread wrapper for multiprocessing |

---

## 7. Scheduler Job Matrix

| Job | Interval | Function | Target |
|-----|----------|-----------|--------|
| RSS Feed Fetch | 15 min | `fetch_feeds` | Worker |
| Crime Fetch | 3 min | `crime_worker.fetch_live_crimes` | Worker |
| Regional Hazards | 2 min | `infra_worker.fetch_regional_hazards` | Worker |
| Cloud Outages | 5 min | `cloud_worker.fetch_cloud_outages` | Worker |
| CISA KEV | 6 hours | `cve_worker.fetch_cisa_kev` | Worker |
| Internal Risk | 6 hours | `services.generate_and_save_internal_risk_snapshot` | Worker |
| Unified Brief | 2 hours | `llm.generate_unified_risk_brief` | Worker |
| DB Maintenance | 60 min | `run_database_maintenance` | Worker |
| ML Retrain | Sunday 02:00 | `job_retrain_ml` | Worker |

---

## 8. API Citations

| API / Service | Purpose | Documentation |
|---------------|---------|-------------|
| schedule | Cron scheduling | https://schedule.readthedocs.io/ |
| aiohttp | Async HTTP | https://docs.aiohttp.org/ |
| feedparser | RSS parsing | https://feedparser.readthedocs.io/ |
| asyncio | Async I/O | https://docs.python.org/3/library/asyncio.html |
