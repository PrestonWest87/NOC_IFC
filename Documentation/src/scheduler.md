# Enterprise Architecture & Functional Specification: `src/scheduler.py`

## 1. Executive Overview

The `src/scheduler.py` module serves as the **Master Orchestration Engine** for the Intelligence Fusion Center. Operating as a persistent, headless background daemon, it manages the entire lifecycle of automated intelligence gathering, data grooming, and system maintenance.

This module is architecturally sophisticated. To handle the high-volume ingestion of dozens of global intelligence feeds simultaneously, it bypasses Python's Global Interpreter Lock (GIL) limitations by employing a **Hybrid Concurrency Model**—combining Asynchronous I/O (`asyncio`/`aiohttp`) for network requests with Multiprocessing (`concurrent.futures`) for CPU-bound Machine Learning and parsing tasks.

---

## 2. The Hybrid Concurrency Ingestion Pipeline

The `fetch_feeds()` function acts as the trigger for the intelligence ingestion pipeline, designed for maximum throughput and fault tolerance.

### 2.1 Asynchronous Network I/O (The Fetch Phase)
Traditional synchronous requests (e.g., `requests.get()`) block the entire application while waiting for a server to respond. To prevent a slow RSS feed from lagging the entire engine, this module uses `aiohttp`.
* **`fetch_all_feeds(feed_data)`**: Wraps all active `FeedSource` URLs into a massive array of concurrent `asyncio` tasks.
* **`fetch_single_feed(session, f_name, f_url)`**: Executes the HTTP GET request. It enforces a strict 15-second timeout and catches connection errors, ensuring that if an external intelligence server drops offline, the worker gracefully logs the failure and continues processing the remaining feeds.

### 2.2 Multiprocessing (The Cognitive Phase)
Once the raw XML/HTML payloads are downloaded into memory, the system must parse the XML, run Regex categorizations, execute ML algorithms, and perform IOC extraction. These are heavily CPU-bound tasks that would freeze an asynchronous event loop.
* **`ProcessPoolExecutor`**: The engine spins up a cluster of separate Python processes (bypassing the GIL).
* **`init_process()`**: A critical memory-management function. It initializes the ML `HybridScorer` *inside* each child process rather than the parent. This prevents the parent process from serializing and cloning massive ML models across IPC (Inter-Process Communication) pipes, which would cause massive memory bloat and crashes.
* **`parse_and_score_feed(...)`**: The core worker function executed by the child processes. It parses the feed, checks a cached `known_links` set to skip duplicate articles, scores the text, categorizes it, and extracts IOCs if the score meets the threat threshold ($\ge$ 50).

### 2.3 Relational Database Commit (The Persistence Phase)
* **`bulk_save_to_db(db_session, arts_data)`**: Reintegrates the processed data from the child processes into the PostgreSQL/SQLite database.
* **Foreign Key Strategy:** It adds the `Article` object to the session and immediately calls `db_session.flush()`. This executes an `INSERT` statement to generate the Primary Key `id` without fully committing the transaction. It then uses this `id` to instantiate and link child `ExtractedIOC` records before calling a final, atomic `db_session.commit()`.
* **Idempotency:** Wraps the commit in a `try...except IntegrityError:` block to silently rollback duplicate insertions that might have bypassed the in-memory checks.

---

## 3. Database Maintenance (Garbage Collection)

To prevent the telemetry database from ballooning into gigabytes of unmanageable stale data, the engine includes a self-cleaning mechanism via `run_database_maintenance()`.

### 3.1 Retention Policies
The engine executes hard purges based on operational relevance:
* **Noise Reduction:** Instantly deletes any article with a score of `0.0` (zero threat relevance).
* **Article Expiration:** Deletes standard intelligence articles older than **30 Days** (unless manually pinned by an analyst: `is_pinned == False`).
* **Hazard Expiration:** Purges NWS/SPC weather hazards older than **2 Days**.
* **Cloud Outage Expiration:** Purges resolved SaaS/IaaS outages older than **1 Day**.

### 3.2 Integrity & Optimization
* **Orphan Cleanup:** Executes a raw SQL query to delete `extracted_iocs` where the parent `article_id` no longer exists, maintaining relational hygiene.
* **PostgreSQL Vacuuming:** If running on a PostgreSQL backend, it safely attempts to execute `VACUUM ANALYZE` commands to reclaim disk space and rebuild query planner statistics.

---

## 4. The Master Cron Scheduler

The module utilizes the `schedule` library to dictate the operational tempo of the entire Intelligence Fusion Center. When the script is executed (`if __name__ == "__main__":`), it spins up an infinite `while True:` loop checking the clock every 1 second to execute pending jobs.

### Scheduled Job Roster
1.  **Threaded Daemons:** Instantiates the Daily Report Generator (`start_report_scheduler`) as a background `daemon=True` thread.
2.  **Every 5 Minutes (Hyper-Tactical):**
    * `fetch_regional_hazards()`: Syncs NWS/SPC physical weather threats.
    * `fetch_cloud_outages()`: Scans major cloud providers for down APIs.
    * `run_telemetry_sync()`: *(Imported from `telemetry_worker.py`)* Assumed to sync raw node states or ITSM webhooks.
3.  **Every 15 Minutes (Operational):**
    * `fetch_feeds()`: Executes the massive Async/Multiprocess OSINT intelligence pull.
4.  **Every 60 Minutes (Housekeeping):**
    * `run_database_maintenance()`: Executes the garbage collection routines.
5.  **Every 6 Hours (Strategic):**
    * `fetch_cisa_kev()`: Updates the master catalog of Known Exploited Vulnerabilities.

**Boot Sequence:** To ensure the dashboard is populated immediately upon a fresh container spin-up, the scheduler manually invokes the intelligence, cloud, regional, and CVE functions once before entering the infinite sleep loop.
