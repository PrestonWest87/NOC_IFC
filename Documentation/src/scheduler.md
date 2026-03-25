# Enterprise Architecture & Functional Specification: `src/scheduler.py`

## 1. Executive Overview

The `src/scheduler.py` module serves as the **Master Orchestration Engine** for the Intelligence Fusion Center (IFC). Operating as a headless background daemon, it manages the lifecycle of automated intelligence gathering, database garbage collection, and machine learning model retraining.

In its latest architectural iteration, the ingestion pipeline has undergone a radical optimization to prevent CPU starvation. By shifting to a hyper-efficient, single-core **Asynchronous Download + Sequential Yield** model, and wrapping all scheduled jobs in dedicated background threads, the worker dramatically reduces the compute overhead required to parse intelligence feeds. This ensures the Streamlit UI and FastAPI webhook endpoints remain highly responsive even on resource-constrained host machines.

---

## 2. Core Architecture: The Low-CPU Ingestion Pipeline

The `fetch_feeds()` function is fundamentally designed to decouple high-speed network I/O from computationally expensive NLP tasks without locking the host machine.

### 2.1 Pre-Loaded Singleton Instances
* **`_global_scorer` & `ioc_engine`:** Rather than instantiating the Machine Learning `HybridScorer` and the massive `EnterpriseIOCExtractor` Regex dictionaries multiple times in memory per feed, the engine initializes them once globally at the top of the script. This saves hundreds of megabytes of RAM and completely eliminates deserialization latency during rapid feed parsing.

### 2.2 Phase 1: Asynchronous Network I/O
* **Execution (`fetch_all_feeds`)**: Utilizes `aiohttp` and `asyncio.gather()` to fire HTTP GET requests to dozens of global RSS feeds concurrently. Because network requests are inherently I/O bound, this phase completes in seconds with virtually zero CPU cost.
* **Resilience**: Enforces a strict 15-second timeout per feed and utilizes spoofed `User-Agent` headers, guaranteeing that a single offline vendor or strict firewall cannot stall the entire pipeline.

### 2.3 Phase 2: Sequential Processing with CPU Yielding
Once the raw XML/HTML data is downloaded, it must be parsed, scored, categorized, and IOC-extracted. The system processes this sequentially using a controlled loop to protect the operating system.

* **Deduplication:** Queries the database for all known article URLs from the last 7 days (`known_links`) before processing, bypassing heavy NLP scoring for articles the system has already ingested.
* **The "Magic Sauce" (CPU Yielding):** At the end of every individual feed loop iteration, the worker executes `time.sleep(0.1)`. 
    * *Architectural Benefit:* While 100 milliseconds is imperceptible to the overall ingestion time, it provides a critical window for the operating system scheduler. It forces the Python process to yield control back to the OS, allowing the web server to process incoming ITSM webhooks or the Streamlit UI to render a dashboard frame, completely eliminating the "UI Freeze" phenomenon.

---

## 3. Database Maintenance & Aggressive Garbage Collection

As the IFC has expanded its telemetry sources to include BGP, Power Grid, Cloud, NWS, and Local Crime, the database grows rapidly. The `run_database_maintenance()` function enforces highly aggressive retention policies to preserve the speed of the SQLite WAL journal.

### 3.1 Retention Expirations
* **Immediate (Score <= 0.0):** Deletes any RSS article evaluated as pure noise.
* **12 Hours:** Purges granular network telemetry: `RegionalOutage` (Power/ISP drops) and `BgpAnomaly` (Route leaks).
* **24 Hours:** Purges resolved `CloudOutage` events.
* **48 Hours:** Purges `RegionalHazard` (NWS Weather polygons).
* **7 Days:** Purges local IT incident tickets (`SolarWindsAlert`), aging vulnerabilities (`CveItem`), and perimeter kinetic threats (`CrimeIncident`).
* **14 Days:** Purges standard OSINT `Article` records (unless they are manually protected via `is_pinned == True`).

### 3.2 Storage Optimization (Vacuuming)
* **Orphan Cleanup:** Executes `DELETE FROM extracted_iocs WHERE article_id NOT IN...` via raw SQL text to prevent dangling IOC indicators from consuming space when their parent articles are purged.
* **SQLite Auto-Commit Maintenance:** Opens a highly specific connection block utilizing `isolation_level="AUTOCOMMIT"` to execute `PRAGMA optimize;` and `PRAGMA wal_checkpoint(TRUNCATE);`. This forces SQLite to immediately flush the Write-Ahead Log back into the main database file and optimize its internal B-tree query planners without causing database lockups.

---

## 4. Automated ML Retraining Pipeline

To ensure the `HybridScorer` adapts to shifting terminology and operator feedback, the scheduler includes a self-updating machine learning loop.

### `job_retrain_ml()`
* **Execution:** Triggers the `train()` function from `src.train_model` to rebuild the Random Forest/TF-IDF pipeline based on newly ingested and manually adjusted data.
* **Hot-Reloading:** Once the new `ml_model.pkl` binary is written to disk, the function executes `_global_scorer = get_scorer()`. This hot-reloads the singleton object in memory, ensuring the new neural weights take effect immediately across all subsequent feed ingestions without requiring a Docker container restart.

---

## 5. The Threaded Master Orchestrator

The engine utilizes the `schedule` library to dictate the operational tempo, spinning in a `while True:` loop checking the clock every 1 second. 

### 5.1 The `run_threaded` Wrapper
To prevent a slow API endpoint (like a struggling municipal open-data server) from stalling the primary clock, every scheduled job is wrapped in `run_threaded(job_func)`. This spawns a `daemon=True` background thread for the execution of the job, ensuring the master loop can immediately proceed to schedule the next task.

### 5.2 Scheduled Job Roster
1.  **Continuous Daemons:** Instantiates the Automated Email Reporter (`start_report_scheduler`) as an independent background thread at startup.
2.  **Every Sunday at 02:00 (Strategic):** Executes `job_retrain_ml` during off-peak hours.
3.  **Every 5 Minutes (Hyper-Tactical):**
    * `fetch_regional_hazards()`: Syncs NWS/SPC physical weather threats.
    * `fetch_cloud_outages()`: Scans major cloud providers for down APIs.
    * `run_telemetry_sync()`: Polls the ODIN power grid, RIPE Stat BGP routes, and IODA ISP outages.
4.  **Every 15 Minutes (Operational):** Executes `fetch_feeds()` for low-CPU Async OSINT intelligence.
5.  **Every 30 Minutes (Kinetic):** Executes `fetch_live_crimes()` to poll local law enforcement APIs.
6.  **Every 60 Minutes (Housekeeping):** Executes `run_database_maintenance()`.
7.  **Every 6 Hours (Vulnerability):** Executes `fetch_cisa_kev()`.

**Boot Sequence:** Before entering the infinite while-loop, the script immediately fires all primary ingestion functions asynchronously via the `run_threaded` wrapper. This guarantees that fresh, correlated data is available on the dashboards the exact moment the container spins up, rather than waiting for the first cron intervals to hit.
