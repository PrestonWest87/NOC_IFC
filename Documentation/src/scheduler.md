# Enterprise Architecture & Functional Specification: `src/scheduler.py` *(Updated)*

## 1. Executive Overview

The `src/scheduler.py` module serves as the **Master Orchestration Engine** for the Intelligence Fusion Center. Operating as a headless background daemon, it manages the lifecycle of automated intelligence gathering and data grooming.

In its latest architectural iteration, the ingestion pipeline has undergone a radical optimization to prevent **CPU Starvation**. By shifting from a heavy multi-processing model (`concurrent.futures`) to a hyper-efficient, single-core **Asynchronous Download + Sequential Yield** model, the worker dramatically reduces the compute overhead required to parse intelligence feeds, ensuring the Streamlit UI and FastAPI endpoints remain highly responsive even on resource-constrained host machines.

---

## 2. Core Architecture: The Low-CPU Ingestion Pipeline

The `fetch_feeds()` function has been fundamentally redesigned to decouple high-speed network I/O from computationally expensive NLP tasks without locking the host machine.

### 2.1 Pre-Loaded Singleton Instances
* **`_global_scorer` & `ioc_engine`:** Rather than spinning up independent Python processes and instantiating the Machine Learning `HybridScorer` and the massive `EnterpriseIOCExtractor` Regex dictionaries multiple times in memory, the engine initializes them once globally at the top of the script. This saves hundreds of megabytes of RAM and prevents deserialization latency.

### 2.2 Phase 1: Asynchronous Network I/O
* **Execution (`fetch_all_feeds`)**: Utilizes `aiohttp` and `asyncio.gather()` to fire HTTP GET requests to dozens of global RSS feeds simultaneously. Because network requests are inherently "waiting" operations, this completes in seconds with virtually zero CPU cost.
* **Resilience**: Enforces a strict 15-second timeout per feed, guaranteeing that a single offline vendor cannot stall the entire pipeline.

### 2.3 Phase 2: Sequential Processing with CPU Yielding
Once the raw XML/HTML data is downloaded, it must be parsed, scored, categorized, and IOC-extracted. Rather than using Python multiprocessing to blast this data through the CPU simultaneously, the system uses a controlled loop.

* **Sequential Execution**: Processes one feed at a time using the pre-loaded `_global_scorer` and `ioc_engine`.
* **The "Magic Sauce" (CPU Yielding):** At the end of every feed loop iteration, the worker executes `time.sleep(0.1)`. 
    * *Architectural Benefit:* While 100 milliseconds is imperceptible to the overall ingestion time (adding ~2 seconds total for 20 feeds), it provides a critical "breath" for the operating system scheduler. It forces the Python process to yield control back to the OS, allowing the `uvicorn` (FastAPI) server to process incoming ITSM webhooks or the Streamlit UI to render a dashboard frame, completely eliminating the "UI Freeze" phenomenon common in heavy Python ETL scripts.

---

## 3. Database Maintenance (Aggressive Garbage Collection)

As the IFC has expanded its telemetry sources (BGP, Power Grid, Cloud, NWS), the database grows rapidly. The `run_database_maintenance()` function has been upgraded with highly aggressive retention policies to preserve the speed of the SQLite WAL journal.

### 3.1 Retention Expirations
* **Immediate (0s):** Deletes any RSS article with a threat score $\le 0.0$.
* **12 Hours:** Purges granular network telemetry: `RegionalOutage` (Power/ISP drops) and `BgpAnomaly` (Route leaks).
* **24 Hours:** Purges resolved `CloudOutage` events.
* **48 Hours:** Purges `RegionalHazard` (NWS Weather polygons).
* **7 Days:** Purges local IT incident tickets (`SolarWindsAlert`) and aging vulnerabilities (`CveItem`).
* **14 Days:** Purges standard OSINT `Article` records (unless they are manually `is_pinned == True`).

### 3.2 Storage Optimization (Vacuuming)
* **Orphan Cleanup:** Executes `DELETE FROM extracted_iocs WHERE article_id NOT IN...` to prevent dangling IOCs from consuming space when their parent articles are deleted.
* **Dialect Awareness:** Uses `engine.dialect.name` to detect the underlying database. 
    * If PostgreSQL, it runs `VACUUM ANALYZE` to rebuild query planners.
    * If SQLite, it safely runs `PRAGMA optimize` to optimize the internal B-tree structures without attempting to lock the entire WAL file during a live session.

---

## 4. The Master Cron Scheduler

The engine utilizes the `schedule` library to dictate the operational tempo, spinning in a `while True:` loop checking the clock every 1 second.

### Scheduled Job Roster
1.  **Threaded Daemons:** Instantiates the Daily Report Generator (`start_report_scheduler`) as a background `daemon=True` thread.
2.  **Every 5 Minutes (Hyper-Tactical):**
    * `fetch_regional_hazards()`: Syncs NWS/SPC physical weather threats.
    * `fetch_cloud_outages()`: Scans major cloud providers for down APIs.
    * `run_telemetry_sync()`: Polls the ODIN power grid, RIPE Stat BGP routes, and IODA ISP outages.
3.  **Every 15 Minutes (Operational):**
    * `fetch_feeds()`: Executes the low-CPU Async OSINT intelligence pull.
4.  **Every 60 Minutes (Housekeeping):**
    * `run_database_maintenance()`: Executes the aggressive garbage collection routines.
5.  **Every 6 Hours (Strategic):**
    * `job_cisa()`: Syncs the CISA Known Exploited Vulnerabilities catalog.

**Boot Sequence:** The script manually fires the primary ingestion functions sequentially upon startup (`Worker Boot`) before entering the `schedule.run_pending()` loop, guaranteeing that fresh data is available the moment the container spins up.
