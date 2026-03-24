# Enterprise Architecture & Data Dictionary: `src/database.py` *(Updated)*

## 1. Executive Overview

The `src/database.py` module is the **Data Persistence and ORM Foundation** of the Intelligence Fusion Center (IFC). In its latest architectural iteration, this module has been heavily refactored to prioritize **High-Throughput Concurrency** and **Read-Optimized Indexing** for edge deployments.

To maximize performance and deployment simplicity in restricted environments, the engine now strictly enforces an optimized file-based SQLite configuration. The Object-Relational Mapping (ORM) models have also been expanded to support the new Kinetic Crime Tracking and Executive Dashboard features, with strategic indexing to prevent database locks during massive, asynchronous telemetry ingestion bursts.

---

## 2. Engine Architecture & Concurrency Optimization

The database engine has been aggressively tuned for edge-compute hardware via specific SQLite PRAGMA commands, transforming it into a high-concurrency datastore capable of handling parallel background worker ingestion alongside rapid UI rendering.

### 2.1 Enforced SQLite Configuration
The system explicitly overrides external `DATABASE_URL` injections to guarantee SQLite execution (`sqlite:////app/data/noc_fusion.db`). This ensures zero-config deployments and guarantees the application utilizes the following high-performance connection arguments (`check_same_thread=False`).

### 2.2 Memory & Concurrency Optimization (PRAGMA Injections)
Using an `@event.listens_for(engine, "connect")` decorator, the engine injects five critical PRAGMA commands upon every connection:
* **Write-Ahead Logging (`journal_mode=WAL`):** Bypasses traditional file-locking, allowing background workers to write telemetry simultaneously while the Streamlit UI performs heavy dashboard reads.
* **Asynchronous Sync (`synchronous=NORMAL`):** Relaxes strict disk-sync constraints to drastically speed up bulk inserts (e.g., pulling thousands of KEVs or RSS articles).
* **RAM Caching (`cache_size=-64000`):** Dedicates a massive 64MB of RAM specifically to the DB cache, accelerating rapid UI reloads and pagination.
* **In-Memory Temp Storage (`temp_store=MEMORY`):** Forces complex `.filter()` queries and temporary table operations into RAM rather than writing to disk.
* **Memory-Mapped I/O (`mmap_size=3000000000`):** Allocates up to 3GB for memory mapping, allowing the OS page cache to deliver lightning-fast data retrieval for the Executive Dashboards.

---

## 3. Object-Relational Mapping (ORM) & Strategic Indexing

To support the massive volume of data parsed by the IFC, the SQLAlchemy schema (`declarative_base()`) utilizes strategic indexing (`index=True`). This ensures heavy queries executed by the AIOps engine run in $O(\log n)$ time rather than triggering full table scans.

### 3.1 High-Frequency Filter Indexes
* **Booleans:** Fields that are constantly polled by background engines are strictly indexed. 
    * `SolarWindsAlert.is_correlated` (Polled rapidly by the AIOps Engine).
    * `CloudOutage.is_resolved` & `RegionalOutage.is_resolved` (Polled for active HUD rendering).
    * `Article.is_pinned` (Polled constantly by the RSS pagination engine).
* **Timestamps:** `published_date`, `updated_at`, `detected_at`, and `received_at` across various tables are indexed to support rapid temporal windowing (e.g., fetching only the last 7 days of crime telemetry).

### 3.2 Core Schema Domains
* **IAM (RBAC):** `User`, `Role`.
* **OSINT & Threat Intel:** `Article`, `FeedSource`, `Keyword`, `ExtractedIOC`, `CveItem`.
* **Physical & Cloud Infrastructure:** `MonitoredLocation`, `RegionalHazard`, `RegionalOutage`, `CloudOutage`, `BgpAnomaly`.
* **Kinetic Perimeter Threat (New):**
    * **`CrimeIncident`**: A newly introduced table storing heavily filtered, localized kinetic threats (arson, theft, violence). Indexed by `id` (incident number) and `timestamp` for rapid spatial/temporal bounding.
* **AIOps & Root Cause:** `SolarWindsAlert`, `TimelineEvent`.
* **System State:** `SystemConfig`, `DailyBriefing`, `SavedReport`.

---

## 4. Database Bootstrap & Auto-Healing (`init_db`)

The `init_db()` function executes a self-healing initialization sequence at application startup, heavily refactored for transactional safety and RBAC modernization.

### 4.1 Descriptive RBAC Auto-Healing
The Role-Based Access Control matrix was entirely rewritten to use highly descriptive, human-readable strings. The seed data now dynamically includes the newly engineered UI modules:
* **Pages Added:** `"📊 Executive Dashboard"`, `"🚨 Crime Intelligence"`.
* **Actions Added:** `"Action: Dispatch Exec Report"`.

**State Check & Override:** Upon startup, `init_db` queries the existing `admin` and `analyst` roles. Rather than just creating them if missing, it forcefully *overwrites* their `allowed_pages` and `allowed_actions` JSON arrays with the new descriptive syntax. This seamlessly "auto-heals" legacy databases to the new module layouts without requiring manual operator intervention.

### 4.2 Strict Session Lifecycle
The entire bootstrap sequence is wrapped in a strict `try...except...finally` block. If a database integrity error occurs during the seeding phase, `session.rollback()` is fired. Crucially, the `finally: session.close()` ensures the initialization connection is permanently released back to the pool, preventing memory leaks and race conditions upon Docker Compose spin-ups.
