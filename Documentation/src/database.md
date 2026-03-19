# Enterprise Architecture & Data Dictionary: `src/database.py` *(Updated)*

## 1. Executive Overview

The `src/database.py` module is the **Data Persistence and ORM Foundation** of the Intelligence Fusion Center (IFC). In its latest architectural iteration, this module has been heavily refactored to prioritize **High-Throughput Concurrency** and **Read-Optimized Indexing**.

While it maintains its agnostic capability to run on both enterprise PostgreSQL clusters and file-based SQLite, the SQLite configuration has been aggressively tuned using PRAGMA statements to support simultaneous reads and writes. Furthermore, the Object-Relational Mapping (ORM) models have been updated with strategic indexing to prevent database locks during massive AIOps telemetry ingestion bursts.

---

## 2. Engine Architecture & Concurrency Optimization

The database engine dynamically configures its connection pooling and threading behavior based on the detected database dialect, with major upgrades to local execution.

### 2.1 SQLite WAL Mode (The Concurrency Upgrade)
Traditionally, SQLite locks the entire database file during a write operation, causing Streamlit UI threads to crash or hang if a background worker is saving telemetry. This limitation has been architecturally bypassed.
* **Timeout Buffer:** `connect_args={"timeout": 30}` ensures that if a momentary lock occurs, the UI will wait gracefully rather than throwing a `OperationalError`.
* **Write-Ahead Logging (WAL):** Using an `@event.listens_for(engine, "connect")` decorator, the engine injects three critical PRAGMA commands upon every connection:
    * `PRAGMA journal_mode=WAL`: Enables Write-Ahead Logging, allowing background workers to write data simultaneously while the UI reads data.
    * `PRAGMA synchronous=NORMAL`: Relaxes strict disk-sync constraints to drastically speed up bulk inserts (e.g., pulling thousands of KEVs).
    * `PRAGMA cache_size=-64000`: Dedicates a massive 64MB of RAM specifically to the SQLite cache, accelerating rapid UI reloads.

### 2.2 PostgreSQL Mode (Enterprise Scale)
* **Aggressive Recycling:** The connection pool configuration now utilizes `pool_recycle=1800` (30 minutes). This forces the SQLAlchemy engine to aggressively recycle connections, preventing stale connection drops caused by restrictive corporate firewalls or cloud load balancers.

---

## 3. Object-Relational Mapping (ORM) & Strategic Indexing

To support the massive volume of data parsed by the IFC, the SQLAlchemy schema (`declarative_base()`) has been upgraded with strategic indexing (`index=True`). This ensures that the heavy `.filter()` queries executed by the AIOps engine and UI dashboards run in $O(\log n)$ time rather than triggering full table scans.

### 3.1 High-Frequency Filter Indexes
* **Booleans:** Fields that are constantly polled by background engines are now strictly indexed. 
    * `SolarWindsAlert.is_correlated` (Polled every 5 seconds by the AIOps Engine).
    * `CloudOutage.is_resolved` & `RegionalOutage.is_resolved` (Polled for active HUD rendering).
    * `Article.is_pinned` (Polled constantly by the RSS pagination engine).
* **Timestamps:** `published_date`, `updated_at`, `detected_at`, and `received_at` across various tables are indexed to support rapid temporal windowing (e.g., fetching only the last 6 hours of telemetry for the AI Shift Brief).
* **Foreign Keys & Pivots:** `ExtractedIOC.article_id`, `SolarWindsAlert.mapped_location`, and categorical fields like `device_type` and `category` are indexed to support high-speed cross-referencing.

### 3.2 Core Schema Domains (Recap)
* **IAM (RBAC):** `User`, `Role`.
* **OSINT & Threat Intel:** `Article`, `FeedSource`, `Keyword`, `ExtractedIOC`, `CveItem`.
* **Physical & Cloud Infrastructure:** `MonitoredLocation`, `RegionalHazard`, `RegionalOutage`, `CloudOutage`, `BgpAnomaly`.
* **AIOps & Root Cause:** `SolarWindsAlert`, `TimelineEvent`, `NodeAlias`.
* **System State:** `SystemConfig`, `DailyBriefing`, `SavedReport`.

---

## 4. Database Bootstrap & Auto-Healing (`init_db`)

The `init_db()` function executes a self-healing initialization sequence at application startup, heavily refactored for transactional safety and RBAC modernization.

### 4.1 Transactional Migration Safety
When running on PostgreSQL, the raw SQL fallback migrations (like `ALTER TABLE`) are now executed inside an `engine.begin() as conn:` context manager. This ensures that the schema evolution commands are safely wrapped in an auto-committing transaction boundary.

### 4.2 Descriptive RBAC Auto-Healing
The Role-Based Access Control matrix was entirely rewritten in the application layer to use highly descriptive, human-readable strings (e.g., `"Tab: Threat Telemetry -> RSS Triage"` instead of `"tab_tt_rss"`).
* **State Check & Override:** Upon startup, `init_db` queries the existing `admin` and `analyst` roles. Rather than just creating them if they are missing, it forcefully *overwrites* their `allowed_pages` and `allowed_actions` JSON arrays with the new descriptive syntax. 
* **Benefit:** This "auto-heals" legacy databases, seamlessly migrating old cryptic permission arrays to the new standard without requiring operators to manually reconstruct their user roles.

### 4.3 Strict Session Lifecycle
The entire bootstrap sequence is wrapped in a strict `try...except...finally` block. If a database integrity error occurs during the seeding phase, `session.rollback()` is fired. Crucially, the `finally: session.close()` ensures the initialization connection is permanently released back to the pool, preventing memory leaks upon container deployment.
