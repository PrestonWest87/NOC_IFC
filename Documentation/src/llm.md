# Enterprise Architecture & Functional Specification: `src/database.py` (Extended Table & Function Deep Dive)

## 1. Executive Overview

This document serves as an exhaustive, function-by-function and table-by-table reference guide for `src/database.py`. It is designed to allow onboarding engineers to immediately understand the exact purpose, schema design, and operational role of every data structure within the Intelligence Fusion Center (IFC).

---

## 2. Engine Initialization & Concurrency Functions

The module begins by establishing the core SQLAlchemy connection, forcing an optimized SQLite deployment path to guarantee zero-configuration edge capabilities.

### `set_sqlite_pragma(dbapi_connection, connection_record)`
* **Functionality:** An event listener attached to the SQLAlchemy engine via the `@event.listens_for(engine, "connect")` decorator. It intercepts every new connection to the database and injects low-level SQLite C-library configurations.
* **Operational Impact:**
    * `PRAGMA journal_mode=WAL`: Enables Write-Ahead Logging, decoupling read locks from write locks. Essential for allowing the Streamlit UI to read dashboards while background workers concurrently insert thousands of CVEs.
    * `PRAGMA cache_size=-64000`: Allocates 64MB of RAM to the database cache, dramatically reducing disk I/O for frequent queries.
    * `PRAGMA temp_store=MEMORY` & `PRAGMA mmap_size=3000000000`: Forces temporary tables and memory-mapped files into RAM, executing complex `GROUP BY` and geospatial queries instantly.

---

## 3. Core System & IAM (Identity and Access Management) Models

These ORM classes define the operational state of the application and control user authorization.

### `User` (Table: `users`)
* **Purpose:** Manages human operator identities and authentication state.
* **Key Fields:**
    * `password_hash`: Stores bcrypt-hashed credentials.
    * `session_token`: Stores persistent UUIDs for browser cookie validation.
    * `role`: A foreign-key equivalent linking the user to a specific RBAC profile.

### `Role` (Table: `roles`)
* **Purpose:** The architectural backbone of the application's Role-Based Access Control.
* **Key Fields:**
    * `allowed_pages` (JSON): An array of strings defining exactly which top-level Streamlit modules the role can render (e.g., `["🌐 Operational Dashboard", "🚨 Crime Intelligence"]`).
    * `allowed_actions` (JSON): An array of granular permission strings enabling specific tabs and UI buttons (e.g., `"Action: Dispatch Exec Report"`).

### `SystemConfig` (Table: `system_config`)
* **Purpose:** A singleton table holding global variables required by background services and the LLM abstraction layer.
* **Key Fields:**
    * `llm_endpoint`, `llm_api_key`, `llm_model_name`: Hot-swappable connection strings for the universal LLM engine.
    * `tech_stack`: A user-defined string of internal vendors (e.g., "SolarWinds, Cisco") cross-referenced by the AI Auditor against new CVEs.
    * `rolling_summary`: Caches the expensive LLM-generated shift briefing to prevent API spam.
    * `smtp_server` -> `smtp_enabled`: Stores the mailing credentials used to autonomously dispatch Outlook HTML SitReps.

### `Keyword` & `FeedSource` (Tables: `keywords`, `feed_sources`)
* **Purpose:** Defines the ingestion scope for the Cyber Threat Intelligence pipelines.
* **Key Fields:** `FeedSource.url` targets the specific RSS endpoint, while `Keyword.weight` determines the numeric value added to an article's threat score if the `Keyword.word` is detected via Regex.

### `SavedReport` (Table: `saved_reports`)
* **Purpose:** A shared organizational repository storing the raw Markdown of deep-dive intelligence reports synthesized via the Map-Reduce LLM engine.

---

## 4. Intelligence & Threat Models

These tables manage the normalized Open-Source Intelligence (OSINT) required for situational awareness.

### `Article` (Table: `articles`)
* **Purpose:** The primary storage unit for all incoming cyber, physical, and geopolitical threat intelligence.
* **Key Fields:**
    * `category`: The specific operational domain assigned by the high-speed Regex triage engine.
    * `score`: The deterministic sum of matched keywords, dictating dashboard prioritization.
    * `ai_bluf`: The LLM-generated Bottom Line Up Front.
    * `is_pinned`: An indexed boolean allowing operators to manually force critical articles to the top of the Operational Dashboard.

### `ExtractedIOC` (Table: `extracted_iocs`)
* **Purpose:** Stores atomized Indicators of Compromise (IPv4, SHA256, Domains) parsed from `Article` text, establishing a relational link for the Threat Hunting UI.

### `CveItem` (Table: `cve_items`)
* **Purpose:** A synchronized, local mirror of the CISA Known Exploited Vulnerabilities catalog.
* **Key Fields:** `cve_id`, `vendor`, `product`. Indexed heavily to allow the AI Security Auditor to rapidly cross-reference emerging exploits offline.

### `DailyBriefing` (Table: `daily_briefings`)
* **Purpose:** Acts as a historical archive for the daily, autonomous Map-Reduce situational reports generated at 06:00 AM.

---

## 5. Grid, Weather, & AIOps Models

These tables construct the physical ontology of the organization and house the raw network telemetry utilized by the RCA deterministic engine.

### `MonitoredLocation` (Table: `monitored_locations`)
* **Purpose:** Defines the exact geospatial locations of critical NOC infrastructure (Data Centers, Cellular Towers).
* **Key Fields:** `lat`, `lon` (for Haversine radius calculations), and `priority` (an integer denoting criticality).

### `CrimeIncident` (Table: `crime_incidents`)
* **Purpose:** The storage target for the `crime_worker.py` daemon. It holds kinetic, real-world events (arson, theft) extracted from local law enforcement APIs.
* **Key Fields:** `distance_miles` guarantees the incident occurred within a strict geofence of HQ, while `severity` triggers UI alarms.

### `RegionalHazard` & `RegionalOutage` (Tables: `regional_hazards`, `regional_outages`)
* **Purpose:** Stores active polygons and geographic warnings generated by the Storm Prediction Center and NWS (e.g., Wildfires, Tornados). The AIOps engine checks these geometries against `MonitoredLocation` coordinates to verify physical kinetic impacts.

### `CloudOutage` & `BgpAnomaly` (Tables: `cloud_outages`, `bgp_anomalies`)
* **Purpose:** Tracks external macro-scale digital failures (e.g., AWS Region outages, Carrier Route Leaks). Used by the AIOps engine to determine if internal alarms are actually upstream dependency failures.

### `SolarWindsAlert` (Table: `solarwinds_alerts`)
* **Purpose:** The heaviest table in the database. It stores the raw JSON payloads received by the FastAPI webhook endpoint.
* **Key Fields:** * `raw_payload`: Stores the unparsed ITSM JSON for ML retraining.
    * `mapped_location`: The physical site name assigned by the heuristic mapping engine.
    * `is_correlated`: An indexed boolean allowing the correlation engine to rapidly skip alerts that have already been packaged into an incident cluster.

### `TimelineEvent` (Table: `timeline_events`)
* **Purpose:** A lightweight, chronological ledger tracking system events and node state changes, rendered as the scrolling ticker tape on the Active Incident Board.

---

## 6. Initialization & Data Seeding

### `init_db()`
* **Functionality:** A self-healing bootstrap sequence executed immediately upon application start.
* **Operational Flow:**
    1.  **Race Condition Mitigation:** Executes `time.sleep(random.uniform(0.1, 1.5))` to prevent database lock collisions when multiple Docker microservices spin up simultaneously.
    2.  **Schema Generation:** Uses `Base.metadata.create_all(bind=engine)` to natively build the SQLite tables if they do not exist.
    3.  **RBAC Auto-Healing:** Hardcodes the `all_pages` and `all_actions` arrays utilizing the new descriptive nomenclature. It checks for the existence of the `admin` and `analyst` roles. If they exist, it *forcefully overwrites* their JSON arrays to ensure legacy databases are automatically upgraded to support the new Executive Dashboard and Crime Intelligence features.
    4.  **Admin Seeding:** If the `User` table is entirely empty, it generates a default `admin` user with a securely hashed bcrypt password.
    5.  **Transactional Integrity:** Operates within a strict `try...except...finally` block, executing `session.rollback()` on failure and `session.close()` to ensure the connection pool is not depleted during bootstrap.
