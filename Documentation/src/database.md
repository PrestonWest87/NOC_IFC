# Enterprise Architecture & Functional Specification: `src/database.py` (Extended Table & Function Deep Dive)

## 1. Executive Overview

This document serves as an exhaustive, table-by-table reference guide for `src/database.py`. It is designed to allow onboarding engineers to immediately understand the exact purpose, schema design, and operational role of every data structure within the Intelligence Fusion Center (IFC).

In its latest architectural iteration, the database schema has been significantly expanded to support the **Service-Oriented Architecture (SOA)**, the **AI Shift Logbook**, and the **Internal Asset Risk Matrix**. It continues to utilize a heavily optimized SQLite deployment path to guarantee zero-configuration edge capabilities while supporting massive asynchronous I/O.

---

## 2. Engine Initialization & Concurrency Functions

The module establishes the core SQLAlchemy connection, forcing an optimized SQLite deployment path to support the hybrid concurrency model (Multiprocessing + Async).

### `set_sqlite_pragma(dbapi_connection, connection_record)`
* **Functionality:** An event listener attached to the SQLAlchemy engine via the `@event.listens_for(engine, "connect")` decorator. It intercepts every new connection and injects low-level SQLite C-library configurations.
* **Operational Impact:**
    * `PRAGMA journal_mode=WAL`: Enables Write-Ahead Logging. This is the critical component that allows the Streamlit UI to read dashboards concurrently while background daemons (like `crime_worker.py` or `webhook_listener.py`) execute heavy write operations without locking the database.
    * `PRAGMA cache_size=-16000`: Allocates 16MB of RAM to the database cache, reducing disk I/O for frequent queries while optimizing the memory footprint for edge-compute hardware.
    * `PRAGMA temp_store=MEMORY` & `PRAGMA mmap_size=268435456`: Forces temporary tables and memory-mapped files into RAM (capped at 256MB), executing complex `GROUP BY` and geospatial intersections instantly.

---

## 3. Core System & IAM (Identity and Access Management) Models

These ORM classes define the operational state of the application and control user authorization.

### `User` (Table: `users`)
* **Purpose:** Manages human operator identities, profile metadata, and authentication state.
* **Key Fields:**
    * `password_hash`: Stores bcrypt-hashed credentials.
    * `session_token`: Stores persistent UUIDs for browser cookie validation.
    * `role`: A foreign-key equivalent linking the user to a specific RBAC profile.
    * `full_name`, `job_title`, `contact_info`: Extended profile metadata utilized by the AI Shift Logbook and Report Builder for attribution.

### `Role` (Table: `roles`)
* **Purpose:** The architectural backbone of the application's Role-Based Access Control.
* **Key Fields:**
    * `allowed_pages` (JSON): An array defining exactly which top-level Streamlit modules the role can render.
    * `allowed_actions` (JSON): Granular permissions enabling specific tabs and UI buttons.
    * `allowed_site_types` (JSON): **[NEW]** An array (e.g., `["Data Center", "Substation"]`) that enforces geographic/operational RBAC, automatically filtering the AIOps Active Board and Regional Grid maps to only show authorized facilities for that specific role.

### `SystemConfig` (Table: `system_config`)
* **Purpose:** A singleton table holding global variables required by background services, the AIOps engine, and the LLM abstraction layer.
* **Key Fields:**
    * `llm_endpoint`, `llm_api_key`, `llm_model_name`: Hot-swappable connection strings for the universal LLM engine.
    * `smtp_server`, `smtp_recipient`, `smtp_enabled`: Stores the mailing credentials used to autonomously dispatch Outlook HTML SitReps and RCA Tickets.
    * `baseline_override_cyber`, `baseline_override_phys`: Locks custom threshold numbers for the Executive Threat Matrix, overriding the automatic 14-day moving average.
    * `unified_brief`, `rolling_summary`: Caches the expensive LLM-generated executive narratives to prevent API spam during UI auto-refreshes.

---

## 4. Internal Asset Risk & Inventory Models (NEW)

These tables support the new Internal Risk Dashboard, tracking the physical and digital footprint of the organization against external threats.

### `HardwareAsset` & `SoftwareAsset` (Tables: `hardware_assets`, `software_assets`)
* **Purpose:** Stores the internal inventory ingested via bulk CSV uploads. 
* **Key Fields (Hardware):** `name`, `ip_address`, `os_family`, `os_vendor`, `instances`, `raw_risk_score`. Provides the baseline attack surface for the AI Security Auditor to evaluate against incoming CISA KEVs.

### `InternalRiskSnapshot` (Table: `internal_risk_snapshots`)
* **Purpose:** Stores point-in-time calculations of the organization's internal vulnerability.
* **Key Fields:** `score`, `total_assets`, `total_osint_hits`, `critical_osint_hits`, and heavily compressed `hw_data_json` / `sw_data_json`. This enables the Executive Dashboard to render historical 14-day deviation trend lines without recalculating millions of rows.

---

## 5. Tactical Operations & Logging Models

### `ShiftLogEntry` (Table: `shift_logs`)
* **Purpose:** The chronological ledger powering the new AI Shift Logbook. Replaces external notepads.
* **Key Fields:**
    * `author_role`: Enforces role-based isolation of logs (e.g., TOC vs. NOC).
    * `shift_period`: Categorizes entries into "Morning" or "Afternoon/Evening" bounds.
    * `is_deleted`: A boolean flag enabling soft-delete auditing. 

### `SavedReport` & `DailyBriefing` (Tables: `saved_reports`, `daily_briefings`)
* **Purpose:** Shared organizational repositories storing the raw Markdown of deep-dive intelligence reports and autonomous Map-Reduce situational briefings.

---

## 6. Open-Source Intelligence (OSINT) & Kinetic Threat Models

These tables manage the normalized intelligence utilized for situational awareness.

### `Article` (Table: `articles`)
* **Purpose:** The primary storage unit for all incoming cyber, physical, and geopolitical threat intelligence.
* **Key Fields:** `category` (assigned by the Term-Hit Density regex engine), `score` (hybrid ML/Regex threat weight), `ai_bluf`, and `is_pinned`.

### `CveItem` (Table: `cve_items`)
* **Purpose:** A synchronized, local mirror of the CISA Known Exploited Vulnerabilities (KEV) catalog. Heavily indexed (`vendor`, `product`) to allow rapid offline cross-referencing against the `HardwareAsset` inventory.

### `CrimeIncident` (Table: `crime_incidents`)
* **Purpose:** The storage target for the `crime_worker.py` daemon.
* **Key Fields:** * `id`: A deterministic MD5 hash of the location and timestamp to prevent CAD API duplication.
    * `distance_miles`: The exact Haversine distance from HQ, driving the UI's 1-to-10 mile radius filters.

---

## 7. Grid, Weather, & AIOps Telemetry Models

These tables construct the physical ontology of the organization and house the raw network telemetry utilized by the AIOps RCA engine.

### `MonitoredLocation` (Table: `monitored_locations`)
* **Purpose:** Defines the exact geospatial locations of critical NOC infrastructure.
* **Key Fields:**
    * `lat`, `lon`, `priority`, `loc_type`, `district`.
    * **[NEW]** `under_maintenance`, `maintenance_etr`, `maintenance_reason`: Allows operators to geofence specific IT facilities with active maintenance windows, officially silencing AIOps correlation alarms while physical work is underway.

### `RegionalHazard` & `CloudOutage` (Tables: `regional_hazards`, `cloud_outages`)
* **Purpose:** Tracks external macro-scale physical and digital failures (e.g., Tornado Warnings, AWS Region outages). Used by the `EnterpriseAIOpsEngine` to determine if internal alarms are actually upstream dependency failures.

### `SolarWindsAlert` (Table: `solarwinds_alerts`)
* **Purpose:** The heaviest table in the database. Stores raw JSON payloads received by the FastAPI webhook endpoint.
* **Key Fields:**
    * `mapped_location`: The physical site name assigned by the heuristic mapping engine.
    * `is_correlated`: Allows the correlation engine to rapidly skip alerts that have already been packaged into an incident cluster.
    * **[NEW]** `is_dispatched`: A boolean flag tracking if the NOC has successfully generated and transmitted an ITSM RemedyForce ticket for this specific alert cluster.

---

## 9. Database Models (Complete Reference)

| Model | Table | Purpose |
|------|-------|---------|
| `User` | `users` | Human operator identities, profiles, authentication |
| `Role` | `roles` | RBAC profiles, allowed pages/actions/site_types |
| `SystemConfig` | `system_config` | Global variables, LLM/SMTP config, risk thresholds |
| `HardwareAsset` | `hardware_assets` | Internal hardware inventory |
| `SoftwareAsset` | `software_assets` | Internal software inventory |
| `InternalRiskSnapshot` | `internal_risk_snapshots` | Point-in-time internal risk calculations |
| `ShiftLogEntry` | `shift_logs` | Tactical operational logs |
| `SavedReport` | `saved_reports` | Custom intelligence reports |
| `DailyBriefing` | `daily_briefings` | AI-synthesized briefings |
| `Article` | `articles` | RSS threat intelligence articles |
| `ExtractedIOC` | `extracted_iocs` | Extracted IOCs from articles |
| `CveItem` | `cve_items` | CISA KEV catalog mirror |
| `CrimeIncident` | `crime_incidents` | Local law enforcement CAD data |
| `RegionalHazard` | `regional_hazards` | NWS weather alerts |
| `CloudOutage` | `cloud_outages` | Cloud service status |
| `BgpAnomaly` | `bgp_anomalies` | RIPE BGP routing anomalies |
| `SolarWindsAlert` | `solarwinds_alerts` | ITSM webhook alerts |
| `ElasticEvent` | `elastic_events` | SIEM event cache |
| `DailyThreatScore` | `daily_threat_scores` | Historical threat scoring |
| `MonitoredLocation` | `monitored_locations` | Geographic facility tracking |
| `GeoJsonCache` | `geojson_caches` | Weather GeoJSON cache |
| `UserWeatherPreference` | `user_weather_preferences` | User weather alert settings |
| `TimelineEvent` | `timeline_events` | Event timeline |
| `FeedSource` | `feed_sources` | RSS feed sources |
| `Keyword` | `keywords` | Scored keywords |

---

## 10. Engine Configuration

| Function | Signature | Purpose |
|----------|----------|---------|
| `init_db` | `() -> None` | Database initialization, schema creation, data seeding |
| `set_sqlite_pragma` | `(dbapi_connection, connection_record) -> None` | Sets WAL, cache_size, temp_store, mmap_size |

---

## 11. API Citations

| API / Service | Purpose | Documentation |
|---------------|---------|-------------|
| SQLAlchemy | ORM | https://docs.sqlalchemy.org/ |
| SQLite | Database | https://www.sqlite.org/docs.html |
| bcrypt | Password hashing | https://pypi.org/project/bcrypt/ |
