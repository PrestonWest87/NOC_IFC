# Enterprise Architecture & Functional Specification: `src/database.py`

## 1. Executive Overview

This document serves as an exhaustive, table-by-table reference guide for `src/database.py`. It is designed to allow onboarding engineers to immediately understand the exact purpose, schema design, and operational role of every data structure within the Intelligence Fusion Center (IFC).

The database schema supports the **Service-Oriented Architecture (SOA)**, the **AI Shift Logbook**, the **Internal Asset Risk Matrix**, and the **24/7 Tiered Alert Escalation Engine**. It utilizes a heavily optimized SQLite deployment path for zero-configuration edge capabilities while supporting PostgreSQL for enterprise clusters.

---

## 2. Engine Configuration & Concurrency

The module establishes the core SQLAlchemy connection, forcing an optimized SQLite deployment path.

### `set_sqlite_pragma(dbapi_connection, connection_record)`

An event listener attached via `@event.listens_for(engine, "connect")`. Intercepts every new connection and injects low-level SQLite C-library configurations.

**Parameters:**
- `dbapi_connection`: Raw DB-API 2.0 connection object
- `connection_record`: SQLAlchemy connection record

**Pragmas Applied:**

| Pragma | Value | Purpose |
|--------|-------|---------|
| `journal_mode` | `WAL` | Write-Ahead Logging enables concurrent reads during write operations |
| `synchronous` | `NORMAL` | Balances durability vs. performance for WAL mode |
| `cache_size` | `-16000` | 16MB cache (negative = kibibytes) for reduced disk I/O |
| `temp_store` | `MEMORY` | Forces temp tables into RAM for faster GROUP BY / sorting |
| `mmap_size` | `268435456` | 256MB memory-mapped I/O for rapid index scans |

### Connection Args

| Arg | Value | Purpose |
|-----|-------|---------|
| `check_same_thread` | `False` | Enables multi-container concurrent SQLite access |
| `timeout` | `30` | Connection wait timeout in seconds |

### `init_db()`

Database initialization routine with schema creation, silent migrations, and seed data.

**Parameters:** None

**Returns:** None

**Execution Flow:**
1. **Startup Delay:** Sleeps 0.1-1.5 seconds to mitigate Docker compose race conditions
2. **Schema Creation:** `Base.metadata.create_all(bind=engine)` creates all ORM-defined tables
3. **Silent Migrations:** Attempts ALTER TABLE statements for schema evolution (all failures pass silently) covering: `solarwinds_alerts` (`is_ticketed`, `is_dispatched`), `roles` (`allowed_site_types`), `monitored_locations` (`district`, `under_maintenance`, `maintenance_etr`, `maintenance_reason`, `last_auto_ticket`, `last_escalation_ticket`, `last_auto_dispatch`, `last_escalation_dispatch`, `status_modified_by`, `status_modified_at`), `shift_logs` (`author_role`, `is_deleted`), `system_config` (`baseline_override_cyber`, `baseline_override_phys`, `unified_brief`, `unified_brief_time`, `last_global_risk`, `last_internal_risk`, `last_risk_alert_time`), `users` (`default_shift`), `crime_incidents` (`is_alert_dispatched`), and `user_weather_prefs` table creation
4. **Seed Data:**
   - Creates or updates `admin` role with ALL_POSSIBLE_PAGES and ALL_POSSIBLE_ACTIONS
   - Creates or updates `analyst` role (all pages except "Settings & Admin")
   - Creates default `admin` user (password: `admin123`, hashed with bcrypt)

---

## 3. Database Model Reference

### 3.1 Core System & IAM Models

#### `User` (Table: `users`)

Manages human operator identities, authentication, and profile metadata.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment primary key |
| `username` | String (unique) | Login username |
| `password_hash` | String | bcrypt-hashed password |
| `role` | String | RBAC role name (e.g., "admin", "analyst") |
| `session_token` | String (nullable) | UUID for cookie-based auth persistence |
| `full_name` | String (nullable) | Display name for UI and shift logs |
| `job_title` | String (nullable) | Professional title |
| `contact_info` | String (nullable) | Contact details |
| `default_shift` | String | Default shift assignment ("Morning", "Afternoon", "Night", "No Shift") |

#### `Role` (Table: `roles`)

RBAC profiles defining functional permissions.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `name` | String (unique) | Role name |
| `allowed_pages` | JSON | Array of page names user can access |
| `allowed_actions` | JSON | Array of granular action permissions |
| `allowed_site_types` | JSON | Geographic/operational site restrictions |

#### `SystemConfig` (Table: `system_config`)

Singleton table for global application configuration.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `llm_endpoint` | String | LLM API base URL (default: `https://api.openai.com/v1`) |
| `llm_api_key` | String | LLM API key |
| `llm_model_name` | String | Model identifier (default: `gpt-4o-mini`) |
| `is_active` | Boolean | LLM enabled flag |
| `tech_stack` | Text | Comma-separated internal tech stack |
| `monitored_asns` | String | Comma-separated BGP ASNs (default: `AS701, AS7922, AS3356`) |
| `rolling_summary` | Text (nullable) | Cached AI rolling summary |
| `rolling_summary_time` | DateTime (nullable) | Rolling summary timestamp |
| `smtp_server` | String (nullable) | SMTP hostname |
| `smtp_port` | Integer | SMTP port (default: 587) |
| `smtp_username` | String (nullable) | SMTP auth user |
| `smtp_password` | String (nullable) | SMTP auth password |
| `smtp_sender` | String (nullable) | From address |
| `smtp_recipient` | String (nullable) | Default recipient |
| `smtp_enabled` | Boolean | SMTP relay enabled |
| `baseline_override_cyber` | Float | Cyber baseline override |
| `baseline_override_phys` | Float | Physical baseline override |
| `unified_brief` | Text (nullable) | Cached AI unified brief |
| `unified_brief_time` | DateTime (nullable) | Unified brief timestamp |
| `last_global_risk` | String (nullable) | Last global risk level |
| `last_internal_risk` | String (nullable) | Last internal risk level |
| `last_risk_alert_time` | DateTime (nullable) | Last risk alert timestamp |

### 3.2 Internal Asset & Risk Models

#### `SoftwareAsset` (Table: `software_assets`)

Internal software inventory for OSINT cross-referencing.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `name` | String | Software name |
| `last_updated` | DateTime | Last modification timestamp |

#### `HardwareAsset` (Table: `hardware_assets`)

Internal hardware inventory with OS, vulnerability, and risk details.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `ip_address` | String | Primary IP (indexed) |
| `asset_name` | String (nullable) | Friendly name |
| `host_type` | String (nullable) | Device classification |
| `ip_addresses` | Text (nullable) | All associated IPs |
| `operating_system` | String (nullable) | OS name |
| `os_architecture` | String (nullable) | OS architecture |
| `os_family` | String (nullable) | OS family |
| `os_product` | String (nullable) | OS product name |
| `os_vendor` | String (nullable) | OS vendor |
| `os_version` | String (nullable) | OS version |
| `instances` | Integer | Total vulnerability instances |
| `critical_instances` | Integer | Critical severity instances |
| `severe_instances` | Integer | Severe severity instances |
| `moderate_instances` | Integer | Moderate severity instances |
| `vulnerabilities` | Integer | Total vulnerability count |
| `critical_vulnerabilities` | Integer | Critical severity count |
| `severe_vulnerabilities` | Integer | Severe severity count |
| `moderate_vulnerabilities` | Integer | Moderate severity count |
| `exploit_count` | Integer | Active exploit references |
| `malware_count` | Integer | Malware association count |
| `raw_risk_score` | Float | Unadjusted risk score |
| `risk_score` | Float | Computed CIS risk score |
| `last_updated` | DateTime | Last modification timestamp |

#### `InternalRiskSnapshot` (Table: `internal_risk_snapshots`)

Point-in-time internal risk calculations for trend analysis.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `timestamp` | DateTime | Snapshot time |
| `score` | Float | CIS risk score (-8 to +8) |
| `risk_level` | String | GREEN/BLUE/YELLOW/ORANGE/RED |
| `total_assets` | Integer | Total tracked assets |
| `total_osint_hits` | Integer | Total OSINT correlations |
| `critical_osint_hits` | Integer | Critical severity hits |
| `hw_data_json` | Text | Serialized hardware risk data |
| `sw_data_json` | Text | Serialized software risk data |

### 3.3 Tactical Operations & Logging Models

#### `ShiftLogEntry` (Table: `shift_logs`)

Chronological ledger for the AI Shift Logbook.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `analyst` | String | Author username |
| `author_role` | String | Role-based isolation |
| `shift_date` | DateTime | Shift date |
| `shift_period` | String | "Morning" / "Afternoon" / "Night" |
| `content` | Text | Log entry content |
| `created_at` | DateTime | Creation timestamp |
| `is_deleted` | Boolean | Soft-delete flag |

#### `SavedReport` (Table: `saved_reports`)

User-generated intelligence reports.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `title` | String | Report title |
| `author` | String | Creator username |
| `content` | Text | Markdown content |
| `created_at` | DateTime | Creation timestamp |

#### `DailyBriefing` (Table: `daily_briefings`)

AI-synthesized daily fusion reports.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `report_date` | DateTime (unique) | Report date |
| `content` | Text | Markdown content |
| `created_at` | DateTime | Creation timestamp |

#### `DailyThreatScore` (Table: `daily_threat_scores`)

Historical threat scoring for baseline deviation analysis.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `record_date` | DateTime (unique) | Date of record |
| `cyber_points` | Float | Cyber CIS score |
| `physical_points` | Float | Physical CIS score |
| `cyber_baseline` | Float | Cyber baseline |
| `physical_baseline` | Float | Physical baseline |

### 3.4 OSINT & Threat Intelligence Models

#### `Article` (Table: `articles`)

Primary storage for RSS threat intelligence.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `title` | String | Article title |
| `link` | String (unique) | Source URL |
| `summary` | Text | Article summary |
| `published_date` | DateTime | Publication time |
| `source` | String | Feed source name |
| `score` | Float | ML/Regex threat score (0-100) |
| `category` | String | Assigned threat category |
| `keywords_found` | JSON | Matched keywords |
| `is_bubbled` | Boolean | Auto-flagged for attention |
| `story_group` | String (nullable) | Story grouping identifier |
| `human_feedback` | Integer | 0=unreviewed, 1=dismiss, 2=keep |
| `ai_bluf` | Text (nullable) | AI-generated BLUF |
| `is_pinned` | Boolean | Operator pinned |

#### `ExtractedIOC` (Table: `extracted_iocs`)

Indicators of Compromise extracted from articles.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `article_id` | Integer | Source article FK |
| `indicator_type` | String | IOC type (IPv4, SHA256, CVE, etc.) |
| `indicator_value` | String | The indicator |
| `context` | Text (nullable) | Surrounding text |
| `detected_at` | DateTime | Extraction time |

#### `CveItem` (Table: `cve_items`)

Local mirror of the CISA Known Exploited Vulnerabilities catalog.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `cve_id` | String (unique) | CVE identifier |
| `vendor` | String | Affected vendor |
| `product` | String | Affected product |
| `vulnerability_name` | String | Vulnerability name |
| `date_added` | DateTime | KEV catalog date |
| `description` | Text | Vulnerability description |
| `required_action` | Text | CISA-required action |
| `due_date` | String | Remediation due date |

#### `FeedSource` (Table: `feed_sources`)

RSS/Atom feed configuration.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `url` | String (unique) | Feed URL |
| `name` | String | Display name |
| `is_active` | Boolean | Enabled flag |

#### `Keyword` (Table: `keywords`)

Scored keywords for threat scoring.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `word` | String (unique) | Keyword text |
| `weight` | Integer | Scoring weight |

### 3.5 Kinetic & Physical Threat Models

#### `CrimeIncident` (Table: `crime_incidents`)

Local law enforcement CAD data.

| Field | Type | Description |
|-------|------|-------------|
| `id` | String (PK) | MD5 hash dedup key |
| `category` | String | FBI UCR category |
| `raw_title` | String | Incident description |
| `timestamp` | DateTime | Incident time |
| `distance_miles` | Float | Distance from HQ |
| `severity` | String | Critical/High/Medium/Low |
| `lat` | Float | Latitude |
| `lon` | Float | Longitude |
| `is_alert_dispatched` | Boolean | SMS alert sent |

#### `RegionalHazard` (Table: `regional_hazards`)

NWS weather alerts.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `hazard_id` | String (unique) | NWS alert ID |
| `hazard_type` | String | Event type (Tornado, Flood, etc.) |
| `severity` | String | Severity level |
| `title` | String | Headline |
| `description` | Text | Full description |
| `location` | String | Affected area |
| `updated_at` | DateTime | Last update |

### 3.6 Infrastructure & Telemetry Models

#### `MonitoredLocation` (Table: `monitored_locations`)

Geospatial tracking of NOC facilities.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `name` | String (unique) | Facility name |
| `lat` | Float | Latitude |
| `lon` | Float | Longitude |
| `loc_type` | String | Facility type (Data Center, Substation, etc.) |
| `district` | String | Operational district |
| `priority` | Integer | Criticality (1-5) |
| `current_spc_risk` | String | Latest SPC risk level |
| `last_updated` | DateTime | Last modification time |
| `under_maintenance` | Boolean | Maintenance window active |
| `maintenance_etr` | DateTime (nullable) | Estimated restoration |
| `maintenance_reason` | Text (nullable) | Reason for maintenance |
| `last_auto_ticket` | DateTime (nullable) | Last auto-ticket time |
| `last_escalation_ticket` | DateTime (nullable) | Last escalation time |
| `last_auto_dispatch` | DateTime (nullable) | Last auto-dispatch time |
| `last_escalation_dispatch` | DateTime (nullable) | Last escalation dispatch |
| `status_modified_by` | String (nullable) | Last modifier user |
| `status_modified_at` | DateTime (nullable) | Last modification time |

#### `CloudOutage` (Table: `cloud_outages`)

Cloud provider status tracking.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `provider` | String | Provider name |
| `service` | String | Affected service |
| `title` | String | Incident title |
| `description` | Text | Details |
| `link` | String | Status page URL |
| `is_resolved` | Boolean | Resolution status |
| `updated_at` | DateTime | Last update |

#### `SolarWindsAlert` (Table: `solarwinds_alerts`)

ITSM webhook alert storage.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `event_type` | String | Alert type |
| `severity` | String | Severity level |
| `node_name` | String | Device hostname |
| `ip_address` | String | Device IP |
| `status` | String | Alert status |
| `sw_timestamp` | String | SolarWinds timestamp |
| `details` | Text | Alert details |
| `node_link` | String | SolarWinds node link |
| `raw_payload` | JSON | Original payload |
| `mapped_location` | String | Physical site mapping |
| `received_at` | DateTime | Ingestion time |
| `resolved_at` | DateTime (nullable) | Resolution time |
| `is_dispatched` | Boolean | Ticket dispatched |
| `is_correlated` | Boolean | RCA cluster assigned |
| `is_ticketed` | Boolean | Remedyforce ticket created |
| `device_type` | String | Heuristic classification |
| `event_category` | String | Event category |
| `ai_root_cause` | Text (nullable) | AI-generated cause |

#### `BgpAnomaly` (Table: `bgp_anomalies`)

RIPE BGP routing anomaly tracking.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `asn` | String | Affected ASN |
| `event_type` | String | Anomaly type |
| `description` | Text | Details |
| `detected_at` | DateTime | Detection time |
| `is_resolved` | Boolean | Resolution status |

#### `RegionalOutage` (Table: `regional_outages`)

Power grid and ISP outage tracking.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `outage_type` | String | Power / ISP |
| `provider` | String | Data source (ORNL, IODA) |
| `description` | Text | Details |
| `affected_area` | String | Geographic area |
| `lat` | Float (nullable) | Center latitude |
| `lon` | Float (nullable) | Center longitude |
| `radius_km` | Float | Impact radius |
| `detected_at` | DateTime | Detection time |
| `is_resolved` | Boolean | Resolution status |

### 3.7 SIEM & Event Models

#### `ElasticEvent` (Table: `elastic_events`)

SIEM event cache from Elasticsearch.

| Field | Type | Description |
|-------|------|-------------|
| `id` | String (PK) | Elastic document _id |
| `timestamp` | DateTime | Event timestamp |
| `index_name` | String | Source Elastic index |
| `severity` | String | Mapped severity |
| `message` | String | Event message |
| `source_ip` | String (nullable) | Source IP |
| `event_category` | String (nullable) | Event category |

#### `TimelineEvent` (Table: `timeline_events`)

Operational timeline for the AIOps board.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `timestamp` | DateTime | Event time |
| `source` | String | Source module |
| `event_type` | String | Alert / Resolution |
| `message` | String | Event description |

### 3.8 Geospatial & User Preference Models

#### `GeoJsonCache` (Table: `geojson_cache`)

Cached weather GeoJSON for map rendering.

| Field | Type | Description |
|-------|------|-------------|
| `feed_name` | String (PK) | Feed identifier |
| `data` | JSON | GeoJSON payload |
| `updated_at` | DateTime | Cache timestamp |

#### `UserWeatherPreference` (Table: `user_weather_prefs`)

User-specific weather alert subscriptions.

| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer (PK) | Auto-increment |
| `username` | String | User identifier |
| `alert_type` | String | NWS event type |

---

## 4. Engine Configuration Summary

| Function | Signature | Purpose |
|----------|-----------|---------|
| `init_db` | `() -> None` | Schema creation, silent migrations, seed data |
| `set_sqlite_pragma` | `(dbapi_connection, connection_record) -> None` | Sets WAL, cache, temp_store, mmap_size |

---

## 5. Seed Data Actions

### Admin Role
- **Pages:** All 8 pages (Global Dashboards through Settings & Admin)
- **Actions:** All actions including Pin Articles, Train ML Model, Boost Threat Score, Trigger AI Functions, Manually Sync Data, Dispatch Exec Report, Submit Shift Log, Dispatch RCA Tickets, Manage Site Maintenance, all sub-tab access

### Analyst Role
- **Pages:** All pages except "Settings & Admin"
- **Actions:** Same full action set as admin

### Default Admin User
- **Username:** `admin`
- **Password:** `admin123` (bcrypt-hashed)
- **Role:** `admin`

---

## 6. API Citations

| API / Service | Purpose | Documentation |
|---------------|---------|---------------|
| SQLAlchemy | ORM | https://docs.sqlalchemy.org/ |
| SQLite | Database | https://www.sqlite.org/docs.html |
| bcrypt | Password hashing | https://pypi.org/project/bcrypt/ |
