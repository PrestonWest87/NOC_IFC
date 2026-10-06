# NOC Intelligence Fusion Center — Database Schema Reference

> **Source of truth:** `src/models/schema.py` (SQLAlchemy declarative models)
> **Engine:** SQLite via `DATABASE_URL`
> **Driver:** SQLAlchemy 2.x with `NullPool`
> **Last verified:** 2026-10-05

The mapped table names, column names, SQLAlchemy types, and nullability in this reference reflect the model metadata in `src/models/schema.py`.

---

## Table of Contents

1. [Entity-Relationship Overview](#1-entity-relationship-overview)
2. [Complete Table Reference](#2-complete-table-reference)
3. [Schema Evolution Strategy](#3-schema-evolution-strategy)
4. [Index Strategy](#4-index-strategy)
5. [Startup Migration and Bootstrap Sequence](#5-startup-migration-and-bootstrap-sequence)
6. [Key Design Decisions](#6-key-design-decisions)
7. [Data Retention Policies](#7-data-retention-policies)

---

## 1. Entity-Relationship Overview

Most operational relationships are logical rather than enforced foreign keys. The account-session, recovery-request/token, and account-audit tables declare SQLAlchemy foreign keys to users or recovery requests; `scheduler_job_config` and legacy name-based relationships do not.

The legacy ER diagram is conceptual: its `(FK→)` labels do not distinguish enforced constraints from logical joins. In particular, `users.role`, `user_weather_prefs.username`, and `extracted_iocs.article_id` are not SQL-enforced foreign keys; Section 6 lists the actual constraints.

```
┌─────────────────────┐       ┌─────────────────────┐
│        users         │       │        roles         │
│─────────────────────│       │─────────────────────│
│ id            (PK)  │       │ id            (PK)  │
│ username      (UQ)  │◄─ ─ ─ │ name          (UQ)  │
│ role (logical)      │       │ allowed_pages (JSON)│
│ session_token       │       │ allowed_actions     │
│ full_name           │       │ allowed_site_types  │
│ account_type        │       └─────────────────────┘
│ email (nullable)    │
│ email_verified_at   │
│ is_active           │
│ created_at          │
│ last_login_at       │
│ last_activity_at    │
│ job_title           │
│ contact_info        │
│ default_shift       │
└────────┬────────────┘       │     user_weather_    │
         │                    │       prefs           │
         │                    │─────────────────────│
         │                    │ id            (PK)  │
          │                    │ username (logical)   │
         │                    │ alert_type           │
         │                    └─────────────────────┘
         │
         │  .role = role.name
         │
         ├──── shift_logs.analyst  (user.username)
         ├──── shift_logs.author_role  (user.role)
         ├──── saved_reports.author  (user.username)
         └──── node_aliases.mapped_location_name
              (logical — node name → site)

┌─────────────────────┐       ┌─────────────────────┐
│     articles         │       │   extracted_iocs     │
│─────────────────────│       │─────────────────────│
│ id            (PK)  │◄─ ─ ─ │ article_id (logical)│
│ title               │       │ indicator_type       │
│ link          (UQ)  │       │ indicator_value      │
│ summary             │       │ context              │
│ published_date      │       │ detected_at          │
│ source              │       └─────────────────────┘
│ score               │
│ category            │       ┌─────────────────────┐
│ keywords_found(JSON)│       │   keyword_scoring     │
│ is_bubbled          │       │─────────────────────│
│ story_group         │       │ articles.score ←    │
│ human_feedback      │       │   keyword.weight     │
│ ai_bluf             │       └─────────────────────┘
│ is_pinned           │
└─────────────────────┘

┌─────────────────────┐       ┌─────────────────────┐
│ solarwinds_alerts    │       │  monitored_locations │
│─────────────────────│       │─────────────────────│
│ id            (PK)  │       │ id            (PK)  │
│ node_name           │       │ name          (UQ)  │──┐
│ mapped_location ────│─ ─ ─ ─│ lat                 │  │
│ is_dispatched       │       │ lon                 │  │
│ is_ticketed         │       │ loc_type            │  │
│ is_correlated       │       │ district            │  │
│ acknowledged_by     │       │ priority            │  │
│ dispatched_by       │       │ under_maintenance   │  │
│ ai_root_cause       │       │ status_modified_by  │  │
└─────────────────────┘       │ status_modified_at  │  │
                              │ last_auto_ticket    │  │
┌─────────────────────┐       │ last_escalation_*   │  │
│   timeline_events    │       └─────────────────────┘  │
│─────────────────────│                                  │
│ id            (PK)  │       ┌─────────────────────┐   │
│ source              │       │   node_aliases       │   │
│ event_type          │       │─────────────────────│   │
│ message             │       │ id            (PK)  │   │
│ timestamp           │       │ node_pattern        │   │
└─────────────────────┘       │ mapped_location_name│───┘
                              │ confidence_score    │   │
┌─────────────────────┐       │ is_verified         │   │
│   system_config      │       └─────────────────────┘   │
│─────────────────────│                                  │
│ id            (PK)  │  singleton row                   │
│ llm_* (endpoint,    │                                  │
│   api_key, model)   │                                  │
│ smtp_* (server,     │                                  │
│   port, user, pass, │                                  │
│   sender, rcpt,     │                                  │
│   enabled)          │                                  │
│ scoring_mode        │                                  │
│ *_override_*        │                                  │
│ unified_brief       │                                  │
│ rolling_summary     │                                  │
│ last_global_risk    │                                  │
│ last_internal_risk  │                                  │
│ alerted_eq_ids      │                                  │
└─────────────────────┘                                  │
                                                         │
┌─────────────────────┐  logical FK via name strings     │
│  crime_incidents     │  to monitored_locations          │
│─────────────────────│  (lat/lon proximity matching)    │
│ id            (PK)  │                                  │
│ category            │       ┌─────────────────────┐    │
│ raw_title           │       │   cve_items          │    │
│ timestamp           │       │─────────────────────│    │
│ severity            │       │ id            (PK)  │    │
│ lat / lon           │       │ cve_id        (UQ)  │    │
│ is_alert_dispatched │       │ vendor / product    │    │
└─────────────────────┘       │ date_added          │    │
                              └─────────────────────┘    │
┌─────────────────────┐                                  │
│   internal_risk_    │       ┌─────────────────────┐    │
│     snapshots       │       │  daily_threat_scores │    │
│─────────────────────│       │─────────────────────│    │
│ id            (PK)  │       │ id            (PK)  │    │
│ timestamp           │       │ record_date   (UQ)  │    │
│ score / risk_level  │       │ cyber/physical      │    │
│ total_assets        │       │   _points/_baseline │    │
│ hw_data_json        │       └─────────────────────┘    │
│ sw_data_json        │                                  │
└─────────────────────┘       ┌─────────────────────┐    │
                              │   daily_briefings    │    │
┌─────────────────────┐       │─────────────────────│    │
│ regional_hazards     │       │ id            (PK)  │    │
│─────────────────────│       │ report_date   (UQ)  │    │
│ id            (PK)  │       │ content             │    │
│ hazard_id     (UQ)  │       └─────────────────────┘    │
│ hazard_type         │                                  │
│ severity            │       ┌─────────────────────┐    │
│ updated_at          │       │   software_assets    │    │
└─────────────────────┘       │─────────────────────│    │
                              │ id            (PK)  │    │
┌─────────────────────┐       │ name          (UQ)  │    │
│ regional_outages     │       └─────────────────────┘    │
│─────────────────────│                                  │
│ id            (PK)  │       ┌─────────────────────┐    │
│ outage_type         │       │  hardware_assets     │    │
│ lat / lon           │       │─────────────────────│    │
│ is_resolved         │       │ id            (PK)  │    │
└─────────────────────┘       │ ip_address     (UQ) │    │
                              │ asset_name          │    │
┌─────────────────────┐       │ risk_score          │    │
│  cloud_outages       │       │ *_vulnerabilities   │    │
│─────────────────────│       └─────────────────────┘    │
│ id            (PK)  │                                  │
│ provider            │       ┌─────────────────────┐    │
│ is_resolved         │       │   elastic_events     │    │
│ updated_at          │       │─────────────────────│    │
└─────────────────────┘       │ id            (PK)  │ ← String PK!
                              │ timestamp           │    │
┌─────────────────────┐       │ severity            │    │
│  bgp_anomalies       │       │ source_ip           │    │
│─────────────────────│       └─────────────────────┘    │
│ id            (PK)  │                                  │
│ asn                 │       ┌─────────────────────┐    │
│ is_resolved         │       │   feed_sources       │    │
└─────────────────────┘       │─────────────────────│    │
                              │ id            (PK)  │    │
┌─────────────────────┐       │ url           (UQ)  │    │
│    saved_reports     │       │ is_active           │    │
│─────────────────────│       └─────────────────────┘    │
│ id            (PK)  │                                  │
│ author              │       ┌─────────────────────┐    │
│ created_at          │       │   geojson_cache      │    │
└─────────────────────┘       │─────────────────────│    │
                              │ feed_name     (PK)  │ ← String PK!
┌─────────────────────┐       │ data          (JSON)│    │
│     keywords         │       └─────────────────────┘    │
│─────────────────────│                                  │
│ id            (PK)  │                                  │
│ word          (UQ)  │                                  │
│ weight              │                                  │
└─────────────────────┘                                  │
```

### Logical Relationship Summary

| Source Table | Source Column | → | Target Table | Target Column | Nature |
|---|---|---|---|---|---|
| `users` | `role` | → | `roles` | `name` | Role-based access |
| `shift_logs` | `analyst` | → | `users` | `username` | Author tracking |
| `shift_logs` | `author_role` | → | `roles` | `name` | Role attribution |
| `saved_reports` | `author` | → | `users` | `username` | Author tracking |
| `extracted_iocs` | `article_id` | → | `articles` | `id` | IOC-to-article link |
| `solarwinds_alerts` | `mapped_location` | → | `monitored_locations` | `name` | Alert-to-site mapping |
| `node_aliases` | `mapped_location_name` | → | `monitored_locations` | `name` | Node name resolution |
| `user_weather_prefs` | `username` | → | `users` | `username` | Per-user preferences |
| `timeline_events` | `source` | → | *(various)* | *(various)* | Event origin tracking |

> **No `ON DELETE CASCADE`** exists. Orphaned `extracted_iocs` are cleaned up by the hourly DB maintenance job.

---

## 2. Complete Table Reference

Column types and nullability reflect the current SQLAlchemy mappings in `src/models/schema.py`. Defaults such as `utcnow`, `list`, and `dict` are client-side SQLAlchemy defaults unless explicitly identified as server defaults. The frozen legacy snapshot is `migrations/schema_v1.py`; revisions `20261002_0002` and `20261005_0003` add invitation revocation and alert dispatch-workflow state. Revision `20261005_0004` backfills legacy webhook alert site metadata. Other migration-only compatibility columns are described in Section 3.

### 2.1 `users` — User Accounts

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `username` | String | YES | — | YES (unique) | UNIQUE |
| `password_hash` | String | YES | — | — | bcrypt hash |
| `role` | String | YES | `"analyst"` | YES | Logical role name → `roles.name`; no SQL foreign key |
| `session_token` | String | YES | NULL | YES | Session tracking |
| `full_name` | String | YES | NULL | — | Display name |
| `job_title` | String | YES | NULL | — | Role description |
| `contact_info` | String | YES | NULL | — | Email/phone |
| `default_shift` | String | YES | `"No Shift"` | — | Shift assignment |
| `theme` | String | YES | `"standard"` | — | User-selected UI theme |
| `account_type` | String(20) | NO | `individual` | YES | `individual` or `display` |
| `email` | String(254) | YES | NULL | — | Optional; required for invitation-created individual accounts |
| `email_normalized` | String(254) | YES | NULL | Unique | Case-folded address; unique when present |
| `email_verified_at` | DateTime | YES | NULL | — | Only verified/approved emails are used for password reset |
| `is_active` | Boolean | NO | `True` | YES | Disabled accounts cannot authenticate |
| `created_at` | DateTime | NO | `utcnow` | — | Account creation time |
| `last_login_at` | DateTime | YES | NULL | YES | Last successful sign-in |
| `last_activity_at` | DateTime | YES | NULL | YES | Last authenticated activity; updated at most every five minutes |

### 2.2 `roles` — Role Definitions

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `name` | String | YES | — | YES (unique) | UNIQUE |
| `allowed_pages` | JSON | YES | — | — | Array of page names |
| `allowed_actions` | JSON | YES | `list` | — | Array of action strings |
| `allowed_site_types` | JSON | YES | `list` | — | Array of site type strings |

### 2.3 `saved_reports` — Report Library

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `title` | String | YES | — | YES | — |
| `author` | String | YES | — | — | username string |
| `content` | Text | YES | — | — | Full report body |
| `created_at` | DateTime | YES | `utcnow` | YES | — |

### 2.4 `feed_sources` — RSS Feed Registry

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `url` | String | YES | — | YES (unique) | UNIQUE |
| `name` | String | YES | — | — | Human-readable name |
| `is_active` | Boolean | YES | `True` | — | Enable/disable toggle |

### 2.5 `keywords` — Scoring Keyword Dictionary

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `word` | String | YES | — | YES (unique) | UNIQUE |
| `weight` | Integer | YES | `10` | — | 0–100 scoring weight |

> **Critical:** 70 keywords are seeded at init. `rescore_all_articles()` runs after every seed to rescale `articles.score`.

### 2.6 `system_config` — Singleton Configuration Store

| Column | Type | Nullable | Default | Index |
|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK |
| `llm_endpoint` | String | YES | `"https://api.openai.com/v1"` | — |
| `llm_api_key` | String | YES | `""` | — |
| `llm_model_name` | String | YES | `"gpt-4o-mini"` | — |
| `is_active` | Boolean | YES | `False` | — |
| `tech_stack` | Text | YES | `"SolarWinds, Cisco SD-WAN, Microsoft Office, Verizon, Cisco"` | — |
| `monitored_asns` | String | YES | `"AS701, AS7922, AS3356"` | — |
| `rolling_summary` | Text | YES | NULL | — |
| `rolling_summary_time` | DateTime | YES | NULL | — |
| `smtp_server` | String | YES | NULL | — |
| `smtp_port` | Integer | YES | `587` | — |
| `smtp_username` | String | YES | NULL | — |
| `smtp_password` | String | YES | NULL | — |
| `smtp_sender` | String | YES | NULL | — |
| `smtp_recipient` | String | YES | NULL | — |
| `smtp_enabled` | Boolean | YES | `False` | — |
| `baseline_override_cyber` | Float | YES | `0.0` | — |
| `baseline_override_phys` | Float | YES | `0.0` | — |
| `unified_brief` | Text | YES | NULL | — |
| `unified_brief_time` | DateTime | YES | NULL | — |
| `global_brief` | Text | YES | NULL | — |
| `global_brief_time` | DateTime | YES | NULL | — |
| `internal_brief` | Text | YES | NULL | — |
| `internal_brief_time` | DateTime | YES | NULL | — |
| `last_global_risk` | String | YES | NULL | — |
| `last_internal_risk` | String | YES | NULL | — |
| `last_risk_alert_time` | DateTime | YES | NULL | — |
| `sys_countermeasures` | Integer | YES | `3` | — |
| `net_countermeasures` | Integer | YES | `3` | — |
| `scoring_mode` | String | YES | `"auto"` | — |
| `cyber_criticality_override` | Integer | YES | `0` | — |
| `cyber_lethality_override` | Integer | YES | `0` | — |
| `physical_criticality_override` | Integer | YES | `0` | — |
| `physical_lethality_override` | Integer | YES | `0` | — |
| `internal_criticality_override` | Integer | YES | `0` | — |
| `internal_lethality_override` | Integer | YES | `0` | — |
| `global_risk_offset` | Integer | YES | `0` | — |
| `internal_risk_offset` | Integer | YES | `0` | — |
| `alerted_eq_ids` | Text | YES | `"[]"` | — |
| `alerted_wildfire_ids` | Text | YES | `"[]"` | — |
| `wildfire_proximity_state` | Text | YES | `"{}"` | — |
| `llm_context_window` | Integer | YES | `128000` | — |
| `public_app_url` | String | YES | `"http://localhost:8501"` | — |
| `failed_login_alert_enabled` | Boolean | NO | `False` | — |
| `failed_login_alert_recipients` | Text | NO | `""` | — |
| `failed_login_alert_threshold` | Integer | NO | `5` | — |
| `failed_login_alert_window_minutes` | Integer | NO | `5` | — |
| `failed_login_alert_last_sent` | DateTime | YES | NULL | — |
| `permission_catalog_version` | Integer | NO | `0` | — | One-time permission grant migration version |
| `scheduler_revision` | Integer | NO | `0` | — | Incremented when a scheduler setting changes |
| `scheduler_applied_revision` | Integer | NO | `0` | — | Latest revision loaded by the scheduler worker |

> **Application convention:** Bootstrap inserts one `SystemConfig` row when the table is empty and application code normally reads the first row. The schema does not enforce singleton cardinality.

### 2.7 `shift_logs` — Shift Logbook

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `analyst` | String | YES | — | YES | username string |
| `author_role` | String | YES | — | YES | role string |
| `shift_date` | DateTime | YES | `utcnow` | YES | Date of shift |
| `shift_period` | String | YES | — | — | e.g. "Day", "Swing", "Night" |
| `content` | Text | YES | — | — | Log body |
| `created_at` | DateTime | YES | `utcnow` | — | Creation timestamp |
| `is_deleted` | Boolean | YES | `False` | YES | Soft delete flag |

### 2.8 `software_assets` — Software Asset Inventory

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `name` | String | YES | — | YES | Software name |
| `last_updated` | DateTime | YES | `utcnow` | — | Last CSV import |

### 2.9 `hardware_assets` — Hardware Asset Inventory (24 columns)

| Column | Type | Nullable | Default | Index |
|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK |
| `ip_address` | String | NO | — | YES |
| `asset_name` | String | YES | — | YES |
| `host_type` | String | YES | — | — |
| `ip_addresses` | Text | YES | — | — |
| `operating_system` | String | YES | — | — |
| `os_architecture` | String | YES | — | — |
| `os_family` | String | YES | — | — |
| `os_product` | String | YES | — | — |
| `os_vendor` | String | YES | — | — |
| `os_version` | String | YES | — | — |
| `instances` | Integer | YES | `0` | — |
| `critical_instances` | Integer | YES | `0` | — |
| `severe_instances` | Integer | YES | `0` | — |
| `moderate_instances` | Integer | YES | `0` | — |
| `vulnerabilities` | Integer | YES | `0` | — |
| `critical_vulnerabilities` | Integer | YES | `0` | — |
| `severe_vulnerabilities` | Integer | YES | `0` | — |
| `moderate_vulnerabilities` | Integer | YES | `0` | — |
| `exploit_count` | Integer | YES | `0` | — |
| `malware_count` | Integer | YES | `0` | — |
| `raw_risk_score` | Float | YES | `0.0` | — |
| `risk_score` | Float | YES | `0.0` | — |
| `last_updated` | DateTime | YES | `utcnow` | — |

### 2.10 `internal_risk_snapshots` — Internal Risk Time Series

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `timestamp` | DateTime | YES | `utcnow` | — | Snapshot time |
| `score` | Float | YES | — | — | Composite risk score |
| `risk_level` | String | YES | — | — | GREEN/BLUE/YELLOW/ORANGE/RED |
| `total_assets` | Integer | YES | — | — | Asset count at snapshot |
| `total_osint_hits` | Integer | YES | — | — | OSINT match count |
| `critical_osint_hits` | Integer | YES | — | — | Critical OSINT count |
| `hw_data_json` | Text | YES | NULL | — | Serialized HW data |
| `sw_data_json` | Text | YES | NULL | — | Serialized SW data |

### 2.11 `articles` — Ingested Intelligence Articles

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `title` | String | YES | — | — | Headline |
| `link` | String | YES | — | YES (unique) | UNIQUE — dedup key |
| `summary` | Text | YES | — | — | Article summary |
| `published_date` | DateTime | YES | `utcnow` | YES | Feed pub date |
| `source` | String | YES | — | YES | Feed name |
| `score` | Float | YES | `0.0` | YES | Keyword-weighted score |
| `category` | String | YES | `"General"` | YES | Categorized label |
| `keywords_found` | JSON | YES | NULL | — | Matched keyword list |
| `is_bubbled` | Boolean | YES | `False` | — | Surface to dashboard |
| `story_group` | String | YES | NULL | — | Cluster/grouping ID |
| `human_feedback` | Integer | YES | `0` | — | ML label: `1` dismiss/noise, `2` keep/important; `0` neutral |
| `ai_bluf` | Text | YES | NULL | — | AI-generated BLUF |
| `is_pinned` | Boolean | YES | `False` | YES | Prevents auto-purge |
| `full_content` | Text | YES | NULL | — | Extracted article content |
| `ingested_at` | DateTime | YES | `utcnow` | YES | Ingestion timestamp |
| `enrichment_status` | String | YES | `"pending"` | YES | Enrichment state |
| `enrichment_attempts` | Integer | YES | `0` | — | Number of extraction attempts |
| `last_enrichment_error` | Text | YES | NULL | — | Latest extraction failure |
| `last_enriched_at` | DateTime | YES | NULL | — | Successful extraction time |

### 2.12 `extracted_iocs` — Indicators of Compromise

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `article_id` | Integer | YES | — | YES | Logical reference to `articles.id`; no SQL foreign key |
| `indicator_type` | String | YES | — | YES | IP/Domain/Hash/URL/CVE |
| `indicator_value` | String | YES | — | YES | The IOC string |
| `context` | Text | YES | NULL | — | Surrounding text |
| `detected_at` | DateTime | YES | `utcnow` | YES | Extraction timestamp |

### 2.13 `cve_items` — CISA KEV Catalog

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `cve_id` | String | YES | — | YES (unique) | UNIQUE |
| `vendor` | String | YES | — | YES | — |
| `product` | String | YES | — | YES | — |
| `vulnerability_name` | String | YES | — | — | — |
| `date_added` | DateTime | YES | — | YES | CISA date added |
| `description` | Text | YES | — | — | — |
| `required_action` | Text | YES | — | — | — |
| `due_date` | String | YES | — | — | Remediation deadline |

### 2.14 `elastic_events` — SIEM Telemetry Cache

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | **String** | NO | — | PK | **String PK** (not Integer) |
| `timestamp` | DateTime | YES | — | YES | Event time |
| `index_name` | String | YES | — | — | ES index |
| `severity` | String | YES | — | YES | Critical/High/Medium/Low |
| `message` | String | YES | — | — | Event message |
| `source_ip` | String | YES | NULL | — | Source IP |
| `event_category` | String | YES | NULL | — | Event type |

### 2.15 `daily_briefings` — Generated Daily Reports

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `report_date` | DateTime | YES | — | YES (unique) | UNIQUE — one per day |
| `content` | Text | YES | — | — | Full briefing text |
| `created_at` | DateTime | YES | `utcnow` | — | Generation time |

### 2.16 `daily_threat_scores` — Threat Score Time Series

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `record_date` | DateTime | YES | — | YES (unique) | UNIQUE — one per day |
| `cyber_points` | Float | YES | `0.0` | — | Daily cyber score |
| `physical_points` | Float | YES | `0.0` | — | Daily physical score |
| `cyber_baseline` | Float | YES | `0.0` | — | Baseline reference |
| `physical_baseline` | Float | YES | `0.0` | — | Baseline reference |

### 2.17 `regional_hazards` — SPC/NWS Hazard Feed

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `hazard_id` | String | YES | — | YES (unique) | UNIQUE — source ID |
| `hazard_type` | String | YES | — | — | Tornado/Flood/etc |
| `severity` | String | YES | — | — | — |
| `title` | String | YES | — | — | — |
| `description` | Text | YES | — | — | — |
| `location` | String | YES | — | — | Free-text location |
| `updated_at` | DateTime | YES | — | YES | Feed update time |

### 2.18 `regional_outages` — Regional Utility Outages

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `outage_type` | String | YES | — | YES | Power/Telecom/etc |
| `provider` | String | YES | — | — | Utility name |
| `description` | Text | YES | — | — | — |
| `affected_area` | String | YES | — | — | Free-text |
| `lat` | Float | YES | NULL | — | — |
| `lon` | Float | YES | NULL | — | — |
| `radius_km` | Float | YES | `10.0` | — | Impact radius |
| `detected_at` | DateTime | YES | `utcnow` | — | — |
| `is_resolved` | Boolean | YES | `False` | YES | — |

### 2.19 `cloud_outages` — Cloud Provider Status

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `provider` | String | YES | — | YES | AWS/Azure/GCP/etc |
| `service` | String | YES | — | — | Service name |
| `title` | String | YES | — | — | — |
| `description` | Text | YES | — | — | — |
| `link` | String | YES | — | — | Status page URL |
| `is_resolved` | Boolean | YES | `False` | YES | — |
| `updated_at` | DateTime | YES | — | YES | — |

### 2.20 `bgp_anomalies` — BGP Hijack/Downtime Events

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `asn` | String | YES | — | YES | Autonomous system # |
| `event_type` | String | YES | — | — | Hijack/Outage/etc |
| `description` | Text | YES | — | — | — |
| `detected_at` | DateTime | YES | `utcnow` | — | — |
| `is_resolved` | Boolean | YES | `False` | YES | — |

### 2.21 `solarwinds_alerts` — NMS Alert Pipeline (24 columns)

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `event_type` | String | YES | — | YES | Alert type |
| `severity` | String | YES | — | — | P1–P5 / Critical |
| `node_name` | String | YES | — | YES | NMS node name |
| `ip_address` | String | YES | — | — | Node IP |
| `status` | String | YES | — | YES | Active/Resolved |
| `sw_timestamp` | String | YES | — | — | SolarWinds time (string) |
| `details` | Text | YES | — | — | Alert body |
| `node_link` | String | YES | — | — | NMS console URL |
| `raw_payload` | JSON | YES | NULL | — | Full webhook JSON |
| `mapped_location` | String | YES | NULL | YES | → `monitored_locations.name` |
| `received_at` | DateTime | YES | `utcnow` | YES | Ingestion time |
| `resolved_at` | DateTime | YES | NULL | YES | Resolution time |
| `is_dispatched` | Boolean | YES | `False` | YES | RCA ticket created |
| `is_ticketed` | Boolean | YES | `False` | YES | Email ticket sent |
| `is_correlated` | Boolean | YES | `False` | YES | AIOps engine matched |
| `needs_dispatch` | Boolean | NO | `False` | — | Operator-selected Needs Dispatch workflow state; added in revision `20261005_0003` |
| `ai_root_cause` | Text | YES | NULL | — | AI-generated RCA |
| `device_type` | String | YES | `"Unknown"` | YES | Router/Switch/etc |
| `event_category` | String | YES | `"Unknown"` | — | Category bucket |
| `acknowledged_by` | String | YES | NULL | — | User who acknowledged |
| `acknowledged_at` | DateTime | YES | NULL | — | — |
| `dispatched_by` | String | YES | NULL | — | User who dispatched |
| `dispatched_at` | DateTime | YES | NULL | — | — |

### 2.22 `timeline_events` — Unified Event Timeline

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `timestamp` | DateTime | YES | `utcnow` | YES | — |
| `source` | String | YES | — | YES | Origin system |
| `event_type` | String | YES | — | YES | Event classification |
| `message` | String | YES | — | — | Human-readable message |
| `site_name` | String(255) | YES | NULL | YES | Structured site scope for AIOps event filtering |

### 2.23 `monitored_locations` — Facility/Site Registry (18 columns)

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `name` | String | YES | — | YES (unique) | UNIQUE — site identifier |
| `lat` | Float | YES | — | — | Latitude |
| `lon` | Float | YES | — | — | Longitude |
| `loc_type` | String | YES | `"General"` | YES | Site type |
| `district` | String | YES | `"Central"` | YES | Operational district |
| `priority` | String | YES | `"P3-Moderate"` | YES | P1-Critical … P5-Planning |
| `current_spc_risk` | String | YES | `"None"` | — | SPC outlook risk |
| `last_updated` | DateTime | YES | `utcnow` | — | — |
| `under_maintenance` | Boolean | YES | `False` | — | Maintenance flag |
| `maintenance_etr` | DateTime | YES | NULL | — | Estimated time to restore |
| `maintenance_reason` | Text | YES | NULL | — | — |
| `last_auto_ticket` | DateTime | YES | NULL | — | Last auto-generated ticket |
| `last_escalation_ticket` | DateTime | YES | NULL | — | Last escalation ticket |
| `last_auto_dispatch` | DateTime | YES | NULL | — | Last auto dispatch |
| `last_escalation_dispatch` | DateTime | YES | NULL | — | Last escalation dispatch |
| `status_modified_by` | String | YES | NULL | — | Last user to modify status |
| `status_modified_at` | DateTime | YES | NULL | — | Status change timestamp |

### 2.24 `crime_incidents` — Perimeter Crime Feed

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | **String** | NO | — | PK | **String PK** (external ID) |
| `category` | String | YES | — | — | Crime type |
| `raw_title` | String | YES | — | — | Original incident title |
| `timestamp` | DateTime | YES | — | YES | Incident time |
| `distance_miles` | Float | YES | — | — | Distance from HQ |
| `severity` | String | YES | — | — | — |
| `lat` | Float | YES | — | — | — |
| `lon` | Float | YES | — | — | — |
| `is_alert_dispatched` | Boolean | YES | `False` | YES | Alert sent |

### 2.25 `geojson_cache` — GeoJSON Layer Cache

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `feed_name` | **String** | NO | — | PK | **String PK** — no Integer id |
| `data` | JSON | YES | — | — | GeoJSON FeatureCollection |
| `updated_at` | DateTime | YES | `utcnow` | — | — |

### 2.26 `node_aliases` — Node Name → Site Mapping

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `node_pattern` | String | YES | — | YES | Regex/glob pattern |
| `mapped_location_name` | String | YES | — | — | Logical reference to `monitored_locations.name` |
| `confidence_score` | Float | YES | `0.0` | — | Mapping confidence |
| `is_verified` | Boolean | YES | `False` | — | Manual verification |

### 2.27 `user_weather_prefs` — User Weather Alert Preferences

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `username` | String | YES | — | YES | Logical reference to `users.username` |
| `alert_type` | String | YES | — | — | Weather alert type |

### 2.28 `failed_login_attempts` — Short-Lived Authentication Alert Evidence

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `username` | String(128) | NO | — | — | Sanitized submitted username |
| `source_ip` | String(64) | YES | NULL | — | Client IP when available |
| `attempted_at` | DateTime | NO | `utcnow` | YES | Failed login time; rows retained for at most 24 hours |

### 2.29 `user_sessions` — Independently Revocable Sessions

Stores one opaque session token and creation timestamp per browser/device. Sessions are deleted on logout, reset, role change, or administrator revocation; durable sign-in/activity timestamps live on `users`.

| Column | Type | Nullable | Default | Index / constraint |
|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | Primary key |
| `user_id` | Integer | NO | — | Index; FK to `users.id` |
| `token` | String | NO | — | Unique index |
| `created_at` | DateTime | NO | `utcnow` | — |

### 2.30 `registration_invites` — Email-Bound Individual Invitations

Stores a hashed single-use token, required invitation email and normalized email, assigned role, creator, expiry, use time, and nullable `revoked_at`. Legacy invitations without email are invalidated during migration. A restore marks pending links revoked without deleting invitation history.

| Column | Type | Nullable | Default | Index / constraint |
|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | Primary key |
| `username` | String | NO | — | Index |
| `role` | String | NO | `analyst` | — |
| `token_hash` | String | NO | — | Unique index |
| `created_by` | String | NO | — | — |
| `created_at` | DateTime | NO | `utcnow` | — |
| `expires_at` | DateTime | NO | — | Index |
| `used_at` | DateTime | YES | NULL | — |
| `revoked_at` | DateTime | YES | NULL | Added by revision `20261002_0002` |
| `email` | String(254) | NO | — | — |
| `email_normalized` | String(254) | NO | — | Index |
| `account_type` | String(20) | NO | `individual` | — |

### 2.31 `email_change_requests` — Approved Recovery-Email Changes

Stores the requested address, normalized address, review status/reviewer/reason, and a hashed verification token. The current approved address is unchanged until approval and mailbox verification complete.

| Column | Type | Nullable | Default | Index / constraint |
|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | Primary key |
| `user_id` | Integer | NO | — | Index; FK to `users.id` |
| `requested_email` | String(254) | NO | — | — |
| `requested_email_normalized` | String(254) | NO | — | Index |
| `status` | String(32) | NO | `pending_review` | Index |
| `requested_at` | DateTime | NO | `utcnow` | Index |
| `reviewed_by_id` | Integer | YES | NULL | FK to `users.id` |
| `reviewed_at` | DateTime | YES | NULL | — |
| `decision_reason` | Text | YES | NULL | — |
| `verification_token_hash` | String(64) | YES | NULL | Unique index |
| `verification_expires_at` | DateTime | YES | NULL | — |
| `verified_at` | DateTime | YES | NULL | — |

### 2.32 `password_reset_requests` — Administrator-Reviewed Recovery Requests

Stores a matched user (when found), a hashed submitted identifier, requester IP, request status, reviewer, and decision reason. Unmatched requests support rate limiting but are excluded from the administrator review queue.

| Column | Type | Nullable | Default | Index / constraint |
|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | Primary key |
| `user_id` | Integer | YES | NULL | Index; FK to `users.id` |
| `identifier_hash` | String(64) | NO | — | Index |
| `requester_ip` | String(64) | YES | NULL | Index |
| `status` | String(32) | NO | `pending_review` | Index |
| `requested_at` | DateTime | NO | `utcnow` | Index |
| `reviewed_by_id` | Integer | YES | NULL | FK to `users.id` |
| `reviewed_at` | DateTime | YES | NULL | — |
| `decision_reason` | Text | YES | NULL | — |
| `reset_email_sent_at` | DateTime | YES | NULL | — |

### 2.33 `password_reset_tokens` — Single-Use Password Reset Links

Stores only a hash of the random reset token, its approved request/user, creation time, expiration, and use time. Raw reset tokens are sent only by email after approval.

| Column | Type | Nullable | Default | Index / constraint |
|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | Primary key |
| `request_id` | Integer | NO | — | Index; FK to `password_reset_requests.id` |
| `user_id` | Integer | NO | — | Index; FK to `users.id` |
| `token_hash` | String(64) | NO | — | Unique index |
| `created_at` | DateTime | NO | `utcnow` | — |
| `expires_at` | DateTime | NO | — | Index |
| `used_at` | DateTime | YES | NULL | — |

### 2.34 `account_audit_events` — Account and Security Audit Trail

Stores actor, affected account, event type, structured details, and timestamp for account creation, review decisions, role/status changes, recovery, and session revocation.

| Column | Type | Nullable | Default | Index / constraint |
|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | Primary key |
| `actor_user_id` | Integer | YES | NULL | Index; FK to `users.id` |
| `subject_user_id` | Integer | YES | NULL | Index; FK to `users.id` |
| `event_type` | String(64) | NO | — | Index |
| `event_detail` | JSON | NO | `dict` | — |
| `created_at` | DateTime | NO | `utcnow` | Index |

### 2.35 `scheduler_job_config` — Persisted Job Schedules

Stores the registered job key, validated interval/daily/weekly schedule fields, enabled state, timezone, updater, and timestamp. `system_config.scheduler_revision` notifies the worker to reload schedules.

| Column | Type | Nullable | Default | Index / constraint |
|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | Primary key |
| `job_key` | String(80) | NO | — | Unique index |
| `schedule_type` | String(16) | NO | `interval` | — |
| `every_value` | Integer | YES | NULL | — |
| `unit` | String(16) | YES | NULL | — |
| `run_at` | String(5) | YES | NULL | — |
| `weekday` | String(12) | YES | NULL | — |
| `timezone` | String(64) | NO | `America/Chicago` | — |
| `enabled` | Boolean | NO | `True` | — |
| `updated_by` | String(128) | YES | NULL | — |
| `updated_at` | DateTime | NO | `utcnow` | — |

---

## 3. Schema Evolution Strategy

Schema changes use Alembic revisions under `migrations/`. `alembic_version` stores the last successfully applied revision. Every API, worker, and webhook startup checks the recorded revision under a shared SQLite migration lock; it applies only revisions newer than the database and performs no schema DDL when the database is current.

The first revision adopts legacy databases without dropping or renaming tables or columns. It uses the frozen `migrations/schema_v1.py` snapshot to create missing tables, adds absent columns from an explicit historical compatibility map, applies one-time backfills, and validates the final baseline column set and normalized-email uniqueness before recording success. It supports empty databases, the pre-Alembic application schema, and known partial upgrades. An unknown older table shape or duplicate normalized email values stops startup; the failure does not advance `alembic_version`, and existing records remain in place. See [Migration Compatibility](MIGRATION_COMPATIBILITY.md) for limits, backfills, and recovery.

### Adding a schema or data migration

1. Change the SQLAlchemy model and add a new forward-only revision under `migrations/versions/` in the same change.
2. Use SQLite-compatible DDL. Guard additions that may already exist after a partial legacy adoption.
3. Keep deterministic data conversions in the revision and make them safe to retry if SQLite leaves partial DDL behind.
4. Do not edit released revisions or add schema changes to `Base.metadata.create_all()` at application startup.
5. Test a fresh SQLite database, a legacy upgrade, and a second startup at head.

`Base.metadata.create_all()` is used only by the one-time adoption revision and isolated tests. Default data seeds remain separate, conditional bootstrap behavior.

### Data Migrations

When a column's semantics change (e.g., `monitored_locations.priority` changed from Integer to String), a data migration is applied:

```python
conn.execute(text(
    "UPDATE monitored_locations SET priority = CASE "
    "WHEN priority = '1' OR priority = 1 THEN 'P1-Critical' "
    "WHEN priority = '2' OR priority = 2 THEN 'P2-High' "
    "ELSE 'P3-Moderate' END "
    "WHERE priority IS NOT NULL AND CAST(priority AS INTEGER) = priority"
))
```

---

## 4. Index Strategy

### Index Summary by Table

Entries may group independent indexes for brevity; a grouped row does not imply a composite index. Primary-key indexes are omitted unless their non-integer type is a design note.

| Table | Column(s) | Index Type | Purpose |
|---|---|---|---|
| `users` | `username` | UNIQUE | Login lookup |
| `users` | `role` | B-tree | Role-based queries |
| `users` | `session_token` | B-tree | Session validation |
| `users` | `email_normalized` | UNIQUE | Case-folded email lookup and uniqueness when present |
| `users` | `account_type`, `is_active` | B-tree | Account directory filtering and active-account checks |
| `users` | `last_login_at`, `last_activity_at` | B-tree | Recent access reporting |
| `user_sessions` | `user_id` | B-tree | Sessions by account |
| `user_sessions` | `token` | UNIQUE | Session lookup |
| `failed_login_attempts` | `attempted_at` | B-tree | Failed-login threshold and expiry queries |
| `registration_invites` | `username`, `token_hash`, `expires_at`, `email_normalized` | B-tree/UNIQUE | Pending invite lookup, token validation, and normalized email lookup |
| `email_change_requests` | `user_id`, `status` | B-tree | Pending recovery-email review lookup |
| `email_change_requests` | `requested_email_normalized`, `requested_at` | B-tree | Email collision and review/retention queries |
| `email_change_requests` | `verification_token_hash` | UNIQUE | One-time email verification lookup |
| `password_reset_requests` | `user_id`, `identifier_hash`, `requester_ip`, `status`, `requested_at` | B-tree | Recovery queue, identifier matching, rate limiting, and retention |
| `password_reset_tokens` | `request_id`, `user_id`, `expires_at` | B-tree | Tokens by request/user and expiration |
| `password_reset_tokens` | `token_hash` | UNIQUE | One-time reset-token lookup |
| `account_audit_events` | `actor_user_id`, `subject_user_id`, `event_type`, `created_at` | B-tree | Account audit filtering and chronology |
| `scheduler_job_config` | `job_key` | UNIQUE | Runtime schedule configuration lookup |
| `roles` | `name` | UNIQUE | Role lookup |
| `articles` | `link` | UNIQUE | Dedup on ingest |
| `articles` | `published_date` | B-tree | Time-range queries |
| `articles` | `source` | B-tree | Source filtering |
| `articles` | `score` | B-tree | Top-N scoring |
| `articles` | `category` | B-tree | Category filtering |
| `articles` | `is_pinned` | B-tree | Pinned filter |
| `articles` | `ingested_at`, `enrichment_status` | B-tree | Ingestion/enrichment queue filtering |
| `extracted_iocs` | `article_id` | B-tree | Orphan cleanup join |
| `extracted_iocs` | `indicator_type` | B-tree | Type filtering |
| `extracted_iocs` | `indicator_value` | B-tree | IOC search |
| `extracted_iocs` | `detected_at` | B-tree | Time-range queries |
| `cve_items` | `cve_id` | UNIQUE | CVE lookup |
| `cve_items` | `vendor`, `product` | B-tree | Vendor/product filtering |
| `cve_items` | `date_added` | B-tree | Time-range queries |
| `elastic_events` | `id` (String) | PK | Event lookup |
| `elastic_events` | `timestamp` | B-tree | Time-range queries |
| `elastic_events` | `severity` | B-tree | Severity filtering |
| `solarwinds_alerts` | `event_type` | B-tree | Alert classification |
| `solarwinds_alerts` | `node_name` | B-tree | Node lookup |
| `solarwinds_alerts` | `status` | B-tree | Active/resolved filter |
| `solarwinds_alerts` | `mapped_location` | B-tree | Site correlation |
| `solarwinds_alerts` | `received_at` | B-tree | Time-range queries |
| `solarwinds_alerts` | `resolved_at` | B-tree | Resolution time |
| `solarwinds_alerts` | `is_dispatched` | B-tree | Dispatch state |
| `solarwinds_alerts` | `is_ticketed` | B-tree | Ticket state |
| `solarwinds_alerts` | `is_correlated` | B-tree | Correlation state |
| `solarwinds_alerts` | `device_type` | B-tree | Device filtering |
| `shift_logs` | `analyst` | B-tree | User filtering |
| `shift_logs` | `author_role` | B-tree | Role filtering |
| `shift_logs` | `shift_date` | B-tree | Date navigation |
| `shift_logs` | `is_deleted` | B-tree | Soft-delete filter |
| `monitored_locations` | `name` | UNIQUE | Site lookup |
| `monitored_locations` | `loc_type` | B-tree | Type filtering |
| `monitored_locations` | `district` | B-tree | District filtering |
| `monitored_locations` | `priority` | B-tree | Priority sorting |
| `regional_hazards` | `hazard_id` | UNIQUE | Dedup on ingest |
| `regional_hazards` | `updated_at` | B-tree | Time-range / purge |
| `regional_outages` | `outage_type` | B-tree | Type filtering |
| `regional_outages` | `is_resolved` | B-tree | Active filter |
| `cloud_outages` | `provider` | B-tree | Provider filtering |
| `cloud_outages` | `is_resolved` | B-tree | Active filter |
| `cloud_outages` | `updated_at` | B-tree | Time-range / purge |
| `bgp_anomalies` | `asn` | B-tree | ASN filtering |
| `bgp_anomalies` | `is_resolved` | B-tree | Active filter |
| `crime_incidents` | `id` (String) | PK | External ID dedup |
| `crime_incidents` | `timestamp` | B-tree | Time-range / purge |
| `crime_incidents` | `is_alert_dispatched` | B-tree | Dispatch state |
| `daily_briefings` | `report_date` | UNIQUE | One-per-day |
| `daily_threat_scores` | `record_date` | UNIQUE | One-per-day |
| `feed_sources` | `url` | UNIQUE | Dedup on ingest |
| `keywords` | `word` | UNIQUE | Keyword lookup |
| `saved_reports` | `title` | B-tree | Title search |
| `saved_reports` | `created_at` | B-tree | Date sorting |
| `software_assets` | `name` | B-tree | Name search |
| `hardware_assets` | `ip_address` | B-tree | IP lookup |
| `hardware_assets` | `asset_name` | B-tree | Name search |
| `user_weather_prefs` | `username` | B-tree | User lookup |
| `timeline_events` | `timestamp` | B-tree | Time-range |
| `timeline_events` | `source` | B-tree | Source filtering |
| `timeline_events` | `event_type` | B-tree | Type filtering |
| `timeline_events` | `site_name` | B-tree | Site-scope filtering |
| `node_aliases` | `node_pattern` | B-tree | Node-pattern lookup |

### SQLite PRAGMA Optimizations

After migrations, startup enables persistent WAL mode. The SQLAlchemy connection event applies connection-local pragmas on every new NullPool connection:

| PRAGMA | Value | Purpose |
|---|---|---|
| `synchronous` | NORMAL | Reduced fsync (WAL ensures crash safety) |
| `cache_size` | -16000 | 16 MB page cache |
| `temp_store` | MEMORY | Temp tables in RAM |
| `mmap_size` | 67108864 | 64 MiB memory-mapped I/O |

---

## 5. Startup Migration and Bootstrap Sequence

`init_db()` in `src/core/db.py` is called before the API lifespan starts its broadcaster, before scheduler jobs are registered, and before the webhook app is created.

### Phase 1 — Check and apply Alembic revisions

`src/core/migration_runner.py` acquires a cross-process lock beside the SQLite file and runs `alembic upgrade head`. The `alembic_version` row records the last successful revision. At head, startup performs a version check and no schema DDL. A migration failure aborts startup.

### Phase 2 — One-time legacy adoption

Revision `20261002_0001` uses the frozen `migrations/schema_v1.py` snapshot to create missing baseline tables, adds only missing legacy columns, creates missing indexes, and applies one-time user, invitation, and priority backfills. Revision `20261002_0002` adds `registration_invites.revoked_at` for auditable invite invalidation during full restore. Revision `20261005_0003` adds a false-default `solarwinds_alerts.needs_dispatch` flag while preserving existing alerts. Revision `20261005_0004` fills `timeline_events.site_name` only for legacy generated webhook alerts with a suffix matching a monitored location. Existing tables and records are retained. Duplicate normalized email values that prevent creation of the unique index fail with an actionable error.

The explicit compatibility column map covers account/recovery fields, scheduler revisions, scoring and alert settings, article enrichment metadata, role site types, alert dispatch fields, location tracking, shift-log state, crime dispatch state, and timeline site metadata. The adoption revision validates every frozen-baseline table's final column set before recording success; later revisions add their versioned fields.

### Phase 3 — SQLite runtime settings

After migration, startup enables WAL. Connection-local synchronous, cache, temp-storage, and mmap settings are applied to each NullPool connection.

### Phase 4 — Conditional data bootstrap

Creates missing starter roles (`admin`, `analyst`, `viewer`, and `user-admin`) from the permission catalog. A one-time catalog migration removes the old broad analyst startup union and maps the legacy AI grant conservatively; subsequent startups do not union grants. Creates `admin` if `DEFAULT_ADMIN_PASSWORD` is set and no users exist.

**Initial admin credentials:** username `admin` and the value of `DEFAULT_ADMIN_PASSWORD`; no user is created when that variable is empty. Optional `DEFAULT_ADMIN_EMAIL` is normalized and verified for recovery/reviewer notifications. If supplied later for an existing email-less bootstrap admin, startup applies it as trusted configuration and completes any matching pending initial recovery-email request.

### Default RSS feeds

Seeds 7 default feeds if they don't exist:

| Feed | URL |
|---|---|
| The Hacker News | `https://feeds.feedburner.com/TheHackersNews` |
| Krebs on Security | `https://krebsonsecurity.com/feed/` |
| BleepingComputer | `https://www.bleepingcomputer.com/feed/` |
| WSJ World News | `https://feeds.a.dj.com/rss/RSSWorldNews.xml` |
| CISA Advisories | `https://www.cisa.gov/cybersecurity-advisories/all.xml` |
| Dark Reading | `https://www.darkreading.com/rss.xml` |
| The Record | `https://therecord.media/feed/` |

### Default keywords

Seeds 70 security-weighted keywords (weight range 30–90). Key examples:

| Keyword | Weight | Keyword | Weight |
|---|---|---|---|
| `ransomware` | 90 | `lockbit` | 85 |
| `breach` | 85 | `blackcat` | 85 |
| `zero-day` | 85 | `log4shell` | 85 |
| `rce` | 80 | `cobalt strike` | 80 |
| `apt` | 80 | `log4j` | 80 |

### System configuration and demo assets

Creates a single default `SystemConfig` row if none exists.

### Optional article rescoring

`RESCORE_ON_STARTUP=true` explicitly opts into a full rescore of `articles.score`; normal startup skips this maintenance work. Keyword changes do not require an API rebuild.

---

## 6. Key Design Decisions

### Declared Foreign Key Constraints

The schema declares foreign keys for independently revocable sessions, account-recovery requests/tokens, and account-audit actor/subject references:

- `user_sessions.user_id` → `users.id`.
- `email_change_requests.user_id` and `reviewed_by_id` → `users.id`.
- `password_reset_requests.user_id` and `reviewed_by_id` → `users.id`.
- `password_reset_tokens.request_id` → `password_reset_requests.id`; `user_id` → `users.id`.
- `account_audit_events.actor_user_id` and `subject_user_id` → `users.id`.

The SQLite connection setup does not enable `PRAGMA foreign_keys`, so applications must not assume SQLite is enforcing those declarations at runtime. Other relationships—including `users.role`, `user_weather_prefs.username`, `extracted_iocs.article_id`, and site/name mappings—are logical joins without declared foreign keys. Hourly maintenance removes orphaned IOC rows.

### JSON Columns for Flexible Data

Used in four tables:

| Table | Column | Contents |
|---|---|---|
| `roles` | `allowed_pages`, `allowed_actions`, `allowed_site_types` | Permission arrays |
| `articles` | `keywords_found` | Matched keyword list |
| `solarwinds_alerts` | `raw_payload` | Full webhook JSON |
| `geojson_cache` | `data` | GeoJSON FeatureCollection |

SQLite stores JSON as TEXT. Queries use string matching, not native JSON operators.

### NullPool for SQLite

```python
engine = create_engine(DATABASE_URL, poolclass=NullPool, ...)
```

`NullPool` disables connection pooling entirely. Each request opens/closes a fresh connection. This avoids pooled-connection contention observed with concurrent FastAPI and scheduler access to the shared SQLite file. SQLite is the only supported application database.

### String Primary Keys

Two tables use String PKs instead of autoincrement Integer:

| Table | PK | Source |
|---|---|---|
| `elastic_events` | `id` (String) | Elasticsearch document `_id` |
| `crime_incidents` | `id` (String) | External API incident ID |
| `geojson_cache` | `feed_name` (String) | Feed identifier (singleton per feed) |

### Singleton Pattern — `system_config`

Bootstrap creates one default `SystemConfig` row when the table is empty, and the application normally reads/writes the first row. The schema does not enforce a singleton constraint, so database tooling should not add duplicate rows.

### Soft Delete — `shift_logs`

Shift log entries use `is_deleted = True` rather than physical deletion. The API filters `is_deleted == False` by default. The `content` is preserved for audit but hidden from summaries.

### Timestamp Conventions

All timestamps are stored as UTC `datetime` objects. The frontend converts to `America/Chicago` via `web/src/utils/timezone.ts`. The `sw_timestamp` column in `solarwinds_alerts` is stored as a raw **String** from the webhook payload (not parsed to DateTime) to preserve the original format.

---

## 7. Data Retention Policies

Centralized retention is enforced by the hourly **`database_maintenance` scheduler job**, which runs `run_database_maintenance()` in `src/scheduler.py`; individual workers also have ingest-time purge functions.

### Centralized Maintenance (`database_maintenance` — runs every 60 min)

| Table | Retention Rule | SQL Logic |
|---|---|---|
| `articles` | **Unpinned score < 50 older than 3 days:** delete | `WHERE score < 50 AND published_date < now()-3d AND is_pinned = False` |
| `articles` | **Unpinned > 30 days:** delete | `WHERE published_date < now()-30d AND is_pinned = False` |
| `solarwinds_alerts` | **> 60 days:** delete | `WHERE received_at < now()-60d` |
| `regional_hazards` | **> 48 hours:** delete | `WHERE updated_at < now()-48h` |
| `regional_outages` | **> 12 hours:** delete | `WHERE detected_at < now()-12h` |
| `bgp_anomalies` | **> 12 hours:** delete | `WHERE detected_at < now()-12h` |
| `cve_items` | **> 7 days:** delete | `WHERE date_added < now()-7d` |
| `cloud_outages` | **Resolved > 24 hours:** delete | `WHERE is_resolved=True AND updated_at < now()-24h` |
| `cloud_outages` | **Unresolved > 14 days:** delete | `WHERE is_resolved=False AND updated_at < now()-14d` |
| `crime_incidents` | **> 7 days:** delete | `WHERE timestamp < now()-7d` |
| `extracted_iocs` | **Orphaned (no parent article):** delete | `WHERE article_id NOT IN (SELECT id FROM articles)` |
| `internal_risk_snapshots` | **> 90 days:** delete | `WHERE timestamp < now()-90d` |
| `timeline_events` | **> 90 days:** delete | `WHERE timestamp < now()-90d` |
| `elastic_events` | **> 72 hours:** delete | `WHERE timestamp < now()-72h` |
| `failed_login_attempts` | **> 24 hours:** delete | `WHERE attempted_at < now()-24h` |
| `password_reset_tokens` | Expired/used tokens older than 30 days | `expires_at < now() OR used_at IS NOT NULL`, and `created_at < now()-30d` |
| `password_reset_requests` | Pending > 30 days becomes expired; terminal/unmatched rows > 90 days are deleted | Status and `requested_at` filters |
| `email_change_requests` | Expired verification requests become expired; terminal rows > 90 days are deleted | Verification expiry and status/`requested_at` filters |

### Worker-Specific Purge

| Worker | Table | Retention Rule |
|---|---|---|
| `cloud_worker` | `cloud_outages` | Resolved > 3 days (additional ingest-time purge; centralized maintenance removes resolved rows after 24 hours) |
| `crime_worker` | `crime_incidents` | > 7 days (purge on ingest) |
| `elastic_worker` | `elastic_events` | > 72 hours (`purge_stale_elastic_data(72)`) |

### Tables With No Automatic Purge

| Table | Reason |
|---|---|
| `users` | Persistent account data |
| `roles` | Persistent permission definitions |
| `system_config` | Singleton — never deleted |
| `feed_sources` | Persistent configuration |
| `keywords` | Persistent scoring dictionary |
| `saved_reports` | User-created — manual delete only |
| `shift_logs` | Soft-deleted via `is_deleted` — retained indefinitely |
| `software_assets` | Persistent inventory — replaced on CSV import |
| `hardware_assets` | Persistent inventory — replaced on CSV import |
| `daily_briefings` | Historical — one per day, retained |
| `daily_threat_scores` | Historical time series — no purge |
| `monitored_locations` | Persistent site registry |
| `node_aliases` | Persistent mapping table |
| `user_weather_prefs` | Persistent user preferences |
| `user_sessions` | Removed by logout/reset/role or administrator revocation; no age-based purge |
| `registration_invites` | Expired, used, and revoked invitation records are retained for history |
| `account_audit_events` | Security audit history is retained |
| `scheduler_job_config` | Persisted schedule rows are retained |
| `geojson_cache` | Overwritten on each fetch, not purged |
