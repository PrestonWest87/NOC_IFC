# NOC Intelligence Fusion Center — Database Schema Reference

> **Source of truth:** `src/models/schema.py` (SQLAlchemy declarative models)
> **Engine:** SQLite (default) or PostgreSQL via `DATABASE_URL` env var
> **Driver:** SQLAlchemy 2.x with `NullPool` for SQLite
> **Last verified:** 2026-07-15

---

## Table of Contents

1. [Entity-Relationship Overview](#1-entity-relationship-overview)
2. [Complete Table Reference](#2-complete-table-reference)
3. [Schema Evolution Strategy](#3-schema-evolution-strategy)
4. [Index Strategy](#4-index-strategy)
5. [init_db() Initialization Sequence](#5-init_db-initialization-sequence)
6. [Key Design Decisions](#6-key-design-decisions)
7. [Data Retention Policies](#7-data-retention-policies)

---

## 1. Entity-Relationship Overview

This schema uses **no formal foreign key constraints**. All cross-table references are logical and enforced at the application layer. The diagram below documents these logical relationships using `~~` notation.

```
┌─────────────────────┐       ┌─────────────────────┐
│        users         │       │        roles         │
│─────────────────────│       │─────────────────────│
│ id            (PK)  │       │ id            (PK)  │
│ username      (UQ)  │◄─ ─ ─ │ name          (UQ)  │
│ role          (FK→) │       │ allowed_pages (JSON)│
│ session_token       │       │ allowed_actions     │
│ full_name           │       │ allowed_site_types  │
│ job_title           │       └─────────────────────┘
│ contact_info        │
│ default_shift       │       ┌─────────────────────┐
└────────┬────────────┘       │     user_weather_    │
         │                    │       prefs           │
         │                    │─────────────────────│
         │                    │ id            (PK)  │
         │                    │ username  (FK→users) │
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
│ id            (PK)  │◄─ ─ ─ │ article_id    (FK→) │
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

### 2.1 `users` — User Accounts

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `username` | String | NO | — | YES (unique) | UNIQUE |
| `password_hash` | String | NO | — | — | bcrypt hash |
| `role` | String | NO | `"analyst"` | YES | FK-like → `roles.name` |
| `session_token` | String | YES | NULL | YES | Session tracking |
| `full_name` | String | YES | NULL | — | Display name |
| `job_title` | String | YES | NULL | — | Role description |
| `contact_info` | String | YES | NULL | — | Email/phone |
| `default_shift` | String | NO | `"No Shift"` | — | Shift assignment |

### 2.2 `roles` — Role Definitions

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `name` | String | NO | — | YES (unique) | UNIQUE |
| `allowed_pages` | JSON | NO | — | — | Array of page names |
| `allowed_actions` | JSON | NO | `list` | — | Array of action strings |
| `allowed_site_types` | JSON | NO | `list` | — | Array of site type strings |

### 2.3 `saved_reports` — Report Library

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `title` | String | NO | — | YES | — |
| `author` | String | NO | — | — | username string |
| `content` | Text | NO | — | — | Full report body |
| `created_at` | DateTime | NO | `utcnow` | YES | — |

### 2.4 `feed_sources` — RSS Feed Registry

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `url` | String | NO | — | YES (unique) | UNIQUE |
| `name` | String | NO | — | — | Human-readable name |
| `is_active` | Boolean | NO | `True` | — | Enable/disable toggle |

### 2.5 `keywords` — Scoring Keyword Dictionary

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `word` | String | NO | — | YES (unique) | UNIQUE |
| `weight` | Integer | NO | `10` | — | 0–100 scoring weight |

> **Critical:** 70 keywords are seeded at init. `rescore_all_articles()` runs after every seed to rescale `articles.score`.

### 2.6 `system_config` — Singleton Configuration Store

| Column | Type | Nullable | Default | Index |
|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK |
| `llm_endpoint` | String | NO | `"https://api.openai.com/v1"` | — |
| `llm_api_key` | String | NO | `""` | — |
| `llm_model_name` | String | NO | `"gpt-4o-mini"` | — |
| `is_active` | Boolean | NO | `False` | — |
| `tech_stack` | Text | NO | `"SolarWinds, Cisco SD-WAN, Microsoft Office, Verizon, Cisco"` | — |
| `monitored_asns` | String | NO | `"AS701, AS7922, AS3356"` | — |
| `rolling_summary` | Text | YES | NULL | — |
| `rolling_summary_time` | DateTime | YES | NULL | — |
| `smtp_server` | String | YES | NULL | — |
| `smtp_port` | Integer | NO | `587` | — |
| `smtp_username` | String | YES | NULL | — |
| `smtp_password` | String | YES | NULL | — |
| `smtp_sender` | String | YES | NULL | — |
| `smtp_recipient` | String | YES | NULL | — |
| `smtp_enabled` | Boolean | NO | `False` | — |
| `baseline_override_cyber` | Float | NO | `0.0` | — |
| `baseline_override_phys` | Float | NO | `0.0` | — |
| `unified_brief` | Text | YES | NULL | — |
| `unified_brief_time` | DateTime | YES | NULL | — |
| `last_global_risk` | String | YES | NULL | — |
| `last_internal_risk` | String | YES | NULL | — |
| `last_risk_alert_time` | DateTime | YES | NULL | — |
| `sys_countermeasures` | Integer | NO | `3` | — |
| `net_countermeasures` | Integer | NO | `3` | — |
| `scoring_mode` | String | NO | `"auto"` | — |
| `cyber_criticality_override` | Integer | NO | `0` | — |
| `cyber_lethality_override` | Integer | NO | `0` | — |
| `physical_criticality_override` | Integer | NO | `0` | — |
| `physical_lethality_override` | Integer | NO | `0` | — |
| `internal_criticality_override` | Integer | NO | `0` | — |
| `internal_lethality_override` | Integer | NO | `0` | — |
| `global_risk_offset` | Integer | NO | `0` | — |
| `internal_risk_offset` | Integer | NO | `0` | — |
| `alerted_eq_ids` | Text | NO | `"[]"` | — |
| `llm_context_window` | Integer | NO | `128000` | — |

> **Singleton pattern:** Only one row exists. Inserted by `init_db()` if absent.

### 2.7 `shift_logs` — Shift Logbook

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `analyst` | String | NO | — | YES | username string |
| `author_role` | String | NO | — | YES | role string |
| `shift_date` | DateTime | NO | `utcnow` | YES | Date of shift |
| `shift_period` | String | NO | — | — | e.g. "Day", "Swing", "Night" |
| `content` | Text | NO | — | — | Log body |
| `created_at` | DateTime | NO | `utcnow` | — | Creation timestamp |
| `is_deleted` | Boolean | NO | `False` | YES | Soft delete flag |

### 2.8 `software_assets` — Software Asset Inventory

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `name` | String | NO | — | YES | Software name |
| `last_updated` | DateTime | NO | `utcnow` | — | Last CSV import |

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
| `last_updated` | DateTime | NO | `utcnow` | — |

### 2.10 `internal_risk_snapshots` — Internal Risk Time Series

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `timestamp` | DateTime | NO | `utcnow` | — | Snapshot time |
| `score` | Float | NO | — | — | Composite risk score |
| `risk_level` | String | NO | — | — | GREEN/BLUE/YELLOW/ORANGE/RED |
| `total_assets` | Integer | NO | — | — | Asset count at snapshot |
| `total_osint_hits` | Integer | NO | — | — | OSINT match count |
| `critical_osint_hits` | Integer | NO | — | — | Critical OSINT count |
| `hw_data_json` | Text | YES | NULL | — | Serialized HW data |
| `sw_data_json` | Text | YES | NULL | — | Serialized SW data |

### 2.11 `articles` — Ingested Intelligence Articles

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `title` | String | NO | — | — | Headline |
| `link` | String | NO | — | YES (unique) | UNIQUE — dedup key |
| `summary` | Text | NO | — | — | Article summary |
| `published_date` | DateTime | NO | `utcnow` | YES | Feed pub date |
| `source` | String | NO | — | YES | Feed name |
| `score` | Float | NO | `0.0` | YES | Keyword-weighted score |
| `category` | String | NO | `"General"` | YES | Categorized label |
| `keywords_found` | JSON | YES | NULL | — | Matched keyword list |
| `is_bubbled` | Boolean | NO | `False` | — | Surface to dashboard |
| `story_group` | String | YES | NULL | — | Cluster/grouping ID |
| `human_feedback` | Integer | NO | `0` | — | Analyst vote (+1/-1) |
| `ai_bluf` | Text | YES | NULL | — | AI-generated BLUF |
| `is_pinned` | Boolean | NO | `False` | YES | Prevents auto-purge |

### 2.12 `extracted_iocs` — Indicators of Compromise

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `article_id` | Integer | NO | — | YES | Logical FK → `articles.id` |
| `indicator_type` | String | NO | — | YES | IP/Domain/Hash/URL/CVE |
| `indicator_value` | String | NO | — | YES | The IOC string |
| `context` | Text | YES | NULL | — | Surrounding text |
| `detected_at` | DateTime | NO | `utcnow` | YES | Extraction timestamp |

### 2.13 `cve_items` — CISA KEV Catalog

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `cve_id` | String | NO | — | YES (unique) | UNIQUE |
| `vendor` | String | NO | — | YES | — |
| `product` | String | NO | — | YES | — |
| `vulnerability_name` | String | NO | — | — | — |
| `date_added` | DateTime | NO | — | YES | CISA date added |
| `description` | Text | NO | — | — | — |
| `required_action` | Text | NO | — | — | — |
| `due_date` | String | NO | — | — | Remediation deadline |

### 2.14 `elastic_events` — SIEM Telemetry Cache

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | **String** | NO | — | PK | **String PK** (not Integer) |
| `timestamp` | DateTime | NO | — | YES | Event time |
| `index_name` | String | NO | — | — | ES index |
| `severity` | String | NO | — | YES | Critical/High/Medium/Low |
| `message` | String | NO | — | — | Event message |
| `source_ip` | String | YES | NULL | — | Source IP |
| `event_category` | String | YES | NULL | — | Event type |

### 2.15 `daily_briefings` — Generated Daily Reports

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `report_date` | DateTime | NO | — | YES (unique) | UNIQUE — one per day |
| `content` | Text | NO | — | — | Full briefing text |
| `created_at` | DateTime | NO | `utcnow` | — | Generation time |

### 2.16 `daily_threat_scores` — Threat Score Time Series

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `record_date` | DateTime | NO | — | YES (unique) | UNIQUE — one per day |
| `cyber_points` | Float | NO | `0.0` | — | Daily cyber score |
| `physical_points` | Float | NO | `0.0` | — | Daily physical score |
| `cyber_baseline` | Float | NO | `0.0` | — | Baseline reference |
| `physical_baseline` | Float | NO | `0.0` | — | Baseline reference |

### 2.17 `regional_hazards` — SPC/NWS Hazard Feed

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `hazard_id` | String | NO | — | YES (unique) | UNIQUE — source ID |
| `hazard_type` | String | NO | — | — | Tornado/Flood/etc |
| `severity` | String | NO | — | — | — |
| `title` | String | NO | — | — | — |
| `description` | Text | NO | — | — | — |
| `location` | String | NO | — | — | Free-text location |
| `updated_at` | DateTime | NO | — | YES | Feed update time |

### 2.18 `regional_outages` — Regional Utility Outages

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `outage_type` | String | NO | — | YES | Power/Telecom/etc |
| `provider` | String | NO | — | — | Utility name |
| `description` | Text | NO | — | — | — |
| `affected_area` | String | NO | — | — | Free-text |
| `lat` | Float | YES | NULL | — | — |
| `lon` | Float | YES | NULL | — | — |
| `radius_km` | Float | NO | `10.0` | — | Impact radius |
| `detected_at` | DateTime | NO | `utcnow` | — | — |
| `is_resolved` | Boolean | NO | `False` | YES | — |

### 2.19 `cloud_outages` — Cloud Provider Status

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `provider` | String | NO | — | YES | AWS/Azure/GCP/etc |
| `service` | String | NO | — | — | Service name |
| `title` | String | NO | — | — | — |
| `description` | Text | NO | — | — | — |
| `link` | String | NO | — | — | Status page URL |
| `is_resolved` | Boolean | NO | `False` | YES | — |
| `updated_at` | DateTime | NO | — | YES | — |

### 2.20 `bgp_anomalies` — BGP Hijack/Downtime Events

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `asn` | String | NO | — | YES | Autonomous system # |
| `event_type` | String | NO | — | — | Hijack/Outage/etc |
| `description` | Text | NO | — | — | — |
| `detected_at` | DateTime | NO | `utcnow` | — | — |
| `is_resolved` | Boolean | NO | `False` | YES | — |

### 2.21 `solarwinds_alerts` — NMS Alert Pipeline (25 columns)

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `event_type` | String | NO | — | YES | Alert type |
| `severity` | String | NO | — | — | P1–P5 / Critical |
| `node_name` | String | NO | — | YES | NMS node name |
| `ip_address` | String | NO | — | — | Node IP |
| `status` | String | NO | — | YES | Active/Resolved |
| `sw_timestamp` | String | NO | — | — | SolarWinds time (string) |
| `details` | Text | NO | — | — | Alert body |
| `node_link` | String | NO | — | — | NMS console URL |
| `raw_payload` | JSON | YES | NULL | — | Full webhook JSON |
| `mapped_location` | String | YES | NULL | YES | → `monitored_locations.name` |
| `received_at` | DateTime | NO | `utcnow` | YES | Ingestion time |
| `resolved_at` | DateTime | YES | NULL | YES | Resolution time |
| `is_dispatched` | Boolean | NO | `False` | YES | RCA ticket created |
| `is_ticketed` | Boolean | NO | `False` | YES | Email ticket sent |
| `is_correlated` | Boolean | NO | `False` | YES | AIOps engine matched |
| `ai_root_cause` | Text | YES | NULL | — | AI-generated RCA |
| `device_type` | String | NO | `"Unknown"` | YES | Router/Switch/etc |
| `event_category` | String | NO | `"Unknown"` | — | Category bucket |
| `acknowledged_by` | String | YES | NULL | — | User who acknowledged |
| `acknowledged_at` | DateTime | YES | NULL | — | — |
| `dispatched_by` | String | YES | NULL | — | User who dispatched |
| `dispatched_at` | DateTime | YES | NULL | — | — |

### 2.22 `timeline_events` — Unified Event Timeline

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `timestamp` | DateTime | NO | `utcnow` | YES | — |
| `source` | String | NO | — | YES | Origin system |
| `event_type` | String | NO | — | YES | Event classification |
| `message` | String | NO | — | — | Human-readable message |

### 2.23 `monitored_locations` — Facility/Site Registry (19 columns)

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `name` | String | NO | — | YES (unique) | UNIQUE — site identifier |
| `lat` | Float | NO | — | — | Latitude |
| `lon` | Float | NO | — | — | Longitude |
| `loc_type` | String | NO | `"General"` | YES | Site type |
| `district` | String | NO | `"Central"` | YES | Operational district |
| `priority` | String | NO | `"P3-Moderate"` | YES | P1-Critical … P5-Planning |
| `current_spc_risk` | String | NO | `"None"` | — | SPC outlook risk |
| `last_updated` | DateTime | NO | `utcnow` | — | — |
| `under_maintenance` | Boolean | NO | `False` | — | Maintenance flag |
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
| `category` | String | NO | — | — | Crime type |
| `raw_title` | String | NO | — | — | Original incident title |
| `timestamp` | DateTime | NO | — | YES | Incident time |
| `distance_miles` | Float | NO | — | — | Distance from HQ |
| `severity` | String | NO | — | — | — |
| `lat` | Float | NO | — | — | — |
| `lon` | Float | NO | — | — | — |
| `is_alert_dispatched` | Boolean | NO | `False` | YES | Alert sent |

### 2.25 `geojson_cache` — GeoJSON Layer Cache

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `feed_name` | **String** | NO | — | PK | **String PK** — no Integer id |
| `data` | JSON | NO | — | — | GeoJSON FeatureCollection |
| `updated_at` | DateTime | NO | `utcnow` | — | — |

### 2.26 `node_aliases` — Node Name → Site Mapping

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `node_pattern` | String | NO | — | YES | Regex/glob pattern |
| `mapped_location_name` | String | NO | — | — | → `monitored_locations.name` |
| `confidence_score` | Float | NO | `0.0` | — | Mapping confidence |
| `is_verified` | Boolean | NO | `False` | — | Manual verification |

### 2.27 `user_weather_prefs` — User Weather Alert Preferences

| Column | Type | Nullable | Default | Index | Constraints |
|---|---|---|---|---|---|
| `id` | Integer | NO | autoincrement | PK | PRIMARY KEY |
| `username` | String | NO | — | YES | → `users.username` |
| `alert_type` | String | NO | — | — | Weather alert type |

---

## 3. Schema Evolution Strategy

This project uses **no Alembic, no migration framework**. All schema changes are managed via inline `ALTER TABLE` statements in `src/core/db.py:init_db()`.

### Pattern

Every new column added since the original `create_all` is guarded by a try/except that silently catches `"duplicate column name"` errors:

```python
try:
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text("ALTER TABLE target_table ADD COLUMN new_col TYPE DEFAULT value"))
except Exception:
    pass  # Column already exists
```

### Rules for Adding Columns

1. **Each ALTER TABLE adds exactly one column.** SQLite does not support `ADD COLUMN a, ADD COLUMN b` in a single statement.
2. **Always provide a DEFAULT.** Existing rows must have a value — SQLite requires this for non-nullable columns.
3. **Wrap in try/except.** Duplicate ALTER is idempotent via the exception swallow.
4. **Place before `Base.metadata.create_all()`** for critical columns needed by API queries at startup.
5. **Test both fresh DB and existing DB paths.** Fresh DBs get the column from `create_all`; existing DBs get it from ALTER.
6. **Never DROP columns.** SQLite supports `ALTER TABLE ... DROP COLUMN` only since 3.35.0 (2021). If a column must be removed, leave it unused.

### Adding a New Table

Tables are created automatically by `Base.metadata.create_all()`. No manual DDL is needed — just define the SQLAlchemy model in `schema.py` and it appears on next restart.

### Adding a New Index

Add `index=True` to the Column definition in `schema.py`. On existing databases, `create_all()` does **not** add missing indexes. To add an index to an existing table:

```python
try:
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_target_col ON target_table (column_name)"))
except Exception:
    pass
```

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

| Table | Column(s) | Index Type | Purpose |
|---|---|---|---|
| `users` | `username` | UNIQUE | Login lookup |
| `users` | `role` | B-tree | Role-based queries |
| `users` | `session_token` | B-tree | Session validation |
| `roles` | `name` | UNIQUE | Role lookup |
| `articles` | `link` | UNIQUE | Dedup on ingest |
| `articles` | `published_date` | B-tree | Time-range queries |
| `articles` | `source` | B-tree | Source filtering |
| `articles` | `score` | B-tree | Top-N scoring |
| `articles` | `category` | B-tree | Category filtering |
| `articles` | `is_pinned` | B-tree | Pinned filter |
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

### SQLite PRAGMA Optimizations

Applied on every connection via the `@event.listens_for(engine, "connect")` handler:

| PRAGMA | Value | Purpose |
|---|---|---|
| `journal_mode` | WAL | Write-ahead logging for concurrent reads |
| `synchronous` | NORMAL | Reduced fsync (WAL ensures crash safety) |
| `cache_size` | -16000 | 16 MB page cache |
| `temp_store` | MEMORY | Temp tables in RAM |
| `mmap_size` | 268435456 | 256 MB memory-mapped I/O |

---

## 5. init_db() Initialization Sequence

`init_db()` in `src/core/db.py` executes in this exact order on every API/container startup:

### Phase 1 — Pre-create ALTER TABLE migrations (lines 46–48)

Runs **before** `create_all()` so that queries during startup don't fail on missing columns:

```
ALTER TABLE system_config ADD COLUMN alerted_eq_ids TEXT DEFAULT '[]'
```

### Phase 2 — Create all tables (line 53)

```python
Base.metadata.create_all(bind=engine)
```

Creates all tables defined in `schema.py` that don't already exist. Idempotent.

### Phase 3 — Post-create ALTER TABLE migrations (lines 58–197)

Adds columns to existing tables that were created before the column was added to the model. Each is individually try/except guarded:

| Order | Table | Columns Added |
|---|---|---|
| 1 | `roles` | `allowed_site_types JSON` |
| 2 | `solarwinds_alerts` | `is_dispatched BOOLEAN DEFAULT 0` |
| 3 | `monitored_locations` | `district VARCHAR DEFAULT 'Central'` |
| 4 | `shift_logs` | `author_role VARCHAR DEFAULT 'analyst'` |
| 5 | `system_config` | `baseline_override_cyber FLOAT DEFAULT 0.0`, `baseline_override_phys FLOAT DEFAULT 0.0` |
| 6 | `monitored_locations` | `under_maintenance BOOLEAN DEFAULT 0`, `maintenance_etr DATETIME`, `maintenance_reason TEXT` |
| 7 | `monitored_locations` | `status_modified_by VARCHAR`, `status_modified_at DATETIME`, `last_auto_ticket DATETIME`, `last_escalation_ticket DATETIME`, `last_auto_dispatch DATETIME`, `last_escalation_dispatch DATETIME` |
| 8 | `user_weather_prefs` | Full table + index (CREATE TABLE IF NOT EXISTS) |
| 9 | `shift_logs` | `is_deleted BOOLEAN DEFAULT 0` |
| 10 | `system_config` | `unified_brief TEXT`, `unified_brief_time DATETIME` |
| 11 | `users` | `default_shift VARCHAR DEFAULT 'No Shift'` |
| 12 | `crime_incidents` | `is_alert_dispatched BOOLEAN DEFAULT 0` |
| 13 | `system_config` | `last_global_risk VARCHAR`, `last_internal_risk VARCHAR`, `last_risk_alert_time DATETIME`, `sys_countermeasures INTEGER DEFAULT 3`, `net_countermeasures INTEGER DEFAULT 3` |
| 14 | `solarwinds_alerts` | `is_ticketed BOOLEAN DEFAULT 0`, `acknowledged_by VARCHAR`, `acknowledged_at DATETIME`, `dispatched_by VARCHAR`, `dispatched_at DATETIME` |
| 15 | `system_config` | `scoring_mode VARCHAR DEFAULT 'auto'`, `cyber_criticality_override INTEGER DEFAULT 0`, `cyber_lethality_override INTEGER DEFAULT 0`, `physical_criticality_override INTEGER DEFAULT 0`, `physical_lethality_override INTEGER DEFAULT 0`, `internal_criticality_override INTEGER DEFAULT 0`, `internal_lethality_override INTEGER DEFAULT 0`, `global_risk_offset INTEGER DEFAULT 0`, `internal_risk_offset INTEGER DEFAULT 0` |
| 16 | `system_config` | `llm_context_window INTEGER DEFAULT 128000` |

### Phase 4 — Data migration (lines 199–213)

Migrates `monitored_locations.priority` from Integer encoding to String encoding (`1` → `"P1-Critical"`, etc.).

### Phase 5 — Seed default roles (lines 215–273)

Creates `admin` and `analyst` roles with full page/action permission arrays. Creates `admin` user if `DEFAULT_ADMIN_PASSWORD` env var is set and no users exist.

**Default admin credentials:** `admin` / value of `DEFAULT_ADMIN_PASSWORD` (or `admin123` if unset).

### Phase 6 — Seed RSS feeds (lines 276–299)

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

### Phase 7 — Seed keywords (lines 301–340)

Seeds 70 security-weighted keywords (weight range 30–90). Key examples:

| Keyword | Weight | Keyword | Weight |
|---|---|---|---|
| `ransomware` | 90 | `lockbit` | 85 |
| `breach` | 85 | `blackcat` | 85 |
| `zero-day` | 85 | `log4shell` | 85 |
| `rce` | 80 | `cobalt strike` | 80 |
| `apt` | 80 | `log4j` | 80 |

### Phase 8 — Seed SystemConfig (lines 342–351)

Creates a single default `SystemConfig` row if none exists.

### Phase 9 — Rescore all articles (lines 353–358)

Calls `rescore_all_articles()` to recompute `articles.score` using the (potentially newly seeded) keyword dictionary. **This is why keyword changes require an API rebuild.**

---

## 6. Key Design Decisions

### No Formal Foreign Key Constraints

The schema deliberately avoids SQLAlchemy `ForeignKey` declarations and SQLite `PRAGMA foreign_keys`. Reasons:

- **Simplicity for SQLite:** FK enforcement adds locking overhead on SQLite's single-writer model.
- **Flexibility for logical joins:** Many relationships are by name string (`node_name` → `monitored_locations.name`), not integer ID, making formal FKs impractical.
- **Orphan cleanup via scheduler:** The hourly `db_maintenance` job runs `DELETE FROM extracted_iocs WHERE article_id NOT IN (SELECT id FROM articles)` to handle orphaned rows.

### JSON Columns for Flexible Data

Used in three tables:

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

`NullPool` disables connection pooling entirely. Each request opens/closes a fresh connection. This prevents `QueuePool` contention issues observed under concurrent FastAPI workers and the background scheduler writing to the same SQLite file. For PostgreSQL deployments, `NullPool` should be replaced with `QueuePool` or `AsyncAdaptedQueuePool`.

### String Primary Keys

Two tables use String PKs instead of autoincrement Integer:

| Table | PK | Source |
|---|---|---|
| `elastic_events` | `id` (String) | Elasticsearch document `_id` |
| `crime_incidents` | `id` (String) | External API incident ID |
| `geojson_cache` | `feed_name` (String) | Feed identifier (singleton per feed) |

### Singleton Pattern — `system_config`

Only one row is ever inserted. The entire application reads/writes this single row for all configuration state. This avoids a key-value table but limits the schema to a fixed set of configuration parameters.

### Soft Delete — `shift_logs`

Shift log entries use `is_deleted = True` rather than physical deletion. The API filters `is_deleted == False` by default. The `content` is preserved for audit but hidden from summaries.

### Timestamp Conventions

All timestamps are stored as UTC `datetime` objects. The frontend converts to `America/Chicago` via `web/src/utils/timezone.ts`. The `sw_timestamp` column in `solarwinds_alerts` is stored as a raw **String** from the webhook payload (not parsed to DateTime) to preserve the original format.

---

## 7. Data Retention Policies

All retention is enforced by the **hourly `db_maintenance` scheduler job** (`src/scheduler.py:db_maintenance`) and individual worker purge functions.

### Centralized Maintenance (`db_maintenance` — runs every 60 min)

| Table | Retention Rule | SQL Logic |
|---|---|---|
| `articles` | **Unpinned score < 50 older than 3 days:** delete | `WHERE score < 50 AND published_date < now()-3d AND is_pinned = False` |
| `articles` | **Unpinned > 30 days:** delete | `WHERE published_date < now()-30d AND is_pinned = False` |
| `solarwinds_alerts` | **> 60 days:** delete | `WHERE received_at < now()-60d` |
| `regional_hazards` | **> 48 hours:** delete | `WHERE updated_at < now()-48h` |
| `regional_outages` | **> 12 hours:** delete | `WHERE detected_at < now()-12h` |
| `bgp_anomalies` | **> 12 hours:** delete | `WHERE detected_at < now()-12h` |
| `cve_items` | **> 7 days:** delete | `WHERE date_added < now()-7d` |
| `cloud_outages` | **All resolved > 24 hours:** delete | `WHERE updated_at < now()-24h` |
| `cloud_outages` | **Unresolved > 14 days:** delete | `WHERE is_resolved=False AND updated_at < now()-14d` |
| `crime_incidents` | **> 7 days:** delete | `WHERE timestamp < now()-7d` |
| `extracted_iocs` | **Orphaned (no parent article):** delete | `WHERE article_id NOT IN (SELECT id FROM articles)` |
| `internal_risk_snapshots` | **> 90 days:** delete | `WHERE timestamp < now()-90d` |
| `timeline_events` | **> 90 days:** delete | `WHERE timestamp < now()-90d` |
| `elastic_events` | **> 72 hours:** delete | `WHERE timestamp < now()-72h` |

### Worker-Specific Purge

| Worker | Table | Retention Rule |
|---|---|---|
| `cloud_worker` | `cloud_outages` | Resolved > 3 days (additional purge on ingest) |
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
| `internal_risk_snapshots` | Historical time series — 90-day retention |
| `daily_briefings` | Historical — one per day, retained |
| `daily_threat_scores` | Historical time series — no purge |
| `monitored_locations` | Persistent site registry |
| `node_aliases` | Persistent mapping table |
| `user_weather_prefs` | Persistent user preferences |
| `timeline_events` | 90-day retention |
| `geojson_cache` | Overwritten on each fetch, not purged |
