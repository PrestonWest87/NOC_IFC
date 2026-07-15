# NOC Intelligence Fusion Center — Services Layer

Enterprise-grade backend services powering the NOC Intelligence Fusion Center. This document covers every module under `src/services/` and `src/utils/`, including core utilities, database access, scoring engines, threat intelligence, and operational infrastructure.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [src/services.py — Data Access Layer](#srcservicespy--data-access-layer)
- [src/services/logic.py — Hybrid Scorer](#srcserviceslogicpy--hybrid-scorer)
- [src/services/categorizer.py — Article Categorizer](#srcservicescategorizerpy--article-categorizer)
- [src/services/ioc_extractor.py — Enterprise IOC Extractor](#srcservicesioc_extractorpy--enterprise-ioc-extractor)
- [src/services/threat_hunter.py — Legacy IOC Extractor](#srcservicesthreat_hunterpy--legacy-ioc-extractor)
- [src/services/aiops_engine.py — Enterprise AIOps Engine](#srcservicesaiops_enginepy--enterprise-aiops-engine)
- [src/utils/llm.py — LLM Interaction](#srcutilsllmpy--llm-interaction)
- [src/utils/mailer.py — Email Sender](#srcutilsmailerpy--email-sender)
- [src/utils/risk_alert.py — Risk Alerting](#srcutilsrisk_alertpy--risk-alerting)
- [src/core/config.py — Settings](#srccoreconfigpy--settings)
- [src/core/db.py — Database Core](#srccoredbpy--database-core)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         API Layer (FastAPI)                         │
│                     src/api/main.py + routes/                       │
├────────────┬────────────┬────────────┬──────────┬──────────────────┤
│ services.py│  logic.py  │ aiops_     │ ioc_     │ threat_          │
│  (DAL)     │ (scorer)   │ engine.py  │ extractor│ hunter.py        │
├────────────┴────────────┴────────────┴──────────┴──────────────────┤
│                     utils/ (llm, mailer, risk_alert)                │
├─────────────────────────────────────────────────────────────────────┤
│                     core/ (config, db — SQLAlchemy)                 │
├─────────────────────────────────────────────────────────────────────┤
│                     SQLite / PostgreSQL                             │
└─────────────────────────────────────────────────────────────────────┘
```

**Data flow**: API routes call into `services.py` (the central DAL) for most operations. Specialized engines (`aiops_engine`, `ioc_extractor`, `logic`) handle domain-specific processing. `utils/` provides cross-cutting concerns (LLM, email, alerting). `core/` manages configuration and database connectivity.

---

## src/services.py — Data Access Layer

**Location**: `src/services.py`  
**Size**: ~3,270+ lines  
**Role**: The central Data Access Layer. Every major feature routes through this module. Organized into 13 functional sections.

### Core Utilities

| Function/Class | Description |
|---|---|
| `TTLCache` | Decorator implementing time-to-live caching with configurable TTL buckets (300s, 600s, 86400s). Thread-safe via `functools.lru_cache` wrapper with manual invalidation. |
| `DotDict` | Dictionary subclass supporting attribute-style access (`d.key` instead of `d["key"]`). Used extensively for passing structured data between layers. |
| `sanitize_text(text)` | Strips PII, control characters, and normalizes unicode from user-supplied text before storage. |
| `priority_tier(score)` | Maps a numeric CIS score to a risk tier label (GREEN/BLUE/YELLOW/ORANGE/RED) based on threshold boundaries. |
| Timezone helpers | `now_cst()`, `format_cst()`, `utc_now()` — Central Time formatting utilities used throughout the frontend and backend for consistent timestamps. |

### Cached Functions

High-frequency lookup functions wrapped in `TTLCache` for performance.

| Function | TTL | Purpose |
|---|---|---|
| `get_cached_config()` | 300s (5 min) | Global configuration from DB. Refreshes every 5 minutes to pick up admin changes without polling. |
| `get_cached_locations()` | 600s (10 min) | All monitored locations. Slower refresh since site topology changes infrequently. |
| `get_cached_geojson()` | 120s (2 min) | GeoJSON feature collection for the regional map. Tight TTL to reflect live hazard overlays. |
| `get_ar_counties_mapping()` | 86400s (24h) | Arkansas county FIPS → name mapping. Static reference data, cached for full day. |
| `get_regional_counties_mapping()` | 86400s (24h) | Multi-state county mapping for regional coverage. Same 24h cache strategy. |

### Auth & Users

| Function | Description |
|---|---|
| `authenticate_user(username, password)` | Validates credentials via bcrypt hash comparison. On success, generates a UUID4 token, stores it in the `users` table, and returns the token. |
| `get_user_by_token(token)` | Resolves a bearer token to a full user record including role, permissions, and allowed site types. Returns `None` for expired/invalid tokens. |
| `update_user_profile(user_id, updates)` | Partial update of user fields (name, title, email). Validates uniqueness constraints on email. |
| `logout_user(token)` | Invalidates a session token by clearing the stored hash. |

### Dashboard

| Function | Description |
|---|---|
| `get_dashboard_metrics()` | Aggregated counts: total articles, active alerts, site statuses, risk levels. Powers the top-level dashboard cards. |
| `get_pinned_articles(user_id)` | Returns pinned articles for a specific user. Supports per-operator intelligence bookmarking. |
| `get_live_articles(limit, offset)` | Time-ordered article feed with pagination. Excludes archived and deduplicated entries. |
| `toggle_pin(article_id, user_id)` | Add/remove a pin bookmark. Returns new pinned state. |
| `boost_score(article_id, weight)` | Manual score boost for operator-driven training. Multiplies existing score by the weight factor. |
| `change_status(article_id, new_status)` | Operator status change (e.g., `new` → `reviewed` → `dismissed`). Triggers keyword weight training when dismissing false positives. |

### CIS Scoring

The **Composite Intelligence Score** system — the analytical core of the platform.

#### `get_executive_grid_intel()` (~270 lines)

The core CIS algorithm for external threat intelligence. Performs:

1. **Ingestion** — Pulls recent articles, CVEs, cloud outages, crime incidents, and weather hazards.
2. **Domain mapping** — Classifies each item into one of 7 infrastructure domains.
3. **Weighted aggregation** — Applies configurable weights per domain and threat type.
4. **Temporal decay** — Older items receive reduced weight based on age.
5. **Cross-domain correlation** — Detects multi-domain attack patterns (e.g., power + comms simultaneous disruption).
6. **Score normalization** — Produces a 0–100 composite score per monitored site.
7. **Tier assignment** — Maps score to GREEN/BLUE/YELLOW/ORANGE/RED risk tier.

#### `calculate_internal_cis_score()` (~330 lines)

A **5-phase pipeline** for internal infrastructure risk scoring:

| Phase | Name | Purpose |
|---|---|---|
| 1 | **Asset Inventory** | Counts hardware/software assets per site. Sites with no inventory are flagged. |
| 2 | **Vulnerability Exposure** | Matches CVEs to known asset software versions. Calculates exposure ratio. |
| 3 | **Operational Health** | Analyzes alert history, maintenance windows, and uptime metrics. |
| 4 | **Environmental Factors** | Incorporates weather hazards, geographic risk, and seismic activity. |
| 5 | **Composite Fusion** | Fuses all phases with configurable weights. Produces final internal CIS score and tier. |

#### `generate_and_save_internal_risk_snapshot()`

Persists a point-in-time risk snapshot to the database. Used for historical trending and trend-line analysis on dashboards.

### Unified Brief

| Function | Description |
|---|---|
| `trigger_unified_brief(progress_callback)` | Orchestrates the map-reduce briefing pipeline. Accepts an optional callback for real-time progress updates via WebSocket. Feeds 30 cyber articles, 20 physical articles, 20 crimes, 20 HW/SW assets, and DB telemetry into a multi-stage LLM pipeline. |
| `generate_unified_brief_email_html(data)` | Produces a rich HTML email template for the executive brief. Includes CIS alert level names (not color codes), Cyber Security Director signature line, and operational formatting aligned with the main branch. |

### Threat Intelligence

| Function | Description |
|---|---|
| `get_paginated_articles(page, per_page, category, search)` | Server-side paginated article list with optional category filter and full-text search. |
| `get_cves(limit, severity)` | Recent CVEs from NVD feed. Filterable by severity (CRITICAL/HIGH/MEDIUM/LOW). |
| `get_cloud_outages(limit)` | Active cloud provider outages (AWS, Azure, GCP). Time-ordered, deduplicated. |
| `get_recent_crimes(limit)` | Recent crime incidents from the crime data feed. Proximity-sorted by monitored sites. |
| `get_hazards(limit)` | Active NWS weather hazards. Includes fire, flood, tornado, and winter storm alerts. |

### Regional Grid

| Function | Description |
|---|---|
| `process_nws_alerts(raw_alerts)` | Normalizes NWS alert JSON into internal hazard format. Deduplicates by event ID, extracts affected zones, and assigns severity tiers. |
| `get_weather_alerts_log()` | Returns the persisted weather alert history for logbook and dashboard display. |
| `calculate_site_intersections(hazards, locations)` | **Bounding-box optimized** spatial intersection. Checks if any monitored site falls within a hazard's geographic extent. Returns intersecting site-hazard pairs with distance calculations. |
| `get_infrastructure_analytics()` | Aggregate infrastructure health metrics across all sites: alert counts by domain, maintenance status, fleet-level trends. |
| `_precompute_geo_matrix()` | Precomputes a site-to-site distance matrix for cluster detection and proximity analysis. Cached in memory. |
| `compile_regional_grid_map()` | The master map compilation function. Returns `[layers[], viewState{}, diagnostics[], toggled_affected[], master_affected[], analytics{}]` — a 6-element array consumed by the frontend `MapContainer`. |
| `_hazard_color(severity)` | Maps hazard severity to a display color (green/yellow/orange/red). |
| `get_active_wildfires()` | Fetches and filters active wildfire perimeters from NIFC. Returns GeoJSON polygons with fire size and containment data. |

### IOC / Hunting

| Function | Description |
|---|---|
| `get_iocs(limit, type_filter, confidence_min)` | Returns extracted IOCs with optional type and confidence filtering. |
| `search_articles_for_hunting(query, date_range)` | Full-text article search scoped to the threat hunting workflow. Returns matching articles with highlighted context windows. |
| `get_osint_pivot_link(ioc_value, ioc_type)` | Generates a contextual OSINT pivot URL for a given IOC (e.g., VirusTotal for IPs, MITRE for CVEs, Shodan for domains). |

### AIOps RCA

| Function | Description |
|---|---|
| `get_aiops_dashboard_data()` | Returns the full AIOps board state: active clusters, site statuses, maintenance windows, and correlation metadata. |
| `acknowledge_cluster(cluster_id, user)` | Marks an alert cluster as acknowledged by an operator. Records `status_modified_by` and `status_modified_at`. |
| `generate_global_sitrep()` | Produces a global situation report from all active alert clusters. Uses LLM for narrative generation with structured data injection. |
| `generate_rca_ticket_text(cluster_data)` | Ported from main branch. Generates dynamic RCA dispatch ticket text with domain-aware formatting, compact alerts, district line, and trigger time. |
| `set_cluster_dispatch(cluster_id, user)` | Transitions cluster to DISPATCHED status. Records operator identity and timestamp. |
| `set_site_maintenance(site_name, user, reason)` | Toggles maintenance mode for a site. Maintenance is **sticky** — must be manually cleared, not auto-removed. |

### Reporting

| Function | Description |
|---|---|
| `get_saved_reports(user_id)` | Returns all saved custom reports for a user, ordered by creation date. |
| `save_custom_report(user_id, report_data)` | Persists a custom report configuration (filters, layout, schedule). |
| `generate_daily_report_email_html(report_data)` | Produces the daily fusion report email template. Includes article summaries, risk scores, and operational metrics. |

### Settings

Full administrative CRUD for system configuration.

| Function | Description |
|---|---|
| `get_all_roles()` | Returns all roles with their permission sets. |
| `create_role(name, permissions)` / `update_role(role_id, updates)` | Role management with permission bitmask. |
| `create_user(username, password, role_id, ...)` | User creation with bcrypt hashing, role assignment, and site-type scoping. |
| `force_reset_pwd(user_id, new_password)` | Admin password reset. Bypasses current password verification. |
| `update_user_role(user_id, role_id)` | Role reassignment. Validates the new role exists and permissions are valid. |
| `save_global_config(key, value)` | Upserts a global configuration key. Cached functions auto-invalidate on change. |
| `add_bulk_keywords(keyword_list)` | Batch insert keywords for the hybrid scorer. Deduplicates by keyword text. |
| `update_keyword_weight(keyword_id, weight)` | Adjusts individual keyword weight for scorer training. |
| `add_bulk_feeds(feed_list)` | Batch insert RSS feed URLs. Validates URL format and checks for duplicates. |
| `delete_record(table, record_id)` | Generic soft/hard delete for any managed table. Respects foreign key constraints. |
| `get_admin_lists()` | Returns all admin-managed lists (keywords, feeds, roles, users) for the Settings page. |
| `backup_database()` / `restore_database(backup_path)` | SQLite backup/restore. Creates a file-system copy of the database file. |
| `export_data(table)` / `import_data(table, data)` | JSON export/import for individual tables. Used for data migration and disaster recovery. |
| `restore_from_db_upload(upload_path)` | Restores from a user-uploaded database file. Validates integrity before swapping. |

### Maintenance

| Function | Description |
|---|---|
| `recategorize_all_articles()` | Re-runs the categorizer on all articles. Used after category pattern updates. |
| `rescore_all_articles()` | Re-runs the hybrid scorer on all articles. Used after keyword weight changes or model retrain. |
| `nuke_tables(table_list)` | **Destructive** — truncates specified tables. Requires confirmation token. |
| `nuke_crime_data()` | Clears all crime incident data. Separate from general nuke for safety. |
| `nuke_weather_data()` | Clears all weather/hazard data. Separate from general nuke for safety. |
| `deduplicate_articles()` | Removes duplicate articles by content hash. Runs as part of the DB maintenance scheduler job (60 min interval). |

---

## src/services/logic.py — Hybrid Scorer

**Location**: `src/services/logic.py`  
**Size**: ~76 lines  
**Role**: Keyword weight + ML model scoring engine. The primary relevance scoring mechanism for all ingested articles.

### Classes

#### `HybridScorer`

An additive scoring engine combining deterministic keyword matching with a trained ML model.

```python
class HybridScorer:
    def __init__(self):
        self.keywords = {}      # {keyword_text: weight} loaded from DB
        self.ml_model = None    # Trained model loaded from disk (pickle/joblib)

    def score(self, text: str) -> float:
        """Returns combined score: keyword_match + ML_adjustment"""
        keyword_score = sum(weight for kw, weight in self.keywords.items() if kw.lower() in text.lower())
        ml_adjustment = self._predict(text)  # boost/penalty/synergy from ML
        return keyword_score + ml_adjustment
```

**Scoring breakdown:**
- **Keyword matching**: Additive — each matching keyword contributes its configured weight. Loaded from the `keywords` table on init.
- **ML adjustment**: The trained model predicts a boost (positive) or penalty (negative) based on contextual analysis. The ML component uses synergy detection — keyword + ML signals combined produce a stronger signal than either alone.

### Module Functions

| Function | Description |
|---|---|
| `get_scorer()` | Singleton accessor. Returns the global `HybridScorer` instance. Creates it on first call. |
| `force_reload_scorer()` | Hot-reloads the scorer with fresh keywords from DB and reloaded ML model from disk. Called after keyword weight updates or scheduled ML retrain (Sunday 02:00). |

---

## src/services/categorizer.py — Article Categorizer

**Location**: `src/services/categorizer.py`  
**Size**: ~46 lines  
**Role**: Rule-based article categorization using regex pattern matching.

### Data

#### `CATEGORIES` dict

8 categories, each with a list of compiled regex patterns:

| Category | Example Patterns |
|---|---|
| `cybersecurity` | `ransomware`, `phishing`, `CVE-\d+`, `zero-day`, `APT\d+` |
| `infrastructure` | `power grid`, `substation`, `SCADA`, `OT network` |
| `weather` | `tornado`, `hurricane`, `flood warning`, `blizzard` |
| `crime` | `shooting`, `robbery`, `arson`, `active shooter` |
| `geopolitical` | `sanctions`, `nation-state`, `cyber espionage` |
| `supply_chain` | `supply chain`, `logistics`, `port closure` |
| `health` | `pandemic`, `outbreak`, `biohazard` |
| `general` | Catch-all for uncategorized content |

### Functions

| Function | Description |
|---|---|
| `categorize_text(text)` | Counts regex pattern matches per category. Returns the category with the highest match count. Returns `"general"` if no patterns match or the text is empty. |

---

## src/services/ioc_extractor.py — Enterprise IOC Extractor

**Location**: `src/services/ioc_extractor.py`  
**Size**: ~150 lines  
**Role**: High-fidelity IOC extraction with de-obfuscation and context preservation.

### Class: `EnterpriseIOCExtractor`

Extracts **18 IOC types** across 5 categories:

| Category | IOC Types |
|---|---|
| **Network** | IPv4, IPv6, Domain, URL, CIDR Range |
| **Host** | File Hash (MD5/SHA1/SHA256), Filename, Registry Key, Mutex |
| **Actor Infrastructure** | C2 Server, Tor Exit Node, APT Alias |
| **Cloud/DevOps** | AWS Access Key, Azure Tenant, GCP Project |
| **Taxonomy** | CVE, MITRE ATT&CK ID, Malware Family |

### Methods

| Method | Description |
|---|---|
| `__init__(self)` | Compiles all 18 regex patterns. Initializes IPv4 whitelist (RFC 1918, loopback, multicast). |
| `refang_payload(text)` | De-obfuscates common evasion techniques: `hxxp` → `http`, `[.]` → `.`, `[@]` → `@`, `DOT` → `.`. Applied before regex matching. |
| `extract(text)` | Main extraction pipeline: refang → regex match all 18 rules → deduplicate by (type, value) → normalize (lowercase domains, uppercase hashes) → attach context window (±100 chars around each match). Returns list of IOC dicts with `{type, value, context, confidence}`. |

### Dependencies

- `re` (compiled patterns)
- No external libraries — pure Python regex extraction

---

## src/services/threat_hunter.py — Legacy IOC Extractor

**Location**: `src/services/threat_hunter.py`  
**Size**: ~70 lines  
**Role**: Simplified IOC extraction for the threat hunting UI. Retained for backward compatibility and fast extraction without context windows.

### Supported IOC Types (8)

`ip_address`, `domain`, `url`, `email`, `file_hash_md5`, `file_hash_sha1`, `file_hash_sha256`, `cve_id`

### Functions

| Function | Description |
|---|---|
| `extract_all_iocs(raw_text)` | Regex-based extraction for 8 IOC types. Returns a list of `{type, value}` dicts. No deduplication, no context windows, no de-obfuscation — intentionally lightweight. |

### Comparison with EnterpriseIOCExtractor

| Feature | Legacy (`threat_hunter`) | Enterprise (`ioc_extractor`) |
|---|---|---|
| IOC types | 8 | 18 |
| De-obfuscation | No | Yes (refang) |
| Context windows | No | Yes (±100 chars) |
| Deduplication | No | Yes |
| Confidence scoring | No | Yes |
| Cloud/DevOps IOCs | No | Yes |

---

## src/services/aiops_engine.py — Enterprise AIOps Engine

**Location**: `src/services/aiops_engine.py`  
**Size**: ~402 lines  
**Role**: Multi-stage correlation engine for operational incident analysis, root cause determination, and fleet-wide pattern detection.

### Class: `EnterpriseAIOpsEngine`

#### Constants

```python
ONTOLOGY = {
    "POWER_SUPPLIES": ["ups", "generator", "pdu", "power", "electrical"],
    "COMMS_EQUIPMENT": ["router", "switch", "firewall", "comm", "network"],
    "PRIMARY_INTERNET": ["internet", "wan", "backhaul", "isp", "fiber"],
    "RTU": ["rtu", "remote terminal", "telemetry unit"],
    "SCADA": ["scada", "hmi", "plc", "supervisory"],
    "COMPUTE": ["server", "compute", "vm", "host", "cpu"],
    "FACILITIES": ["facility", "building", "hvac", "physical", "site"],
}

TIER_RANKING = {
    "POWER_SUPPLIES": 1,    # Highest priority — power loss cascades
    "COMMS_EQUIPMENT": 2,
    "PRIMARY_INTERNET": 3,
    "RTU": 4,
    "SCADA": 5,
    "COMPUTE": 6,
    "FACILITIES": 7,         # Lowest priority
}
```

#### Methods

| Method | Description |
|---|---|
| `_get_domain(node_type, node_name)` | Classifies a node into one of 7 infrastructure domains using keyword matching against the ONTOLOGY. Falls back to `FACILITIES` for unrecognized types. |
| `_determine_patient_zero(alerts)` | **Patient-zero tier scoring** — analyzes alert topology, severity, and temporal ordering to identify the originating incident. Uses a weighted scoring model that favors early-occurring, high-severity alerts in higher-priority domains. |
| `identify_fleet_outages(incidents, threshold=5)` | Groups incidents by provider. When `threshold` or more sites sharing a provider are affected simultaneously, flags it as a fleet outage. Returns fleet-level impact analysis. |
| `generate_chronic_insights()` | 60-day historical analysis. Identifies recurring patterns: repeated failures at the same site, seasonal trends, chronic underperformers. Produces actionable insights for maintenance planning. |
| `calculate_root_cause(site_name, data, ...)` | **7-stage correlation chain**: (1) gather all alerts, (2) determine patient zero, (3) map to ontology domains, (4) check cascade dependencies, (5) cross-reference with maintenance history, (6) evaluate environmental factors, (7) produce root cause hypothesis with confidence score. |
| `analyze_and_cluster(active_alerts)` | **Entry point** for the AIOps board. Groups raw alerts by site, runs clustering, and returns structured cluster data with correlation metadata, patient-zero identification, and recommended actions. |

### Domain Cascade Model

The engine models infrastructure dependencies as a directed acyclic graph:

```
POWER_SUPPLIES → COMPUTE → RTU → SCADA
       ↓              ↓
COMMS_EQUIPMENT → PRIMARY_INTERNET
       ↓
FACILITIES
```

A failure in `POWER_SUPPLIES` (tier 1) will cascade to downstream domains. The engine detects cascade patterns and identifies the root domain to prevent misattribution.

### Dependencies

- `src/services.py` (DAL for alert and site data)
- `src/services/categorizer.py` (for incident classification)

---

## src/utils/llm.py — LLM Interaction

**Location**: `src/utils/llm.py`  
**Size**: ~800+ lines  
**Role**: Unified LLM interface supporting OpenAI API-compatible and Ollama models. Manages context windows, map-reduce summarization, and all AI-generated content.

### Data Structures

#### `_brief_progress_store`

Thread-safe in-memory store for tracking async brief generation progress. Updated via callbacks and consumed by WebSocket for real-time frontend display.

```python
_brief_progress_store = {
    "stage": "fetching_data",       # Current pipeline stage
    "progress": 0.35,               # 0.0 – 1.0
    "message": "Processing cyber articles...",
    "started_at": datetime,
    "completed": False,
    "error": None,
}
```

#### `MODEL_CONTEXT_WINDOWS`

| Model | Context Window |
|---|---|
| GPT-4o | 128,000 tokens |
| GPT-4o-mini | 128,000 tokens |
| GPT-3.5-turbo | 16,385 tokens |
| Llama 3 (Ollama) | 8,192 tokens |
| Mistral (Ollama) | 32,768 tokens |
| Custom Ollama | Configurable via env |

### Core Functions

| Function | Description |
|---|---|
| `call_llm(messages, config)` | Flexible LLM call. Automatically selects endpoint (OpenAI API vs local Ollama), manages context window truncation, handles retries with exponential backoff. Returns parsed response or raises on failure. |
| `_map_reduce_summarize(items, chunk_size, overlap, per_chunk_callback)` | Map-reduce pipeline for processing data that exceeds the model's context window. Chunks input items, summarizes each chunk in parallel, then fuses chunk summaries into a final output. Supports per-chunk progress callbacks. |

### Generation Functions

| Function | Stage Pipeline | Description |
|---|---|---|
| `generate_unified_risk_brief(data, progress_callback)` | 5 stages | The main executive briefing generator. Stages: (1) fetch data, (2) chunk and summarize, (3) generate cyber narrative, (4) generate physical narrative, (5) fuse into executive summary. Reports progress via callback. |
| `generate_daily_fusion_report(data)` | 3 stages | Daily operations fusion report. Combines article summaries, alert analytics, and site health into a structured report. |
| `generate_bluf(text)` | 1 stage | "Bottom Line Up Front" — condenses lengthy intelligence text into a 2-3 sentence executive summary. |
| `generate_siem_triage_summary(alerts)` | 1 stage | SIEM alert triage. Groups related alerts, identifies false positive patterns, and produces a prioritized action list. |
| `generate_executive_weather_brief(hazards, sites)` | 1 stage | Weather impact brief for executive consumption. Translates NWS jargon into operational language (e.g., "tornado warning" → "potential service disruption to 3 sites in sector 7"). |
| `generate_aggregated_shift_summary(entries)` | 1 stage | Aggregates shift logbook entries into a coherent narrative summary with key events highlighted. |
| `build_custom_intel_report(config, data)` | 2 stages | Builds a custom intelligence report from user-defined parameters (scope, filters, format). |
| `cross_reference_cves(cves, assets)` | 1 stage | Cross-references CVE list against known asset inventory to identify exposure. Returns prioritized remediation list. |

### Context Window Management

When input exceeds the model's context window:

1. **Automatic chunking** — Input is split into overlapping chunks sized to 80% of the context window (leaving room for system prompt + output).
2. **Parallel processing** — Chunks are summarized concurrently.
3. **Recursive fusion** — Chunk summaries are concatenated and re-summarized if they still exceed the window.
4. **Graceful degradation** — If the model is unavailable, returns a structured fallback message rather than failing silently.

---

## src/utils/mailer.py — Email Sender

**Location**: `src/utils/mailer.py`  
**Size**: ~77 lines  
**Role**: SMTP email sending with TLS encryption, authentication, and comprehensive error handling.

### Functions

| Function | Description |
|---|---|
| `send_alert_email(subject, body, recipient_override=None, is_html=False)` | Sends an email via SMTP with STARTTLS. Constructs MIME multipart message (text + optional HTML). Supports recipient override for testing. |

### Error Handling

| Exception | Behavior |
|---|---|
| `SMTPAuthenticationError` | Logs credential failure. Returns error dict with `"auth_failed"` code. |
| `SMTPConnectError` | Logs connection failure with host/port details. Returns error dict with `"connection_failed"` code. |
| `SMTPException` | Catches all other SMTP errors. Logs full traceback. Returns generic error dict. |
| `Exception` | Catch-all for non-SMTP failures (DNS, timeout). Logs and returns error dict. |

### Configuration

SMTP settings loaded from `src/core/config.py` → `Settings`:
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`
- TLS enforced via `starttls()`
- Timeout: 10 seconds per connection

### Dependencies

- `smtplib` (stdlib)
- `email.mime.multipart`, `email.mime.text` (stdlib)
- `src/core/config.py` (SMTP settings)

---

## src/utils/risk_alert.py — Risk Alerting

**Location**: `src/utils/risk_alert.py`  
**Size**: ~242 lines  
**Role**: Automated risk alert generation and delivery when global or internal CIS scores change tiers.

### Constants

```python
RISK_TIER_ORDER = ["GREEN", "BLUE", "YELLOW", "ORANGE", "RED"]
```

### Functions

| Function | Description |
|---|---|
| `is_increase(from_level, to_level)` | Returns `True` if `to_level` represents a higher risk than `from_level` based on `RISK_TIER_ORDER`. Lateral moves (same tier) return `False`. |
| `should_send_alert()` | **4-hour cooldown** check. Prevents alert fatigue by ensuring no more than one alert per 4-hour window. Reads the last alert timestamp from global config. |
| `check_and_alert(global_risk, internal_risk)` | **Main entry point**. Compares previous and current risk tiers for both global and internal scores. If an increase is detected and cooldown has elapsed, builds and sends the alert email. Records the alert timestamp. |
| `build_alert_email_body(global_from, global_to, internal_from, internal_to)` | Formats a plain-text alert email with before/after tier comparison, timestamp, and operational guidance. |
| `build_eq_alert_email_body(earthquake_data)` | Earthquake-specific alert format. Includes magnitude, depth, distance to nearest site, and estimated impact radius. |

### Alert Flow

```
Score Change Detected
        ↓
  is_increase() ──→ No ──→ [No Alert]
        ↓ Yes
  should_send_alert() ──→ Cooldown Active ──→ [No Alert]
        ↓ Clear
  build_alert_email_body()
        ↓
  send_alert_email()
        ↓
  Record timestamp for cooldown
```

---

## src/core/config.py — Settings

**Location**: `src/core/config.py`  
**Size**: ~39 lines  
**Role**: Centralized configuration via Pydantic `BaseSettings` with environment variable loading.

### Class: `Settings`

Extends `pydantic.BaseSettings` with `.env` file support.

| Field | Type | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | `str` | `sqlite:////app/data/noc_fusion.db` | SQLAlchemy connection string |
| `ELASTIC_URL` | `str` | `""` | Elasticsearch endpoint (optional) |
| `ELASTIC_API_KEY` | `str` | `""` | Elasticsearch API key (optional) |
| `CRIME_ALERT_SMS` | `str` | `""` | Crime alert SMS recipient |
| `CRIME_ALERT_EMAIL` | `str` | `""` | Crime alert email recipient |
| `RISK_ALERT_RECIPIENTS` | `str` | `""` | Comma-separated risk alert email list |
| `SMTP_HOST` | `str` | `""` | SMTP server hostname |
| `SMTP_PORT` | `int` | `587` | SMTP server port |
| `SMTP_USER` | `str` | `""` | SMTP username |
| `SMTP_PASSWORD` | `str` | `""` | SMTP password |

### Functions

| Function | Description |
|---|---|
| `setup_logging()` | Configures root logger with a stdout handler. Format: `[%(asctime)s] %(levelname)s %(name)s: %(message)s`. Log level from `LOG_LEVEL` env var, defaults to `INFO`. |

---

## src/core/db.py — Database Core

**Location**: `src/core/db.py`  
**Size**: ~358 lines  
**Role**: SQLAlchemy engine configuration, session management, and database initialization with migrations and seed data.

### Engine Configuration

```python
engine = create_engine(
    DATABASE_URL,
    poolclass=NullPool,      # SQLite — avoids QueuePool contention
    connect_args={"check_same_thread": False},
)
```

SQLite pragmas applied on each connection:
- `PRAGMA journal_mode=WAL` — Write-Ahead Logging for concurrent reads
- `PRAGMA mmap_size=268435456` — 256MB memory-mapped I/O
- `PRAGMA foreign_keys=ON`

### Session Management

| Component | Description |
|---|---|
| `SessionLocal` | SQLAlchemy `sessionmaker` bound to the engine. Non-scoped for simplicity. |
| `get_db()` | FastAPI dependency injection helper. Yields a session and ensures cleanup on request completion. |

### `init_db()` — 9-Phase Initialization

Called on application startup. Performs schema creation, column migrations, and seed data insertion.

| Phase | Operation | Notes |
|---|---|---|
| 1 | **Create all tables** | `Base.metadata.create_all()` — idempotent |
| 2 | **Column migrations** | ALTER TABLE ADD COLUMN for each known missing column. Split into per-column try/except blocks to prevent one failure from blocking subsequent migrations. |
| 3 | **Seed roles** | Inserts default roles: `admin`, `operator`, `viewer` with appropriate permission sets |
| 4 | **Seed admin user** | Creates `admin` / `admin123` if not exists. bcrypt hashed. |
| 5 | **Seed RSS feeds** | Inserts default feed URLs for cybersecurity, weather, crime, and infrastructure news |
| 6 | **Seed keywords** | Inserts 70 default keywords with weights for the hybrid scorer. **Critical**: keywords must be seeded before any scoring. |
| 7 | **Rescale scores** | After keyword seeding, rescales all existing article scores to account for new keyword weights |
| 8 | **Seed global config** | Inserts default configuration values (risk thresholds, alert settings, UI preferences) |
| 9 | **Create indexes** | Performance indexes on frequently queried columns (timestamps, foreign keys, status fields) |

### Column Migration Safety

ALTER TABLE operations are wrapped in individual try/except blocks:

```python
try:
    engine.execute("ALTER TABLE articles ADD COLUMN status TEXT DEFAULT 'new'")
except Exception:
    pass  # Column already exists
```

This prevents the common SQLite issue where a failed ALTER TABLE (due to existing column) blocks all subsequent migrations in the same run.

### Dependencies

- `sqlalchemy` (engine, session, Column types)
- `src/core/config.py` (DATABASE_URL)
- `src/models/schema.py` (all ORM models via `Base`)

---

## Cross-Module Dependencies

```
services.py ──────────────────────────────────────────────┐
  ├── core/db.py (all DB operations)                      │
  ├── core/config.py (settings)                           │
  ├── services/logic.py (scoring)                         │
  ├── services/categorizer.py (article classification)    │
  ├── services/ioc_extractor.py (IOC extraction)          │
  ├── services/aiops_engine.py (correlation)              │
  ├── utils/llm.py (brief generation)                     │
  ├── utils/mailer.py (email delivery)                    │
  └── utils/risk_alert.py (risk notifications)            │
                                                           │
api/main.py ──────────────────────────────────────────────┤
  └── services.py (all route handlers delegate here)      │
                                                           │
scheduler.py ─────────────────────────────────────────────┤
  └── services.py (data ingestion + maintenance jobs)     │
                                                           │
webhook_listener.py ─────────────────────────────────────┤
  └── services.py (inbound webhook processing)            │
                                                           │
utils/llm.py ────────────────────────────────────────────┤
  └── core/config.py (LLM endpoint config)                │
                                                           │
utils/mailer.py ─────────────────────────────────────────┤
  └── core/config.py (SMTP config)                        │
                                                           │
utils/risk_alert.py ─────────────────────────────────────┤
  ├── core/config.py (recipients)                         │
  └── utils/mailer.py (alert delivery)                    │
                                                           │
services/aiops_engine.py ────────────────────────────────┤
  └── services.py (DAL for site/alert data)               │
                                                           │
services/logic.py ───────────────────────────────────────┤
  └── core/db.py (keyword loading)                        │
└─────────────────────────────────────────────────────────┘
```

---

## Scheduler Job → Service Mapping

| Scheduler Job | Service Module | Key Functions |
|---|---|---|
| RSS Feed Fetch (15 min) | `services.py` | Article ingestion, deduplication, categorization, scoring |
| Crime Fetch (3 min) | `services.py` | Crime data ingestion, geocoding, proximity scoring |
| Regional Hazards (2 min) | `services.py` | NWS alert processing, site intersection calculation |
| Cloud Outages (5 min) | `services.py` | Cloud provider API polling, deduplication |
| CISA KEV (6 hours) | `services.py` | KEV catalog sync, CVE enrichment |
| Internal Risk (1 hour) | `services.py` | `calculate_internal_cis_score()`, `generate_and_save_internal_risk_snapshot()` |
| Unified Brief (30 min) | `services.py` + `utils/llm.py` | `trigger_unified_brief()` → map-reduce LLM pipeline |
| DB Maintenance (60 min) | `services.py` | `deduplicate_articles()`, old data purge, index optimization |
| ML Retrain (Sunday 02:00) | `services/logic.py` | `force_reload_scorer()` after model retrain |
| Tiered Alert Escalation (1 min) | `services.py` + `utils/risk_alert.py` | P1-P5 SLA tracking, cascade handling, flapping detection |
