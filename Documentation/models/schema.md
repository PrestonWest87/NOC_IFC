# Database Models (Schema)

**File:** `src/models/schema.py`

Defines all 25 SQLAlchemy ORM models for the NOC Fusion Center database. Each model corresponds to a database table and encapsulates the schema for that entity.

**Base class:** `declarative_base()` — all models inherit from this.

---

## Model Index

| # | Class | Table | Purpose |
|---|-------|-------|---------|
| 1 | `User` | `users` | Application user accounts |
| 2 | `Role` | `roles` | RBAC role definitions |
| 3 | `SavedReport` | `saved_reports` | Persisted generated reports |
| 4 | `FeedSource` | `feed_sources` | RSS/Atom feed configuration |
| 5 | `Keyword` | `keywords` | Scoring keywords with weights |
| 6 | `SystemConfig` | `system_config` | Global system configuration |
| 7 | `ShiftLogEntry` | `shift_logs` | Shift handover log entries |
| 8 | `SoftwareAsset` | `software_assets` | Software inventory |
| 9 | `HardwareAsset` | `hardware_assets` | Hardware inventory with vulnerabilities |
| 10 | `InternalRiskSnapshot` | `internal_risk_snapshots` | Periodic internal risk scoring snapshots |
| 11 | `Article` | `articles` | Aggregated news/intelligence articles |
| 12 | `ExtractedIOC` | `extracted_iocs` | Indicators of Compromise extracted from articles |
| 13 | `CveItem` | `cve_items` | CISA KEV catalog entries |
| 14 | `ElasticEvent` | `elastic_events` | Elasticsearch SIEM events |
| 15 | `DailyBriefing` | `daily_briefings` | Generated daily briefing content |
| 16 | `DailyThreatScore` | `daily_threat_scores` | Daily cyber/physical threat scores |
| 17 | `RegionalHazard` | `regional_hazards` | Regional natural hazards (NWS, SPC) |
| 18 | `RegionalOutage` | `regional_outages` | Regional infrastructure outages |
| 19 | `CloudOutage` | `cloud_outages` | Cloud service provider outages |
| 20 | `BgpAnomaly` | `bgp_anomalies` | BGP routing anomalies |
| 21 | `SolarWindsAlert` | `solarwinds_alerts` | SolarWinds NPM/ NTA alerts |
| 22 | `TimelineEvent` | `timeline_events` | Unified timeline events |
| 23 | `MonitoredLocation` | `monitored_locations` | NOC-monitored facility/site locations |
| 24 | `CrimeIncident` | `crime_incidents` | Perimeter crime incidents |
| 25 | `GeoJsonCache` | `geojson_cache` | Cached GeoJSON boundary data |
| 26 | `NodeAlias` | `node_aliases` | SolarWinds node-to-location alias mapping |
| 27 | `UserWeatherPreference` | `user_weather_prefs` | Per-user weather alert preferences |

---

## `User` — `users`

User accounts for the NOC Fusion application.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `username` | `String` | Unique, Index | — | Login username |
| `password_hash` | `String` | — | — | Bcrypt password hash |
| `role` | `String` | Index | `"analyst"` | Role name (foreign-key-like reference to `roles.name`) |
| `session_token` | `String` | Nullable, Index | — | Active session token |
| `full_name` | `String` | Nullable | — | Display name |
| `job_title` | `String` | Nullable | — | Job position |
| `contact_info` | `String` | Nullable | — | Contact details |
| `default_shift` | `String` | — | `"No Shift"` | Default shift assignment |

---

## `Role` — `roles`

Role-Based Access Control definitions.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `name` | `String` | Unique, Index | — | Role name (e.g., `admin`, `analyst`) |
| `allowed_pages` | `JSON` | — | — | List of page names the role can access |
| `allowed_actions` | `JSON` | — | `list` (empty) | List of action/tab permissions |
| `allowed_site_types` | `JSON` | — | `list` (empty) | List of permitted site/location types |

---

## `SavedReport` — `saved_reports`

Persisted generated reports for later retrieval and sharing.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `title` | `String` | Index | — | Report title |
| `author` | `String` | — | — | Author username |
| `content` | `Text` | — | — | Full report content (markdown or JSON) |
| `created_at` | `DateTime` | Index | `datetime.utcnow` | Creation timestamp |

---

## `FeedSource` — `feed_sources`

Configured RSS/Atom feed sources for article ingestion.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `url` | `String` | Unique, Index | — | Feed URL |
| `name` | `String` | — | — | Human-readable feed name |
| `is_active` | `Boolean` | — | `True` | Whether the feed is actively polled |

---

## `Keyword` — `keywords`

Scoring keywords with associated weight values used for article relevance scoring.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `word` | `String` | Unique, Index | — | Keyword text |
| `weight` | `Integer` | — | `10` | Scoring weight (higher = more important) |

---

## `SystemConfig` — `system_config`

Singleton-like table holding global application configuration.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `llm_endpoint` | `String` | — | `"https://api.openai.com/v1"` | LLM API base URL |
| `llm_api_key` | `String` | — | `""` | LLM API key |
| `llm_model_name` | `String` | — | `"gpt-4o-mini"` | LLM model identifier |
| `is_active` | `Boolean` | — | `False` | LLM integration enabled flag |
| `tech_stack` | `Text` | — | `"SolarWinds, Cisco SD-WAN, Microsoft Office, Verizon, Cisco"` | NOC technology stack description |
| `monitored_asns` | `String` | — | `"AS701, AS7922, AS3356"` | Monitored BGP AS numbers |
| `rolling_summary` | `Text` | Nullable | — | Rolling situational summary text |
| `rolling_summary_time` | `DateTime` | Nullable | — | Last rolling summary update time |
| `smtp_server` | `String` | Nullable | — | SMTP server hostname |
| `smtp_port` | `Integer` | — | `587` | SMTP server port |
| `smtp_username` | `String` | Nullable | — | SMTP authentication username |
| `smtp_password` | `String` | Nullable | — | SMTP authentication password |
| `smtp_sender` | `String` | Nullable | — | Email sender address |
| `smtp_recipient` | `String` | Nullable | — | Default email recipient |
| `smtp_enabled` | `Boolean` | — | `False` | SMTP integration enabled flag |
| `baseline_override_cyber` | `Float` | — | `0.0` | Manual override for cyber baseline score |
| `baseline_override_phys` | `Float` | — | `0.0` | Manual override for physical baseline score |
| `unified_brief` | `Text` | Nullable | — | Latest unified briefing text |
| `unified_brief_time` | `DateTime` | Nullable | — | Last unified briefing generation time |
| `last_global_risk` | `String` | Nullable | — | Last computed global risk level string |
| `last_internal_risk` | `String` | Nullable | — | Last computed internal risk level string |
| `last_risk_alert_time` | `DateTime` | Nullable | — | Timestamp of last risk alert dispatch |
| `sys_countermeasures` | `Integer` | — | `3` | System-level countermeasure count |
| `net_countermeasures` | `Integer` | — | `3` | Network-level countermeasure count |

---

## `ShiftLogEntry` — `shift_logs`

Shift handover log entries submitted by analysts.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `analyst` | `String` | Index | — | Analyst username |
| `author_role` | `String` | Index | — | Role of the author at time of writing |
| `shift_date` | `DateTime` | Index | `datetime.utcnow` | Date of the shift |
| `shift_period` | `String` | — | — | Shift period label (e.g., `"Day"`, `"Night"`) |
| `content` | `Text` | — | — | Log entry content |
| `created_at` | `DateTime` | — | `datetime.utcnow` | Entry creation timestamp |
| `is_deleted` | `Boolean` | Index | `False` | Soft-delete flag |

---

## `SoftwareAsset` — `software_assets`

Inventory record for software assets.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `name` | `String` | Index | — | Software name |
| `last_updated` | `DateTime` | — | `datetime.utcnow` | Last inventory update timestamp |

---

## `HardwareAsset` — `hardware_assets`

Detailed hardware asset inventory with vulnerability and risk scoring data.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `ip_address` | `String` | Not Null, Index | — | Primary IP address of the asset |
| `asset_name` | `String` | Nullable, Index | — | Hostname or asset display name |
| `host_type` | `String` | Nullable | — | Type of host (server, workstation, network device) |
| `ip_addresses` | `Text` | Nullable | — | JSON-encoded list of all IP addresses |
| `operating_system` | `String` | Nullable | — | OS description string |
| `os_architecture` | `String` | Nullable | — | CPU architecture (x86_64, arm64) |
| `os_family` | `String` | Nullable | — | OS family (Windows, Linux, macOS) |
| `os_product` | `String` | Nullable | — | OS product name |
| `os_vendor` | `String` | Nullable | — | OS vendor |
| `os_version` | `String` | Nullable | — | OS version string |
| `instances` | `Integer` | Nullable | `0` | Total instance count |
| `critical_instances` | `Integer` | Nullable | `0` | Critical-severity instance count |
| `severe_instances` | `Integer` | Nullable | `0` | Severe-severity instance count |
| `moderate_instances` | `Integer` | Nullable | `0` | Moderate-severity instance count |
| `vulnerabilities` | `Integer` | Nullable | `0` | Total vulnerability count |
| `critical_vulnerabilities` | `Integer` | Nullable | `0` | Critical vulnerability count |
| `severe_vulnerabilities` | `Integer` | Nullable | `0` | Severe vulnerability count |
| `moderate_vulnerabilities` | `Integer` | Nullable | `0` | Moderate vulnerability count |
| `exploit_count` | `Integer` | Nullable | `0` | Number of known exploits targeting this asset |
| `malware_count` | `Integer` | Nullable | `0` | Number of malware detections |
| `raw_risk_score` | `Float` | Nullable | `0.0` | Unnormalized risk score |
| `risk_score` | `Float` | Nullable | `0.0` | Normalized risk score (0-100 scale) |
| `last_updated` | `DateTime` | — | `datetime.utcnow` | Last risk assessment update |

---

## `InternalRiskSnapshot` — `internal_risk_snapshots`

Periodic snapshots of internal network risk computed from asset vulnerability data.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `timestamp` | `DateTime` | — | `datetime.utcnow` | Snapshot creation time |
| `score` | `Float` | — | — | Aggregate internal risk score |
| `risk_level` | `String` | — | — | Risk level label (GREEN/BLUE/YELLOW/ORANGE/RED) |
| `total_assets` | `Integer` | — | — | Total number of hardware assets evaluated |
| `total_osint_hits` | `Integer` | — | — | Total OSINT hits across all assets |
| `critical_osint_hits` | `Integer` | — | — | Critical-severity OSINT hits |
| `hw_data_json` | `Text` | — | — | JSON-serialized hardware asset data snapshot |
| `sw_data_json` | `Text` | — | — | JSON-serialized software asset data snapshot |

---

## `Article` — `articles`

Aggregated news and intelligence articles from RSS feeds, with scoring and categorization.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `title` | `String` | — | — | Article headline |
| `link` | `String` | Unique, Index | — | Source URL (deduplication key) |
| `summary` | `Text` | — | — | Article summary or full text |
| `published_date` | `DateTime` | Index | `datetime.utcnow` | Original publication date |
| `source` | `String` | Index | — | Source feed name |
| `score` | `Float` | Index | `0.0` | Computed relevance score |
| `category` | `String` | Index | `"General"` | Categorization label |
| `keywords_found` | `JSON` | — | — | Matched keywords with scores |
| `is_bubbled` | `Boolean` | — | `False` | Flagged for attention (bubbled up) |
| `story_group` | `String` | Nullable | — | Story clustering group identifier |
| `human_feedback` | `Integer` | — | `0` | Human feedback rating |
| `ai_bluf` | `Text` | Nullable | — | AI-generated bottom-line-up-front summary |
| `is_pinned` | `Boolean` | Index | `False` | Pinned/starred by analyst |

---

## `ExtractedIOC` — `extracted_iocs`

Indicators of Compromise extracted from article content via pattern matching.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `article_id` | `Integer` | Index | — | FK reference to `articles.id` |
| `indicator_type` | `String` | Index | — | IOC type (IP, domain, hash, URL, etc.) |
| `indicator_value` | `String` | Index | — | The indicator value |
| `context` | `Text` | Nullable | — | Surrounding context snippet |
| `detected_at` | `DateTime` | Index | `datetime.utcnow` | Detection timestamp |

---

## `CveItem` — `cve_items`

CISA Known Exploited Vulnerabilities (KEV) catalog entries.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `cve_id` | `String` | Unique, Index | — | CVE identifier (e.g., CVE-2024-1234) |
| `vendor` | `String` | Index | — | Affected vendor |
| `product` | `String` | Index | — | Affected product |
| `vulnerability_name` | `String` | — | — | Vulnerability name/title |
| `date_added` | `DateTime` | Index | — | Date added to KEV catalog |
| `description` | `Text` | — | — | Vulnerability description |
| `required_action` | `Text` | — | — | Remediation action required |
| `due_date` | `String` | — | — | Due date for remediation (string from CISA) |

---

## `ElasticEvent` — `elastic_events`

Ingested Elasticsearch SIEM events for correlation and display.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `String` | PK | — | Elasticsearch document ID |
| `timestamp` | `DateTime` | Index | — | Event timestamp |
| `index_name` | `String` | — | — | Source Elasticsearch index |
| `severity` | `String` | Index | — | Event severity level |
| `message` | `String` | — | — | Event log message |
| `source_ip` | `String` | Nullable | — | Source IP address |
| `event_category` | `String` | Nullable | — | Event category |

---

## `DailyBriefing` — `daily_briefings`

Auto-generated daily situational briefings.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `report_date` | `DateTime` | Unique, Index | — | Date of the briefing |
| `content` | `Text` | — | — | Full briefing content |
| `created_at` | `DateTime` | — | `datetime.utcnow` | Record creation timestamp |

---

## `DailyThreatScore` — `daily_threat_scores`

Daily aggregated cyber and physical threat scores with baselines.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `record_date` | `DateTime` | Unique, Index | — | Date of the score record |
| `cyber_points` | `Float` | — | `0.0` | Aggregated cyber threat points |
| `physical_points` | `Float` | — | `0.0` | Aggregated physical threat points |
| `cyber_baseline` | `Float` | — | `0.0` | Cyber baseline reference value |
| `physical_baseline` | `Float` | — | `0.0` | Physical baseline reference value |

---

## `RegionalHazard` — `regional_hazards`

Regional natural hazard alerts from NWS, SPC, and other sources.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `hazard_id` | `String` | Unique, Index | — | Source hazard identifier |
| `hazard_type` | `String` | — | — | Type (tornado, flood, thunderstorm, etc.) |
| `severity` | `String` | — | — | Severity level |
| `title` | `String` | — | — | Alert title |
| `description` | `Text` | — | — | Full alert description |
| `location` | `String` | — | — | Affected location/area |
| `updated_at` | `DateTime` | Index | — | Last update timestamp |

---

## `RegionalOutage` — `regional_outages`

Reported regional infrastructure outages (power, water, telecom, etc.).

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `outage_type` | `String` | Index | — | Type of outage (power, fiber, etc.) |
| `provider` | `String` | — | — | Service provider |
| `description` | `Text` | — | — | Outage details |
| `affected_area` | `String` | — | — | Geographic area description |
| `lat` | `Float` | Nullable | — | Latitude of outage center |
| `lon` | `Float` | Nullable | — | Longitude of outage center |
| `radius_km` | `Float` | — | `10.0` | Affected radius in kilometers |
| `detected_at` | `DateTime` | — | `datetime.utcnow` | Detection timestamp |
| `is_resolved` | `Boolean` | Index | `False` | Resolution status |

---

## `CloudOutage` — `cloud_outages`

Cloud service provider outage and incident reports.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `provider` | `String` | Index | — | Cloud provider (AWS, Azure, GCP, etc.) |
| `service` | `String` | — | — | Affected service name |
| `title` | `String` | — | — | Incident title |
| `description` | `Text` | — | — | Incident description |
| `link` | `String` | — | — | URL to incident details |
| `is_resolved` | `Boolean` | Index | `False` | Resolution status |
| `updated_at` | `DateTime` | Index | — | Last update timestamp |

---

## `BgpAnomaly` — `bgp_anomalies`

BGP routing anomalies detected from monitoring sources.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `asn` | `String` | Index | — | Affected AS number |
| `event_type` | `String` | — | — | Type of anomaly (hijack, leak, route flap) |
| `description` | `Text` | — | — | Anomaly description |
| `detected_at` | `DateTime` | — | `datetime.utcnow` | Detection timestamp |
| `is_resolved` | `Boolean` | Index | `False` | Resolution status |

---

## `SolarWindsAlert` — `solarwinds_alerts`

Ingested SolarWinds NPM/NTA alerts with enrichment, correlation, and dispatch tracking.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `event_type` | `String` | Index | — | Normalized event type |
| `severity` | `String` | — | — | Alert severity (Critical, Warning, etc.) |
| `node_name` | `String` | Index | — | Affected node hostname |
| `ip_address` | `String` | — | — | Node IP address |
| `status` | `String` | Index | — | Alert status |
| `sw_timestamp` | `String` | — | — | Original SolarWinds timestamp |
| `details` | `Text` | — | — | Alert details text |
| `node_link` | `String` | — | — | Deep link to SolarWinds node |
| `raw_payload` | `JSON` | Nullable | — | Full original webhook payload |
| `mapped_location` | `String` | Nullable, Index | — | Resolved MonitoredLocation name |
| `received_at` | `DateTime` | Index | `datetime.utcnow` | Webhook receipt timestamp |
| `resolved_at` | `DateTime` | Nullable, Index | — | Alert resolution timestamp |
| `is_dispatched` | `Boolean` | Index | `False` | Whether a dispatch action was taken |
| `is_ticketed` | `Boolean` | Index | `False` | Whether a ticket was created |
| `is_correlated` | `Boolean` | Index | `False` | Whether AIOps correlation was run |
| `ai_root_cause` | `Text` | Nullable | — | AI-predicted root cause |
| `device_type` | `String` | Index | `"Unknown"` | Classified device type |
| `event_category` | `String` | — | `"Unknown"` | Classified event category |

---

## `TimelineEvent` — `timeline_events`

Unified chronological event feed aggregating alerts, incidents, and system events.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `timestamp` | `DateTime` | Index | `datetime.utcnow` | Event timestamp |
| `source` | `String` | Index | — | Source system name |
| `event_type` | `String` | Index | — | Event type classification |
| `message` | `String` | — | — | Event message text |

---

## `MonitoredLocation` — `monitored_locations`

Monitored facility/site locations with spatial coordinates, risk tracking, maintenance scheduling, and escalation state.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `name` | `String` | Unique, Index | — | Location/site name |
| `lat` | `Float` | — | — | Latitude |
| `lon` | `Float` | — | — | Longitude |
| `loc_type` | `String` | Index | `"General"` | Location type (NOC, Data Center, POP, etc.) |
| `district` | `String` | Index | `"Central"` | Administrative district |
| `priority` | `Integer` | Index | `3` | Priority level (1=highest) |
| `current_spc_risk` | `String` | — | `"None"` | Current SPC storm risk rating |
| `last_updated` | `DateTime` | — | `datetime.utcnow` | Last risk assessment update |
| `under_maintenance` | `Boolean` | — | `False` | Site under scheduled maintenance |
| `maintenance_etr` | `DateTime` | Nullable | — | Estimated time of maintenance completion |
| `maintenance_reason` | `Text` | Nullable | — | Reason for maintenance |
| `last_auto_ticket` | `DateTime` | Nullable | — | Last automatic ticket creation time |
| `last_escalation_ticket` | `DateTime` | Nullable | — | Last escalation ticket time |
| `last_auto_dispatch` | `DateTime` | Nullable | — | Last automatic dispatch action time |
| `last_escalation_dispatch` | `DateTime` | Nullable | — | Last escalation dispatch time |
| `status_modified_by` | `String` | Nullable | — | Username who last modified status |
| `status_modified_at` | `DateTime` | Nullable | — | Last status modification timestamp |

---

## `CrimeIncident` — `crime_incidents`

Perimeter crime incidents scraped from law enforcement data feeds.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `String` | PK, Index | — | Source incident ID |
| `category` | `String` | — | — | Crime category |
| `raw_title` | `String` | — | — | Original incident title/description |
| `timestamp` | `DateTime` | Index | — | Incident timestamp |
| `distance_miles` | `Float` | — | — | Distance from NOC perimeter (miles) |
| `severity` | `String` | — | — | Severity classification |
| `lat` | `Float` | — | — | Latitude |
| `lon` | `Float` | — | — | Longitude |
| `is_alert_dispatched` | `Boolean` | Index | `False` | Whether an alert was dispatched |

---

## `GeoJsonCache` — `geojson_cache`

Cached GeoJSON boundary data from external geographic feeds.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `feed_name` | `String` | PK, Index | — | Source feed identifier |
| `data` | `JSON` | — | — | Cached GeoJSON feature collection |
| `updated_at` | `DateTime` | — | `datetime.utcnow` | Cache update timestamp |

---

## `NodeAlias` — `node_aliases`

Maps SolarWinds node name patterns to MonitoredLocation entries, with confidence scoring and verification.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `node_pattern` | `String` | Index | — | Node name pattern (glob-like or substring) |
| `mapped_location_name` | `String` | — | — | Target MonitoredLocation name |
| `confidence_score` | `Float` | — | `0.0` | Auto-mapping confidence (0.0-1.0) |
| `is_verified` | `Boolean` | — | `False` | Human-verified flag |

---

## `UserWeatherPreference` — `user_weather_prefs`

Per-user subscription to specific weather alert types.

| Column | Type | Constraints | Default | Description |
|--------|------|-------------|---------|-------------|
| `id` | `Integer` | PK, Index | auto | Primary key |
| `username` | `String` | Index | — | Username |
| `alert_type` | `String` | — | — | Weather alert type subscribed |

---
