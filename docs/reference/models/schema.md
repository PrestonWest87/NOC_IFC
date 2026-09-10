# Module: `src.models.schema`

SQLAlchemy ORM models for the NOC Intelligence Fusion Center. Contains 27 table definitions.

---

## Model Index

| # | Table | Class | Description |
|---|-------|-------|-------------|
| 1 | `users` | `User` | Authentication & authorization |
| 2 | `roles` | `Role` | RBAC role definitions |
| 3 | `saved_reports` | `SavedReport` | Custom report library |
| 4 | `feed_sources` | `FeedSource` | RSS/Atom feed configuration |
| 5 | `keywords` | `Keyword` | Scoring keyword registry |
| 6 | `system_config` | `SystemConfig` | AI/SMTP/risk baseline configuration |
| 7 | `shift_logs` | `ShiftLogEntry` | Operator shift log entries |
| 8 | `software_assets` | `SoftwareAsset` | Internal software inventory |
| 9 | `hardware_assets` | `HardwareAsset` | Internal hardware inventory with vulnerability data |
| 10 | `internal_risk_snapshots` | `InternalRiskSnapshot` | Asset risk posture history |
| 11 | `articles` | `Article` | RSS/OSINT intelligence articles |
| 12 | `extracted_iocs` | `ExtractedIOC` | Autonomously extracted indicators |
| 13 | `cve_items` | `CveItem` | CISA KEV vulnerability catalog |
| 14 | `elastic_events` | `ElasticEvent` | Elasticsearch synced security events |
| 15 | `daily_briefings` | `DailyBriefing` | Daily fusion report archive |
| 16 | `daily_threat_scores` | `DailyThreatScore` | 14-day threat score baseline |
| 17 | `regional_hazards` | `RegionalHazard` | Weather/geospatial hazards |
| 18 | `regional_outages` | `RegionalOutage` | Regional infrastructure outages |
| 19 | `cloud_outages` | `CloudOutage` | Cloud service status records |
| 20 | `bgp_anomalies` | `BgpAnomaly` | BGP routing anomalies |
| 21 | `solarwinds_alerts` | `SolarWindsAlert` | Ingested infrastructure alerts |
| 22 | `timeline_events` | `TimelineEvent` | Activity feed for RCA board |
| 23 | `monitored_locations` | `MonitoredLocation` | Facility/site registry |
| 24 | `crime_incidents` | `CrimeIncident` | Law enforcement CAD data |
| 25 | `geojson_cache` | `GeoJsonCache` | Cached geospatial GeoJSON |
| 26 | `node_aliases` | `NodeAlias` | SolarWinds node-to-site mapping |
| 27 | `user_weather_prefs` | `UserWeatherPreference` | User weather alert preferences |

---

## Model Details

### User
**Table**: `users`

| Column | Type | Default | Index | Description |
|--------|------|---------|-------|-------------|
| `id` | `Integer PK` | auto | Y | Primary key |
| `username` | `String` | — | Y (unique) | Login username |
| `password_hash` | `String` | — | — | bcrypt password hash |
| `role` | `String` | `"analyst"` | Y | FK to `roles.name` |
| `session_token` | `String` | `nullable` | Y | Active JWT session token |
| `full_name` | `String` | `nullable` | — | Display name |
| `job_title` | `String` | `nullable` | — | Job title (e.g., "NOC Analyst") |
| `contact_info` | `String` | `nullable` | — | Email or contact number |
| `default_shift` | `String` | `"No Shift"` | — | Default Morning/Afternoon/Night/No Shift |

---

### Role
**Table**: `roles`

| Column | Type | Default | Index | Description |
|--------|------|---------|-------|-------------|
| `id` | `Integer PK` | auto | Y | Primary key |
| `name` | `String` | — | Y (unique) | Role name (admin, analyst, or custom) |
| `allowed_pages` | `JSON` | — | — | Array of allowed page identifiers |
| `allowed_actions` | `JSON` | `list` | — | Array of action permission strings |
| `allowed_site_types` | `JSON` | `list` | — | Array of geographic/operational site type restrictions |

---

### SystemConfig
**Table**: `system_config`

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | `Integer PK` | auto | Primary key |
| `llm_endpoint` | `String` | `"https://api.openai.com/v1"` | LLM API endpoint URL |
| `llm_api_key` | `String` | `""` | LLM API key |
| `llm_model_name` | `String` | `"gpt-4o-mini"` | LLM model identifier |
| `is_active` | `Boolean` | `False` | Whether AI features are enabled |
| `tech_stack` | `Text` | `"SolarWinds, Cisco SD-WAN, Microsoft Office, Verizon, Cisco"` | Organizational tech stack for AI context |
| `monitored_asns` | `String` | `"AS701, AS7922, AS3356"` | Monitored BGP ASNs |
| `rolling_summary` | `Text` | `nullable` | Current rolling summary text |
| `rolling_summary_time` | `DateTime` | `nullable` | Last summary generation time |
| `smtp_server` | `String` | `nullable` | SMTP server hostname |
| `smtp_port` | `Integer` | `587` | SMTP server port |
| `smtp_username` | `String` | `nullable` | SMTP authentication username |
| `smtp_password` | `String` | `nullable` | SMTP authentication password |
| `smtp_sender` | `String` | `nullable` | From address for outgoing emails |
| `smtp_recipient` | `String` | `nullable` | Default recipient for outgoing emails |
| `smtp_enabled` | `Boolean` | `False` | Whether SMTP is configured |
| `baseline_override_cyber` | `Float` | `0.0` | Manual override for cyber baseline |
| `baseline_override_phys` | `Float` | `0.0` | Manual override for physical baseline |
| `unified_brief` | `Text` | `nullable` | Latest AI-generated unified brief |
| `unified_brief_time` | `DateTime` | `nullable` | Brief generation timestamp |
| `last_global_risk` | `String` | `nullable` | Last calculated global risk level |
| `last_internal_risk` | `String` | `nullable` | Last calculated internal risk level |
| `last_risk_alert_time` | `DateTime` | `nullable` | Last risk alert sent time |
| `sys_countermeasures` | `Integer` | `3` | System countermeasures count |
| `net_countermeasures` | `Integer` | `3` | Network countermeasures count |
| `scoring_mode` | `String` | `"auto"` | Scoring mode (auto/manual/override) |
| `cyber_criticality_override` | `Integer` | `0` | Override for cyber criticality |
| `cyber_lethality_override` | `Integer` | `0` | Override for cyber lethality |
| `physical_criticality_override` | `Integer` | `0` | Override for physical criticality |
| `physical_lethality_override` | `Integer` | `0` | Override for physical lethality |
| `internal_criticality_override` | `Integer` | `0` | Override for internal criticality |
| `internal_lethality_override` | `Integer` | `0` | Override for internal lethality |
| `global_risk_offset` | `Integer` | `0` | Manual offset for global risk level |
| `internal_risk_offset` | `Integer` | `0` | Manual offset for internal risk level |
| `alerted_eq_ids` | `Text` | `"[]"` | JSON list of alerted earthquake IDs |

---

### SolarWindsAlert
**Table**: `solarwinds_alerts`

| Column | Type | Default | Index | Description |
|--------|------|---------|-------|-------------|
| `id` | `Integer PK` | auto | Y | Primary key |
| `event_type` | `String` | — | Y | Alert type (e.g., Node Down, Interface Down) |
| `severity` | `String` | — | — | Alert severity level |
| `node_name` | `String` | — | Y | Device/node hostname |
| `ip_address` | `String` | — | — | Device IP address |
| `status` | `String` | — | Y | Alert status (Active, Resolved, Acknowledged) |
| `sw_timestamp` | `String` | — | — | Original SolarWinds timestamp |
| `details` | `Text` | — | — | Alert details/description |
| `node_link` | `String` | — | — | SolarWinds node URL |
| `raw_payload` | `JSON` | `nullable` | — | Complete webhook payload |
| `mapped_location` | `String` | `nullable` | Y | FK to `monitored_locations.name` |
| `received_at` | `DateTime` | `utcnow` | Y | When the alert was ingested |
| `resolved_at` | `DateTime` | `nullable` | Y | When the alert was resolved |
| `is_dispatched` | `Boolean` | `False` | Y | Whether a dispatch ticket was sent |
| `is_ticketed` | `Boolean` | `False` | Y | Whether automatically ticketed by escalation engine |
| `is_correlated` | `Boolean` | `False` | Y | Whether processed by AIOps correlation engine |
| `ai_root_cause` | `Text` | `nullable` | — | AI-determined root cause |
| `device_type` | `String` | `"Unknown"` | Y | Classified device type (ontology domain) |
| `event_category` | `String` | `"Unknown"` | — | Event category classification |

---

### MonitoredLocation
**Table**: `monitored_locations`

| Column | Type | Default | Index | Description |
|--------|------|---------|-------|-------------|
| `id` | `Integer PK` | auto | Y | Primary key |
| `name` | `String` | — | Y (unique) | Site/facility name |
| `lat` | `Float` | — | — | Latitude |
| `lon` | `Float` | — | — | Longitude |
| `loc_type` | `String` | `"General"` | Y | Location type (Fiber Hut, Data Center, etc.) |
| `district` | `String` | `"Central"` | Y | Operational district |
| `priority` | `Integer` | `3` | Y | Site priority (1-5) |
| `current_spc_risk` | `String` | `"None"` | — | Latest SPC risk level |
| `last_updated` | `DateTime` | `utcnow` | — | Last modification time |
| `under_maintenance` | `Boolean` | `False` | — | Whether site is in maintenance mode |
| `maintenance_etr` | `DateTime` | `nullable` | — | Estimated time of maintenance resolution |
| `maintenance_reason` | `Text` | `nullable` | — | Reason for maintenance |
| `last_auto_ticket` | `DateTime` | `nullable` | — | Last automatic ticket timestamp |
| `last_escalation_ticket` | `DateTime` | `nullable` | — | Last escalation ticket (used for site mute) |
| `last_auto_dispatch` | `DateTime` | `nullable` | — | Last automatic dispatch timestamp |
| `last_escalation_dispatch` | `DateTime` | `nullable` | — | Last escalation dispatch timestamp |
| `status_modified_by` | `String` | `nullable` | — | Username who last modified site status |
| `status_modified_at` | `DateTime` | `nullable` | — | When site status was last modified |

---

### Article
**Table**: `articles`

| Column | Type | Default | Index | Description |
|--------|------|---------|-------|-------------|
| `id` | `Integer PK` | auto | Y | Primary key |
| `title` | `String` | — | — | Article title |
| `link` | `String` | — | Y (unique) | Source URL |
| `summary` | `Text` | — | — | Article summary/description |
| `published_date` | `DateTime` | `utcnow` | Y | Publication timestamp |
| `source` | `String` | — | Y | Feed source name |
| `score` | `Float` | `0.0` | Y | Hybrid relevance score (0-100) |
| `category` | `String` | `"General"` | Y | Classified category (8 categories) |
| `keywords_found` | `JSON` | — | — | List of matched keywords |
| `is_bubbled` | `Boolean` | `False` | — | Whether article exceeds alert threshold (>=45) |
| `story_group` | `String` | `nullable` | — | Story grouping identifier |
| `human_feedback` | `Integer` | `0` | — | Analyst feedback (-1, 0, 1) |
| `ai_bluf` | `Text` | `nullable` | — | AI-generated bottom-line-up-front summary |
| `is_pinned` | `Boolean` | `False` | Y | Whether article is pinned by analyst |

---

### ShiftLogEntry
**Table**: `shift_logs`

| Column | Type | Default | Index | Description |
|--------|------|---------|-------|-------------|
| `id` | `Integer PK` | auto | Y | Primary key |
| `analyst` | `String` | — | Y | Analyst name |
| `author_role` | `String` | — | Y | Role of the author (analyst, admin) |
| `shift_date` | `DateTime` | `utcnow` | Y | Date of the shift |
| `shift_period` | `String` | — | — | Morning, Afternoon, or Night |
| `content` | `Text` | — | — | Free-text log content |
| `created_at` | `DateTime` | `utcnow` | — | Entry creation timestamp |
| `is_deleted` | `Boolean` | `False` | Y | Soft-delete flag |

---

### HardwareAsset
**Table**: `hardware_assets`

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | `Integer PK` | auto | Primary key |
| `ip_address` | `String` | — | Device IP |
| `asset_name` | `String` | `nullable` | Hostname/asset tag |
| `host_type` | `String` | `nullable` | Device classification |
| `ip_addresses` | `Text` | `nullable` | JSON list of associated IPs |
| `operating_system` | `String` | `nullable` | OS name |
| `os_architecture` | `String` | `nullable` | OS architecture |
| `os_family` | `String` | `nullable` | OS family |
| `os_product` | `String` | `nullable` | OS product name |
| `os_vendor` | `String` | `nullable` | OS vendor |
| `os_version` | `String` | `nullable` | OS version |
| `instances` | `Integer` | `0` | Total instance count |
| `critical_instances` | `Integer` | `0` | Critical severity instances |
| `severe_instances` | `Integer` | `0` | Severe severity instances |
| `moderate_instances` | `Integer` | `0` | Moderate severity instances |
| `vulnerabilities` | `Integer` | `0` | Total vulnerability count |
| `critical_vulnerabilities` | `Integer` | `0` | Critical vulnerability count |
| `severe_vulnerabilities` | `Integer` | `0` | Severe vulnerability count |
| `moderate_vulnerabilities` | `Integer` | `0` | Moderate vulnerability count |
| `exploit_count` | `Integer` | `0` | Available exploit count |
| `malware_count` | `Integer` | `0` | Associated malware count |
| `raw_risk_score` | `Float` | `0.0` | Raw calculated risk score |
| `risk_score` | `Float` | `0.0` | Normalized risk score |
| `last_updated` | `DateTime` | `utcnow` | Last scan/update timestamp |

---

### InternalRiskSnapshot
**Table**: `internal_risk_snapshots`

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | `Integer PK` | auto | Primary key |
| `timestamp` | `DateTime` | `utcnow` | Snapshot time |
| `score` | `Float` | — | Overall risk score |
| `risk_level` | `String` | — | CIS risk level (GREEN-BLUE-YELLOW-ORANGE-RED) |
| `total_assets` | `Integer` | — | Total monitored assets |
| `total_osint_hits` | `Integer` | — | Total OSINT vulnerability matches |
| `critical_osint_hits` | `Integer` | — | Critical OSINT matches |
| `hw_data_json` | `Text` | — | Hardware asset data snapshot |
| `sw_data_json` | `Text` | — | Software asset data snapshot |

---

### CloudOutage
**Table**: `cloud_outages`

| Column | Type | Default | Index | Description |
|--------|------|---------|-------|-------------|
| `id` | `Integer PK` | auto | Y | Primary key |
| `provider` | `String` | — | Y | Cloud provider name |
| `service` | `String` | — | — | Affected service name |
| `title` | `String` | — | — | Outage title |
| `description` | `Text` | — | — | Outage description |
| `link` | `String` | — | — | Status page URL |
| `is_resolved` | `Boolean` | `False` | Y | Whether the outage is resolved |
| `updated_at` | `DateTime` | — | Y | Last update timestamp |

---

### RegionalHazard
**Table**: `regional_hazards`

| Column | Type | Default | Index | Description |
|--------|------|---------|-------|-------------|
| `id` | `Integer PK` | auto | Y | Primary key |
| `hazard_id` | `String` | — | Y (unique) | Source hazard identifier |
| `hazard_type` | `String` | — | — | NWS/SPC/USGS hazard type |
| `severity` | `String` | — | — | Classified severity level |
| `title` | `String` | — | — | Hazard title |
| `description` | `Text` | — | — | Full description |
| `location` | `String` | — | — | Geographic location string |
| `updated_at` | `DateTime` | — | Y | Last update timestamp |

---

### CrimeIncident
**Table**: `crime_incidents`

| Column | Type | Default | Index | Description |
|--------|------|---------|-------|-------------|
| `id` | `String PK` | — | Y | Source incident ID |
| `category` | `String` | — | — | Incident category/type |
| `raw_title` | `String` | — | — | Original incident description |
| `timestamp` | `DateTime` | — | Y | Incident timestamp |
| `distance_miles` | `Float` | — | — | Distance from monitored location |
| `severity` | `String` | — | — | Classified severity (High/Critical/Low/Info) |
| `lat` | `Float` | — | — | Latitude |
| `lon` | `Float` | — | — | Longitude |
| `is_alert_dispatched` | `Boolean` | `False` | Y | Whether perimeter alert was sent |

---

### Remaining Models

| Table | Key Columns | Notes |
|-------|-------------|-------|
| `saved_reports` | `id`, `title`, `author`, `content` (Text), `created_at` | Custom report library |
| `feed_sources` | `id`, `url` (unique), `name`, `is_active` | RSS/Atom feed registry |
| `keywords` | `id`, `word` (unique), `weight` | 70 default keywords seeded |
| `software_assets` | `id`, `name`, `last_updated` | Simple software inventory |
| `extracted_iocs` | `id`, `article_id`, `indicator_type`, `indicator_value`, `context` | FK to `articles.id` |
| `cve_items` | `id`, `cve_id` (unique), `vendor`, `product`, `date_added` | CISA KEV catalog |
| `elastic_events` | `id` (String PK), `timestamp`, `severity`, `message`, `source_ip` | Elasticsearch sync |
| `daily_briefings` | `id`, `report_date` (unique), `content` | Fusion report archive |
| `daily_threat_scores` | `id`, `record_date` (unique), `cyber_points`, `physical_points` | 14-day baseline |
| `regional_outages` | `id`, `outage_type`, `provider`, `lat`, `lon`, `radius_km`, `is_resolved` | Regional power/ISP outages |
| `bgp_anomalies` | `id`, `asn`, `event_type`, `description`, `is_resolved` | RIPE RIS routing anomalies |
| `timeline_events` | `id`, `timestamp`, `source`, `event_type`, `message` | RCA activity feed |
| `geojson_cache` | `feed_name` (PK), `data` (JSON), `updated_at` | SPC/NWS/USGS cached |
| `node_aliases` | `id`, `node_pattern`, `mapped_location_name`, `confidence_score`, `is_verified` | SolarWinds mapping |
| `user_weather_prefs` | `id`, `username`, `alert_type` | Weather preferences |

---

## Base Configuration

All models inherit from `declarative_base()`:

```python
from sqlalchemy.orm import declarative_base
Base = declarative_base()
```

The `init_db()` function in `src/core/db.py` calls `Base.metadata.create_all(bind=engine)` and seeds default data:
- Admin and analyst users
- Admin and analyst roles with all permissions
- 70 default keywords with weights
- 12 default RSS feed sources
- Default system configuration
- Rescales all existing articles with current keyword weights
