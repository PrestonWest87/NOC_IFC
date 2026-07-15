# Trigger & Action Flow Reference

> Enterprise-grade reference for every trigger in the NOC Intelligence Fusion Center and the complete action flows they initiate.

---

## Table of Contents

1. [SolarWinds Webhook Triggers](#1-solarwinds-webhook-triggers)
2. [Scheduler Job Triggers](#2-scheduler-job-triggers)
3. [User Action Triggers](#3-user-action-triggers)
4. [WebSocket Triggers](#4-websocket-triggers)

---

## 1. SolarWinds Webhook Triggers

### POST /webhook/solarwinds

| Attribute | Value |
|-----------|-------|
| **Trigger** | SolarWinds Orion sends a JSON alert payload to port 8100 |
| **Source** | SolarWinds Orion via webhook action |
| **Endpoint** | `POST http://<host>:8100/webhook/solarwinds` |
| **Handler** | `src/webhook_listener.py` |

#### Complete Action Flow

```
SolarWinds Orion
  │
  ▼
POST /webhook/solarwinds  (raw JSON body)
  │
  ├─ 1. Receive raw JSON
  │     └─ Parse body → validate JSON structure
  │
  ├─ 2. smart_extract()
  │     └─ Normalize: node_name, ip, severity, alert_level, event_type, status
  │
  ├─ 3. classify_device()
  │     └─ Fingerprint (node_name + event_type) → map to one of 7 ontology domains:
  │        PRIMARY_INTERNET | COMMS_EQUIPMENT | POWER_SUPPLIES | RTU |
  │        SCADA | COMPUTE | FACILITIES
  │
  ├─ 4. Check resolution status
  │     └─ Scan status field for keywords: resolved, up, ok, clear, operational, recovered
  │
  ├─ 5a. IF RESOLUTION detected:
  │       ├─ Query active (unresolved) alerts for matching node_name
  │       ├─ Mark all matching alerts → Resolved, set resolved_at
  │       ├─ Create TimelineEvent(type=Resolution)
  │       ├─ COMMIT
  │       └─ DONE
  │
  └─ 5b. IF NEW ALERT:
        ├─ Create SolarWindsAlert record (includes raw_payload)
        ├─ Create TimelineEvent(type=Alert)
        ├─ COMMIT
        └─ Scheduler tiered escalation picks up within 1 minute
```

#### Outputs

| Artifact | Table | Notes |
|----------|-------|-------|
| Alert record | `solarwinds_alerts` | New row with raw payload, domain, severity |
| Timeline event | `timeline_events` | Type: `Alert` or `Resolution` |
| Resolved alerts | `solarwinds_alerts` | All matching alerts marked `status='Resolved'` (on resolution) |

---

## 2. Scheduler Job Triggers

All scheduler jobs are defined in `src/scheduler.py` and run inside the **worker container**.

---

### 2.1 fetch_feeds

| Attribute | Value |
|-----------|-------|
| **Interval** | Every 15 minutes |
| **Source** | `src/scheduler.py` → feed worker |
| **DB tables** | `articles`, `extracted_iocs` |

#### Action Flow

```
Schedule library fires
  │
  ├─ 1. Query active FeedSources from DB
  │
  ├─ 2. Build known_links set (articles from last 7 days for dedup)
  │
  ├─ 3. Async fetch all feeds in chunks of 5
  │     └─ For each feed URL: aiohttp GET → feedparser.parse()
  │
  ├─ 4. For each parsed entry:
  │     ├─ HybridScorer.score()          → risk_score, risk_level
  │     ├─ categorize_text()              → category
  │     └─ ioc_engine.extract()           → IOCs (optional)
  │
  ├─ 5. bulk_save_to_db() in batches of 100
  │
  └─ 6. deduplicate_articles()
        └─ Remove exact link duplicates + title similarity matches
```

#### Outputs

| Artifact | Table | Notes |
|----------|-------|-------|
| Articles | `articles` | Scored, categorized, with dedup |
| IOCs | `extracted_iocs` | IPs, domains, hashes extracted from article text |

---

### 2.2 fetch_live_crimes

| Attribute | Value |
|-----------|-------|
| **Interval** | Every 3 minutes |
| **Source** | `src/scheduler.py` → crime worker |
| **DB tables** | `crime_incidents` |

#### Action Flow

```
Schedule library fires
  │
  ├─ 1. Call crime worker fetch_live_crimes()
  │
  ├─ 2. Save CrimeIncident records to DB
  │
  └─ 3. dispatch_perimeter_crime_alerts()
        ├─ Check for new high-severity crimes within 0.4 miles of monitored locations
        └─ Send SMS-via-email alert for each qualifying crime
```

#### Outputs

| Artifact | Table | Notes |
|----------|-------|-------|
| Crime incidents | `crime_incidents` | New records from data source |
| Email alerts | SMTP | Perimeter crime alerts to configured recipients |

---

### 2.3 fetch_regional_hazards

| Attribute | Value |
|-----------|-------|
| **Interval** | Every 2 minutes |
| **Source** | `src/scheduler.py` → infra worker |
| **DB tables** | `regional_hazards`, `geojson_cache` |

#### Action Flow

```
Schedule library fires
  │
  ├─ 1. Call infra worker fetch_regional_hazards()
  │
  ├─ 2. Update RegionalHazard records
  │
  ├─ 3. Update GeoJsonCache with NWS GeoJSON
  │
  ├─ 4. Calculate site intersections with hazard polygons
  │     └─ Match hazard geometry against monitored location coordinates
  │
  ├─ 5. Check earthquake proximity (50-mile radius)
  │     └─ Compare earthquake epicenter distance to each monitored site
  │
  └─ 6. Optional email SitRep (if conditions warrant)
```

#### Outputs

| Artifact | Table | Notes |
|----------|-------|-------|
| Hazards | `regional_hazards` | Updated NWS hazard data |
| GeoJSON cache | `geojson_cache` | Latest NWS GeoJSON polygons |
| Site intersections | Calculated | Hazards affecting monitored locations |
| Email | SMTP | Optional situation report |

---

### 2.4 fetch_cloud_outages

| Attribute | Value |
|-----------|-------|
| **Interval** | Every 5 minutes |
| **Source** | `src/scheduler.py` → cloud worker |
| **DB tables** | `cloud_outages` |

#### Action Flow

```
Schedule library fires
  │
  ├─ 1. Call cloud worker fetch_cloud_outages()
  │
  └─ 2. Update CloudOutage records
        └─ Merge new outage data into existing table (upsert by provider+event)
```

#### Outputs

| Artifact | Table | Notes |
|----------|-------|-------|
| Cloud outages | `cloud_outages` | Provider outage status updates |

---

### 2.5 run_telemetry_sync

| Attribute | Value |
|-----------|-------|
| **Interval** | Every 5 minutes |
| **Source** | `src/scheduler.py` → telemetry worker |
| **DB tables** | `bgp_anomalies`, `elastic_events` |

#### Action Flow

```
Schedule library fires
  │
  └─ Call telemetry worker run_telemetry_sync()
        ├─ Sync BGP anomalies from upstream sources
        └─ Sync Elastic events from upstream sources
```

#### Outputs

| Artifact | Table | Notes |
|----------|-------|-------|
| BGP anomalies | `bgp_anomalies` | BGP route/flow anomalies |
| Elastic events | `elastic_events` | Correlated SIEM telemetry |

---

### 2.6 fetch_cisa_kev

| Attribute | Value |
|-----------|-------|
| **Interval** | Every 6 hours |
| **Source** | `src/scheduler.py` → cve worker |
| **DB tables** | `cve_items` |

#### Action Flow

```
Schedule library fires
  │
  └─ Call cve_worker fetch_cisa_kev()
        └─ Update CveItem records from CISA Known Exploited Vulnerabilities catalog
```

#### Outputs

| Artifact | Table | Notes |
|----------|-------|-------|
| CVE items | `cve_items` | KEV catalog entries with exploit status |

---

### 2.7 job_internal_risk

| Attribute | Value |
|-----------|-------|
| **Interval** | Every 1 hour |
| **Source** | `src/scheduler.py` |
| **DB tables** | `internal_risk_snapshots` |

#### Action Flow

```
Schedule library fires
  │
  ├─ 1. generate_and_save_internal_risk_snapshot()
  │     └─ Gather internal telemetry, asset posture, IOC matches
  │
  ├─ 2. calculate_internal_cis_score()
  │     └─ Compute C/I/L components → composite score → risk level
  │
  ├─ 3. Save InternalRiskSnapshot row
  │
  └─ 4. check_and_alert()
        └─ If risk level increased since last snapshot → send email alert
```

#### Outputs

| Artifact | Table | Notes |
|----------|-------|-------|
| Risk snapshot | `internal_risk_snapshots` | C/I/L scores, composite, risk level |
| Email alert | SMTP | Only on risk level increase |

---

### 2.8 job_unified_brief

| Attribute | Value |
|-----------|-------|
| **Interval** | Every 30 minutes |
| **Source** | `src/scheduler.py` |
| **DB tables** | `system_config` (unified_brief key) |

#### Action Flow

```
Schedule library fires
  │
  ├─ 1. Gather telemetry:
  │     ├─ Latest internal risk snapshot
  │     ├─ NWS hazard summary
  │     └─ Crime incident summary
  │
  ├─ 2. get_executive_grid_intel()
  │     └─ Global CIS scores across all 7 domains
  │
  ├─ 3. generate_unified_risk_brief()
  │     └─ LLM map-reduce pipeline:
  │        ├─ Map: per-source chunk summaries (temp 0.35)
  │        └─ Reduce: executive synthesis with mandatory OSINT disclaimer
  │
  ├─ 4. Save to SystemConfig (key: unified_brief)
  │
  └─ 5. check_and_alert()
        └─ If global risk level increased → send email alert
```

#### Outputs

| Artifact | Table | Notes |
|----------|-------|-------|
| Brief text | `system_config` | Updated unified_brief value |
| Email alert | SMTP | Only on global risk level increase |

---

### 2.9 job_tiered_alert_escalation

| Attribute | Value |
|-----------|-------|
| **Interval** | Every 1 minute |
| **Source** | `src/scheduler.py` |
| **DB tables** | `solarwinds_alerts`, `monitored_locations` |

This is the most complex scheduler job. It runs a full enterprise AIOps correlation and escalation cycle.

#### Action Flow

```
Schedule library fires
  │
  ├─ 1. Query unresolved SolarWindsAlerts (last 12 hours)
  │
  ├─ 2. EnterpriseAIOpsEngine.analyze_and_cluster()
  │     └─ Group alerts by site using 7-domain correlation engine
  │
  └─ 3. For each site with undispatched alerts:
        │
        ├─ 3a. calculate_root_cause()
        │      └─ 7-stage correlation:
        │         ├─ Stage 1: Domain fingerprinting
        │         ├─ Stage 2: Temporal clustering
        │         ├─ Stage 3: Spatial grouping
        │         ├─ Stage 4: Patient-zero identification (tier scoring)
        │         ├─ Stage 5: Cascade detection
        │         ├─ Stage 6: SLA/P1-P5 mapping
        │         └─ Stage 7: Chronic insight generation
        │
        ├─ 3b. Determine business hours
        │      └─ M-F 0600–2000 America/Chicago
        │
        ├─ 3c. Select escalation rules
        │      ├─ DAY_SHIFT rules (business hours)
        │      └─ AFTER_HOURS rules (nights/weekends)
        │
        ├─ 3d. Detect cascading alerts
        │      └─ Higher-priority sibling alerts at same site
        │
        ├─ 3e. Check node cooldown (flapping detection)
        │      └─ Skip if same node alerted within cooldown window
        │
        ├─ 3f. Check site-level on-page mute
        │      └─ 1-hour cooldown per site; skip paging if muted
        │
        ├─ 3g. Dispatch ticket email
        │      └─ To: REMEDYFORCE_TICKET_EMAIL
        │      └─ Body: RCA ticket text (compact alerts, district line, trigger time)
        │
        ├─ 3h. If AFTER_HOURS:
        │      ├─ Send NOC notification email
        │      └─ Page on-call personnel
        │
        └─ 3i. Mark alerts
               ├─ Update SolarWindsAlert.is_ticketed = True
               └─ Update MonitoredLocation tracking fields
                  (status_modified_by, status_modified_at)
```

#### Outputs

| Artifact | Table | Notes |
|----------|-------|-------|
| Ticket emails | SMTP | To Remedyforce ticket queue |
| After-hours pages | SMTP | NOC notification + on-call paging |
| Alert state | `solarwinds_alerts` | `is_ticketed` flag set |
| Location tracking | `monitored_locations` | `status_modified_by`, `status_modified_at` updated |

---

### 2.10 job_retrain_ml

| Attribute | Value |
|-----------|-------|
| **Interval** | Sundays at 02:00 CST |
| **Source** | `src/scheduler.py` |
| **DB tables** | `articles` (rescored) |

#### Action Flow

```
Schedule fires (Sunday 02:00)
  │
  ├─ 1. train() ML model pipeline
  │     └─ Retrain on labeled article corpus
  │
  ├─ 2. force_reload_scorer()
  │     └─ Hot-reload HybridScorer with new model (no restart)
  │
  └─ 3. rescore_all_articles()
        └─ Re-score every existing article with fresh model
```

#### Outputs

| Artifact | Table | Notes |
|----------|-------|-------|
| ML model | filesystem | Updated model pickle file |
| Rescored articles | `articles` | All risk_score/risk_level values updated |

---

### 2.11 run_database_maintenance

| Attribute | Value |
|-----------|-------|
| **Interval** | Every 60 minutes |
| **Source** | `src/scheduler.py` |

#### Action Flow

```
Schedule library fires
  │
  ├─ 1. deduplicate_articles()
  │     └─ Remove exact link duplicates + title-similarity pairs
  │
  ├─ 2. Purge old data per retention policy
  │     └─ Drop rows older than configured TTL per table
  │
  ├─ 3. Delete orphaned IOCs
  │     └─ Remove ExtractedIOC rows whose parent article was purged
  │
  └─ 4. SQLite-specific optimizations
        ├─ PRAGMA optimize
        └─ WAL checkpoint
```

#### Outputs

| Artifact | Table | Notes |
|----------|-------|-------|
| Cleaned DB | all tables | Deduplicated, purged, optimized |

---

### 2.12 job_daily_email_unified_brief

| Attribute | Value |
|-----------|-------|
| **Interval** | Daily at 07:00 CST |
| **Source** | `src/scheduler.py` |

#### Action Flow

```
Schedule fires (daily 07:00)
  │
  ├─ 1. Load latest unified brief from SystemConfig
  │
  ├─ 2. Generate rich HTML email body
  │     └─ CIS alert level names (not color codes)
  │     └─ Cyber Security Director sign-off line
  │
  └─ 3. Send via SMTP to RISK_ALERT_RECIPIENTS
```

#### Outputs

| Artifact | Table | Notes |
|----------|-------|-------|
| Email | SMTP | Daily unified brief to configured recipients |

---

## 3. User Action Triggers

All user-initiated actions follow this general pattern:

```
React Component
  → useMutation / api.{method}()
    → API route (FastAPI)
      → services.py function
        → DB operation (SQLAlchemy)
          → Response
            → queryClient.invalidateQueries()
              → UI refresh
```

---

### 3.1 Login

| Attribute | Value |
|-----------|-------|
| **Component** | `web/src/pages/LoginPage.tsx` |
| **Endpoint** | `POST /api/v1/auth/login` |

#### Action Flow

```
User submits credentials
  │
  ├─ 1. React LoginPage → POST /auth/login
  │
  ├─ 2. authenticate_user()
  │     ├─ Query user by username
  │     ├─ bcrypt verify password hash
  │     └─ Generate UUID session token
  │
  ├─ 3. Return user object + token
  │
  ├─ 4. AuthContext stores token (localStorage)
  │
  └─ 5. Redirect to dashboard
```

---

### 3.2 Generate Unified Brief

| Attribute | Value |
|-----------|-------|
| **Component** | `web/src/pages/DashboardPage.tsx` |
| **Endpoint** | `POST /api/v1/dashboard/generate-unified-brief` |

#### Action Flow

```
User clicks "Generate Brief"
  │
  ├─ 1. POST /dashboard/generate-unified-brief
  │     └─ Spawn background thread → return generation_id immediately
  │
  ├─ 2. Frontend polls GET /brief-generation-status every 2 seconds
  │     └─ Progress bar updates from response
  │
  ├─ 3. On "complete" status:
  │     ├─ Invalidate sys-config query
  │     ├─ Refresh brief display
  │     └─ Auto-clear progress indicator
  │
  └─ 4. On "error" status:
        └─ Display error, stop polling
```

---

### 3.3 Acknowledge Alert

| Attribute | Value |
|-----------|-------|
| **Component** | `web/src/pages/AiopsRcaPage.tsx` |
| **Endpoint** | `POST /api/v1/rca/acknowledge` |

#### Action Flow

```
User clicks "Acknowledge" on alert cluster
  │
  ├─ 1. POST /rca/acknowledge
  │     └─ Body: cluster_id, alert_ids
  │
  ├─ 2. acknowledge_cluster()
  │     ├─ Update alerts as correlated
  │     └─ Update MonitoredLocation.status_modified_by/at
  │
  ├─ 3. Broadcast RCA_UPDATE via WebSocket
  │     └─ ws_manager.broadcast({"type": "RCA_UPDATE", ...})
  │
  └─ 4. Frontend receives WebSocket event → refreshes cluster view
```

---

### 3.4 Dispatch RCA Ticket

| Attribute | Value |
|-----------|-------|
| **Component** | `web/src/pages/AiopsRcaPage.tsx` |
| **Endpoint** | `POST /api/v1/rca/dispatch` |

#### Action Flow

```
User clicks "Dispatch Ticket"
  │
  ├─ 1. POST /rca/dispatch
  │     └─ Body: cluster_id, alert_ids
  │
  ├─ 2. set_cluster_dispatch()
  │     ├─ Generate RCA ticket text (compact alerts, district line)
  │     ├─ Update alerts: is_ticketed = True
  │     └─ Update MonitoredLocation tracking fields
  │
  ├─ 3. Broadcast RCA_UPDATE via WebSocket
  │
  └─ 4. Frontend receives WebSocket event → refreshes cluster view
```

---

### 3.5 Set Site Maintenance

| Attribute | Value |
|-----------|-------|
| **Component** | `web/src/pages/AiopsRcaPage.tsx` |
| **Endpoint** | `POST /api/v1/rca/site-maintenance` |

#### Action Flow

```
User clicks "Set Maintenance"
  │
  ├─ 1. POST /rca/site-maintenance
  │     └─ Body: location_id, under_maintenance, etr, reason
  │
  ├─ 2. set_site_maintenance()
  │     ├─ Toggle MonitoredLocation.under_maintenance
  │     ├─ Set ETR (estimated time to resolution) and reason
  │     └─ Clear location cache
  │
  ├─ 3. Broadcast RCA_UPDATE via WebSocket
  │
  └─ 4. Frontend receives WebSocket event → refreshes cluster view
```

**Note:** Maintenance is sticky — it persists until manually cleared. The auto-clear escalation guard does not affect maintenance status.

---

### 3.6 Edit Keyword Weight

| Attribute | Value |
|-----------|-------|
| **Component** | `web/src/pages/SettingsPage.tsx` |
| **Endpoint** | `PATCH /api/v1/admin/keywords/{id}` |

#### Action Flow

```
User clicks w:N label → number input appears
  │
  ├─ 1. User enters new weight (1–100) → Enter or blur
  │
  ├─ 2. PATCH /admin/keywords/{id}
  │     └─ Body: { weight: <value> }
  │
  ├─ 3. update_keyword_weight()
  │     ├─ Validate weight ∈ [1, 100]
  │     └─ Update DB row
  │
  ├─ 4. force_reload_scorer()
  │     └─ Hot-reload HybridScorer with updated keyword weights
  │
  ├─ 5. Return updated keyword object
  │
  └─ 6. Invalidate admin-lists query → UI refreshes with new weight
```

---

### 3.7 Bulk Add Keywords

| Attribute | Value |
|-----------|-------|
| **Component** | `web/src/pages/SettingsPage.tsx` |
| **Endpoint** | `POST /api/v1/admin/keywords/bulk` |

#### Action Flow

```
User submits raw keyword text
  │
  ├─ 1. POST /admin/keywords/bulk?raw_text=...
  │
  ├─ 2. add_bulk_keywords()
  │     ├─ Parse word,weight pairs from raw text
  │     ├─ Validate each weight ∈ [1, 100]
  │     ├─ Filter out duplicates (existing keywords)
  │     └─ Bulk insert new keywords
  │
  ├─ 3. COMMIT
  │
  └─ 4. Return created keywords → UI refreshes
```

---

### 3.8 Import Locations

| Attribute | Value |
|-----------|-------|
| **Component** | `web/src/pages/SettingsPage.tsx` |
| **Endpoint** | `POST /api/v1/admin/location/import` |

#### Action Flow

```
User uploads location CSV / submits form
  │
  ├─ 1. POST /admin/location/import?mode=add|upsert|replace
  │
  ├─ 2. import_locations()
  │     ├─ mode=add:      Insert new rows only (skip duplicates)
  │     ├─ mode=upsert:   Insert or update by matching key
  │     └─ mode=replace:  Truncate + reload full dataset
  │
  ├─ 3. Clear location cache
  │
  └─ 4. Return import summary → UI refreshes
```

---

## 4. WebSocket Triggers

| Attribute | Value |
|-----------|-------|
| **Endpoint** | `ws://<host>:8101/ws` |
| **Handler** | `src/api/main.py` → `ws_manager` |
| **Protocol** | JSON messages over WebSocket |

### Broadcast Mechanism

```
API endpoint / background task
  │
  ├─ BackgroundTasks.add_task(ws_manager.broadcast, payload)
  │
  └─ ws_manager.broadcast()
        └─ Iterate all connected clients → send JSON message
```

### Dashboard Polling

| Attribute | Value |
|-----------|-------|
| **Interval** | Every 5 seconds |
| **Payload type** | `dashboard_update` |
| **Content** | Current CIS metrics, alert counts, risk levels |

```
Server-side timer (5s)
  │
  └─ Collect current dashboard state
        └─ ws_manager.broadcast({"type": "dashboard_update", "data": {...}})
              └─ All connected clients receive current metrics
```

### RCA UPDATE Events

The following user actions trigger an `RCA_UPDATE` broadcast to all connected WebSocket clients:

| Action | Endpoint | Trigger |
|--------|----------|---------|
| Investigate cluster | `POST /rca/analyze` | User opens cluster details |
| Acknowledge alert | `POST /rca/acknowledge` | User acknowledges cluster |
| Dispatch ticket | `POST /rca/dispatch` | User dispatches RCA ticket |
| Set site maintenance | `POST /rca/site-maintenance` | User toggles maintenance mode |
| Send ticket email | `POST /rca/send-ticket` | User manually sends ticket |

```
User action completes
  │
  ├─ DB state updated
  ├─ MonitoredLocation tracking fields updated
  │
  └─ ws_manager.broadcast({"type": "RCA_UPDATE", ...})
        │
        └─ All WebSocket clients
              └─ React useAIOpsWebSocket hook
                    └─ queryClient.invalidateQueries() → UI refresh
```

---

## Appendix: Email Alert Summary

| Trigger | Recipients | Condition |
|---------|------------|-----------|
| Perimeter crime alert | Configured SMS gateway | High-severity crime < 0.4 mi from site |
| Internal risk increase | `RISK_ALERT_RECIPIENTS` | Risk level escalated since last snapshot |
| Unified brief risk increase | `RISK_ALERT_RECIPIENTS` | Global risk level escalated |
| Daily unified brief | `RISK_ALERT_RECIPIENTS` | Always at 07:00 CST |
| Tiered escalation ticket | `REMEDYFORCE_TICKET_EMAIL` | Undispatched alerts at a site |
| After-hours NOC notification | NOC distribution list | After-hours escalation |
| After-hours on-call paging | On-call rotation list | After-hours escalation |
| Optional SitRep | Configured recipients | Regional hazard conditions warrant |

---

## Appendix: Ontology Domains

All 7 domains must be consistent across webhook classification, AIOps correlation, and UI display:

| Domain | Description |
|--------|-------------|
| `PRIMARY_INTERNET` | WAN/ISP connectivity, DNS, BGP |
| `COMMS_EQUIPMENT` | Switches, routers, firewalls, wireless |
| `POWER_SUPPLIES` | UPS, PDU, generators, utility power |
| `RTU` | Remote terminal units, PLCs, field I/O |
| `SCADA` | SCADA servers, HMI, historians |
| `COMPUTE` | Servers, VMs, containers, applications |
| `FACILITIES` | HVAC, physical security, environmental sensors |

---

## Appendix: Risk Level Hierarchy

```
GREEN  <  BLUE  <  YELLOW  <  ORANGE  <  RED
```

Used for: CIS scoring, alert escalation, email triggers, dashboard display, and brief generation.
