# NOC Intelligence Fusion Center - Agent Instructions

## Overview

Enterprise intelligence HUD for Network Operations Centers. Ingests RSS feeds, weather/telemetry data, crime incidents, and generates AI-powered reports.

Branch `architecture/monolith-to-decoupled` — a complete rewrite from main's Streamlit monolithic app to a decoupled FastAPI + React SPA. Full enterprise-grade documentation available in `Documentation/`.

## Architecture

- **Frontend** (`web/`): React + TypeScript + Vite SPA on port 5173 (production: nginx)
- **API** (`src/api/main.py`): FastAPI REST + WebSocket on port 8101
- **Worker** (`src/scheduler.py`): Background scheduler for data ingestion
- **Webhook** (`src/webhook_listener.py`): FastAPI gateway on port 8100
- **Database**: SQLite (default) or PostgreSQL (set `DATABASE_URL` in `.env`)

## Developer Commands

```bash
# Build and run all services (production mode)
docker compose up --build -d

# Run with Vite dev server (hot reload)
docker compose --profile dev up --build -d

# Monitor background worker logs
docker compose logs -f worker

# Monitor API logs
docker compose logs -f api

# Restart API after code changes
docker compose restart api

# Restart web after frontend changes
docker compose up --build -d --force-recreate web

# Frontend dev (standalone)
cd web && npm run dev
```

## Key Files

| File | Purpose |
|------|--------|
| `web/src/App.tsx` | React app entrypoint |
| `web/src/pages/*.tsx` | Page components (9 pages) |
| `web/src/components/Layout.tsx` | Sidebar navigation layout |
| `web/src/components/AIOpsMap.tsx` | AIOps map visualization |
| `web/src/components/BidirectionalCommands.tsx` | WebSocket command interface |
| `web/src/hooks/useAIOpsWebSocket.ts` | WebSocket real-time hook |
| `web/src/utils/api.ts` | API client (axios) |
| `web/src/utils/AuthContext.tsx` | Auth state management |
| `web/src/styles/theme.css` | Dark theme CSS variables |
| `src/api/main.py` | FastAPI + WebSocket broadcaster |
| `src/api/routes/` | 13 API route modules |
| `src/services.py` | Data Access Layer (DAL) — 104 functions |
| `src/services/aiops_engine.py` | Ported Enterprise AIOps correlation engine |
| `src/services/logic.py` | Scoring logic |
| `src/services/categorizer.py` | Article categorization |
| `src/services/ioc_extractor.py` | IOC extraction engine |
| `src/services/threat_hunter.py` | Threat hunting logic |
| `src/core/db.py` | SQLAlchemy engine and session |
| `src/core/config.py` | Pydantic settings + logging setup |
| `src/models/schema.py` | Database models (27 tables) |
| `src/scheduler.py` | Background task scheduler |
| `src/webhook_listener.py` | SolarWinds webhook gateway on port 8100 |
| `src/utils/llm.py` | LLM interaction utilities |
| `src/utils/mailer.py` | Email sending utilities |
| `src/utils/risk_alert.py` | Risk alert checking |

## Environment Variables (`.env`)

```
DATABASE_URL=sqlite:////app/data/noc_fusion.db  # Required
RISK_ALERT_RECIPIENTS=email1,email2              # For risk alerts
```

## Default Credentials

- Login: `admin` / `admin123`
- Webhook: `POST http://localhost:8100/webhook/solarwinds`

## Frontend Routes

| Route | Page | Description |
|-------|------|-------------|
| `/login` | LoginPage | Authentication |
| `/` | DashboardPage | Global Dashboards (Operational, Risk, Internal, Brief) |
| `/threat-telemetry` | ThreatTelemetryPage | RSS, KEV, Cloud, Crime map |
| `/regional-grid` | RegionalGridPage | Geospatial map, hazards, weather |
| `/threat-hunting` | ThreatHuntingPage | IOC matrix, deep hunt builder |
| `/aiops-rca` | AiopsRcaPage | Active board, patterns, global correlation |
| `/shift-logbook` | ShiftLogbookPage | Shift logs and history |
| `/reporting` | ReportingPage | Daily fusion, report builder, library |
| `/settings` | SettingsPage | Admin: facilities, assets, RSS, AI, users, backup |

## API Endpoints

Prefix: `/api/v1/`

| Group | Prefix | Description |
|-------|--------|-------------|
| Auth | `/auth` | Login, logout, profile |
| Dashboard | `/dashboard` | Metrics, intel, articles |
| Threat | `/threat` | CVEs, cloud outages, crime, articles |
| Regional | `/regional` | Locations, geojson, analytics, weather |
| Hunting | `/hunting` | IOCs, OSINT pivot, article search |
| RCA | `/rca` | Dashboard, analyze, acknowledge, dispatch |
| AIOps | `/aiops` | Dashboard, sitrep, sites |
| Logbook | `/logbook` | Shift entries |
| Reporting | `/reporting` | Briefings, saved reports |
| LLM | `/llm` | Connection test, weather brief |
| Email | `/email` | Send emails |
| Settings | `/settings` | Config, users |
| Admin | `/admin` | Roles, locations, backup, nuke |

## Scheduler Jobs

| Job | Interval (refactor) | Interval (main) | Notes |
|-----|--------------------|-----------------|-------|
| RSS Feed Fetch | 15 min | 15 min | Same |
| Crime Fetch | 3 min | 3 min | Same |
| Regional Hazards | 2 min | 2 min | Same |
| Cloud Outages | 5 min | 5 min | Same |
| CISA KEV | 6 hours | 6 hours | Same |
| Internal Risk | 6 hours | **1 hour** | Main runs 6x more often — should match |
| Unified Brief | 2 hours | **30 min** | Main runs 4x more often — should match |
| DB Maintenance | 60 min | 60 min | Same |
| ML Retrain | Sunday 02:00 | Sunday 02:00 | Same |
| Tiered Alert Escalation | **1 min** | **1 min** | Ported from main — requires `REMEDYFORCE_TICKET_EMAIL` env var |

## Risk Levels

GREEN < BLUE < YELLOW < ORANGE < RED

## WebSocket

- Connect to `ws://localhost:8101/ws`
- Receives `dashboard_update` payloads every 5 seconds
- Send JSON commands back through the WebSocket for bidirectional control

## Dark Mode Theme

The application uses CSS custom properties for theming. All components use inline styles referencing CSS variables defined in `web/src/styles/theme.css`. Variables include:
- `--bg-primary`, `--bg-secondary`, `--bg-card` for backgrounds
- `--text-primary`, `--text-secondary`, `--text-muted` for text
- `--accent-blue`, `--accent-cyan`, `--accent-green`, etc. for accents
- `--risk-green`, `--risk-blue`, `--risk-yellow`, `--risk-orange`, `--risk-red` for risk levels

---

## Completed Work

All fixes committed and pushed to `origin/architecture/monolith-to-decoupled`.

### AIOps RCA Page — Popup Save + Dispatch/Maintenance

- **/site-maintenance route**: Changed from query params (`str = ""`) to JSON `Body(...)` — frontend sends JSON body, backend now reads it correctly. Verified: maintenance flag persists on save, clears on reset.
- **Permission gating**: `require_action(action)` FastAPI dependency — dispatch gated behind `Action: Dispatch RCA Tickets`, maintenance behind `Action: Manage Site Maintenance`. Frontend conditionally renders dispatch/maint controls based on `user.allowed_actions`. Admin gets 200, observer gets 403.
- **/dispatch route**: Gated with `require_action("Action: Dispatch RCA Tickets")`.

### Correlation Engine — Ported from Main

- **`EnterpriseAIOpsEngine`** in `src/services/aiops_engine.py`:
  - Ontology: `PRIMARY_INTERNET`, `COMMS_EQUIPMENT`, `POWER_SUPPLIES`, `RTU`, `SCADA`, `COMPUTE`, `FACILITIES` (7 domains, 8-tier ranking)
  - `_get_domain(node_type, node_name, primary_comms)` — uses node_name + primary_comms for classification
  - `_determine_patient_zero` tier scoring: `(9-tier)*2000` with 8-tier ranking
  - Maintenance auto-clear: expired ETR dates auto-unset in `calculate_root_cause`
  - SLA/priority mapping: P1-P5 from `max_alert_level`
  - Fleet outage detection: checks `PRIMARY_INTERNET`/`COMMS_EQUIPMENT`
- **/analyze route**: Queries CloudOutage/RegionalHazard/BgpAnomaly from DB, iterates per-site calling `calculate_root_cause`
- **`generate_chronic_insights`**: Converts pandas DataFrames → dicts via `to_json(orient="records")`
- **Webhook classifier**: Updated fingerprints to match engine ontology (`PRIMARY_INTERNET`, `COMMS_EQUIPMENT`, etc.)

### Regional Grid

- **PDS detection**: Added `"PDS"` check in `process_nws_alerts` event_type/headline
- **/compile-map**: Converts JSON → DataFrame → `_precompute_geo_matrix` → filter by toggles → returns `[layers, viewState, diagnostics, toggled_affected, master_affected, analytics]`
- **Executive Dash tab**: Analytics payload (SPC/NWS/district distributions, risk matrices, `at_risk_sites`, `highest_risk`) embedded as index [5] in compile-map response instead of separate stub endpoint. compile-map query fires for both geospatial and executive tabs.
- **/infrastructure-analytics**: Removed stub endpoint

---

## Remaining Work — Port from Main

### Completed

1. **Tiered Alert Escalation scheduler job** — Ported from main:
   - 24/7 RCA ticketing with business hours detection
   - P1-P5 SLA escalation logic (P1=30min, P2=1hr, P3=2hr, P4=4hr, P5=8hr)
   - Smart on-call paging (NOC vs ITNetwork for SWF devices)
   - Flapping node detection via cooldown
   - Cascade handling (escalated alerts override target)
   - Site-level onpage mute via `last_escalation_ticket`
   - Boot sequence calls `schedule.every(1).minutes.do(run_threaded, job_tiered_alert_escalation)`

2. **Google Cloud outage date filtering** — Fixed:
   - Added `days_back` parameter to `get_cloud_outages()` (default: 7 days)
   - Filter by `updated_at >= cutoff` in query
   - `/threat/cloud-outages` route accepts `days_back` query param
   - `run_database_maintenance()` purges unresolved CloudOutages older than 14 days

3. **RSS article deduplication** — Added `deduplicate_articles(session)` function:
   - Removes exact link duplicates (concurrency edge cases)
   - Removes near-duplicate titles (SequenceMatcher > 85%) within same source
   - Called from `run_database_maintenance()` and after each feed fetch

4. **Scheduler intervals — matched to main**:
   - Internal Risk: 6 hours → **1 hour**
   - Unified Brief: 2 hours → **30 minutes**

### Model columns added
- `is_ticketed` to `SolarWindsAlert` (used by escalation engine)
- `last_auto_ticket`, `last_escalation_ticket`, `last_auto_dispatch`, `last_escalation_dispatch` to `MonitoredLocation`
- `status_modified_by`, `status_modified_at` to `MonitoredLocation`

### Completed

5. **Webhook alert level normalization** — Fixed:
   - Added `alert_level` extraction in `smart_extract()` — pulls `Alert_Level` from payload or `Custom_Properties_Universal`
   - Inject `Normalized_Alert_Level` into `raw_payload` before DB insert
   - Added `AlertName` to event_type extraction chain

6. **Article pagination verification** — Fixed:
   - Category filter was hardcoded to `"All"` in API route — added `cat_filter` query param wiring it to `get_paginated_articles()`. Frontend's category dropdown now works.
   - Verified: page clamping, total/total_pages in UI, independent per-tab page tracking, search page size dropdown all work

7. **Keyword seeding + article rescoring** — Fixed:
   - Seeded 70 default NOC/cybersecurity keywords in `init_db()` (ransomware 90, breach 85, exploit 80, etc.)
   - Added `rescore_all_articles()` in `services.py` — re-scores every article using current keywords + categorizer + IOC extractor
   - Called from `init_db()` after keyword seeding — 149 existing articles rescored on container start
   - Live tab now shows **154 articles across 8 pages** (was 0 due to empty keyword table)
   - Fixed CISA Advisories feed URL: `feed.xml` (404) → `all.xml` (works)
   - Removed stale broken CISA feed entry from DB

### Low Priority

7. **Frontend known issues**:
   - Production web container lacks source volume mount — all frontend changes require `docker compose up --build -d --force-recreate web`
   - Regional grid frontend accesses `compileResponse[3]` and `compileResponse[4]` — fragile array index pattern

## Critical Context

- **Keywords must be seeded for scorer**: `init_db()` seeds 70 keywords + rescales all existing articles. Rebuild API container after DB reset to trigger re-seed.
- **Domain names must be consistent**: engine, webhook classifier, and all conditionals use `PRIMARY_INTERNET`, `COMMS_EQUIPMENT`, `POWER_SUPPLIES`, `RTU`, `SCADA`, `COMPUTE`, `FACILITIES`
- **Permission strings**: `Action: Dispatch RCA Tickets` and `Action: Manage Site Maintenance` must match exactly in backend and frontend
- **`web` container has no source mount**: rebuild with `docker compose up --build -d --force-recreate web` after frontend changes
- **compile-map response**: returns `[layers[], viewState{}, diagnostics[], toggled_affected[], master_affected[], analytics{}]` — frontend accesses by index
- **All fixes on `architecture/monolith-to-decoupled`**: working tree clean, pushed to `origin/architecture/monolith-to-decoupled`
