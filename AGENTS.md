# NOC Intelligence Fusion Center — Agent Instructions

## Overview

Enterprise intelligence HUD for Network Operations Centers. Ingests RSS feeds, weather/telemetry data, crime incidents, and generates AI-powered reports.

Branch `architecture/monolith-to-decoupled` — a complete rewrite from main's Streamlit monolithic app to a decoupled FastAPI + React SPA.

## Architecture

- **Frontend** (`web/`): React + TypeScript + Vite SPA (port 5173 dev, nginx prod)
- **API** (`src/api/main.py`): FastAPI REST + WebSocket on port 8101
- **Worker** (`src/scheduler.py`): Background scheduler for data ingestion
- **Webhook** (`src/webhook_listener.py`): FastAPI gateway on port 8100
- **Database**: SQLite (default) or PostgreSQL (`DATABASE_URL` in `.env`)

## Developer Commands

```bash
# Build and run all services (production — nginx static build)
docker compose up --build -d

# Run with Vite dev server + hot reload
docker compose --profile dev up --build -d

# Monitor logs
docker compose logs -f worker   # background scheduler
docker compose logs -f api      # FastAPI + WebSocket
docker compose logs -f web      # Frontend (nginx, no HMR)

# Restart services
docker compose restart api                           # API changes
docker compose up --build -d --force-recreate web    # Frontend changes (rebuild needed)

# Frontend dev standalone
cd web && npm run dev
```

## Key Files

| File | Purpose |
|------|---------|
| `web/src/App.tsx` | React app entrypoint |
| `web/src/pages/*.tsx` | Page components |
| `web/src/components/Layout.tsx` | Sidebar navigation layout |
| `web/src/components/AIOpsMap.tsx` | AIOps map visualization |
| `web/src/components/MapContainer.tsx` | Geospatial map container |
| `web/src/components/ThemeSelector.tsx` | Dark/light theme toggle |
| `web/src/components/BidirectionalCommands.tsx` | WebSocket command interface |
| `web/src/hooks/useAIOpsWebSocket.ts` | WebSocket real-time hook |
| `web/src/utils/api.ts` | API client (axios) |
| `web/src/utils/AuthContext.tsx` | Auth state management |
| `web/src/utils/timezone.ts` | America/Chicago timezone formatting |
| `web/src/utils/routeConfig.ts` | Route/permission config |
| `web/src/styles/theme.css` | Dark theme CSS variables |
| `web/src/themes/themes.css` | Full theme system |
| `src/api/main.py` | FastAPI + WebSocket broadcaster |
| `src/api/routes/` | API route modules |
| `src/services.py` | Data Access Layer (DAL) |
| `src/services/aiops_engine.py` | Enterprise AIOps correlation engine |
| `src/services/logic.py` | Scoring logic |
| `src/services/categorizer.py` | Article categorization |
| `src/services/ioc_extractor.py` | IOC extraction engine |
| `src/services/threat_hunter.py` | Threat hunting logic |
| `src/core/db.py` | SQLAlchemy engine and session |
| `src/core/config.py` | Pydantic settings + logging setup |
| `src/models/schema.py` | Database models |
| `src/scheduler.py` | Background task scheduler |
| `src/webhook_listener.py` | SolarWinds webhook gateway on port 8100 |
| `src/utils/llm.py` | LLM interaction utilities |
| `src/utils/mailer.py` | Email sending utilities |
| `src/utils/risk_alert.py` | Risk alert checking |

## Environment Variables (`.env`)

```
DATABASE_URL=sqlite:////app/data/noc_fusion.db   # Required
RISK_ALERT_RECIPIENTS=email1,email2               # Risk alerts
REMEDYFORCE_TICKET_EMAIL=ticket@solarwinds.com    # Tiered escalation
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
| RCA | `/rca` | Dashboard, analyze, acknowledge, dispatch, send-ticket |
| AIOps | `/aiops` | Dashboard, sitrep, sites |
| Logbook | `/logbook` | Shift entries |
| Reporting | `/reporting` | Briefings, saved reports |
| LLM | `/llm` | Connection test, weather brief |
| Email | `/email` | Send emails, broadcast brief |
| Settings | `/settings` | Config, users |
| Admin | `/admin` | Roles, locations, backup, nuke, assets |

## Scheduler Jobs

| Job | Interval | Notes |
|-----|----------|-------|
| RSS Feed Fetch | 15 min | — |
| Crime Fetch | 3 min | — |
| Regional Hazards | 2 min | — |
| Cloud Outages | 5 min | — |
| CISA KEV | 6 hours | — |
| Internal Risk | 1 hour | Matches main |
| Unified Brief | 30 min | Matches main |
| DB Maintenance | 60 min | Dedup + purge old data |
| ML Retrain | Sunday 02:00 | — |
| Tiered Alert Escalation | 1 min | P1-P5 SLA, cascade, flapping detection |

## Risk Levels

GREEN < BLUE < YELLOW < ORANGE < RED

## WebSocket

- Connect to `ws://localhost:8101/ws`
- Receives `dashboard_update` payloads every 5 seconds
- Send JSON commands back for bidirectional control

## Theme

CSS custom properties in `web/src/styles/theme.css` and `web/src/themes/themes.css`. Variables:
- `--bg-primary`, `--bg-secondary`, `--bg-card`
- `--text-primary`, `--text-secondary`, `--text-muted`
- `--accent-blue`, `--accent-cyan`, `--accent-green`, etc.
- `--risk-green`, `--risk-blue`, `--risk-yellow`, `--risk-orange`, `--risk-red`

---

## What's Been Done

### Shift Logbook
- Layout overhaul, day-stepper navigation, independent explorer tab
- Soft delete with reason field
- Auto-assign shift from user profile (name + title)
- Fallback text summary when LLM generation >30s (prevents 504)

### Settings — Internal Assets
- Asset CSV import endpoints for hardware/software assets
- Site types pulled from DB (`get_all_site_types()` merges DB `loc_type` values with defaults)
- Frontend fetches site types from `/regional/site-types` for role management
- Missing assets tab visibility fixed
- `Tab: Settings -> Internal Assets` permission added

### Settings — CIS Scoring Configuration
- Scoring overrides (manual/hybrid/auto modes) with C/I/L override columns
- `Scoring Configuration` card in Settings page
- Global/Internal Risk override panels in DashboardPage

### Unified Brief
- Map-reduce pipeline ported from main (replaces single-pass generation)
- Mandatory OSINT correlation disclaimer in executive summary
- Feeds 30 cyber articles, 20 phys articles, 20 crimes, 20 HW/SW assets + DB telemetry
- Temperature 0.35, improved prompt for operational translation
- Email formatting aligned with main: CIS alert level names (not color codes), Cyber Security Director line
- `POST /email/broadcast-brief` endpoint

### RCA Dispatch Tickets
- `generate_rca_ticket_text` ported from main — dynamic domains, compact alerts, clearer descriptions
- Cluster data used for trigger time, alert details
- District line in ticket header
- Manual dispatch email format matches auto-scheduler (same subject, body wrapper, plain text)
- `POST /rca/send-ticket` endpoint
- Cascade indentation bug fixed (non-cascade tickets were blocked)

### Email System
- SMTP field mapping fixed in `/email/send`
- Broadcast brief endpoint added
- CIS alert level names used throughout
- Comprehensive logging added across all email modules

### AIOps RCA Page
- Site type filtering via `user.allowed_site_types`
- Color logic: investigating > dispatched > maintenance > action required
- Window-fill fullscreen (CSS fixed positioning, not Fullscreen API)
- Green when no active alerts, coloring only when alerts present
- Auto-clear investigating transition guard (prevents clearing all on dashboard refetch)
- Maintenance is sticky (auto-clear removed; must be manually cleared)
- Save-site race condition fixed (sequential mutations, not `Promise.allSettled`)
- UTC date rollover maintenance wipe fixed

### RCA Tracking Display
- `status_modified_by`, `status_modified_at` columns on `MonitoredLocation`
- Tracking info (acknowledged/dispatched/modified by user @ time) in correlation cards, maintenance banner, site dialog
- Forwarded through scatterplot data to map popups

### Timezone
- All frontend times converted to America/Chicago
- `web/src/utils/timezone.ts` — centralized formatting

### DB & Migration
- `NullPool` for SQLite to avoid `QueuePool` contention
- ALTER TABLE split into per-column try/except (prevents silent skips)
- Missing `monitored_locations` columns added
- `alerted_eq_ids` column race condition fixed

### Other Fixes
- Blank screen on login for single-page users — redirect to first allowed page
- Email sending field mapping
- Regional grid tooltips respect toggles, earthquake tooltip enhanced with depth/time
- Earthquake email alerts deduplicated
- DB pool exhaustion, production nginx allows 10.0.0.0/8 + test.weasts.net

---

## Completed Earlier

- **Tiered Alert Escalation**: 1-min loop, P1-P5 SLA, business hours, on-call paging, flapping detection, cascade handling, site-level mute
- **Correlation Engine**: 7-domain ontology, patient-zero tier scoring, SLA/P1-P5 mapping, fleet outage detection, chronic insights
- **Regional Grid**: PDS detection, compile-map response `[layers, viewState, diagnostics, toggled_affected, master_affected, analytics]`, executive dash analytics embedded
- **Google Cloud outage date filtering**, RSS deduplication, scheduler intervals matched to main
- **Webhook alert level normalization**, article pagination/category filter, keyword seeding + rescoring

## Critical Context

- **Keywords must be seeded for scorer**: `init_db()` seeds 70 keywords + rescales all existing articles. Rebuild API container after DB reset.
- **Domain names**: `PRIMARY_INTERNET`, `COMMS_EQUIPMENT`, `POWER_SUPPLIES`, `RTU`, `SCADA`, `COMPUTE`, `FACILITIES` — must be consistent everywhere.
- **Permission strings**: `Action: Dispatch RCA Tickets`, `Action: Manage Site Maintenance`, `Tab: Settings -> Internal Assets`, `Tab: Dashboards -> Unified Brief` must match exactly in backend and frontend.
- **`web` container has source mount with hot reload**: changes to `web/` files are reflected instantly via Vite HMR.
- **compile-map response**: `[layers[], viewState{}, diagnostics[], toggled_affected[], master_affected[], analytics{}]` — frontend accesses by index.
- **All changes on `architecture/monolith-to-decoupled`**, pushed to `origin/architecture/monolith-to-decoupled`.
