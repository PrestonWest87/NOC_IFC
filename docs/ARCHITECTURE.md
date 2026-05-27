# NOC Intelligence Fusion Center — Architecture

## Overview

Enterprise intelligence HUD for Network Operations Centers. Ingests RSS feeds, weather/telemetry data, crime incidents, and generates AI-powered reports. React SPA frontend with FastAPI backend, SQLite/PostgreSQL persistence, and background scheduler for automated data ingestion.

---

## 1. System Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Browser    │────▶│  nginx:5173  │────▶│  API:8101    │
│  (React SPA) │     │  (web svc)   │     │  (FastAPI)   │
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                 │
                    ┌────────────────────────────┼────────────────────┐
                    │                            │                    │
               ┌────▼─────┐              ┌──────▼──────┐      ┌─────▼──────┐
               │  Worker   │              │  Webhook    │      │  SQLite /  │
               │ scheduler │              │  :8100      │      │ PostgreSQL │
               │ (5 jobs)  │              │  (FastAPI)  │      │  (volume)  │
               └───────────┘              └─────────────┘      └────────────┘
```

### Service Components

| Service | Image | Port | Command |
|---------|-------|------|---------|
| `api` | `noc_ifc-api` (Python 3.11) | 8101 | `uvicorn src.api.main:app --port 8101` |
| `worker` | `noc_ifc-api` | — | `python src/scheduler.py` |
| `webhook` | `noc_ifc-api` | 8100 | `python src/webhook_listener.py` |
| `web` | `nginx` (built from `web/`) | 5173 | nginx serving static build |
| `web-dev` | `node:20-alpine` (profile: dev) | 5173 | `npm run dev` with hot reload |

### Data Volume

- `./data:/app/data` — SQLite database file, persistent across restarts

---

## 2. Directory Structure

```
/
├── src/                          # Python backend
│   ├── api/
│   │   ├── main.py               # FastAPI app, WebSocket broadcaster
│   │   ├── ws_manager.py         # WebSocket connection manager
│   │   └── routes/
│   │       ├── auth.py           # Login, logout, profile
│   │       ├── dashboard.py      # Metrics, intel, articles
│   │       ├── rca.py            # AIOps RCA endpoints
│   │       ├── regional.py       # Regional grid / geospatial
│   │       ├── threat.py         # CVEs, cloud, crime
│   │       ├── hunting.py        # IOC matrix, OSINT
│   │       ├── logbook.py        # Shift log entries
│   │       ├── reporting.py      # Briefings, saved reports
│   │       ├── settings.py       # Config endpoints
│   │       ├── settings_admin.py # User/role management
│   │       ├── aiops.py          # AI endpoints
│   │       ├── llm.py            # LLM proxy
│   │       └── email.py          # Email dispatch
│   ├── core/
│   │   ├── db.py                 # SQLAlchemy engine & session
│   │   └── config.py             # Logging setup
│   ├── models/
│   │   └── schema.py             # All ORM models
│   ├── services/
│   │   ├── aiops_engine.py       # EnterpriseAIOpsEngine
│   │   └── ... (future)
│   ├── services.py               # Data Access Layer (DAL)
│   ├── scheduler.py              # Background job scheduler
│   ├── webhook_listener.py       # Webhook gateway
│   ├── workers/
│   │   └── infra_worker.py       # Infrastructure fetch jobs
│   └── utils/
│       └── llm.py                # LLM integration helpers
├── web/                          # React frontend
│   ├── src/
│   │   ├── App.tsx               # Router, protected routes
│   │   ├── pages/
│   │   │   ├── LoginPage.tsx
│   │   │   ├── DashboardPage.tsx
│   │   │   ├── AiopsRcaPage.tsx
│   │   │   ├── RegionalGridPage.tsx
│   │   │   ├── ThreatTelemetryPage.tsx
│   │   │   ├── ThreatHuntingPage.tsx
│   │   │   ├── ShiftLogbookPage.tsx
│   │   │   ├── ReportingPage.tsx
│   │   │   └── SettingsPage.tsx
│   │   ├── components/
│   │   │   └── Layout.tsx        # Sidebar navigation
│   │   ├── hooks/
│   │   │   └── useAIOpsWebSocket.ts
│   │   ├── utils/
│   │   │   ├── api.ts            # Axios client (token interceptor)
│   │   │   ├── AuthContext.tsx    # Auth state management
│   │   │   └── permissions.ts    # Tab-level permission helpers
│   │   └── styles/
│   │       └── theme.css         # CSS custom properties (dark theme)
│   ├── nginx.conf                # Reverse proxy config
│   └── Dockerfile                # Multi-stage build
├── AGENTS.md                     # Agent instructions
├── docker-compose.yml
├── Dockerfile                    # Python services
├── requirements.txt
└── .env                          # Environment variables
```

---

## 3. Database Schema

### Core Tables (SQLAlchemy, `src/models/schema.py`)

| Table | Key Columns | Purpose |
|-------|-------------|---------|
| `users` | `id`, `username`, `password_hash`, `session_token`, `role` | Authentication & authorization |
| `roles` | `id`, `name`, `allowed_pages` (JSON), `allowed_actions` (JSON), `allowed_site_types` (JSON) | RBAC definitions |
| `solarwinds_alerts` | `id`, `node_name`, `status`, `device_type`, `mapped_location`, `is_dispatched`, `is_correlated` | Ingested infrastructure alerts |
| `monitored_locations` | `id`, `name`, `lat`, `lon`, `loc_type`, `under_maintenance`, `maintenance_etr` | Facility/site registry |
| `timeline_events` | `id`, `source`, `event_type`, `message`, `timestamp` | Activity feed for RCA board |
| `regional_outages` | `id`, `location`, `provider`, `is_resolved` | Regional infrastructure outages |
| `cve_items` | `id`, `cve_id`, `date_added` | CISA KEV feed cache |
| `cloud_outages` | `id`, `provider`, `status`, `is_resolved` | Cloud service status |
| `bgp_anomalies` | `id`, `asn`, `is_resolved` | BGP routing anomalies |
| `regional_hazards` | `id`, `hazard_type`, `location`, `lat`, `lon`, `radius_km` | Weather/geospatial hazards |
| `crime_incidents` | `id`, `category`, `lat`, `lon`, `severity` | Crime data feed |
| `shift_log_entries` | `id`, `analyst`, `content`, `shift_period`, `is_deleted` | Operator shift logs |
| `feed_sources` | `id`, `url`, `category`, `is_active` | RSS feed configuration |
| `system_config` | `id`, `is_active`, `llm_endpoint`, `llm_api_key` | AI/LLM configuration |
| `geojson_cache` | `feed_name`, `data` (JSON), `updated_at` | Cached GeoJSON (SPC, NWS, USGS) |

---

## 4. Permission / RBAC System

### Architecture

Permissions are **frontend-enforced** with backend API checks on critical actions. The system is flat (no hierarchy) — each action permission is a string.

### Permission Strings

```
# Actions (9)
Action: Pin Articles
Action: Train ML Model
Action: Boost Threat Score
Action: Trigger AI Functions
Action: Manually Sync Data
Action: Dispatch Exec Report
Action: Submit Shift Log
Action: Dispatch RCA Tickets          # Gates dispatch endpoint
Action: Manage Site Maintenance       # Gates site-maintenance endpoint

# Tab permissions (~38)
Tab: <Module> -> <Tab Name>
```

### Default Roles

| Role | Pages | Actions |
|------|-------|---------|
| `admin` | All 8 pages | All 47 permissions (hardcoded) |
| `analyst` | All except Settings | All 47 permissions (seeded in DB) |
| (custom) | Configurable via Settings UI | Configurable via Settings UI |

### Enforcement Points

| Layer | Mechanism |
|-------|-----------|
| Page access | `ProtectedRoute` in `App.tsx` checks `user.allowed_pages` |
| Tab visibility | `getAllowedTabs()` filters `TAB_PERMISSION_MAP` |
| Action buttons | Component-level checks of `user.allowed_actions` |
| Backend API | `require_action(action)` FastAPI dependency on dispatch, site-maintenance |
| Sidebar nav | `Layout.tsx` filters nav items by `allowed_pages` |

---

## 5. API Routes

All under `/api/v1/`, grouped by router:

| Group | Prefix | Auth | Key Endpoints |
|-------|--------|------|---------------|
| Auth | `/auth` | None | `/login`, `/me`, `/logout`, `/update-profile` |
| Dashboard | `/dashboard` | None | `/metrics`, `/intel`, `/articles` |
| RCA | `/rca` | Token (dispatch, maint only) | `/dashboard`, `/analyze`, `/dispatch`, `/site-maintenance`, `/acknowledge`, `/generate-ticket`, `/sitrep` |
| Regional | `/regional` | None | `/locations`, `/geojson`, `/compile-map`, `/infrastructure-analytics`, `/weather-alerts-log`, `/forecast` |
| Threat | `/threat` | None | `/cve`, `/cloud-outages`, `/crime`, `/articles` |
| Hunting | `/hunting` | None | `/iocs`, `/osint-pivot`, `/article-search` |
| Logbook | `/logbook` | None | `/entries`, `/save`, `/delete` |
| Reporting | `/reporting` | None | `/brief`, `/generate`, `/saved-reports` |
| Settings | `/settings` | None | `/config`, `/users`, `/rss-sources` |
| Admin | `/admin` | None | `/roles`, `/users`, `/locations`, `/backup` |

### RCA Engine Flow

```
POST /rca/analyze
  ├── get_aiops_dashboard_data()        # Fetch active alerts
  ├── EnterpriseAIOpsEngine()
  │   ├── analyze_and_cluster(alerts)   # Group by site
  │   ├── identify_fleet_outages()      # Carrier-wide events
  │   ├── calculate_root_cause()        # Per-site RCA
  │   └── generate_chronic_insights()   # 60-day trends
  └── Return {clustered, fleet_outages, root_cause, chronic_insights}
```

### AIOps Engine Ontology (7 Domains)

| Domain | Tier | Device Types |
|--------|------|--------------|
| `POWER_SUPPLIES` | 1 | UPS, Generator, PDU, DC Controller |
| `PRIMARY_INTERNET` | 2 | VSAT, Cellular, SD-WAN, Modem |
| `COMMS_EQUIPMENT` | 3 | Router, Switch, Firewall |
| `COMPUTE` | 4 | VM Host, Server, Storage |
| `RTU` | 5 | RTU, NTEST RTU |
| `SCADA` | 6 | Sub Equipment, Meter, Plant Equipment |
| `FACILITIES` | 7 | Access Control, IP Camera, HVAC |
| `UNKNOWN_DOMAIN` | 8 | Unclassified |

---

## 6. Frontend Architecture

### Stack

| Library | Purpose |
|---------|---------|
| React 18 | UI framework |
| TypeScript | Type safety |
| Vite | Build tool / dev server |
| react-router-dom v7 | Client-side routing |
| @tanstack/react-query v5 | Server state, caching, mutations |
| deck.gl / react-map-gl | Geospatial map visualization |
| maplibre-gl | Map tiles (free, no API key) |
| recharts | Charts and graphs |
| axios | HTTP client (with token interceptor) |
| zustand | Lightweight client state |
| lucide-react | Icon library |

### Data Flow

```
User Action → useMutation → api.post() → FastAPI → DB
                                   ↓
                   queryClient.invalidateQueries()
                                   ↓
                    useQuery refetches → UI updates

WebSocket ← broadcaster (5s interval)
     ↓
useAIOpsWebSocket → dashboard_update → state update
```

### Route Map

| Route | Component | Permission Required |
|-------|-----------|---------------------|
| `/login` | LoginPage | None |
| `/` | DashboardPage | Global Dashboards |
| `/threat-telemetry` | ThreatTelemetryPage | Threat Telemetry |
| `/regional-grid` | RegionalGridPage | Regional Grid |
| `/threat-hunting` | ThreatHuntingPage | Threat Hunting & IOCs |
| `/aiops-rca` | AiopsRcaPage | AIOps RCA |
| `/shift-logbook` | ShiftLogbookPage | Shift Logbook |
| `/reporting` | ReportingPage | Reporting & Briefings |
| `/settings` | SettingsPage | Settings & Admin |

### Theming

CSS custom properties in `theme.css`. All components use inline styles referencing variables:

- `--bg-primary`, `--bg-secondary`, `--bg-card` — backgrounds
- `--text-primary`, `--text-secondary`, `--text-muted` — text
- `--accent-blue`, `--accent-cyan`, `--accent-green`, etc. — action colors
- `--risk-green` through `--risk-red` — risk level colors

---

## 7. Regional Grid — Weather/Site Intersection

### Pipeline

```
NWS API → fetch_regional_hazards() → GeoJsonCache (DB)
                                          ↓
get_cached_geojson() ← @TTLCache(ttl=120s)
       ↓
_precompute_geo_matrix()
  ├── Parse SPC day1/day2/day3 contours
  ├── Parse NWS alerts (AR + OOS feeds)
  │     └── process_nws_alerts() — PDS detection, severity classification
  ├── Parse fire risk counties (FIPS-based)
  ├── Parse active wildfires (NIFC API)
  ├── Parse USGS earthquakes
  └── calculate_site_intersections()
        └── Shapely Point.within(polygon) with bounding-box pre-check
              ↓
POST /regional/compile-map
  ├── Receives: toggles, selected_events, map_df (JSON array)
  ├── Calls _precompute_geo_matrix (converts JSON array → DataFrame)
  ├── Filters master_affected_sites by toggle state
  └── Returns: [layers[], viewState{}, diagnostics[], toggled_affected[], master_affected[]]

Alternative: Frontend builds map layers client-side from raw GeoJSON (SPC, NWS, USGS)
```

### Severity Classification

| Condition | Severity |
|-----------|----------|
| `Warning` or `Emergency` in event type | Warning |
| `PDS` in event type or headline (not Warning) | PDS Watch |
| Fire Weather `Red Flag` or `Warning` | Extreme |
| Fire Weather `Watch` | High |
| Earthquake M >= 5.0 | High (Red) |
| Earthquake M >= 4.0 | Medium (Orange) |
| Earthquake M >= 3.0 | Low (Yellow) |
| SPC HIGH/MDT/ENH/SLGT/MRGL/TSTM | As labeled |

---

## 8. Scheduler Jobs

Defined in `src/scheduler.py`:

| Job | Interval | Description |
|-----|----------|-------------|
| `fetch_all_rss()` | 15 min | Poll RSS feed sources |
| `fetch_crime_data()` | 3 min | Crime incident feed |
| `fetch_regional_hazards()` | 2 min | NWS, SPC, USGS data |
| `check_cloud_outages()` | 5 min | Cloud provider status APIs |
| `sync_cisa_kev()` | 6 hours | CISA Known Exploited Vulnerabilities |
| `calculate_internal_risk()` | 6 hours | Internal risk scoring |
| `generate_unified_brief()` | 2 hours | AI-powered situation report |
| `db_maintenance()` | 60 min | DB cleanup and optimization |
| `ml_retrain()` | Sunday 02:00 | Retrain ML models |

---

## 9. WebSocket

- **Endpoint**: `ws://localhost:8101/ws`
- **Payload**: `{"type": "dashboard_update", "alerts": [...], "events": [...], "alert_count": N}`
- **Interval**: Every 5 seconds
- **Bi-directional**: Send JSON commands back through the socket
- **Frontend**: `useAIOpsWebSocket` hook in `web/src/hooks/useAIOpsWebSocket.ts`

---

## 10. Webhook Listener

- **Endpoint**: `POST http://localhost:8100/webhook/solarwinds`
- **Port**: 8100 (separate service from API)
- **Flow**:
  1. Receive raw JSON payload
  2. Extract node name, IP, status, device type via `smart_extract()`
  3. Classify device type via `classify_device()` (fingerprint-based)
  4. Check for resolution indicators (word-boundary regex on status)
  5. Create or resolve `SolarWindsAlert` records
  6. Create `TimelineEvent` entries
- **Resolution detection**: `re.search(r'\bup\b', status)` — word-boundary matching to avoid false positives (e.g., "upstream")

---

## 11. Risk Levels

```
GREEN < BLUE < YELLOW < ORANGE < RED
```

Used in dashboard risk scoring, alert prioritization, and site status indicators.

---

## 12. Environment Variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `DATABASE_URL` | Yes | `sqlite:////app/data/noc_fusion.db` | Database connection string |
| `RISK_ALERT_RECIPIENTS` | No | — | Comma-separated email recipients for risk alerts |

---

## 13. Deployment

### Production
```bash
docker compose up --build -d
```

### Development (with hot reload)
```bash
docker compose --profile dev up --build -d
```

### Manual Rebuilds
```bash
# After backend changes
docker compose up --build -d api
docker compose restart web     # Refresh nginx DNS cache

# After frontend changes (production)
docker compose up --build -d --force-recreate web

# After frontend changes (dev — picks up automatically via volume)
```

### Logs
```bash
docker compose logs -f api       # API server
docker compose logs -f worker    # Background scheduler
docker compose logs -f webhook   # Webhook gateway
docker compose logs -f web       # Frontend / nginx
```

---

## 14. Default Credentials

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | admin |

Created on first startup by `src/core/db.py` seed logic.
