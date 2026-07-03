# NOC Intelligence Fusion Center — Architecture

## Overview

Enterprise intelligence HUD for Network Operations Centers. Ingests RSS feeds, weather/telemetry data, crime incidents, and generates AI-powered reports. React SPA frontend with FastAPI backend, SQLite/PostgreSQL persistence, background scheduler for automated data ingestion, and webhook gateway for ITSM telemetry.

---

## 1. System Architecture

```
+------------------+       +------------------+       +------------------+
|   Browser        |       |   nginx:5173     |       |   FastAPI:8101   |
|   (React SPA)    | ----> |   (web service)   | ----> |   (API service)  |
+------------------+       +------------------+       +--------+---------+
                                                                   |
+------------------------------------------------------------------+-------+
|                                                                          |
+------------------+          +------------------+          +--------------+
|   Worker         |          |   Webhook:8100   |          |  SQLite /    |
|   (scheduler)    |          |   (FastAPI gw)   |          |  PostgreSQL  |
+------------------+          +------------------+          +--------------+
```

### Service Components

| Service | Image | Port | Command | Description |
|---------|-------|------|---------|-------------|
| `api` | `noc_ifc-api` (Python 3.11) | 8101 | `uvicorn src.api.main:app --host 0.0.0.0 --port 8101 --reload` | FastAPI REST API + WebSocket broadcaster |
| `worker` | `noc_ifc-api` | — | `python -u src/scheduler.py` | Background scheduler for 10 automated jobs |
| `webhook` | `noc_ifc-api` | 8100 | `python -u src/webhook_listener.py` | FastAPI gateway for SolarWinds ITSM telemetry |
| `web` | `nginx` (built from `web/`) | 5173 | nginx serving static build | Production React SPA |
| `web-dev` | `node:20-alpine` (profile: dev) | 5173 | `npm run dev -- --host 0.0.0.0` | Development Vite dev server with hot reload |

### Data Volume

- `./data:/app/data` — SQLite database file, persistent across restarts

---

## 2. Directory Structure

```
/
├── src/                              # Python backend
│   ├── api/
│   │   ├── main.py                   # FastAPI app, WebSocket broadcaster, 13 route routers
│   │   ├── ws_manager.py             # WebSocket ConnectionManager (connect/disconnect/broadcast)
│   │   └── routes/
│   │       ├── auth.py               # Login, logout, profile (prefix: /api/v1/auth)
│   │       ├── dashboard.py          # Metrics, intel, articles (prefix: /api/v1/dashboard)
│   │       ├── rca.py                # RCA: dashboard, analyze, acknowledge, dispatch, maintenance,
│   │       │                         #   investigate, generate-ticket, send-ticket, sitrep,
│   │       │                         #   clear-events, nuke-alerts, resolve-alert
│   │       ├── regional.py           # Locations, geojson, compile-map, weather (prefix: /api/v1/regional)
│   │       ├── threat.py             # CVEs, cloud outages, crime, articles (prefix: /api/v1/threat)
│   │       ├── hunting.py            # IOCs, OSINT pivot, article search (prefix: /api/v1/hunting)
│   │       ├── logbook.py            # Shift entries CRUD, summary generation (prefix: /api/v1/logbook)
│   │       ├── reporting.py          # Briefings, saved reports, custom generation (prefix: /api/v1/reporting)
│   │       ├── settings.py           # Config, users (prefix: /api/v1/settings)
│   │       ├── settings_admin.py     # Roles, users, locations, backup, nuke (prefix: /api/v1/admin)
│   │       ├── aiops.py              # AIOps dashboard, sitrep, sites (prefix: /api/v1/aiops)
│   │       ├── llm.py                # LLM connection test, weather brief (prefix: /api/v1/llm)
│   │       └── email.py              # Email dispatch (prefix: /api/v1/email)
│   ├── core/
│   │   ├── config.py                 # Pydantic Settings + logging setup
│   │   └── db.py                     # SQLAlchemy engine, session, init_db() with seed data
│   ├── models/
│   │   └── schema.py                 # 27 SQLAlchemy ORM models
│   ├── services/
│   │   ├── aiops_engine.py           # EnterpriseAIOpsEngine (ontology, RCA, fleet detection)
│   │   ├── categorizer.py            # Article categorization (8 categories)
│   │   ├── ioc_extractor.py          # IOC extraction engine
│   │   ├── logic.py                  # HybridScorer (keyword + ML scoring)
│   │   └── threat_hunter.py          # Threat hunting logic
│   ├── utils/
│   │   ├── llm.py                    # LLM interaction utilities
│   │   ├── mailer.py                 # SMTP email sending
│   │   └── risk_alert.py             # Risk level escalation monitoring
│   ├── workers/
│   │   ├── base_worker.py            # Abstract BaseWorker class
│   │   ├── cloud_worker.py           # 18+ cloud provider status fetcher
│   │   ├── crime_worker.py           # Police CAD feed fetcher
│   │   ├── cve_worker.py             # CISA KEV catalog fetcher
│   │   ├── elastic_worker.py         # Elasticsearch telemetry sync
│   │   ├── infra_worker.py           # SPC, NWS, USGS hazard fetcher
│   │   ├── report_worker.py          # Daily fusion report scheduler
│   │   └── telemetry_worker.py       # ORNL, RIPE, IODA telemetry fetcher
│   ├── services.py                   # Data Access Layer (104 functions)
│   ├── scheduler.py                  # Background job orchestrator (10 jobs)
│   ├── webhook_listener.py           # Webhook gateway (port 8100)
│   ├── app.py                        # Legacy Streamlit entry (deprecated)
│   ├── database.py                   # Legacy DB shim
│   ├── train_model.py                # ML model trainer
│   ├── migrate_to_sqlite.py          # Postgres-to-SQLite migration
│   └── test_elastic.py               # Elasticsearch diagnostic
├── web/                              # React frontend
│   ├── src/
│   │   ├── App.tsx                   # Router, 9 protected routes, permission gating
│   │   ├── main.tsx                  # Vite entry point, theme initialization
│   │   ├── pages/
│   │   │   ├── LoginPage.tsx         # /login
│   │   │   ├── DashboardPage.tsx     # / (Operational, Risk, Internal, Brief)
│   │   │   ├── ThreatTelemetryPage.tsx   # /threat-telemetry
│   │   │   ├── RegionalGridPage.tsx  # /regional-grid
│   │   │   ├── ThreatHuntingPage.tsx # /threat-hunting
│   │   │   ├── AiopsRcaPage.tsx      # /aiops-rca
│   │   │   ├── ShiftLogbookPage.tsx  # /shift-logbook
│   │   │   ├── ReportingPage.tsx     # /reporting
│   │   │   └── SettingsPage.tsx      # /settings
│   │   ├── components/
│   │   │   ├── Layout.tsx            # Collapsible sidebar navigation
│   │   │   ├── AIOpsMap.tsx          # DeckGL scatterplot map for RCA
│   │   │   ├── MapContainer.tsx      # Generic deck.gl wrapper with ResizeObserver
│   │   │   ├── BidirectionalCommands.tsx  # WebSocket command interface
│   │   │   └── ThemeSelector.tsx     # 6-theme switcher
│   │   ├── hooks/
│   │   │   └── useAIOpsWebSocket.ts  # WebSocket with exponential-backoff reconnect
│   │   ├── store/
│   │   │   └── useAppStore.ts        # Zustand global state store
│   │   ├── utils/
│   │   │   ├── api.ts                # Axios client with token interceptor
│   │   │   ├── AuthContext.tsx        # Auth state + JWT management
│   │   │   ├── permissions.ts        # Tab-level permission resolution
│   │   │   ├── notifications.ts      # Browser notification dedup
│   │   │   ├── routeConfig.ts        # Route definitions
│   │   │   └── timezone.ts           # Timezone utilities
│   │   └── styles/
│   │       ├── theme.css             # CSS custom properties (dark theme)
│   │       ├── components.css        # Reusable component classes
│   │       └── themes.css            # 5 alternative theme overrides
│   ├── nginx.conf                    # Reverse proxy /api/ and /ws to backend
│   ├── Dockerfile                    # Multi-stage build (node-builder + nginx)
│   ├── vite.config.ts                # Vite dev server config
│   ├── tsconfig.json                 # TypeScript strict mode
│   ├── index.html                    # SPA entry point
│   └── package.json                  # Dependencies: deck.gl, maplibre, react, zustand, axios
├── Documentation/                    # Enterprise function-level documentation
│   ├── ARCHITECTURE.md               # This file
│   ├── api/                          # API docs (main, ws_manager, 13 route modules)
│   ├── config/                       # Docker, nginx, Vite, TS config docs
│   ├── core/                         # config.py, db.py docs
│   ├── models/                       # schema.py docs (27 tables)
│   ├── services/                     # services.py, aiops_engine.py, etc.
│   ├── ui/                           # Legacy Streamlit docs
│   ├── utils/                        # llm.py, mailer.py, risk_alert.py
│   ├── web/                          # React frontend docs
│   └── workers/                      # 8 worker module docs
├── docs/                             # Usage, setup, navigation guides
│   ├── GETTING_STARTED.md            # Full setup and installation
│   ├── USER_GUIDE.md                 # Feature usage and navigation
│   └── DEPLOYMENT.md                 # Production deployment guide
├── AGENTS.md                         # AI agent instructions for future work
├── CHANGELOG.md                      # Release notes
├── docker-compose.yml                # 5 services (api, worker, webhook, web, web-dev)
├── Dockerfile                        # Python 3.11-slim with psycopg2 build deps
├── requirements.txt                  # Python dependencies
├── .env.example                      # Environment variable template
├── .gitignore                        # Python, Node, IDE, secrets
├── .dockerignore                     # Build context exclusions
└── LICENSE
```

---

## 3. Database Schema

### All Tables (SQLAlchemy, `src/models/schema.py`) — 27 Models

| Table | Key Columns | Relationships | Purpose |
|-------|-------------|--------------|---------|
| `users` | `id`, `username`, `password_hash`, `session_token`, `role`, `full_name`, `job_title`, `contact_info`, `default_shift` | FK to `roles.name` via `role` | Authentication & authorization |
| `roles` | `id`, `name`, `allowed_pages` (JSON), `allowed_actions` (JSON), `allowed_site_types` (JSON) | Referenced by `users.role` | RBAC definitions |
| `feed_sources` | `id`, `url`, `name`, `is_active` | — | RSS feed configuration |
| `keywords` | `id`, `word`, `weight` | — | Scoring keywords (70 default) |
| `system_config` | `id`, `llm_*`, `smtp_*`, `scoring_mode`, `unified_brief`, `*_override`, `*_offset` | — | AI/SMTP/risk baseline config |
| `articles` | `id`, `title`, `link`, `summary`, `score`, `category`, `keywords_found`, `is_bubbled`, `is_pinned`, `human_feedback` | Has many `ExtractedIOC` | RSS/OSINT intelligence articles |
| `extracted_iocs` | `id`, `article_id`, `indicator_type`, `indicator_value`, `context` | FK to `articles.id` | Autonomously extracted IOCs |
| `solarwinds_alerts` | `id`, `event_type`, `severity`, `node_name`, `ip_address`, `status`, `device_type`, `event_category`, `mapped_location`, `is_dispatched`, `is_ticketed`, `is_correlated`, `ai_root_cause`, `raw_payload` (JSON) | Mapped to `monitored_locations` | Ingested infrastructure alerts |
| `monitored_locations` | `id`, `name`, `lat`, `lon`, `loc_type`, `district`, `priority`, `under_maintenance`, `maintenance_etr`, `maintenance_reason`, `last_auto_ticket`, `last_escalation_ticket`, `last_auto_dispatch`, `last_escalation_dispatch`, `status_modified_by`, `status_modified_at` | FK target for `solarwinds_alerts.mapped_location` | Facility/site registry |
| `timeline_events` | `id`, `source`, `event_type`, `message`, `timestamp` | — | Activity feed for RCA board |
| `shift_logs` | `id`, `analyst`, `author_role`, `shift_date`, `shift_period`, `content`, `is_deleted` | — | Operator shift logs |
| `cve_items` | `id`, `cve_id`, `vendor`, `product`, `vulnerability_name`, `date_added`, `description`, `required_action`, `due_date` | — | CISA KEV feed cache |
| `cloud_outages` | `id`, `provider`, `service`, `title`, `description`, `link`, `is_resolved`, `updated_at` | — | Cloud service status (18+ providers) |
| `regional_hazards` | `id`, `hazard_id`, `hazard_type`, `severity`, `title`, `description`, `location`, `updated_at` | — | Weather/geospatial hazards |
| `regional_outages` | `id`, `outage_type`, `provider`, `description`, `affected_area`, `lat`, `lon`, `radius_km`, `is_resolved` | — | Regional infrastructure outages |
| `bgp_anomalies` | `id`, `asn`, `event_type`, `description`, `is_resolved` | — | BGP routing anomalies |
| `crime_incidents` | `id`, `category`, `raw_title`, `timestamp`, `distance_miles`, `severity`, `lat`, `lon`, `is_alert_dispatched` | — | Law enforcement CAD data |
| `internal_risk_snapshots` | `id`, `timestamp`, `score`, `risk_level`, `total_assets`, `total_osint_hits`, `hw_data_json`, `sw_data_json` | — | Internal asset risk posture history |
| `daily_briefings` | `id`, `report_date`, `content` | — | Daily fusion report archive |
| `daily_threat_scores` | `id`, `record_date`, `cyber_points`, `physical_points`, `cyber_baseline`, `physical_baseline` | — | 14-day threat score baseline |
| `hardware_assets` | `id`, `ip_address`, `asset_name`, `host_type`, `operating_system`, `vulnerabilities`, `risk_score` | — | Internal hardware inventory |
| `software_assets` | `id`, `name`, `last_updated` | — | Internal software inventory |
| `saved_reports` | `id`, `title`, `author`, `content`, `created_at` | — | Custom report library |
| `elastic_events` | `id`, `timestamp`, `index_name`, `severity`, `message`, `source_ip`, `event_category` | — | Elasticsearch synced events |
| `geojson_cache` | `feed_name` (PK), `data` (JSON), `updated_at` | — | Cached GeoJSON (SPC, NWS, USGS) |
| `node_aliases` | `id`, `node_pattern`, `mapped_location_name`, `confidence_score`, `is_verified` | — | SolarWinds node-to-site mapping |
| `user_weather_prefs` | `id`, `username`, `alert_type` | — | User weather alert preferences |

---

## 4. Permission / RBAC System

### Architecture

Permissions are **dual-layer enforced**: frontend UI gating with backend API authorization on critical actions. The system is flat (no hierarchy) — each action permission is a unique string.

### Permission Strings

```
# Actions (9 core)
Action: Pin Articles
Action: Train ML Model
Action: Boost Threat Score
Action: Trigger AI Functions
Action: Manually Sync Data
Action: Dispatch Exec Report
Action: Submit Shift Log
Action: Dispatch RCA Tickets          # Gates /rca/dispatch and /rca/send-ticket
Action: Manage Site Maintenance       # Gates /rca/site-maintenance

# Tab permissions (~38)
Tab: <Module> -> <Tab Name>
```

### Default Roles

| Role | Pages | Actions |
|------|-------|---------|
| `admin` | All 9 pages | All permissions (hardcoded in auth route) |
| `analyst` | All except Settings | All actions (seeded in DB) |
| (custom) | Configurable via Settings UI | Configurable via Settings UI |

### Enforcement Points

| Layer | Mechanism |
|-------|-----------|
| Page access | `ProtectedRoute` in `App.tsx` checks `user.allowed_pages` |
| Tab visibility | `getAllowedTabs()` filters `TAB_PERMISSION_MAP` from `permissions.ts` |
| Action buttons | Component-level checks of `user.allowed_actions` array |
| Backend API | `require_action(action)` FastAPI dependency on `/rca/dispatch`, `/rca/site-maintenance`, `/rca/investigate`, `/rca/send-ticket` |
| Sidebar nav | `Layout.tsx` filters nav items by `allowed_pages` |

---

## 5. API Routes

All under `/api/v1/`, grouped by router:

| Group | Prefix | Auth | Key Endpoints |
|-------|--------|------|---------------|
| Auth | `/auth` | None | `POST /login`, `POST /logout`, `GET /profile`, `PUT /profile` |
| Dashboard | `/dashboard` | None | `GET /metrics`, `GET /pinned-articles`, `GET /internal-risk`, `GET /global-risk`, `GET /threat-scores`, `GET /intel`, `GET /articles`, `GET /unified-brief`, `PATCH /articles/{id}/pin`, `PATCH /articles/{id}/feedback`, `POST /refresh-brief`, `POST /generate-brief` |
| RCA | `/rca` | Token (dispatch, maint, investigate only) | `GET /dashboard`, `POST /analyze`, `POST /acknowledge`, `POST /dispatch` (gated), `POST /site-maintenance` (gated), `POST /investigate` (gated), `POST /generate-ticket`, `POST /send-ticket` (gated), `GET /sitrep`, `POST /sitrep`, `POST /clear-events`, `POST /nuke-alerts`, `POST /resolve-alert` |
| Regional | `/regional` | None | `GET /locations`, `GET /geojson`, `GET /analytics`, `POST /compile-map`, `POST /sync-hazards`, `GET /weather` |
| Threat | `/threat` | None | `GET /cves`, `GET /cloud-outages`, `GET /crime-incidents`, `GET /articles`, `POST /fetch-feeds`, `POST /sync-kev`, `POST /sync-cloud` |
| Hunting | `/hunting` | None | `GET /iocs`, `GET /osint-pivot/{ioc_type}/{value}`, `GET /search-articles` |
| Logbook | `/logbook` | None | `GET /entries`, `POST /entries`, `PATCH /entries/{id}`, `POST /generate-summary` |
| Reporting | `/reporting` | None | `GET /briefings`, `POST /broadcast`, `GET|POST|DELETE /saved-reports`, `GET|POST /daily-fusion`, `POST /generate-custom` |
| AIOps | `/aiops` | None | `GET /dashboard`, `GET /sitrep`, `GET /sites`, `PATCH /sites/{id}/acknowledge` |
| LLM | `/llm` | None | `POST /test-connection`, `POST /weather-brief` |
| Email | `/email` | None | `POST /send` |
| Settings | `/settings` | None | `GET /config`, `PUT /config`, `GET /users` |
| Admin | `/admin` | None | `GET|POST /roles`, `GET|POST|PUT|DELETE /users`, `GET|POST|PUT|DELETE /locations`, `POST /backup`, `POST /restore`, `POST /maintenance`, `POST /train-ml`, `POST /nuke` |

### RCA Engine Flow

```
POST /rca/analyze
  ├── get_aiops_dashboard_data()        # Fetch active alerts + events + grid
  ├── EnterpriseAIOpsEngine()
  │   ├── analyze_and_cluster(alerts)   # Group alerts by mapped site
  │   ├── identify_fleet_outages()      # Detect carrier-wide communication/power failures
  │   ├── calculate_root_cause(site, cluster, weather, clouds, bgp, fleet)
  │   │   ├── Maintenance auto-clear: expired ETRs unset automatically
  │   │   ├── Patient Zero determination via (9 - tier) * 2000 scoring
  │   │   ├── SLA/P1-P5 mapping from max_alert_level
  │   │   └── Fleet outage detection checks PRIMARY_INTERNET/COMMS_EQUIPMENT
  │   └── generate_chronic_insights()   # 60-day trend analysis
  └── Return {clustered, fleet_outages, root_cause, chronic_insights, events}
```

### Investigation State (In-Memory)

The backend maintains a `set()` of site names currently under investigation. This state survives page refreshes but resets on server restart:

```
POST /rca/investigate
  Body: {"site": "SiteName", "is_investigating": true/false}
  → (gated: Action: Dispatch RCA Tickets)
  → Adds/removes site from INVESTIGATING_SITES set
  → Broadcasts RCA_UPDATE via WebSocket to all clients
  → GET /rca/dashboard returns investigating_sites[] in response
```

### AIOps Engine Ontology (7 Domains)

| Domain | Tier | Priority | Device Types |
|--------|------|----------|--------------|
| `POWER_SUPPLIES` | 1 | Highest | UPS, Generator, PDU, DC Controller, HVAC |
| `PRIMARY_INTERNET` | 2 | Critical | VSAT, Cellular, SD-WAN, Modem, Radio |
| `COMMS_EQUIPMENT` | 3 | High | Router (ASR/ISR), Switch (Nexus/Catalyst), Firewall (ASA/Palo/FortiGate), AP/WLC |
| `COMPUTE` | 4 | Medium | VM Host, Server, Storage (SAN/NAS), ESXi |
| `RTU` | 5 | Medium | RTU, NTEST RTU, Substation RTU |
| `SCADA` | 6 | Low | Sub Equipment, Meter, Plant Equipment, Relay, SEL |
| `FACILITIES` | 7 | Low | Access Control, IP Camera, DC Power |
| `UNKNOWN_DOMAIN` | 8 | Lowest | Unclassified |

### Webhook Classifier Fingerprints

Device classification in `webhook_listener.py` uses keyword fingerprints mapped 1:1 to engine ontology:

| Device Class | Keywords |
|-------------|----------|
| `PRIMARY_INTERNET` | vsat, cellular, sd-wan, modem, radio, isp, internet |
| `COMMS_EQUIPMENT` | fw, firewall, asa, palo, fortigate, meraki, rtr, router, asr, isr, gateway, sw, switch, nexus, catalyst, idf, mdf, ap, wireless, wlc |
| `POWER_SUPPLIES` | ups, pdu, ats, battery, generator, hvac, ac unit, dc power, dc controller |
| `COMPUTE` | vm, host, server, storage, san, nas, esxi |
| `SCADA` | rtu, plc, meter, substation, plant, relay, sel- |
| (default) | `Network Node` (fallback) |

---

## 6. Frontend Architecture

### Stack

| Library | Purpose |
|---------|---------|
| React 18 | UI framework |
| TypeScript | Type safety with strict mode |
| Vite 5 | Build tool / dev server with HMR |
| react-router-dom v7 | Client-side routing |
| @tanstack/react-query v5 | Server state, caching, mutations, query invalidation |
| deck.gl v9 / react-map-gl | Geospatial map visualization (ScatterplotLayer, PolygonLayer) |
| maplibre-gl v4 | Map tiles (free, no API key required) |
| recharts | Charts and graphs |
| axios | HTTP client with token interceptor |
| zustand | Lightweight client state for WebSocket payloads |
| lucide-react | Icon library |

### Data Flow

```
User Action → useMutation → api.post() → FastAPI → DB
                                   ↓
                   queryClient.invalidateQueries()
                                   ↓
                    useQuery refetches → UI re-render

WebSocket ← broadcaster (5s interval on server)
     ↓
useAIOpsWebSocket → dashboard_update → Zustand store → UI
     ↓ (send)
JSON commands echoed to all clients
```

### WebSocket Bi-Directional Protocol

| Direction | Message Type | Payload | Description |
|-----------|-------------|---------|-------------|
| Server → Client | `dashboard_update` | `{type, alerts[], events[], grid[], alert_count}` | Dashboard metrics every 5s |
| Server → Client | `RCA_UPDATE` | `{type: "RCA_UPDATE"}` | Trigger client re-fetch after dispatch/ack/maintenance |
| Client → Server | `INVESTIGATING_UPDATE` | `{type, site, is_investigating}` | Investigation lock state |
| Client → Server | `RCA_UPDATE` | `{type: "RCA_UPDATE"}` | Manual resync trigger |

### Route Map

| Route | Component | Permission Required |
|-------|-----------|---------------------|
| `/login` | LoginPage | None |
| `/` | DashboardPage | Global Dashboards (4 tabs) |
| `/threat-telemetry` | ThreatTelemetryPage | Threat Telemetry (4 tabs) |
| `/regional-grid` | RegionalGridPage | Regional Grid (6 tabs) |
| `/threat-hunting` | ThreatHuntingPage | Threat Hunting & IOCs (3 tabs) |
| `/aiops-rca` | AiopsRcaPage | AIOps RCA (3 tabs) |
| `/shift-logbook` | ShiftLogbookPage | Shift Logbook (2-column layout) |
| `/reporting` | ReportingPage | Reporting & Briefings (3 tabs) |
| `/settings` | SettingsPage | Settings & Admin (10 tabs) |

### Theming System

Six themes implemented via CSS custom properties and `data-theme` attribute:

1. **Standard** — Deep navy dark theme (default)
2. **NOC Terminal** — Green monospace on black
3. **High Contrast (Dark)** — Bright white on very dark gray
4. **Cyberpunk** — Magenta/cyan/neon green
5. **Solarized Dark** — Amber/gold on dark brown
6. **Midnight Ocean** — Deep blues

Applied via `ThemeSelector` component, persisted in `localStorage` under key `noc_theme`. `initTheme()` in `main.tsx` prevents FOUC.

---

## 7. Regional Grid — Weather/Site Intersection

### Pipeline

```
NWS API → fetch_regional_hazards() (infra_worker) → GeoJsonCache (DB)
                                                       ↓
get_cached_geojson() ← @TTLCache(ttl=120s)
        ↓
_precompute_geo_matrix()
  ├── Parse SPC day1/day2/day3 convective outlook contours
  ├── Parse NWS alerts (AR + OOS region feeds)
  │     └── process_nws_alerts() — PDS detection, severity classification
  ├── Parse fire risk counties (FIPS-based)
  ├── Parse active wildfires (NIFC API)
  ├── Parse USGS earthquakes (M0+)
  └── calculate_site_intersections() — Shapely Point.within(polygon)
                                            ↓
POST /regional/compile-map
  ├── Receives: toggles, selected_events, map_df (JSON array)
  ├── Converts JSON → DataFrame
  ├── Calls _precompute_geo_matrix
  ├── Filters master_affected_sites by toggle state
  └── Returns: [layers[], viewState{}, diagnostics[], toggled_affected[], master_affected[], analytics{}]
```

### compile-map Response Structure

Index-based array accessed by frontend:

| Index | Field | Description |
|-------|-------|-------------|
| [0] | `layers` | DeckGL layer configurations |
| [1] | `viewState` | Map view state (center, zoom, bounds) |
| [2] | `diagnostics` | Per-site hazard intersection diagnostics |
| [3] | `toggled_affected` | Affected sites matching current toggle state |
| [4] | `master_affected` | All sites with any hazard intersection |
| [5] | `analytics` | Executive dashboard payload (SPC/NWS/district distributions, risk matrices, at_risk_sites, highest_risk) |

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

| Job | Interval | Function | Description |
|-----|----------|----------|-------------|
| RSS Feed Fetch | 15 min | `fetch_feeds` | Poll configured RSS/Atom feeds using aiohttp + feedparser |
| Crime Feed | 3 min | `fetch_live_crimes` | Fetch geofenced law enforcement CAD data via ArcGIS geocoding |
| Regional Hazards | 2 min | `fetch_regional_hazards` | Query NWS alerts, SPC day1/2/3 outlooks, USGS earthquakes |
| Cloud Outages | 5 min | `fetch_cloud_outages` | Monitor 18+ cloud provider status pages |
| BGP/Telemetry | 5 min | `run_telemetry_sync` | ORNL ODIN power, RIPE RIS BGP, IODA ISP alerts |
| CISA KEV Sync | 6 hours | `fetch_cisa_kev` | Mirror Known Exploited Vulnerabilities catalog |
| Internal Risk | 1 hour | `job_internal_risk` | Score internal asset inventory against active CVEs |
| Unified Brief | 30 min | `job_unified_brief` | Generate LLM-synthesized intelligence brief |
| DB Maintenance | 60 min | `run_database_maintenance` | Purge stale telemetry, deduplicate articles, vacuum SQLite |
| ML Retrain | Sunday 02:00 | `job_retrain_ml` | Retrain HybridScorer from analyst feedback |
| Tiered Alert Escalation | 1 min | `job_tiered_alert_escalation` | 24/7 RCA ticketing with P1-P5 SLA enforcement |
| Daily Email Brief | 07:00 CST | `job_daily_email_unified_brief` | Sends latest Unified Brief via SMTP |

### Boot Sequence

On container start, the scheduler runs all jobs immediately (except ML retrain) in this order:
1. Tiered Alert Escalation
2. CISA KEV Sync
3. Regional Hazards
4. Cloud Outages
5. BGP/Telemetry
6. Crime Feed
7. RSS Feed Fetch
8. Internal Risk
9. Unified Brief

### Tiered Alert Escalation Engine

Runs every 1 minute. Comprehensive 24/7 alert management with dual dispatch paths:

**Business Rules:**
- **Day Shift** (0600-2000 M-F): Remedyforce tickets only. P1 immediate, P2-P5 with 10-min wait.
- **After Hours** (Nights/Weekends): Full escalation path — tickets + NOC notifications + smart on-page.
- **Cascade Detection**: Higher-priority alerts within a cluster override the dispatch target.
- **Node Flapping**: Cooldown timer prevents repeat notifications for recently ticketed nodes.
- **Site Mute**: Sites recently onpaged are suppressed for 1 hour.

**SLA Tiers:**

| Tier | Day Shift Wait | After Hours Wait | Target SLA | Requires On-Page |
|------|---------------|-----------------|------------|------------------|
| P1-High | 0 min | 0 min | 1 Hour | Yes (AH only) |
| P1-Low | 0 min | 45 min | 4 Hours | Yes (AH only) |
| P2-High | 10 min | 30 min | 2.5 Hours | No |
| P2-Low | 10 min | 45 min | 4 Hours | No |
| P3 | 10 min | 45 min | 8 Hours | No |
| P4 | 10 min | 60 min | 24 Hours | No |
| P5 | 10 min | 120 min | 72 Hours | No |

**Dispatch Destinations** (from environment):
- `REMEDYFORCE_TICKET_EMAIL`: Primary ticket destination (required)
- `NOC_NOTIFY_EMAIL`: NOC notification (after hours only)
- `NOC_ONPAGE_EMAIL`: On-page for NOC devices (SWF nodes)
- `ITNETWORK_ONPAGE_EMAIL`: On-page for IT/Network devices (fiber huts/cabinets)

---

## 9. WebSocket Interface

- **Endpoint**: `ws://localhost:8101/ws`
- **Payload**: `{"type": "dashboard_update", "alerts": [...], "events": [...], "grid": [...], "alert_count": N}`
- **Interval**: Every 5 seconds
- **Bi-directional**: Send JSON commands back through the socket
- **Frontend**: `useAIOpsWebSocket` hook in `web/src/hooks/useAIOpsWebSocket.ts`
- **Connection Manager**: `ConnectionManager` class in `src/api/ws_manager.py` — handles connect/disconnect, deduplication, stale connection cleanup

---

## 10. Webhook Listener

- **Endpoint**: `POST http://localhost:8100/webhook/solarwinds`
- **Port**: 8100 (separate FastAPI service from main API)
- **Flow**:
  1. Receive raw JSON payload asynchronously
  2. Queue background processing via FastAPI `BackgroundTasks`
  3. Extract node name, IP, severity, alert level, event type via `smart_extract()`
  4. Classify device type via `classify_device()` (keyword fingerprint → engine ontology domain)
  5. Inject `Normalized_Alert_Level` into `raw_payload` for escalation engine
  6. Check for resolution indicators (word-boundary regex matching)
  7. Create or resolve `SolarWindsAlert` records
  8. Create `TimelineEvent` entries for alert/ resolution
- **Alert Level Extraction Chain**: `Alert_Level` → `Custom_Properties_Universal.Alert_Level` → `Normalized_Alert_Level`
- **Resolution Detection**: `re.search(r'\b(resolved|up|ok|clear|operational|recovered)\b', status)` — word-boundary matching to avoid false positives

---

## 11. Risk Levels

```
GREEN < BLUE < YELLOW < ORANGE < RED
```

Used by the MS-ISAC/CIS Alert Framework for dashboard risk scoring, alert prioritization, site status indicators, and the tiered escalation engine. Risk alerts are checked both on unified brief generation and internal risk calculation.

---

## 12. Environment Variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `DATABASE_URL` | Yes | `sqlite:////app/data/noc_fusion.db` | Database connection string |
| `SECRET_KEY` | No | Auto-generated | JWT signing key |
| `RISK_ALERT_RECIPIENTS` | No | — | Comma-separated email recipients for risk alerts |
| `REMEDYFORCE_TICKET_EMAIL` | No | — | Email address for tiered alert escalation ticketing |
| `NOC_NOTIFY_EMAIL` | No | — | NOC notification email (after hours) |
| `NOC_ONPAGE_EMAIL` | No | — | On-page destination for NOC devices |
| `ITNETWORK_ONPAGE_EMAIL` | No | — | On-page destination for IT/Network devices |
| `LLM_API_URL` | No | — | Custom LLM endpoint for AI features |
| `ELASTIC_URL` | No | — | Elasticsearch connection URL |
| `ELASTIC_API_KEY` | No | — | Elasticsearch API key |

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

# After frontend changes (production container — no source mount)
docker compose up --build -d --force-recreate web

# After frontend changes (dev profile — picks up via volume mount)
```

### Logs
```bash
docker compose logs -f api       # API server
docker compose logs -f worker    # Background scheduler
docker compose logs -f webhook   # Webhook gateway (port 8100)
docker compose logs -f web       # Frontend / nginx
```

### Database Reset
```bash
docker compose down
rm data/noc_fusion.db
docker compose up --build -d
# init_db() recreates tables, seeds roles, users, 70 keywords, default feeds, and rescales all articles
```

---

## 14. Default Credentials

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | admin |

Created on first startup by `src/core/db.py:init_db()` seed logic. Also seeds an `analyst` user (analyst/analyst123).

---

## 15. Key Architectural Decisions

### Decoupling from Streamlit
The original monolithic Streamlit application has been fully replaced by a decoupled FastAPI + React SPA. Legacy Streamlit files remain in `src/ui/` and `src/app.py` for reference but are not used in the current architecture.

### SQLite with NullPool
SQLite is the default database. The engine uses `NullPool` to avoid `QueuePool` contention issues. PostgreSQL is supported via `DATABASE_URL` override. SQLite-specific pragmas (`synchronous`, `journal_mode=WAL`, `cache_size`, `foreign_keys`) are set on connection via event listener.

### Hybrid Scoring Engine
Article relevance scoring combines:
- **Keyword matching** — 70 seeded keywords with configurable weights (5-90)
- **ML classification** — Scikit-Learn TfidfVectorizer + LogisticRegression trained on analyst feedback
- **IOC extraction** — Bonus scoring for articles with high-value indicators
- **Category synergy** — Cross-category bonus for multi-domain threat articles

### Deduplication
Articles are deduplicated both on insert (link uniqueness constraint) and post-insert (SequenceMatcher > 85% title similarity within same source). Deduplication runs after every feed fetch cycle and during scheduled DB maintenance.
