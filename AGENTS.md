# NOC Intelligence Fusion Center - Agent Instructions

## Overview

Enterprise intelligence HUD for Network Operations Centers. Ingests RSS feeds, weather/telemetry data, crime incidents, and generates AI-powered reports.

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

# Frontend dev (standalone)
cd web && npm run dev
```

## Key Files

| File | Purpose |
|------|--------|
| `web/src/App.tsx` | React app entrypoint |
| `web/src/pages/*.tsx` | Page components (9 pages) |
| `web/src/components/Layout.tsx` | Sidebar navigation layout |
| `web/src/hooks/useAIOpsWebSocket.ts` | WebSocket real-time hook |
| `web/src/utils/api.ts` | API client (axios) |
| `web/src/utils/AuthContext.tsx` | Auth state management |
| `web/src/styles/theme.css` | Dark theme CSS variables |
| `src/api/main.py` | FastAPI + WebSocket broadcaster |
| `src/api/routes/*.py` | API route handlers |
| `src/services.py` | Data Access Layer (DAL) |
| `src/core/db.py` | SQLAlchemy engine and session |
| `src/models/schema.py` | Database models |
| `src/scheduler.py` | Background task scheduler |

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
| Logbook | `/logbook` | Shift entries |
| Reporting | `/reporting` | Briefings, saved reports |
| Settings | `/settings` | Config, users |
| Admin | `/admin` | Roles, locations, backup, nuke |

## Scheduler Jobs

| Job | Interval |
|-----|---------|
| RSS Feed Fetch | 15 min |
| Crime Fetch | 3 min |
| Regional Hazards | 2 min |
| Cloud Outages | 5 min |
| CISA KEV | 6 hours |
| Internal Risk | 6 hours |
| Unified Brief | 2 hours |
| DB Maintenance | 60 min |
| ML Retrain | Sunday 02:00 |

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
