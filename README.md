# NOC Intelligence Fusion Center

> **Enterprise intelligence Heads-Up Display for Network Operations Centers.**
>
> **Branch: `architecture/monolith-to-decoupled`** — Complete rewrite from Streamlit monolith to decoupled FastAPI + React SPA.
>
> See [CHANGELOG.md](./CHANGELOG.md) for full release notes.

---

## Quick Start

```bash
cp .env.example .env
docker compose up --build -d
```

Open **http://localhost:8501**. Set `DEFAULT_ADMIN_PASSWORD` before first startup, then log in as `admin` with that password.

### Development (hot reload)

```bash
docker compose --profile dev up --build -d
```

---

## Architecture

```
Browser (React SPA) → nginx:8501 → FastAPI:8101 → SQLite/PostgreSQL
                                        ↓
                          + Worker + Webhook:8100
```

Four Docker services: **api** (FastAPI + WebSocket), **worker** (scheduled jobs), **webhook** (SolarWinds gateway on port 8100), **web** (nginx-served React SPA exposed on port 8501).

---

## Key Features

| Module | Description |
|--------|-------------|
| **Global Dashboards** | Operational KPIs, global risk matrix (CIS framework), internal asset posture, AI unified brief |
| **Threat Telemetry** | RSS/OSINT triage, CISA KEV catalog, 18+ cloud providers, geofenced crime map |
| **Regional Grid** | Deck.gl map with SPC/NWS/USGS overlays, PDS detection, executive analytics dashboard |
| **Threat Hunting** | IOC extraction matrix, OSINT pivot to VirusTotal/Shodan, LLM-powered hunt builder |
| **AIOps RCA** | Enterprise correlation engine (7-domain ontology), fleet detection, chronic insights, P1-P5 SLA enforcement |
| **Shift Logbook** | Entry management, AI summaries, day/week explorer, soft delete, CSV export |
| **Reporting** | Daily fusion briefs, custom AI report builder, shared library, email broadcast |
| **Settings & Admin** | RBAC, facilities/assets, RSS/ML/theme/SMTP/LLM config, backup/restore |

---

## Documentation

| Resource | Location | Description |
|----------|----------|-------------|
| **Setup & Install** | [docs/GETTING_STARTED.md](./docs/GETTING_STARTED.md) | Prerequisites, installation, configuration, troubleshooting |
| **User Guide** | [docs/USER_GUIDE.md](./docs/USER_GUIDE.md) | Feature usage, navigation, best practices, workflows |
| **Deployment Guide** | [docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md) | Production deployment, CI/CD, scaling, hardening |
| **Architecture** | [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) | Runtime topology, routes, data flow, and security |
| **API Reference** | [docs/API.md](./docs/API.md) | REST endpoint contract and WebSocket overview |
| **Frontend Docs** | [docs/FRONTEND.md](./docs/FRONTEND.md) | Routes, state, realtime behavior, and UI boundaries |
| **Model Reference** | [docs/DATABASE_SCHEMA.md](./docs/DATABASE_SCHEMA.md) | Database tables, migrations, and retention |
| **Service Docs** | [docs/CODE_REFERENCE.md](./docs/CODE_REFERENCE.md) | Function-level reference index under `docs/reference/` |
| **Scheduler** | [docs/SCHEDULER.md](./docs/SCHEDULER.md) | Current intervals, execution model, and escalation |
| **Operations Quick Reference** | [docs/OPERATIONS_REFERENCE.md](./docs/OPERATIONS_REFERENCE.md) | Frequencies, variables, commands, and safe DB actions |
| **Troubleshooting** | [docs/TROUBLESHOOTING.md](./docs/TROUBLESHOOTING.md) | Diagnostic commands and remediation runbooks |
| **Agent Instructions** | [AGENTS.md](./AGENTS.md) | Developer commands, key files, remaining work |
| **Release Notes** | [CHANGELOG.md](./CHANGELOG.md) | Full changelog for v2.0.0 |

---

## Technology Stack

### Backend
- **Framework**: FastAPI (Python 3.11) with uvicorn ASGI
- **Database**: SQLAlchemy ORM (SQLite default, PostgreSQL supported) with NullPool for SQLite
- **WebSocket**: Native FastAPI with ConnectionManager and 10-second broadcaster
- **ML**: Scikit-Learn TfidfVectorizer + LogisticRegression
- **Geospatial**: Shapely point-in-polygon, Haversine distance
- **Async**: aiohttp for feed ingestion, BackgroundTasks for webhook processing
- **Scheduling**: `schedule` library with a bounded two-thread executor and boot sequence

### Frontend
- **Framework**: React 18 + TypeScript (strict mode)
- **Build**: Vite 5 with HMR
- **State**: Zustand (client), TanStack React Query v5 (server)
- **Maps**: deck.gl v9 + react-map-gl + MapLibre GL (free, no API key)
- **Charts**: Recharts
- **HTTP**: Axios with session-token interceptor
- **Routing**: React Router v7
- **Styling**: CSS custom properties with 6 dark themes
- **Icons**: Lucide React

---

## Frontend Routes

| Route | Page | Tabs |
|-------|------|------|
| `/login` | LoginPage | — |
| `/` | DashboardPage | Operational, Global Risk, Internal Risk, Unified Brief |
| `/threat-telemetry` | ThreatTelemetryPage | RSS Triage (Pinned/Live/Low/Search), CISA KEV, Cloud, Crime |
| `/regional-grid` | RegionalGridPage | Geospatial, Executive Dashboard, Analytics, Location Matrix, Alerts, Weather |
| `/threat-hunting` | ThreatHuntingPage | IOC Matrix, Deep Hunt Builder, Elastic SIEM |
| `/aiops-rca` | AiopsRcaPage | Active Board, Patterns, Global Correlation |
| `/shift-logbook` | ShiftLogbookPage | Two-column: entry form + explorer |
| `/reporting` | ReportingPage | Daily Fusion, Custom Builder, Shared Library |
| `/settings` | SettingsPage | Profile, Theme, Facilities, Assets, RSS, ML, AI/SMTP, Users, Backup, Danger Zone |

---

## API Endpoints

All routes under `/api/v1/` — 14 route modules:

| Group | Prefix | Key Endpoints |
|-------|--------|--------------|
| Auth | `/auth` | `POST /login`, `POST /logout`, `GET /profile`, `PUT /profile` |
| Dashboard | `/dashboard` | `GET /metrics`, `GET /intel`, `GET /articles`, `GET /unified-brief`, `PATCH /articles/{id}/pin`, `POST /generate-brief` |
| RCA | `/rca` | `GET /dashboard`, `POST /analyze`, `POST /acknowledge`, `POST /dispatch` (gated), `POST /site-maintenance` (gated), `POST /investigate` (gated), `POST /generate-ticket`, `POST /send-ticket` (gated), `GET /sitrep` |
| Regional | `/regional` | `GET /locations`, `GET /geojson`, `POST /compile-map`, `GET /weather` |
| Threat | `/threat` | `GET /cves`, `GET /cloud-outages`, `GET /crime-incidents`, `GET /articles` |
| Hunting | `/hunting` | `GET /iocs`, `GET /osint-pivot/{type}/{value}`, `GET /search-articles` |
| Logbook | `/logbook` | `GET /entries`, `POST /entries`, `PATCH /entries/{id}`, `POST /generate-summary` |
| Reporting | `/reporting` | `GET /briefings`, `POST /broadcast`, `CRUD /saved-reports`, `GET|POST /daily-fusion`, `POST /generate-custom` |
| AIOps | `/aiops` | `GET /dashboard`, `GET /sitrep`, `GET /sites`, `PATCH /sites/{id}/acknowledge` |
| LLM | `/llm` | `POST /test-connection`, `POST /weather-brief` |
| Email | `/email` | `POST /send` |
| Settings | `/settings` | `GET|PUT /config`, `GET /users` |
| Admin | `/admin` | `CRUD /users`, `CRUD /locations`, `CRUD /roles`, `POST /backup`, `POST /restore`, `POST /nuke` |

---

## Scheduler Jobs

Run by the `worker` container (`python -u src/scheduler.py`):

| Job | Interval |
|-----|----------|
| Tiered Alert Escalation | **1 minute** |
| RSS Feed Capture | **5 minutes** |
| Article Enrichment | **3 minutes** |
| Regional Hazards (NWS/SPC/USGS) | **7 minutes** |
| Crime Feed | **10 minutes** |
| Cloud Outages (18+ providers) | **8 minutes** |
| BGP/Telemetry (ORNL/RIPE/IODA) | **6 minutes** |
| CISA KEV Sync | **7 hours** |
| Internal Risk | **2 hours** |
| Internal Asset Brief | **3 hours** |
| Unified Brief | **6 hours** |
| Global Threat Brief | **Daily at 02:00** |
| DB Maintenance | **60 minutes** |
| ML Retrain | Sunday 02:00 |
| Daily Email Brief | 07:00 CST |

---

## Environment Variables

The complete environment template is [`.env.example`](./.env.example). See [Getting Started](./docs/GETTING_STARTED.md#environment-configuration) and the [environment reference](./docs/reference/config/env_example.md) for defaults, consumers, and security guidance.

---

## Webhook

```
POST http://<host>:8100/webhook/solarwinds
Content-Type: application/json
```

The webhook listener normalizes SolarWinds ITSM alerts, classifies devices into the AIOps ontology (5 domains + fallback), injects normalized alert levels for the escalation engine, and persists alerts for AIOps correlation.

---

## Initial Access

Set `DEFAULT_ADMIN_PASSWORD` in `.env` before first startup. The database seeds an `admin` user only when no users exist and a non-empty password is provided. No hard-coded password is guaranteed by the current seed logic.

**Change default passwords immediately in production.**

---

## License

See [LICENSE](./LICENSE).

---

## AI Addendum

This codebase was generated by artificial intelligence — primarily Google Gemini 2.5 Pro, with supplementary work by an Anthropic Claude-powered agent (OpenCode/big-pickle). System architecture, feature requirements, NOC operational workflows, and security policies were directed by a human engineer.
