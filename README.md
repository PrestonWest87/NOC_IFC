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

Open **http://localhost:5173** — Login: `admin` / `admin123`

### Development (hot reload)

```bash
docker compose --profile dev up --build -d
```

---

## Architecture

```
Browser (React SPA) → nginx:5173 → FastAPI:8101 → SQLite/PostgreSQL
                                        ↓
                          + Worker + Webhook:8100
```

Four Docker services: **api** (FastAPI + WebSocket), **worker** (10 background jobs), **webhook** (SolarWinds gateway on port 8100), **web** (nginx-served React SPA on port 5173).

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
| **Architecture** | [Documentation/ARCHITECTURE.md](./Documentation/ARCHITECTURE.md) | System design, routes, scheduler, RBAC, engine ontology |
| **API Reference** | [Documentation/api/](./Documentation/api/) | All 13 route modules + WebSocket manager |
| **Frontend Docs** | [Documentation/web/](./Documentation/web/) | All 9 pages, 5 components, hooks, store, utilities |
| **Model Reference** | [Documentation/models/schema.md](./Documentation/models/schema.md) | All 27 database tables |
| **Service Docs** | [Documentation/services/](./Documentation/services/) | DAL (104 functions), correlation engine, scoring, IOC extraction |
| **Worker Docs** | [Documentation/workers/](./Documentation/workers/) | All 8 background workers |
| **Agent Instructions** | [AGENTS.md](./AGENTS.md) | Developer commands, key files, remaining work |
| **Release Notes** | [CHANGELOG.md](./CHANGELOG.md) | Full changelog for v2.0.0 |

---

## Technology Stack

### Backend
- **Framework**: FastAPI (Python 3.11) with uvicorn ASGI
- **Database**: SQLAlchemy ORM (SQLite default, PostgreSQL supported) with NullPool for SQLite
- **WebSocket**: Native FastAPI with ConnectionManager and 5-second broadcaster
- **ML**: Scikit-Learn TfidfVectorizer + LogisticRegression
- **Geospatial**: Shapely point-in-polygon, Haversine distance
- **Async**: aiohttp for feed ingestion, BackgroundTasks for webhook processing
- **Scheduling**: `schedule` library with threaded execution (10 jobs + boot sequence)

### Frontend
- **Framework**: React 18 + TypeScript (strict mode)
- **Build**: Vite 5 with HMR
- **State**: Zustand (client), TanStack React Query v5 (server)
- **Maps**: deck.gl v9 + react-map-gl + MapLibre GL (free, no API key)
- **Charts**: Recharts
- **HTTP**: Axios with JWT token interceptor
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

All routes under `/api/v1/` — 13 route modules:

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
| Regional Hazards (NWS/SPC/USGS) | **2 minutes** |
| Crime Feed | **3 minutes** |
| Cloud Outages (18+ providers) | **5 minutes** |
| BGP/Telemetry (ORNL/RIPE/IODA) | **5 minutes** |
| RSS Feed Fetch | **15 minutes** |
| CISA KEV Sync | **6 hours** |
| Internal Risk | **1 hour** |
| Unified Brief | **30 minutes** |
| DB Maintenance | **60 minutes** |
| ML Retrain | Sunday 02:00 |
| Daily Email Brief | 07:00 CST |

---

## Environment Variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `DATABASE_URL` | Yes | `sqlite:////app/data/noc_fusion.db` | Database connection string |
| `SECRET_KEY` | No | Auto-generated | JWT signing key |
| `RISK_ALERT_RECIPIENTS` | No | — | Email recipients for risk alerts |
| `REMEDYFORCE_TICKET_EMAIL` | No | — | Tiered escalation ticket destination |
| `NOC_NOTIFY_EMAIL` | No | — | NOC notification (after hours) |
| `NOC_ONPAGE_EMAIL` | No | — | NOC on-page destination |
| `ITNETWORK_ONPAGE_EMAIL` | No | — | IT/Network on-page destination |
| `LLM_API_URL` | No | — | Custom LLM endpoint |

---

## Webhook

```
POST http://<host>:8100/webhook/solarwinds
Content-Type: application/json
```

The webhook listener normalizes SolarWinds ITSM alerts, classifies devices into the AIOps ontology (5 domains + fallback), injects normalized alert levels for the escalation engine, and persists alerts for AIOps correlation.

---

## Default Credentials

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | Administrator |
| `analyst` | `analyst123` | Analyst |

**Change default passwords immediately in production.**

---

## License

See [LICENSE](./LICENSE).

---

## AI Addendum

This codebase was generated by artificial intelligence — primarily Google Gemini 2.5 Pro, with supplementary work by an Anthropic Claude-powered agent (OpenCode/big-pickle). System architecture, feature requirements, NOC operational workflows, and security policies were directed by a human engineer.
