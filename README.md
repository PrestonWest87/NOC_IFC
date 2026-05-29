# NOC Intelligence Fusion Center

Enterprise intelligence Heads-Up Display (HUD) for Network Operations Centers. Ingests multi-domain telemetry from RSS feeds, CISA vulnerabilities, cloud infrastructure providers, regional weather grids, BGP routing tables, law enforcement CAD feeds, and internal asset inventories. A hybrid intelligence engine combining machine learning classification, deterministic regex scoring, causal correlation analysis, and edge-optimized large language models provides automated threat synthesis and root cause analysis.

## Architecture

The platform has been restructured from a monolithic Streamlit application into a decoupled service-oriented architecture comprising four containerized services.

```
+------------------+       +------------------+       +------------------+
|   Browser        |       |   nginx:5173     |       |   FastAPI:8101   |
|   (React SPA)    | ----> |   (web service)   | ----> |   (API service)  |
+------------------+       +------------------+       +--------+---------+
                                                                 |
+-----------------------------------------------------------------+-------+
|                                                                         |
+------------------+          +------------------+          +-------------+
|   Worker         |          |   Webhook:8100   |          |  SQLite /   |
|   (scheduler)    |          |   (FastAPI gw)   |          | PostgreSQL  |
+------------------+          +------------------+          +-------------+
```

### Service Components

| Service | Image | Port | Entrypoint | Description |
|---------|-------|------|------------|-------------|
| api | noc_ifc-api (Python 3.11) | 8101 | uvicorn src.api.main:app | FastAPI REST API + WebSocket broadcaster |
| worker | noc_ifc-api | - | python src/scheduler.py | Background scheduler for automated data ingestion |
| webhook | noc_ifc-api | 8100 | python src/webhook_listener.py | FastAPI gateway for external ITSM telemetry (SolarWinds) |
| web | nginx (built from web/) | 5173 | nginx serving static build | Production React SPA |
| web-dev | node:20-alpine | 5173 | npm run dev | Development Vite dev server with hot reload |

## Technology Stack

### Backend
- **API Framework**: FastAPI with uvicorn ASGI server
- **Database**: SQLAlchemy ORM supporting SQLite (default) and PostgreSQL
- **WebSocket**: Native FastAPI WebSocket with broadcast manager
- **Machine Learning**: Scikit-Learn TF-IDF vectorization and Multinomial Naive Bayes classification
- **Geospatial**: Shapely point-in-polygon intersection, Haversine distance calculations
- **External Integrations**: aiohttp for async HTTP, feedparser for RSS, ArcGIS geocoding

### Frontend
- **Framework**: React 18 with TypeScript
- **Build Tool**: Vite
- **State Management**: Zustand
- **HTTP Client**: Axios
- **Geospatial Visualization**: deck.gl (ScatterplotLayer, PolygonLayer) with MapLibre basemaps
- **Routing**: React Router v6
- **Styling**: CSS custom properties with dark theme

## Frontend Routes

| Route | Page | Description |
|-------|------|-------------|
| /login | LoginPage | Authentication gateway |
| / | DashboardPage | Global operational, risk, internal, and brief dashboards |
| /threat-telemetry | ThreatTelemetryPage | RSS triage, CISA KEV, cloud outages, perimeter crime map |
| /regional-grid | RegionalGridPage | Geospatial map with weather hazards, SPC outlooks, NWS alerts |
| /threat-hunting | ThreatHuntingPage | IOC matrix, OSINT pivot tool, deep hunt builder |
| /aiops-rca | AiopsRcaPage | Active alert board, pattern recognition, global correlation |
| /shift-logbook | ShiftLogbookPage | Shift entries, auto-draft reports, log explorer |
| /reporting | ReportingPage | Daily fusion brief, custom report builder, shared library |
| /settings | SettingsPage | Facility/assets management, RSS sources, AI config, users, backup |

## API Endpoints

All API routes are prefixed with `/api/v1/` and organized into domain-specific route modules.

| Group | Prefix | Description |
|-------|--------|-------------|
| Auth | /auth | Login, logout, profile retrieval |
| Dashboard | /dashboard | Metrics aggregation, intelligence feeds, article retrieval |
| Threat | /threat | CVE catalog, cloud outages, crime data, paginated articles |
| Regional | /regional | Monitored locations, GeoJSON compilation, weather analytics |
| Hunting | /hunting | IOC extraction, OSINT pivot, article search |
| RCA | /rca | Root cause dashboard, site analysis, acknowledgment, dispatch |
| AIOps | /aiops | Site dashboard, situational reports, site status |
| Logbook | /logbook | Shift entry CRUD, auto-draft, calendar queries |
| Reporting | /reporting | Briefings generation, saved reports management |
| LLM | /llm | Connection testing, weather brief generation |
| Email | /email | Outbound SMTP dispatch |
| Settings | /settings | System configuration, user preferences |
| Admin | /admin | Role management, location CRUD, database backup, system nuke |

## Background Scheduler Jobs

The worker service runs a scheduled task engine with the following job intervals:

| Job | Interval | Description |
|-----|----------|-------------|
| RSS Feed Fetch | 15 minutes | Poll configured RSS/Atom feeds for threat intelligence |
| Crime Feed | 3 minutes | Fetch geofenced law enforcement CAD data |
| Regional Hazards | 2 minutes | Query NWS alerts, SPC outlooks, wildfire data |
| Cloud Outages | 5 minutes | Monitor 18+ cloud provider status pages |
| CISA KEV Sync | 6 hours | Mirror Known Exploited Vulnerabilities catalog |
| Internal Risk | 1 hour | Score internal asset inventory against active CVEs |
| Unified Brief | 30 minutes | Generate LLM-synthesized intelligence brief |
| DB Maintenance | 60 minutes | Purge stale telemetry, deduplicate articles, vacuum |
| ML Retrain | Sunday 02:00 | Retrain Scikit-Learn model from analyst feedback |
| Tiered Alert Escalation | 1 minute | 24/7 RCA ticketing with P1-P5 SLA enforcement |

## Key Features by Module

### Global Dashboards
- Operational dashboard with 24-hour KPI panels, auto-rotating threat triage, infrastructure status monitoring, and LLM-powered AI analysis summaries.
- Global Risk executive matrix evaluating unified threat posture against 14-day baseline deviation using MS-ISAC/CIS Alert Framework (GREEN through RED).
- Internal Asset Posture tracking organizational hardware and software against active OSINT threats with historical trend analysis.
- Unified Brief displaying autonomous Map-Reduce narrative merging global OSINT threat with internal asset risk matrix.

### Threat Telemetry
- RSS triage with pagination across Pinned, Live, Low, and Search sub-tabs supporting manual pinning, boosting, and ML training queue submission.
- Offline CISA Known Exploited Vulnerabilities catalog with full-text search.
- Multi-provider cloud status monitoring across 18+ IaaS/SaaS platforms.
- Geofenced crime incident map with dynamic radius filtering and interactive row selection.

### Regional Grid
- Deck.gl geospatial map overlaying NOC facilities with SPC convective outlooks, NWS warnings/watches, NIFC active wildfires, and NWS red flag warnings.
- Executive dash with infrastructure exposure analytics by district, priority, and threat type.
- Hazard analytics computing precise point-in-polygon intersections between facilities and weather geometries.
- Location matrix and alerts log for raw data inspection.

### Threat Hunting and IOC Extraction
- Live global IOC matrix displaying autonomously extracted IPv4, SHA256, domain, CVE, and MITRE ATT&CK indicators with hyperlinked OSINT pivots to VirusTotal and Shodan.
- Deep hunt builder accepting target entities and generating custom Splunk/SIEM queries, MITRE mappings, and YARA rules via LLM.

### AIOps Root Cause Analysis
- Active board rendering auto-focusing map of alerting locations with Supreme Patient Zero algorithm using topological tier scoring, severity weighting, and time offset analysis.
- Global fleet event detection identifying massive carrier outages.
- Predictive analytics performing Pandas aggregations to detect state-flapping nodes and chronic instability patterns.
- Global correlation graphing causal links between external intelligence and internal telemetry drops.
- Tiered alert escalation engine with P1-P5 SLA enforcement, business hours detection, and smart on-call paging.

### Shift Logbook
- Active shift entry with manual logging and auto-draft engine polling AIOps for active outage downtimes.
- Persistent daily summaries with autonomous end-of-morning and end-of-day handoff reports.
- Aggregated executive summaries targeting organizational roles with LLM analysis over current week or month periods.
- Log explorer with day/week calendar interface, soft-delete auditing, modal expansions, and CSV export.

### Reporting and Briefings
- Daily fusion briefing archive with automated AI-synthesized situational reports converting markdown to inline-CSS HTML for enterprise Outlook delivery.
- Custom report builder with multi-select interface for manual article aggregation into targeted LLM pipelines.
- Shared library for organizational storage and retrieval of generated custom reports.

### Settings and Administration
- Facility and internal asset management with bulk JSON/CSV import.
- RSS source management and ML training interface for keyword weighting and model recalibration.
- AI and SMTP configuration for LLM endpoints, tech stack inputs, mail servers, and risk baseline overrides.
- Role-based access control with granular page-level and action-level permissions and geographic site type restrictions.
- Backup and restore with master JSON export/import.
- Maintenance tools for garbage collection, telemetry purging, taxonomy migration, and database reset.

## Data Model

The database schema comprises 27 tables organized into the following domains:

- Identity and Access: Users, Roles, Permissions, Login history
- Threat Intelligence: Articles, Extracted IOCs, CVE Items, CVSS scores
- Infrastructure: Monitored Locations, Hardware assets, Software assets
- Telemetry: Cloud Outages, Regional Hazards, BGP Anomalies, Crime Incidents
- AIOps: SolarWinds Alerts, RCA results, Dispatch records
- Operations: Shift Logs, Briefings, Reports, Scheduled Reports
- Configuration: Keywords, RSS Feeds, Settings, Audit Logs

## Security and Permissions

The platform implements role-based access control (RBAC) with the following characteristics:

- Roles are mapped to specific page routes and UI actions.
- Administrators can create custom roles with granular allowed_site_type restrictions for geographic/operational map filtering.
- Permission strings follow the pattern Action: <Description> (e.g., Action: Dispatch RCA Tickets) and must match exactly between backend dependency injection and frontend conditional rendering.
- The login endpoint returns user profile with an allowed_actions array for frontend permission gating.
- Default credentials: admin / admin123 (should be reset in production).

## WebSocket Interface

- Endpoint: ws://localhost:8101/ws
- Receives dashboard_update payloads at 5-second intervals containing aggregated metrics.
- Supports bidirectional command transmission: send JSON commands through the WebSocket which are processed by the API and forwarded to the scheduler or other subsystems.

## Getting Started

### Prerequisites
- Docker Engine v20.10.0 or higher
- Docker Compose v2.0.0 or higher
- 4 GB RAM minimum, 15 GB SSD recommended

### Installation

1. Clone the repository and navigate to the project root.
2. Configure environment variables in .env (see .env.example).
3. Build and start all services:
   docker compose up --build -d
4. Access the dashboard at http://localhost:5173.
5. To use the Vite development server with hot reload:
   docker compose --profile dev up --build -d

### Developer Commands

| Command | Description |
|---------|-------------|
| docker compose logs -f worker | Monitor background scheduler logs |
| docker compose logs -f api | Monitor API server logs |
| docker compose logs -f web | Monitor frontend logs |
| docker compose restart api | Restart API after backend changes |
| docker compose up --build -d --force-recreate web | Rebuild frontend after changes |
| cd web && npm run dev | Run frontend dev server standalone |

### Webhook Configuration

Point external monitoring tools (SolarWinds, PRTG, Datadog) to:
POST http://<host>:8100/webhook/solarwinds

The webhook listener normalizes incoming ITSM alert payloads, extracts device classifications, and persists alerts for AIOps correlation.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| DATABASE_URL | Yes | sqlite:///data/noc_fusion.db | Database connection string |
| RISK_ALERT_RECIPIENTS | No | - | Comma-separated email recipients for risk alerts |
| REMEDYFORCE_TICKET_EMAIL | No | - | Email address for tiered alert escalation ticketing |
| SECRET_KEY | No | auto-generated | JWT signing key |
| LLM_API_URL | No | - | Custom LLM endpoint for AI features |

## Documentation

Full enterprise-grade function-by-function documentation for every source file in this codebase is available in the documentation/ directory, organized by architectural layer:

- documentation/api/ - FastAPI application, WebSocket manager, and all 13 route modules
- documentation/core/ - Configuration management and database engine
- documentation/models/ - All 27 SQLAlchemy ORM models
- documentation/services/ - Data access layer (104 functions), AIOps correlation engine, categorizer, IOC extractor, hybrid scorer, threat hunter
- documentation/workers/ - All 8 background worker modules
- documentation/utils/ - LLM interaction utilities, mailer, risk alert engine
- documentation/ui/ - Streamlit UI layer (legacy pages, components, utilities)
- documentation/web/ - React SPA (entry points, 9 pages, 5 components, hooks, store, utilities, styles)
- documentation/config/ - Dockerfiles, docker-compose, nginx, Vite, TypeScript, and deployment configuration

## Risk Level Taxonomy

GREEN - BLUE - YELLOW - ORANGE - RED

## AI Addendum

The entirety of this codebase was generated by artificial intelligence.

The Python backend, TypeScript React frontend, SQLAlchemy schema, Scikit-Learn machine learning pipeline, Deck.gl geospatial visualizations, LLM prompt engineering, Docker infrastructure, and all supporting configuration were written by AI assistants based on continuous iterative prompting.

Primary code generation was performed by Google Gemini (version 2.5 Pro). Supplementary refactoring, bug resolution, feature porting, and enterprise documentation generation were performed by an Anthropic Claude-powered agent (opencode/big-pickle operating through the OpenCode CLI interface) under the architecture/monolith-to-decoupled branch.

While the code was AI-generated, the system architecture, feature requirements, NOC operational workflow methodologies, optimization targeting, security policy enforcement, and hallucination debugging were orchestrated and directed entirely by a human engineer. This project serves as a practical demonstration of AI-assisted software engineering to rapidly build customized, enterprise-grade critical infrastructure monitoring tools.

## License

See LICENSE file for details.
