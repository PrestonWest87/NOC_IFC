# NOC Intelligence Fusion Center — Architecture

> **Version:** 2.0  
> **Branch:** `architecture/monolith-to-decoupled`  
> **Last Updated:** 2026-07-15

---

## Table of Contents

1. [System Context (C4 Level 1)](#1-system-context-c4-level-1)
2. [Container Diagram (C4 Level 2)](#2-container-diagram-c4-level-2)
3. [Technology Stack](#3-technology-stack)
4. [Data Flow Overview](#4-data-flow-overview)
5. [Security Architecture](#5-security-architecture)
6. [Scalability & Performance](#6-scalability--performance)
7. [External Integrations](#7-external-integrations)
8. [Data Model](#8-data-model)
9. [Deployment](#9-deployment)
10. [Observability & Operations](#10-observability--operations)

---

## 1. System Context (C4 Level 1)

The **NOC Intelligence Fusion Center (IFC)** is an enterprise-grade intelligence HUD purpose-built for Network Operations Centers. It serves as the single pane of glass through which NOC analysts monitor, correlate, and respond to cyber, physical, and environmental threats across a distributed infrastructure.

The system operates on a continuous ingest-process-disseminate cycle: raw intelligence is pulled from over a dozen external sources, processed through an AI-powered correlation engine that applies a 7-domain ontology and patient-zero tier scoring model, and surfaced to analysts via a real-time React dashboard with WebSocket-driven updates.

### External Actors

| Actor | Direction | Protocol | Description |
|-------|-----------|----------|-------------|
| **NOC Analysts** | Inbound | HTTPS/WSS | Primary users of the React SPA; interact via dashboard, threat hunting, RCA, and reporting interfaces |
| **SolarWinds Orion** | Inbound | HTTP POST | Sends device down/up webhooks for monitored infrastructure to port 8100 |
| **RSS Feeds** | Outbound (pull) | HTTPS | 30+ cybersecurity, news, and threat intelligence sources fetched every 15 minutes |
| **NWS API** | Outbound (pull) | HTTPS | National Weather Service forecast and severe weather alerts for configured facility locations |
| **FBI Crime API / Local Feeds** | Outbound (pull) | HTTPS | Crime incident data for physical threat correlation near NOC facilities |
| **USGS** | Outbound (pull) | HTTPS | Earthquake event data for seismic threat monitoring |
| **CISA** | Outbound (pull) | HTTPS | Known Exploited Vulnerabilities (KEV) catalog, refreshed every 6 hours |
| **NIFC ArcGIS** | Outbound (pull) | HTTPS | Active wildfire incident data for environmental hazard monitoring |
| **Cloud Provider Status** | Outbound (pull) | HTTPS | Google Cloud and other provider outage feeds for cloud service disruption awareness |
| **SMTP Gateway** | Outbound | SMTP | Email delivery for executive briefings, risk alerts, RCA dispatch tickets, and escalation notifications |
| **OpenAI / Ollama LLM** | Outbound | HTTPS | Large language model for unified brief generation, weather briefings, and shift log summaries |

### Core Responsibilities

- **Intelligence Ingestion** — Continuous pull-based collection from cyber, physical, environmental, and vulnerability sources with deduplication and persistence.
- **AI-Powered Correlation** — EnterpriseAIOpsEngine applies a 7-domain ontology (PRIMARY_INTERNET, COMMS_EQUIPMENT, POWER_SUPPLIES, RTU, SCADA, COMPUTE, FACILITIES) with patient-zero tier scoring, fleet outage detection, and chronic insight generation.
- **Risk Scoring** — Dynamic CIS (Cyber, Internal, Safety) scoring with manual, hybrid, and auto modes. Risk levels cascade GREEN → BLUE → YELLOW → ORANGE → RED.
- **Real-Time Dashboard** — WebSocket-driven React SPA with sub-second update propagation, geospatial map visualization, and role-based view filtering.
- **Automated Reporting** — Map-reduce pipeline generates executive fusion briefs combining cyber, physical, and operational intelligence with OSINT correlation disclaimers.
- **Incident Response** — RCA tracking, dispatch ticket generation, maintenance scheduling, and tiered alert escalation with SLA enforcement.

---

## 2. Container Diagram (C4 Level 2)

The system is composed of four independently deployable containers orchestrated via Docker Compose:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Docker Compose Stack                            │
│                                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │    Webhook    │  │     API      │  │    Worker    │  │     Web    │ │
│  │   :8100       │  │   :8101      │  │   (no port)  │  │  :8501/:5173│ │
│  │  FastAPI      │  │  FastAPI     │  │  Scheduler   │  │ React+nginx│ │
│  │              │  │  + WebSocket │  │  + aiohttp   │  │  + Vite    │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └─────┬──────┘ │
│         │                 │                 │                │          │
│         └─────────────────┴────────┬────────┴────────────────┘          │
│                                    │                                    │
│                          ┌─────────▼─────────┐                         │
│                          │  SQLite / Postgres │                         │
│                          │  (Shared Volume)   │                         │
│                          └───────────────────┘                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.1 API Container (FastAPI)

| Property | Value |
|----------|-------|
| **Port** | 8101 (exposed) |
| **Framework** | FastAPI (async) |
| **Runtime** | Python 3.11 + uvicorn |
| **Database** | SQLAlchemy ORM with NullPool (SQLite) or QueuePool (PostgreSQL) |

**Responsibilities:**

- Serves 13 route modules mounted under the `/api/v1/` prefix, each encapsulating a bounded context:
  - `/auth` — Login, logout, session management, user profile
  - `/dashboard` — Global metrics, intelligence summaries, article listings
  - `/threat` — CVE data, cloud outages, crime incidents, threat articles
  - `/regional` — Facility locations, GeoJSON layers, analytics, weather
  - `/hunting` — IOC management, OSINT pivot, article search
  - `/rca` — RCA dashboard, analysis, acknowledgment, dispatch, ticket sending
  - `/aiops` — AIOps dashboard, site-level situation reports
  - `/logbook` — Shift log entries with LLM-generated summaries
  - `/reporting` — Unified briefings, saved report management
  - `/llm` — LLM connection testing, weather briefing generation
  - `/email` — Email sending, broadcast brief distribution
  - `/settings` — System configuration, user management
  - `/admin` — Role management, facility management, backup/restore, asset management
- Exposes a WebSocket endpoint at `/ws` that broadcasts `dashboard_update` payloads every 10 seconds to connected clients.
- Spawns background threads for async brief generation to avoid blocking the event loop on long-running LLM calls.
- No global authentication middleware — each endpoint independently validates session tokens from the `Authorization` header.
- Mounts static React build assets for production serving when the web container is not in use.

**Key Design Decisions:**

- Per-endpoint auth allows public health-check endpoints and internal-only admin routes without middleware complexity.
- NullPool for SQLite eliminates connection pool contention in single-instance deployments.
- Route modules are organized by domain in `src/api/routes/` with thin handler functions that delegate to the Data Access Layer (`src/services.py`).

### 2.2 Worker Container (Python Scheduler)

| Property | Value |
|----------|-------|
| **Port** | None (no inbound traffic) |
| **Runtime** | Python 3.11 |
| **HTTP Client** | aiohttp (async, chunked) |
| **Scheduler** | `schedule` library with 1-minute tick |

**Responsibilities:**

- Executes 12 scheduled jobs on defined intervals:

| Job | Interval | Description |
|-----|----------|-------------|
| RSS Feed Fetch | 15 min | Fetches 30+ feeds with 5-concurrent chunked parallelism, async HTTP |
| Crime Data Fetch | 3 min | Pulls FBI crime API and local feeds |
| Regional Hazards | 2 min | NWS alerts, NIFC wildfires, USGS earthquakes |
| Cloud Outages | 5 min | Google Cloud and provider status pages |
| CISA KEV Update | 6 hours | Downloads and parses CISA Known Exploited Vulnerabilities |
| Internal Risk Eval | 1 hour | Evaluates internal asset health and risk posture |
| Unified Brief | 30 min | Map-reduce pipeline for executive fusion briefing |
| DB Maintenance | 60 min | Deduplicates articles, purges stale data, optimizes |
| ML Retrain | Sunday 02:00 | Retrains categorization and scoring models on fresh data |
| Tiered Alert Escalation | 1 min | P1-P5 SLA tracking, business hours, on-call paging, flapping detection |

- Runs the **EnterpriseAIOpsEngine** for real-time alert correlation across the 7-domain ontology with patient-zero tier scoring.
- Manages tiered alert escalation with:
  - P1-P5 severity classification and SLA timers
  - Business hours awareness (configurable)
  - On-call paging via email
  - Flapping detection (repeated up/down transitions)
  - Cascade handling (parent-child device dependencies)
  - Site-level mute for maintenance windows
- Performs ML model retraining weekly on the latest classified article corpus.
- Memory-bounded: Docker resource limit of 1GB with explicit garbage collection after each feed cycle.

### 2.3 Webhook Container (FastAPI)

| Property | Value |
|----------|-------|
| **Port** | 8100 (exposed) |
| **Framework** | FastAPI |
| **Runtime** | Python 3.11 + uvicorn |

**Responsibilities:**

- Receives SolarWinds Orion device down/up webhooks at `POST /webhook/solarwinds`.
- Classifies incoming devices against the 7-domain ontology (PRIMARY_INTERNET, COMMS_EQUIPMENT, POWER_SUPPLIES, RTU, SCADA, COMPUTE, FACILITIES).
- Smart payload extraction: handles SolarWinds v1 and v2 webhook formats, extracts device name, IP, status, and custom properties.
- Background task processing via FastAPI's `BackgroundTasks` to ensure immediate 200 OK response while correlation runs asynchronously.
- Normalizes webhook alert levels to the system's internal risk scale (GREEN → BLUE → YELLOW → ORANGE → RED).
- Persists processed alerts to the shared database for consumption by the API and Worker containers.
- Deduplicates incoming alerts using `alerted_eq_ids` column to prevent duplicate processing.

**Key Design Decisions:**

- Separate container isolates the public-facing webhook endpoint from the internal API, reducing attack surface.
- Immediate 200 OK with background processing prevents SolarWinds timeout retries on slow correlations.

### 2.4 Web Container (React SPA)

| Property | Value |
|----------|-------|
| **Dev Port** | 5173 (Vite HMR) |
| **Prod Port** | 8501 (nginx static) |
| **Framework** | React 18 + TypeScript |
| **Build** | Vite |
| **Map** | Maplibre GL |

**Responsibilities:**

- Serves 8 page components with role-based routing controlled by `routeConfig.ts`:

| Route | Page | Description |
|-------|------|-------------|
| `/login` | LoginPage | Authentication with bcrypt verification |
| `/` | DashboardPage | Global dashboards: Operational, Risk, Internal, Brief |
| `/threat-telemetry` | ThreatTelemetryPage | RSS feeds, KEV, cloud outages, crime map |
| `/regional-grid` | RegionalGridPage | Geospatial map, hazard overlays, weather |
| `/threat-hunting` | ThreatHuntingPage | IOC matrix, deep hunt builder |
| `/aiops-rca` | AiopsRcaPage | Active board, patterns, global correlation |
| `/shift-logbook` | ShiftLogbookPage | Shift log entries and history |
| `/reporting` | ReportingPage | Daily fusion, report builder, library |
| `/settings` | SettingsPage | Admin: facilities, assets, RSS, AI, users, backup |

- Maintains a persistent WebSocket connection to the API for real-time dashboard updates.
- Theme system with dark/light modes via CSS custom properties in `themes.css`.
- Geospatial visualization via Maplibre GL with compile-map response parsing.
- Zustand for lightweight state management.
- Timezone-normalized display (America/Chicago) via centralized `timezone.ts` utilities.

---

## 3. Technology Stack

### Backend

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Runtime | Python 3.11 | Application runtime |
| Framework | FastAPI | Async REST API + WebSocket |
| ORM | SQLAlchemy 2.x | Database abstraction |
| Database | SQLite (default) / PostgreSQL | Persistent storage |
| HTTP Client | aiohttp | Async RSS/external API fetching |
| Scheduler | schedule | Cron-like job execution |
| ML | scikit-learn | Article categorization and scoring models |
| LLM | OpenAI API / Ollama | Brief generation, weather summaries, shift log AI |
| Auth | bcrypt | Password hashing |
| Validation | Pydantic v2 | Request/response models and settings |
| Caching | cachetools (TTLCache) | TTL-based in-memory caching |

### Frontend

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Framework | React 18 | Component-based SPA |
| Language | TypeScript | Type safety |
| Build | Vite | Fast dev server + production bundling |
| Map | Maplibre GL | Geospatial visualization |
| HTTP | Axios | REST API client |
| State | Zustand | Lightweight global state |
| Styling | CSS Custom Properties | Theming (dark/light) |
| WebSocket | Native WebSocket API | Real-time updates |

### Infrastructure

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Orchestration | Docker Compose | Multi-container deployment |
| Reverse Proxy | nginx | Static file serving, SSL termination |
| Runtime | Node.js 20 | Frontend build (dev) and production serving |
| Volumes | Docker named volumes | Persistent database storage |
| Network | Docker bridge | Inter-container communication |

---

## 4. Data Flow Overview

### 4.1 Ingestion Flow

```
                         ┌─────────────────────────────────────────┐
                         │           External Sources               │
                         │                                         │
   RSS Feeds ──────────┐ │  NWS API ────────────┐                 │
   30+ sources          │ │  Weather data         │                 │
                        │ │                       │                 │
   FBI Crime ───────────┤ │  USGS ───────────────┤                 │
   Crime incidents      │ │  Earthquake data      │                 │
                        │ │                       │                 │
   CISA KEV ────────────┤ │  NIFC ArcGIS ────────┤                 │
   Vulnerability list   │ │  Wildfire data        │                 │
                        │ │                       │                 │
   Cloud Status ────────┘ │  Google Cloud ────────┘                 │
                        │  Provider outages      │                 │
                        └──────────┬──────────────┘                 │
                                   │                                │
                                   ▼                                │
                        ┌─────────────────────┐                    │
                        │    Worker Container  │                    │
                        │  (schedule + aiohttp)│                    │
                        │                     │                    │
                        │  • Fetch (chunked 5) │                    │
                        │  • Parse + normalize │                    │
                        │  • Deduplicate       │                    │
                        │  • Categorize (ML)   │                    │
                        │  • Score (CIS)       │                    │
                        │  • Persist to DB     │                    │
                        └──────────┬──────────┘                    │
                                   │                                │
                                   ▼                                │
                        ┌─────────────────────┐                    │
                        │  SQLite / PostgreSQL │                    │
                        │  (Shared Volume)     │                    │
                        │                     │                    │
                        │  • articles          │                    │
                        │  • incidents          │                    │
                        │  • iocs              │                    │
                        │  • locations         │                    │
                        │  • weather_cache      │                   │
                        │  • shift_logs        │                    │
                        └──────────┬──────────┘                    │
                                   │                                │
                                   ▼                                │
                        ┌─────────────────────┐                    │
                        │   API Container      │◄─── SolarWinds    │
                        │  (FastAPI :8101)     │    Webhooks       │
                        │                     │    (:8100)         │
                        │  REST: /api/v1/*     │                    │
                        │  WS:   /ws           │                    │
                        └──────────┬──────────┘                    │
                                   │                                │
                    ┌──────────────┼──────────────┐                │
                    ▼              ▼              ▼                │
            ┌──────────┐  ┌──────────────┐  ┌──────────┐          │
            │ React SPA│  │  WebSocket   │  │  SMTP    │          │
            │ Dashboard│  │  Push Updates│  │  Alerts  │          │
            │ (REST)   │  │  (5s interval)│ │  Email   │          │
            └──────────┘  └──────────────┘  └──────────┘          │
                                                                  │
                         ┌─────────────────────────────────────────┘
                         │
   SolarWinds ──────► Webhook Container (:8100)
   Orion               │
   Webhooks            ├── Parse payload (v1/v2 format)
                       ├── Classify device (7-domain ontology)
                       ├── Normalize alert level
                       ├── Persist to DB (BackgroundTasks)
                       └── Immediate 200 OK response
```

### 4.2 User Interaction Flow

```
   NOC Analyst
        │
        ▼
   React SPA (port 8501)
        │
        ├── Authentication ──► POST /api/v1/auth/login
        │                       (bcrypt verify, session token)
        │
        ├── Dashboard ──► GET /api/v1/dashboard/metrics
        │                 (aggregated stats, recent intel)
        │
        ├── Threat Intel ──► GET /api/v1/threat/articles
        │                    (paginated, filtered, scored)
        │
        ├── Geospatial ──► GET /api/v1/regional/compile-map
        │                   (layers, viewState, analytics)
        │
        ├── RCA Actions ──► POST /api/v1/rca/acknowledge
        │                    POST /api/v1/rca/dispatch
        │                    POST /api/v1/rca/send-ticket
        │
        └── Real-Time ──► WebSocket /ws
                           (dashboard_update every 5s)
```

### 4.3 AIOps Correlation Flow

```
   Raw Alerts (DB)
        │
        ▼
   EnterpriseAIOpsEngine
        │
        ├── 1. Domain Classification
        │      (7-domain ontology mapping)
        │
        ├── 2. Patient-Zero Identification
        │      (root cause tier scoring)
        │
        ├── 3. Fleet Outage Detection
        │      (multi-site pattern matching)
        │
        ├── 4. Cascade Analysis
        │      (parent-child dependencies)
        │
        ├── 5. SLA/P1-P5 Mapping
        │      (severity + business hours)
        │
        ├── 6. Chronic Insight Generation
        │      (recurring pattern analysis)
        │
        └── 7. Risk Score Aggregation
               (CIS scoring with overrides)
```

---

## 5. Security Architecture

### 5.1 Authentication & Authorization

The IFC employs a **per-endpoint token-based authentication model** without global middleware. This design was chosen to:

- Allow public health-check and status endpoints without middleware bypass logic
- Enable fine-grained control per route module
- Simplify the webhook container (no auth required for SolarWinds integration)

**Session Flow:**

1. User submits credentials to `POST /api/v1/auth/login`.
2. Backend verifies password against bcrypt hash.
3. On success, a session token is generated and returned to the client.
4. Client stores the token and includes it in the `Authorization` header on all subsequent requests.
5. Each protected endpoint independently validates the token and extracts the user identity.

**Password Security:**

- All passwords are hashed with bcrypt (cost factor ≥10).
- Plaintext passwords are never stored, logged, or transmitted after authentication.

### 5.2 Role-Based Access Control (RBAC)

Access control operates across three dimensions:

| Dimension | Description | Examples |
|-----------|-------------|----------|
| **Page Permissions** | Controls visibility of navigation items and routing | `Tab: Dashboards -> Unified Brief`, `Tab: Settings -> Internal Assets` |
| **Action Permissions** | Controls executable operations | `Action: Dispatch RCA Tickets`, `Action: Manage Site Maintenance` |
| **Site Type Permissions** | Controls which facility types a user can interact with | User allowed on `SUBSTATION`, `DATA_CENTER` but not `GENERATION` |

Permissions are evaluated at both the API layer (each endpoint checks the session's role) and the frontend layer (route config and UI element visibility).

### 5.3 Default Credentials

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `admin123` |

> **⚠ Production Warning:** Default credentials must be changed before deployment to any non-development environment.

### 5.4 Network Security

| Layer | Configuration |
|-------|---------------|
| **CORS** | Permissive (all origins) — suitable for internal network deployment. Restrict for internet-facing deployments. |
| **Webhook Endpoint** | Port 8100 — accepts SolarWinds traffic only. Firewall rules should restrict source IPs. |
| **API Endpoint** | Port 8101 — internal traffic. Not exposed to public internet. |
| **WebSocket** | Port 8101 — authenticated via session token during handshake. |
| **Database** | File-based SQLite on Docker named volume. No network exposure. |

### 5.5 Data Protection

- Secrets and API keys are managed via `.env` file, never committed to version control.
- The `.env` file is mounted as a Docker secret volume.
- Database files reside on Docker named volumes, isolated from host filesystem.
- SMTP credentials are passed via environment variables, not stored in code.

---

## 6. Scalability & Performance

### 6.1 Database Optimization

| Strategy | Implementation | Benefit |
|----------|---------------|---------|
| **NullPool** | SQLite connections use `NullPool` to avoid `QueuePool` contention | Eliminates connection pool overhead in single-instance mode |
| **Batch Writes** | Bulk inserts grouped in transactions | Reduces I/O operations during high-throughput ingestion |
| **Scheduled Maintenance** | Hourly dedup and purge cycle | Prevents unbounded table growth |
| **ALTER TABLE Split** | Schema migrations execute one column at a time with try/except | Prevents silent skip of partial migrations |

### 6.2 Caching

| Strategy | Implementation | Benefit |
|----------|---------------|---------|
| **TTLCache** | `cachetools.TTLCache` with configurable TTL on expensive queries | Reduces redundant DB hits for dashboard metrics |
| **Weather Cache** | Cached weather data in dedicated table with timestamp-based staleness | Avoids repeated NWS API calls (rate-limited) |
| **Article Cache** | In-memory cache for recently scored articles | Prevents re-scoring on every dashboard refresh |

### 6.3 Concurrency

| Strategy | Implementation | Benefit |
|----------|---------------|---------|
| **Async HTTP** | aiohttp with chunked fetching (5 concurrent) | Parallel RSS feed ingestion without thread overhead |
| **Background Threads** | FastAPI `BackgroundTasks` for LLM calls and webhook processing | Non-blocking response for slow operations |
| **Garbage Collection** | Explicit `gc.collect()` after feed cycles | Prevents memory creep during long-running worker |
| **Memory Limit** | Docker container capped at 1GB | Prevents OOM kills on constrained hosts |

### 6.4 Feed Ingestion Performance

```
   RSS Fetch Cycle (15 min interval)
        │
        ├── 30+ feeds divided into chunks of 5
        │
        ├── Each chunk fetched concurrently (aiohttp)
        │   ├── HTTP GET with timeout (10s)
        │   ├── XML parse (feedparser)
        │   ├── Dedup against DB (title hash)
        │   ├── Categorize (ML model)
        │   └── Score (CIS scoring)
        │
        ├── Chunk N+1 starts after chunk N completes
        │
        ├── Memory flushed after each chunk
        │
        └── Full cycle completes in <60 seconds
```

### 6.5 Scalability Considerations

| Constraint | Current State | Path Forward |
|------------|---------------|--------------|
| **Single Instance** | SQLite, single Docker Compose stack | Migrate to PostgreSQL for multi-instance |
| **WebSocket Scale** | In-memory broadcast (single process) | Add Redis pub/sub for multi-worker WebSocket fan-out |
| **Worker Scale** | Single-threaded scheduler | Move to Celery for distributed task execution |
| **API Scale** | Single uvicorn worker | Add gunicorn with multiple worker processes |
| **Asset Volume** | CSV import for HW/SW assets | Batch API for high-volume asset onboarding |

---

## 7. External Integrations

### 7.1 RSS Feed Sources

| # | Source | Category | URL Pattern |
|---|--------|----------|-------------|
| 1 | The Hacker News | Cybersecurity | `https://feeds.feedburner.com/TheHackersNews` |
| 2 | Krebs on Security | Cybersecurity | `https://krebsonsecurity.com/feed/` |
| 3 | BleepingComputer | Cybersecurity | `https://www.bleepingcomputer.com/feed/` |
| 4 | WSJ Cybersecurity | Cybersecurity | `https://feeds.a.dj.com/rss/RSSCybersecurity` |
| 5 | CISA Advisories | Vulnerability | `https://www.cisa.gov/cybersecurity-advisories/all.xml` |
| 6 | Dark Reading | Cybersecurity | `https://www.darkreading.com/rss.xml` |
| 7 | The Record | Threat Intel | `https://therecord.media/feed` |
| 8+ | Additional Sources | Various | Configurable via Settings page |

### 7.2 Government & Open Data

| Source | Endpoint | Refresh | Purpose |
|--------|----------|---------|---------|
| **NWS API** | `api.weather.gov` | 2 min | Weather forecasts and severe alerts for facility locations |
| **NIFC ArcGIS** | `services3.arcgis.com` | 2 min | Active wildfire incidents near facilities |
| **USGS** | `earthquake.usgs.gov` | 2 min | Seismic events by proximity to assets |
| **FBI Crime API** | `crime-data-explorer.fr.cloud.gov` | 3 min | Crime incidents near facility locations |
| **CISA KEV** | `cisa.gov/sites/default/files/feeds` | 6 hours | Known Exploited Vulnerabilities catalog |

### 7.3 Cloud & Infrastructure

| Source | Purpose | Method |
|--------|---------|--------|
| **Google Cloud Status** | Cloud provider outage monitoring | HTTP scrape of status page |
| **SolarWinds Orion** | Device down/up webhooks | POST webhook to port 8100 |

### 7.4 AI & Machine Learning

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **LLM (Primary)** | OpenAI API | Unified brief generation, weather briefings, shift log summaries |
| **LLM (Fallback)** | Ollama (local) | Self-hosted inference when cloud API is unavailable |
| **ML Pipeline** | scikit-learn | Article categorization model, CIS scoring model |
| **ML Retraining** | Weekly (Sunday 02:00) | Models retrained on latest classified article corpus |

### 7.5 Email & Notifications

| Channel | Protocol | Purpose |
|---------|----------|---------|
| **SMTP** | SMTP/TLS | Executive briefings, RCA dispatch tickets, risk alerts, escalation notifications |
| **WebSocket** | WSS | Real-time dashboard push updates (5-second interval) |
| **REST Polling** | HTTPS | Manual refresh of dashboard data, article listings |

---

## 8. Data Model

### 8.1 Core Entities

| Entity | Description | Key Relationships |
|--------|-------------|-------------------|
| **Article** | Ingested news/threat article | Many-to-many with IOC, Category |
| **MonitoredLocation** | Facility/substation/site | Has alerts, maintenance windows, tracking info |
| **Alert** | Processed security/operational alert | Belongs to location, has severity/tier |
| **IOC** | Extracted indicator of compromise | Many-to-many with Article |
| **ShiftLog** | Shift handoff log entry | Created by User, LLM-generated summary |
| **User** | System user | Has role, allowed site types, permissions |
| **Role** | Permission group | Maps to page + action permissions |
| **SavedReport** | Generated report artifact | Tied to date range and report type |
| **InternalAsset** | Hardware/software asset | Categorized by site, type, criticality |
| **Keyword** | Scoring seed keyword | Used by CIS scoring algorithm |

### 8.2 Schema Evolution

- Schema migrations are applied on API startup via `ALTER TABLE` statements.
- Each column addition is wrapped in individual `try/except` to prevent partial migration failures.
- Missing columns are detected and added automatically (self-healing schema).

---

## 9. Deployment

### 9.1 Docker Compose Profiles

| Profile | Containers | Use Case |
|---------|-----------|----------|
| **default** | api, worker, webhook, web | Production — nginx serves static React build |
| **dev** | api, worker, webhook, web (Vite) | Development — Vite HMR on port 5173 |

### 9.2 Port Mapping

| Service | Container Port | Host Port | Protocol |
|---------|---------------|-----------|----------|
| API | 8101 | 8101 | HTTP |
| Webhook | 8100 | 8100 | HTTP |
| Web (prod) | 8501 | 8501 | HTTP |
| Web (dev) | 5173 | 5173 | HTTP |

### 9.3 Build Commands

```bash
# Production (static build + nginx)
docker compose up --build -d

# Development (Vite HMR)
docker compose --profile dev up --build -d

# Rebuild specific service
docker compose up --build -d --force-recreate api

# Monitor service logs
docker compose logs -f worker
docker compose logs -f api
docker compose logs -f web
```

### 9.4 Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | `sqlite:////app/data/noc_fusion.db` | Database connection string |
| `RISK_ALERT_RECIPIENTS` | No | — | Comma-separated email list for risk alerts |
| `REMEDYFORCE_TICKET_EMAIL` | No | — | RCA dispatch ticket destination |
| `OPENAI_API_KEY` | No | — | OpenAI API key for LLM features |
| `OLLAMA_BASE_URL` | No | `http://localhost:11434` | Ollama fallback LLM endpoint |

### 9.5 Volumes

| Volume | Mount Point | Purpose |
|--------|-------------|---------|
| `noc_data` | `/app/data` | SQLite database persistence |

---

## 10. Observability & Operations

### 10.1 Logging

- Python `logging` module with structured log output to stdout/stderr.
- Each container logs to Docker's logging driver (`docker compose logs`).
- Key log events:
  - Feed ingestion cycles (count, duration, errors)
  - Webhook received/processed/failed
  - LLM generation latency
  - Alert escalation triggers
  - Schema migration attempts

### 10.2 Health Indicators

| Indicator | Check Method | Threshold |
|-----------|-------------|-----------|
| **API Availability** | HTTP GET `/api/v1/auth/login` | 200 OK |
| **Webhook Availability** | HTTP GET port 8100 | 200 OK |
| **Database Connectivity** | API startup schema migration | Successful ALTER TABLE |
| **WebSocket Connectivity** | Client reconnect logic | Auto-reconnect on disconnect |
| **Feed Freshness** | Last successful RSS fetch timestamp | < 30 minutes stale |

### 10.3 Operational Runbook

| Scenario | Resolution |
|----------|-----------|
| API not responding | `docker compose restart api` — checks logs for migration errors |
| Feeds not updating | `docker compose logs worker` — check for aiohttp timeouts or DB locks |
| Webhook not receiving | Verify SolarWinds webhook URL points to port 8100; check firewall rules |
| WebSocket disconnects | Client auto-reconnects; if persistent, restart API container |
| Database locked (SQLite) | Restart API and worker containers; consider migration to PostgreSQL |
| LLM generation timeout | Fallback to Ollama local model; check OPENAI_API_KEY validity |
| Memory pressure on worker | Verify 1GB limit; check for feed cycle memory leaks in logs |

---

## Appendix A: Domain Ontology

The 7-domain ontology is the foundation of the EnterpriseAIOpsEngine's correlation model. Every device, alert, and incident is classified into one of these domains:

| Domain | Description | Example Assets |
|--------|-------------|----------------|
| `PRIMARY_INTERNET` | Internet connectivity and upstream providers | ISP routers, BGP peers |
| `COMMS_EQUIPMENT` | Internal communications infrastructure | Switches, firewalls, VPN concentrators |
| `POWER_SUPPLIES` | Power delivery systems | UPS, PDUs, generators |
| `RTU` | Remote Terminal Units | SCADA RTUs, protocol translators |
| `SCADA` | Supervisory Control and Data Acquisition | HMI stations, historians |
| `COMPUTE` | Processing and storage | Servers, VMs, storage arrays |
| `FACILITIES` | Physical facility systems | HVAC, access control, fire suppression |

## Appendix B: Risk Level Definitions

| Level | Name | Description |
|-------|------|-------------|
| 1 | GREEN | Normal operations; no active alerts |
| 2 | BLUE | Low severity; informational alerts, no SLA impact |
| 3 | YELLOW | Medium severity; SLA clock running, investigation needed |
| 4 | ORANGE | High severity; SLA approaching breach, immediate action required |
| 5 | RED | Critical severity; SLA breached, active incident, escalation triggered |

## Appendix C: CIS Scoring

CIS (Cyber-Internal-Safety) scoring provides a composite risk posture across three dimensions:

| Dimension | Scope | Override Modes |
|-----------|-------|----------------|
| **Cyber** | Network, endpoint, vulnerability, threat intel | Manual / Hybrid / Auto |
| **Internal** | Asset health, maintenance status, internal risk eval | Manual / Hybrid / Auto |
| **Safety** | Physical hazards, weather, seismic, fire, crime | Manual / Hybrid / Auto |

Override modes allow operators to set fixed scores (Manual), blend AI and operator judgment (Hybrid), or rely entirely on automated scoring (Auto).

---

*Document generated for NOC IFC v2.0 — Architecture branch `architecture/monolith-to-decoupled`*
