# NOC Intelligence Fusion Center — Agent Instructions

## Overview

Enterprise intelligence HUD for Network Operations Centers. Ingests RSS feeds, weather/telemetry data, crime incidents, and SolarWinds alerts. Processes through an AI-powered correlation engine with CIS scoring, generates risk briefs, and provides real-time visualization via a React SPA with WebSocket updates.

Branch `architecture/monolith-to-decoupled` — a complete rewrite from main's Streamlit monolithic app to a decoupled FastAPI + React SPA.

---

## Documentation Index

Comprehensive enterprise documentation is in `docs/`:

| Document | Contents |
|----------|----------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System context, C4 container model, technology stack, data flow overview, security, scalability |
| [API.md](docs/API.md) | Complete API reference — all 110+ endpoints with paths, methods, parameters, request/response schemas |
| [DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md) | All 27 tables with columns, types, constraints, indexes, relationships, migration strategy, retention policies |
| [DATA_FLOWS.md](docs/DATA_FLOWS.md) | 8 complete pipelines with ASCII diagrams: RSS ingestion, CIS scoring, internal risk, brief generation, webhook, AIOps correlation, risk alerting, weather telemetry |
| [TRIGGER_ACTION_FLOWS.md](docs/TRIGGER_ACTION_FLOWS.md) | Every trigger (webhook, scheduler, user action, WebSocket) mapped to its complete action flow |
| [SERVICES.md](docs/SERVICES.md) | All 11 service modules with function signatures, class hierarchies, call chains, dependencies |
| [SCHEDULER.md](docs/SCHEDULER.md) | All 12 background jobs with intervals, execution order, thread safety, retention policies |
| [ESCALATION.md](docs/ESCALATION.md) | Tiered alert escalation: SLA dictionaries, business hours, dispatch channels, cascade detection, flapping logic |
| [WEBHOOK.md](docs/WEBHOOK.md) | SolarWinds webhook gateway: payload normalization, device classification, resolution detection |
| [FRONTEND.md](docs/FRONTEND.md) | React SPA: component tree, routing, hooks, state management, theme system, WebSocket client |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Docker Compose, environment variables, commands, production considerations, troubleshooting |

---

## Quick Reference

### Containers

| Service | Tech | Port | Purpose |
|---------|------|------|---------|
| `api` | FastAPI | 8101 | REST + WebSocket |
| `worker` | Python scheduler | — | Background jobs (RSS, scoring, escalation) |
| `webhook` | FastAPI | 8100 | SolarWinds webhook gateway |
| `web` | nginx / Vite | 5173/8501 | React SPA |

### Developer Commands

```bash
# Production build and run
docker compose up --build -d

# Dev mode with Vite hot reload
docker compose --profile dev up --build -d

# Monitor logs
docker compose logs -f worker
docker compose logs -f api
docker compose logs -f web
docker compose logs -f webhook

# Restart single service
docker compose restart api

# Rebuild frontend
docker compose up --build -d --force-recreate web

# Standalone frontend
cd web && npm run dev
```

### Environment Variables (`.env`)

```
DATABASE_URL=sqlite:////app/data/noc_fusion.db   # Required
RISK_ALERT_RECIPIENTS=email1,email2               # Risk alerts
REMEDYFORCE_TICKET_EMAIL=ticket@solarwinds.com    # Tiered escalation
NOC_NOTIFY_EMAIL=noc@example.com                  # After-hours NOC notification
NOC_ONPAGE_EMAIL=noc-page@example.com             # NOC oncall paging
ITNETWORK_ONPAGE_EMAIL=net-page@example.com       # IT Network oncall
CRIME_ALERT_SMS=sms@gateway.com                   # Crime alert SMS via email
DEFAULT_ADMIN_PASSWORD=admin123                   # First-run admin password
```

### Default Credentials

- Login: `admin` / `admin123`
- Webhook target: `POST http://host:8100/webhook/solarwinds`

### Risk Levels

`GREEN < BLUE < YELLOW < ORANGE < RED`

### Infrastructure Ontology (7 domains)

| Domain | Examples |
|--------|----------|
| `PRIMARY_INTERNET` | VSAT, cellular, SD-WAN, modem, radio, ISP link |
| `COMMS_EQUIPMENT` | Firewall, router, switch, AP, gateway, WLC |
| `POWER_SUPPLIES` | UPS, PDU, ATS, battery, generator, HVAC |
| `RTU` | RTU, remote terminal unit |
| `SCADA` | PLC, meter, substation, relay, SEL |
| `COMPUTE` | VM, host, server, storage, SAN, NAS |
| `FACILITIES` | Physical facility/site infrastructure |

### Permission Strings (must match exactly)

- `Action: Dispatch RCA Tickets`
- `Action: Manage Site Maintenance`
- `Tab: Settings -> Internal Assets`
- `Tab: Dashboards -> Unified Brief`
- All permission strings must match between backend Role model and frontend routeConfig.ts

### Frontend Routes

| Route | Page | Component File |
|-------|------|----------------|
| `/login` | LoginPage | `web/src/pages/LoginPage.tsx` |
| `/` | DashboardPage | `web/src/pages/DashboardPage.tsx` |
| `/threat-telemetry` | ThreatTelemetryPage | `web/src/pages/ThreatTelemetryPage.tsx` |
| `/regional-grid` | RegionalGridPage | `web/src/pages/RegionalGridPage.tsx` |
| `/threat-hunting` | ThreatHuntingPage | `web/src/pages/ThreatHuntingPage.tsx` |
| `/aiops-rca` | AiopsRcaPage | `web/src/pages/AiopsRcaPage.tsx` |
| `/shift-logbook` | ShiftLogbookPage | `web/src/pages/ShiftLogbookPage.tsx` |
| `/reporting` | ReportingPage | `web/src/pages/ReportingPage.tsx` |
| `/settings` | SettingsPage | `web/src/pages/SettingsPage.tsx` |

## Key Files

| File | Purpose |
|------|---------|
| `src/api/main.py` | FastAPI app entry, router mounting, WebSocket manager |
| `src/api/routes/*.py` | 13 route modules (auth, dashboard, threat, regional, hunting, rca, aiops, logbook, reporting, settings, admin, llm, email) |
| `src/services.py` | Central Data Access Layer (~3270 lines) |
| `src/services/aiops_engine.py` | EnterpriseAIOpsEngine — clustering, patient zero, RCA |
| `src/services/logic.py` | HybridScorer — keyword + ML scoring |
| `src/services/categorizer.py` | Article categorization (8 categories via regex) |
| `src/services/ioc_extractor.py` | Enterprise IOC extraction (18 types, 5 categories) |
| `src/services/threat_hunter.py` | Legacy IOC extraction |
| `src/core/db.py` | DB engine + session + init_db() (schema + seed data) |
| `src/core/config.py` | Pydantic settings + logging |
| `src/models/schema.py` | 27 SQLAlchemy models |
| `src/scheduler.py` | Background job orchestrator (12 jobs) |
| `src/webhook_listener.py` | SolarWinds webhook gateway (port 8100) |
| `src/utils/llm.py` | LLM interaction (OpenAI/Ollama), map-reduce brief pipeline |
| `src/utils/mailer.py` | SMTP email sending |
| `src/utils/risk_alert.py` | Risk level change detection + alerting |
| `web/src/pages/DashboardPage.tsx` | Dashboard with brief generation progress polling |

## Scheduler Jobs

| Job | Interval | Description |
|-----|----------|-------------|
| RSS Feed Fetch | 15 min | Async RSS ingestion → score → categorize → extract IOCs → dedup |
| Crime Fetch | 3 min | Crime API data + perimeter alert dispatch |
| Regional Hazards | 2 min | NWS weather, USGS earthquakes, site intersections |
| Cloud Outages | 5 min | Google Cloud status |
| Telemetry Sync | 5 min | BGP anomalies, elastic events |
| CISA KEV | 6 hours | Known Exploited Vulnerabilities catalog |
| Internal Risk | 1 hour | Internal CIS scoring pipeline |
| Unified Brief | 30 min | AI map-reduce brief generation |
| Global Brief | 1 hour | AI map-reduce US critical infrastructure threat brief (incl. weather & crime) |
| Internal Brief | 2 hours | AI map-reduce internal asset OSINT correlation brief |
| Tiered Escalation | 1 min | P1-P5 SLA, cascade, flapping, oncall paging |
| DB Maintenance | 60 min | Dedup + data purge per retention policy |
| ML Retrain | Sunday 02:00 | scikit-learn model training + hot reload |
| Daily Email Brief | 07:00 CST | Email unified brief to recipients |

## Critical Context

- **Keywords must be seeded for scorer**: `init_db()` seeds 70 keywords + rescales all existing articles. Rebuild API container after DB reset.
- **compile-map response format**: `[layers[], viewState{}, diagnostics[], toggled_affected[], master_affected[], analytics{}]` — frontend accesses by index.
- **Web container has source mount with hot reload** in dev mode: changes to `web/` files reflected instantly via Vite HMR.
- **Brief generation_id persisted in sessionStorage**: survives SPA navigation; polling resumes on return.
- **All changes on `architecture/monolith-to-decoupled`**, pushed to `origin/architecture/monolith-to-decoupled`.

## What's Been Done (Changelog)

### Brief Generation Progress
- Async background thread with 5-stage progress (gathering, cyber_map, phys_map, synthesizing, complete)
- Frontend polls `/dashboard/brief-generation-status` every 2 seconds
- Progress persisted in `sessionStorage` across SPA navigation
- Progress bar with stage message, item counts, percent

### Inline Keyword Weight Editing
- Click `w:N` label on any keyword row → inline number input (1-100)
- Enter/blur saves, Escape cancels
- Frontend + backend validation (1-100)
- `force_reload_scorer()` on edit so changes take effect immediately
- Bulk add also validates weight range

### Shift Logbook
- Layout overhaul, day-stepper navigation, independent explorer tab
- Soft delete with reason field
- Auto-assign shift from user profile (name + title)
- Fallback text summary when LLM generation >30s (prevents 504)

### Settings — Internal Assets
- Asset CSV import endpoints for hardware/software assets
- Site types pulled from DB (`get_all_site_types()` merges DB `loc_type` values with defaults)
- Frontend fetches site types from `/regional/site-types` for role management

### Settings — CIS Scoring Configuration
- Scoring overrides (manual/hybrid/auto modes) with C/I/L override columns
- Global/Internal Risk override panels in DashboardPage

### Unified Brief
- Map-reduce pipeline ported from main (replaces single-pass generation)
- Mandatory OSINT correlation disclaimer in executive summary
- Temperature 0.35, improved prompt for operational translation
- Email formatting aligned with main: CIS alert level names, Cyber Security Director line
- `POST /email/broadcast-brief` endpoint

### Global Threat Brief (US Critical Infrastructure)
- Embedded in Global Risk tab below the CIS scoring panels
- Map-reduce pipeline with larger chunk size (20 items) covering ALL relevant articles
- CI-relevance filtering via 30+ sector keywords
- APT/nation-state keyword detection for dedicated section
- US vs Global article classification
- Separate sections: US CI Threat Assessment, APT & Nation-State Activity, Global Threat Landscape, Vulnerability & Exploit Intelligence, Local Weather & Perimeter Posture
- Local weather hazards (NWS, SPC, earthquakes) and perimeter crime data included via physical map-reduce
- No internal risk coverage (unlike Unified Brief)
- Same progress bar UI as Unified Brief with session persistence
- Scheduler: runs every 1 hour via `job_global_brief`
- DB: `global_brief` / `global_brief_time` columns on SystemConfig
- API: `POST /dashboard/generate-global-brief`, `GET /dashboard/global-brief-generation-status`

### Internal Asset Risk Brief
- Embedded in Internal Risk tab below the scoring overrides
- Map-reduce pipeline correlating hardware/software assets against OSINT feeds and CISA KEVs
- Uses `InternalRiskSnapshot` data (hw_data/sw_data JSON blobs) as input
- Analyzes each asset against recent OSINT/CISA KEVs, correlates CVEs to exact deployed versions
- Groups by risk tier, provides patching recommendations
- Three-part structure: map (per-asset correlation), reduce (synthesis), master prompt (executive risk assessment)
- Same progress bar UI as Global/Unified Brief with session persistence (`internal_brief_gen_id` in sessionStorage)
- Scheduler: runs every 2 hours via `job_internal_brief`
- DB: `internal_brief` / `internal_brief_time` columns on SystemConfig
- API: `POST /dashboard/generate-internal-brief`, `GET /dashboard/internal-brief-generation-status`
- Dummy assets seeded for testing: 15 hardware (Cisco, Palo Alto, Microsoft, Schneider Electric, Rockwell) + 30 software (Windows, SQL Server, Exchange, VMware, Ubuntu, RHEL, Docker, etc.)

### RCA Dispatch Tickets
- `generate_rca_ticket_text` ported from main — dynamic domains, compact alerts, district header
- Manual dispatch email format matches auto-scheduler
- Cascade indentation bug fixed

### AIOps RCA Page
- Site type filtering via `user.allowed_site_types`
- Color logic: investigating > dispatched > maintenance > action required
- Window-fill fullscreen (CSS fixed positioning)
- Auto-clear investigating transition guard
- Maintenance is sticky (must be manually cleared)
- Save-site race condition fixed (sequential mutations)
- UTC date rollover maintenance wipe fixed

### RCA Tracking Display
- `status_modified_by`, `status_modified_at` on `MonitoredLocation`
- Tracking info in correlation cards, maintenance banner, site dialog, map popups

### Tiered Alert Escalation
- 1-min loop, P1-P5 SLA, business hours (M-F 0600-2000 Central)
- Dual SLA dictionaries (day shift vs after hours)
- On-call paging (NOC / ITNETWORK based on device type)
- Flapping detection via node cooldown
- Cascade detection (sibling alert priority escalation)
- Site-level mute (1h cooldown from last escalation)

### Correlation Engine
- 7-domain ontology, patient-zero tier scoring
- SLA/P1-P5 mapping, fleet outage detection (≥5 sites same provider)
- Chronic insights (60-day historical analysis)
- 7-stage RCA correlation chain

### Other Fixes
- Blank screen on login for single-page users — redirect to first allowed page
- Regional grid tooltips respect toggles, earthquake tooltip with depth/time
- Earthquake email alerts deduplicated
- DB pool exhaustion (NullPool for SQLite)
- Production nginx allows 10.0.0.0/8 + test.weasts.net
- Missing `monitored_locations` columns added via migration
- `alerted_eq_ids` column race condition fixed
