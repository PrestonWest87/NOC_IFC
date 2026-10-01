# NOC Intelligence Fusion Center — Agent Instructions

## Overview

Enterprise intelligence HUD for Network Operations Centers. Ingests RSS feeds, weather/telemetry data, crime incidents, and SolarWinds alerts. Processes through an AI-powered correlation engine with CIS scoring, generates risk briefs, and provides real-time visualization via a React SPA with WebSocket updates.

The application rewrite is on `architecture/monolith-to-decoupled` — a decoupled FastAPI + React SPA. For the current implementation, the user has directed that all changes be made on `main`, then synchronized to `architecture/monolith-to-decoupled` after verification.

## Active Implementation Plan — User, Permissions, and Application Settings

**Implementation branch:** `main` (user-directed). `origin/main` was pulled before work began and was already up to date. Keep this checklist current as work progresses. After implementation and verification, merge/synchronize `main` into `architecture/monolith-to-decoupled` and verify both branches contain the same intended changes. Do not force-push.

### 0. Branch and baseline

- [x] Confirm the working tree is clean on `main` and pull `origin/main`.
- [x] Record this implementation plan in `AGENTS.md`.
- [x] Record baseline Python tests and frontend production build results: `python3 -m unittest discover -v` attempted 17 tests but all errored because local Python lacks `pydantic_settings`; `npm run build` passed with existing >500 kB bundle chunk warnings.
- [x] Inventory the route-to-page/action/tab/site-type permission matrix and user/scheduler data migrations.

### 1. Permissions and error reporting

- [x] Create one canonical permission catalog for pages, tabs, actions, and descriptions; preserve or explicitly migrate existing role grants.
- [x] Add distinct grants for report generation, email sending/broadcasting, risk-score overrides, scheduler management, user management, recovery review, and recovery-email approval.
- [x] Enforce permissions server-side across sensitive RCA/email/settings endpoints, category mutations, tab routes, and user-scoped data.
- [x] Require AIOps Active Board access for WebSocket data; filter site data by the connected user's allowed site types; authorize WebSocket commands and revalidate sessions.
- [x] Remove startup logic that silently unions broad analyst grants. Migrate built-in roles without granting new sensitive permissions by default.
- [x] Standardize structured 401/403 responses and frontend messaging. A 403 retains the session and identifies the missing permission; a 401 may clear the session.
- [x] Add API and WebSocket authorization tests for allowed, denied, and administrator/reviewer cases.

### 2. Account model, invitations, and access history

- [x] Add account type (`individual` or `display`), nullable normalized email, active status, creation time, last sign-in, and last activity fields.
- [x] Require email for individual invitations; allow administrator-created display accounts without email. Keep email optional in the database to support display accounts.
- [x] Add additive migrations for existing SQLite/PostgreSQL schemas. Existing email-less accounts are individual until classified; display accounts are exempt.
- [x] Implement user-requested email changes as pending requests requiring user-administrator approval and mailbox verification.
- [x] Record durable last sign-in and last activity. Throttle activity updates once per five minutes and display both timestamps in America/Chicago.

### 3. Administrator-reviewed account recovery

- [x] Add permission-based recovery reviewers and notify eligible reviewers who have a verified email address.
- [x] Add a user-admin queue to approve or deny password-reset requests and recovery-email changes, including reviewer, timestamp, and decision reason.
- [x] On reset approval, email a hashed, expiring, single-use reset link; rate-limit requests and revoke sessions after reset.
- [x] Keep public responses generic. Accounts without approved recovery email, including display accounts, use administrator-assisted recovery.
- [x] Add service and HTTP tests for recovery-email submission, reviewer notification, approval, mailbox verification, no-reviewer feedback, and bootstrap-admin setup, alongside reset approval/denial, expiry/replay, email-less accounts, self-approval denial, and session revocation.

### 4. Users & Roles redesign

- [x] Replace the form-card layout with a searchable/filterable directory showing identity, account type, role, status, recovery-email state, last sign-in, and last activity.
- [x] Provide separate “Invite Individual” and “Create Display Account” flows, plus pending-invitation management.
- [x] Add profile edits, role/account-type changes, disable/reactivate, session revocation, administrator-assisted reset, and recovery/email-request actions.
- [x] Show individual users without approved recovery email a persistent prompt; display accounts are exempt.
- [x] Extract user-management components from `SettingsPage.tsx` and use accessible status/error messages.

### 5. Application Settings and dynamic scheduler

- [x] Add an Application Settings tab with separately permissioned sections for risk scoring, scheduler timing, and global application settings.
- [x] Move global/internal risk overrides, baselines, offsets, countermeasures, application links, and failed-login alert settings out of Dashboard/AI & SMTP.
- [x] Replace delegated broad config writes with validated category-specific APIs and action permissions.
- [x] Add a scheduler job registry with defaults, supported schedules, America/Chicago timezone, and safe per-job bounds; persist and expose settings.
- [x] Dynamically reload scheduler settings without restart while preserving in-flight/non-overlap behavior and startup-run policy. Escalation cannot be disabled or configured below its 1-minute minimum.
- [x] Consolidate the separate Daily Fusion report scheduler into the main scheduler.
- [x] Add scheduler validation, runtime reload, and authorization tests.

### 6. Dead-code and efficiency audit

- [x] Confirm repository-only dead-code candidates: removed unused `BidirectionalCommands`, `get_user_by_username`, `Layout.showProfile`, and unreferenced Streamlit dependencies. Retained `/aiops/*` endpoints for external compatibility.
- [x] Make Settings queries permission- and tab-aware; resolve user/session/role grants in one database session without a stale permission cache.
- [x] Profile-independent cleanup is limited to confirmed candidates; update documentation. Broader performance rewrites remain measurement-driven.

### 7. Verification and branch synchronization

- [x] Test upgrade from an existing SQLite schema and startup with a fresh SQLite database. PostgreSQL service was unavailable for an integration run.
- [x] Run final verification on both branches: `DATABASE_URL=sqlite:// /tmp/opencode/noc-venv/bin/python -m unittest discover -v` (59 tests passed), Python `compileall`, and `web/npm run build` (passed; existing >500 kB chunk warning).
- [x] Review `git status`, `git diff`, and `git diff --check` on `main`; no whitespace errors remain.
- [x] Mirror verified `main` changes into the `architecture/monolith-to-decoupled` worktree, run the same checks there, and verify tracked-tree and untracked-source parity. Changes remain uncommitted and unpublished on both branches.

---

## Documentation Index

Comprehensive enterprise documentation is in `docs/`:

| Document | Contents |
|----------|----------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System context, C4 container model, technology stack, data flow overview, security, scalability |
| [API.md](docs/API.md) | Complete API reference — all 110+ endpoints with paths, methods, parameters, request/response schemas |
| [DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md) | All 35 tables with columns, types, constraints, indexes, relationships, migration strategy, retention policies |
| [DATA_FLOWS.md](docs/DATA_FLOWS.md) | 8 complete pipelines with ASCII diagrams: RSS ingestion, CIS scoring, internal risk, brief generation, webhook, AIOps correlation, risk alerting, weather telemetry |
| [TRIGGER_ACTION_FLOWS.md](docs/TRIGGER_ACTION_FLOWS.md) | Every trigger (webhook, scheduler, user action, WebSocket) mapped to its complete action flow |
| [SERVICES.md](docs/SERVICES.md) | All 11 service modules with function signatures, class hierarchies, call chains, dependencies |
| [SCHEDULER.md](docs/SCHEDULER.md) | All 19 registry-managed background jobs with schedules, execution order, thread safety, retention policies |
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

The complete environment template and source mapping are maintained in [`.env.example`](.env.example), [Getting Started](docs/GETTING_STARTED.md#environment-configuration), and [the environment reference](docs/reference/config/env_example.md). Do not maintain a second abbreviated variable list here.

### Initial Access

- Set `DEFAULT_ADMIN_PASSWORD` before first startup; no hard-coded production password is guaranteed by the current seed logic.
- `DEFAULT_ADMIN_EMAIL` is optional trusted bootstrap configuration. It can initialize an existing email-less bootstrap admin on API/worker startup; administrator-created display accounts can remain email-less.
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
- `Action: Send Email`
- `Action: Generate Reports`
- `Action: Adjust Risk Scoring Overrides`
- `Action: Manage Scheduler Settings`
- `Action: Manage Application Settings`
- `Action: Train ML Model`
- `Action: Manage Users`
- `Action: Manage Roles`
- `Action: Review Account Recovery Requests`
- `Action: Approve Recovery Email Changes`
- `Action: Generate Risk Snapshot`
- `Action: Run RCA Analysis`
- `Action: Clear AIOps Data`
- `Action: Manage Shift Logs`
- `Tab: Settings -> Internal Assets`
- `Tab: Settings -> Application Settings`
- `Tab: Dashboards -> Unified Brief`
- `src/core/permissions.py` is the canonical backend/role-editor catalog; frontend route/tab/action references must match it (checked by `test_frontend_permission_keys_exist_in_canonical_catalog`).

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
| `src/api/routes/*.py` | 17 route modules, including permissions, user administration, and application settings |
| `src/services.py` | Central Data Access Layer (~5250 lines) |
| `src/services/aiops_engine.py` | EnterpriseAIOpsEngine — clustering, patient zero, RCA |
| `src/services/logic.py` | HybridScorer — keyword + ML scoring |
| `src/services/categorizer.py` | Article categorization (8 categories via regex) |
| `src/services/ioc_extractor.py` | Enterprise IOC extraction (18 types, 5 categories) |
| `src/core/db.py` | DB engine + session + init_db() (schema + seed data) |
| `src/core/config.py` | Pydantic settings + logging |
| `src/models/schema.py` | 35 SQLAlchemy models |
| `src/core/permissions.py` | Canonical page, tab, and action permission catalog |
| `src/core/scheduler_registry.py` | Scheduler defaults, bounds, timezone, and startup policy |
| `src/scheduler.py` | Background job orchestrator and frequency controls |
| `src/webhook_listener.py` | SolarWinds webhook gateway (port 8100) |
| `src/utils/llm.py` | LLM interaction (OpenAI/Ollama), map-reduce brief pipeline |
| `src/utils/mailer.py` | SMTP email sending |
| `src/utils/risk_alert.py` | Risk level change detection + alerting |
| `web/src/components/UsersRolesTab.tsx` | User directory, invitation, display-account, and role management |
| `web/src/components/ApplicationSettingsTab.tsx` | Risk scoring, scheduler, and global application settings |
| `web/src/pages/DashboardPage.tsx` | Dashboard with brief generation progress polling |

## Scheduler Jobs

| Job | Interval | Description |
|-----|----------|-------------|
| RSS Feed Fetch | 5 min | Async RSS ingestion → score → categorize → extract IOCs → dedup |
| Article Enrichment | 3 min | Full-content extraction for high-score articles |
| Maintenance Expiry | 5 min | Clear site maintenance after its ETR |
| Crime Fetch | 10 min | Crime API data + perimeter alert dispatch |
| Regional Hazards | 7 min | NWS weather, USGS earthquakes, site intersections |
| Cloud Outages | 8 min | Cloud provider status |
| Telemetry Sync | 6 min | BGP anomalies, Elastic events |
| Elastic Cache Sync | 6 min | Refresh high-severity Elastic events |
| CISA KEV | 7 hours | Known Exploited Vulnerabilities catalog |
| Internal Risk | 2 hours | Internal CIS scoring pipeline |
| Rolling Summary | 30 min | AI shift handoff summary |
| Unified Brief | 6 hours | AI map-reduce brief generation |
| Global Brief | Daily 02:00 | AI map-reduce US critical infrastructure threat brief |
| Internal Brief | 3 hours | AI map-reduce internal asset OSINT correlation brief |
| Tiered Escalation | 1 min | P1-P5 SLA, cascade, flapping, oncall paging |
| DB Maintenance | 60 min | Dedup + data purge per retention policy |
| ML Retrain | Sunday 02:00 | scikit-learn model training + hot reload |
| Daily Fusion Report | 06:00 CST | Generate and store the previous day's report |
| Daily Email Brief | 07:00 CST | Email unified brief to recipients |

## Critical Context

- **Keywords must be seeded for scorer**: `init_db()` seeds 70 keywords + rescales all existing articles. Rebuild API container after DB reset.
- **compile-map response format**: `[layers[], viewState{}, diagnostics[], toggled_affected[], master_affected[], analytics{}]` — frontend accesses by index.
- **Web container has source mount with hot reload** in dev mode: changes to `web/` files reflected instantly via Vite HMR.
- **Brief generation_id persisted in sessionStorage**: survives SPA navigation; polling resumes on return.
- **Current implementation branch:** `main`, as requested. Keep `architecture/monolith-to-decoupled` synchronized after verification; do not force-push.

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
- Global/Internal Risk controls live in Settings -> Application Settings and require `Action: Adjust Risk Scoring Overrides`

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
- Scheduler default: daily at 02:00 Central via the persisted Application Settings job registry
- DB: `global_brief` / `global_brief_time` columns on SystemConfig
- API: `POST /dashboard/generate-global-brief`, `GET /dashboard/global-brief-generation-status`
- Email: `POST /email/broadcast-global-brief` (sends formatted HTML with red header, US CI focus)

### Internal Asset Risk Brief
- Embedded in Internal Risk tab below the scoring overrides
- Map-reduce pipeline correlating hardware/software assets against OSINT feeds and CISA KEVs
- Uses `InternalRiskSnapshot` data (hw_data/sw_data JSON blobs) as input
- Analyzes each asset against recent OSINT/CISA KEVs, correlates CVEs to exact deployed versions
- Groups by risk tier, provides patching recommendations
- Three-part structure: map (per-asset correlation), reduce (synthesis), master prompt (executive risk assessment)
- Same progress bar UI as Global/Unified Brief with session persistence (`internal_brief_gen_id` in sessionStorage)
- Scheduler default: every 3 hours via the persisted Application Settings job registry
- DB: `internal_brief` / `internal_brief_time` columns on SystemConfig
- API: `POST /dashboard/generate-internal-brief`, `GET /dashboard/internal-brief-generation-status`
- Email: `POST /email/broadcast-internal-brief` (sends formatted HTML with purple header, asset risk focus)
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
- Settings tabs follow explicit tab grants; management actions remain separately permissioned and legacy backup/destructive operations stay administrator-only
- Initial administrator recovery email can be bootstrapped with `DEFAULT_ADMIN_EMAIL`; startup applies it to an existing email-less admin and completes a matching pending setup request.
- DB pool exhaustion (NullPool for SQLite)
- Production nginx allows 10.0.0.0/8 + test.weasts.net
- Missing `monitored_locations` columns added via migration
- `alerted_eq_ids` column race condition fixed
