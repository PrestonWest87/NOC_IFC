# NOC Intelligence Fusion Center — Agent Instructions

## Overview

Enterprise intelligence HUD for Network Operations Centers. Ingests RSS feeds, weather/telemetry data, crime incidents, and SolarWinds alerts. Processes through an AI-powered correlation engine with CIS scoring, generates risk briefs, and provides real-time visualization via a React SPA with WebSocket updates.

The application rewrite is on `architecture/monolith-to-decoupled` — a decoupled FastAPI + React SPA. Earlier completed work was user-directed on `main`; current Operational Email and Settings reference-directory work remains on the published `dev` branch based on `origin/main`.

Automated tests under `tests/` are local-only and intentionally excluded from version control by user request. Do not stage or re-add test files unless asked.

## Active Implementation Plan — Operational Email

**Implementation branch:** `dev`, based on the clean `origin/main` commit and published as `origin/dev`. Keep this feature on `dev` only; do not merge it into `main` or `architecture/monolith-to-decoupled` without a later user request. Preserve the unrelated untracked integration-plan documents in the worktree. The dev Compose project is `noc-ifc-dev`, uses `./data-dev` and Docker's built-in `bridge` network, and publishes host ports 8102 (API), 8099 (webhook), 8503 (web), and 5174 (Vite HMR).

- [x] Confirm the `dev` branch starts at `origin/main`, preserve untracked docs, and publish `origin/dev`.
- [x] Add persistent editable template defaults, message/delivery history, bounded attachment storage, BCC envelope handling, and one-time/daily/weekly scheduled delivery.
- [x] Add the top-level Operational Email page and blanket page authorization; keep shared template-default editing administrator-only and leave non-admin role grants explicit.
- [x] Verify dev port mappings, host-gateway proxying on the built-in bridge, and isolated `data-dev` storage alongside the existing stack.
- [x] Run Python/migration/API and frontend/Compose checks, update reference docs, and review the diff.
- [x] Commit intended source only and push the completed `dev` changes.

### Operational Email Enhancements — Active

- [x] Enable BCC for every Operational Email template and preserve existing alert/report email behavior.
- [x] Add fiber maintenance notice details (A/Z locations, circuit IDs, impact choice, departmental impact) and linked repeatable outage updates/resolution notices.
- [x] Default event time labels to application-local `CST`/`CDT`; send Morning Report from the latest Global Dashboard shift analysis as-is.
- [x] Add administrator-managed signatures with default/optional selection and immutable sent/scheduled snapshots.
- [x] Update migration, API/UI/source docs, local-only tests, and verify fresh/existing SQLite upgrades, Python suite, frontend/container builds, and dev Compose health.
- [x] Review and push intended source/docs only to `dev`; preserve unrelated untracked integration-plan documents and keep test files unstaged.

## Active Implementation Plan — Settings Email Contacts and Network Orders

**Implementation branch:** `dev`. Keep this user-directed feature on `dev`; do not merge it into `main` or `architecture/monolith-to-decoupled` without a later request. Preserve unrelated untracked integration-plan documents and keep local-only tests unstaged.

- [x] Add Fiber and ONPAGE email contact directories and an A/Z network-order/circuit reference table with an additive SQLite migration.
- [x] Add the Email Contacts and Network Orders & Circuits Settings tabs, explicit tab grants, read endpoints, and administrator-only table replacement endpoints.
- [x] Validate row fields, bounds, single email addresses/phones, preserve display order, and audit replacements without storing contact values in audit details.
- [x] Update API, permission, schema, Settings UI/source documentation, and local-only service/API/migration tests.
- [ ] Verify fresh and existing SQLite migrations, Python suite, frontend/API/Compose builds, docs contracts, and dev health; review and push intended source/docs only to `dev`.

## Completed Implementation Plan — User, Permissions, and Application Settings

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
- [x] Add additive compatibility migrations for existing account schemas. Existing email-less accounts are individual until classified; display accounts are exempt.
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
- [x] Mirror verified `main` changes into the `architecture/monolith-to-decoupled` worktree, run the same checks there, and verify tracked-tree and untracked-source parity.

---

## Completed Implementation Plan — Startup Migrations and Efficiency

**Implementation branch:** `main` (user-directed). The checked-in progress log is `docs/IMPLEMENTATION_LOG_EFFICIENCY_AND_MIGRATIONS.md`. Verified changes are synchronized to `/tmp/opencode/noc-arch` (`architecture/monolith-to-decoupled`) and parity-checked.

- [x] Confirm clean `main` worktree and record the implementation plan/log.
- [x] Add Alembic startup migration runner, SQLite lock, and legacy adoption revision; run migrations before pragmas, seeds, API readiness, or jobs.
- [x] Preserve production Elasticsearch and ML training/scoring behavior.
- [x] Finish SQLite-only documentation and Python/frontend dependency cleanup.
- [x] Finish bounded analytics, DataFrame removal, and batched ingestion paths.
- [x] Run fresh/legacy/partial/concurrent migration tests, the 77-test Python suite, compile checks, and frontend build/audit.
- [x] Review the main diff/status, update the progress log, and pass `git diff --check`.
- [x] Mirror verified changes to the architecture worktree, run checks there, and verify parity.

---

## Completed Implementation Plan — Encrypted Full Backup and Restore

**Implementation branch:** `main` (user-directed). Full snapshots are stored under the shared `./data/backups` volume; `.env` remains external. Verified changes are synchronized to `/tmp/opencode/noc-arch` after main-branch checks.

- [x] Add AES-256-GCM authenticated full SQLite/model packages, key rotation support, checksum/manifest validation, byte bounds, manual retention, and three scheduled backups.
- [x] Add administrator APIs/UI for backup management, large streaming downloads, validated restore staging, and progress-monitored UI restore; retain and label legacy partial tools.
- [x] Add UI-managed maintenance restore with cross-container writer quiescence, pre-restore backup, migration compatibility, atomic DB/model installation, rollback, and restored-session/link invalidation; retain the offline CLI fallback.
- [x] Add the auditable registration-invite revocation column/migration and persistent, atomically written ML model path.
- [x] Run the Python 3.11 container suite (97 tests), `compileall`, API and frontend image builds, Nginx config test, Compose validation, and `git diff --check`.
- [x] Mirror verified changes into the architecture worktree and verify source parity.

---

## Implementation Plan — Monitored Site Contacts and ONPAGE Email Context

**Implementation branch:** `main` (user-directed). Contacts are stored in a separate one-to-many table, managed by administrators, and shown only as reference text in automatic ONPAGE email bodies; they are not email recipients.

- [x] Add an additive SQLite migration and `MonitoredLocationContact` model with optional name, phone, email, and stable display order.
- [x] Add administrator-only contact read/replace APIs; keep contact details out of shared location payloads.
- [x] Add frontend and server-side validation for optional names, single email addresses, international-style phones/extensions, field bounds, and contact-count bounds.
- [x] Add a multiple-contact editor in Settings → Facilities and place contacts after the target SLA in eligible automatic ONPAGE bodies.
- [x] Preserve contacts for same-name sites in location replacement imports and clean them up when sites are explicitly removed.
- [x] Add local-only migration, API, service, validation, and escalation tests; update API, schema, migration, escalation, UI, and source-reference documentation.
- [x] Verify the 144-test Python suite, Python compilation, API image build, frontend production build, and documentation contracts; OpenAPI reports 178 paths / 191 operations.
- [x] Mirror verified changes to `architecture/monolith-to-decoupled` and verify parity on both worktrees.

---

## Implementation Plan — Internal Brief and Shift Summary Reliability

**Implementation branch:** `main` (user-directed). Production logs supplied by the user show Qwen chat requests returning empty content; the test worktree's unavailable local AI is not treated as production evidence.

- [x] Trace the internal-brief path where `AI failed to process batch.` reached synthesis and failure text was saved as a successful report.
- [x] Require all internal and shift-summary map batches to succeed; reject empty responses and explicit incomplete/skeleton report notices.
- [x] Preserve the last successful internal brief on failure, hide known legacy failure notices from dashboard reads, and reject broadcasts of them.
- [x] Correct end-of-day/week log scopes to include all shift periods and exclude prior generated rollups; isolate LLM work in its own session and label the source-only fallback.
- [x] Bound shift-log text and adapt map batch size to the configured model context; cache unknown Ollama context metadata briefly and recognize Qwen 3 metadata keys.
- [x] Add local-only internal-brief, Ollama context, shift/EOD/EOW, authorization, and failure-path tests; update API, data-flow, scheduler, service, and UI documentation.
- [x] Run the 157-test Python suite on both worktrees, Python compilation, frontend production build, and Docker Compose build/restart; verify healthy local services, clean `git diff --check`, and matching changed-file contents across `main` and `architecture/monolith-to-decoupled`.

---

## Implementation Plan — Regional Weather Freshness and US Map Reliability

**Implementation branch:** `main` (user-directed). NWS alerts poll centrally every 60 seconds. Coverage includes Arkansas and the 50-mile outward border strip across all six Arkansas neighbors: Louisiana, Texas, Mississippi, Missouri, Oklahoma, and Tennessee. The map basemap is contiguous-US-only, with live hazard layers loaded on demand.

- [x] Add a versioned local contiguous-US basemap and regional county geometry; use the latter for accurate geospatial filtering and buffer calculations.
- [x] Split NWS polling from slower regional-hazard jobs; poll one combined seven-state active-alert query every 60 seconds with identifying User-Agent, conditional caching where supported, and non-aggressive backoff.
- [x] Reconcile alert snapshots and CAP update/cancel references; enforce CAP `expires` across active map/log/analytics views while retaining last-good data and exposing feed freshness/errors.
- [x] Extend NWS/USGS/wildfire coverage to the Arkansas 50-mile border corridor; include county/zone-based alerts where polygon geometry is absent and mark any unavoidable state-level fallback.
- [x] Make map data layer/viewport scoped; render local basemap/sites first and avoid unnecessary full-GeoJSON fetches and repeated geometry compilation.
- [x] Add additive migrations, local-only lifecycle/coverage/scheduler/API tests, and update source-aligned documentation.
- [x] Verify Python tests/compile, frontend build, API/container build as appropriate, and `git diff --check`; synchronize verified changes to `/tmp/opencode/noc-arch` and verify parity.
- [x] Both worktrees passed 171 Python tests, compilation, API/web image builds, Compose config, Nginx syntax, and diff checks. The main Compose stack was restarted; API/web/webhook are healthy, the worker is running, and live NWS polling succeeded both at startup and on the recurring schedule (12 source alerts: 1 Arkansas, 2 border-strip alerts).

---

## Implementation Plan — Runtime Integrations and Local LLM Providers

**Implementation branch:** `main` (user-directed). The work started from a clean `main` that matched the freshly fetched `origin/main`. Alert/Elastic database overrides take precedence over `.env` fallbacks; the existing `Action: Manage Application Settings` grant controls the integration editor. AI provider options are OpenAI-compatible, both Ollama APIs, and vLLM.

- [x] Add a compatibility migration, nullable `SystemConfig` overrides, environment fallback resolver, validated integration API, audit entries, and editable notification/Elastic settings UI with write-only Elastic API key handling.
- [x] Route risk, escalation, wildfire, crime, daily-email, and Elastic runtime consumers through dynamic settings; invalidate and retry the process-local Elastic client when appropriate.
- [x] Add persisted provider selection and a shared provider-aware LLM request adapter for OpenAI-compatible, Ollama native/OpenAI-compatible, and vLLM endpoints; add provider-aware local model connection testing and endpoint help.
- [x] Add local-only settings, migration, Elastic client, LLM protocol, endpoint policy, and authorization tests; update source-aligned API/configuration/schema/deployment/UI documentation.
- [x] Fetch/check GitHub `main`; both worktrees pass 184 Python tests, Python compilation, frontend production build, API/web container builds, Compose config, documentation contracts, and `git diff --check`.
- [x] Rebuild/redeploy the test Compose stack; API/web/webhook are healthy, worker is running, and the live SQLite database migrated to `20261105_0008`.
- [x] Synchronize verified source changes to `architecture/monolith-to-decoupled`; confirm changed-file content parity and repeat tests/build/config checks there.

---

## Documentation Index

Comprehensive enterprise documentation is in `docs/`:

See [docs/README.md](docs/README.md) for the complete documentation catalog. The entries below highlight the main architecture and operational references.

| Document | Contents |
|----------|----------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System context, C4 container model, technology stack, data flow overview, security, scalability |
| [GETTING_STARTED.md](docs/GETTING_STARTED.md) | Installation, first startup, environment setup, and initial operations |
| [USER_GUIDE.md](docs/USER_GUIDE.md) | Current workspace features and operator workflows |
| [API.md](docs/API.md) | Complete REST operation inventory and endpoint behavior; path/method coverage is checked against the FastAPI OpenAPI schema |
| [PERMISSIONS.md](docs/PERMISSIONS.md) | Exact page, tab, action, site-type, built-in-role, and enforcement contracts |
| [DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md) | All 44 tables with columns, types, constraints, indexes, relationships, migration strategy, retention policies |
| [MIGRATION_COMPATIBILITY.md](docs/MIGRATION_COMPATIBILITY.md) | Supported older SQLite upgrade shapes, additive migration behavior, failure handling, and safety-test coverage |
| [DATA_FLOWS.md](docs/DATA_FLOWS.md) | Ingestion, scoring, internal risk, reporting, webhook/AIOps, hazard/telemetry, provider-worker, and retention flows |
| [TRIGGER_ACTION_FLOWS.md](docs/TRIGGER_ACTION_FLOWS.md) | Every trigger (webhook, scheduler, user action, WebSocket) mapped to its complete action flow |
| [SERVICES.md](docs/SERVICES.md) | All 11 service modules with function signatures, class hierarchies, call chains, dependencies |
| [SCHEDULER.md](docs/SCHEDULER.md) | All 22 registry-managed background jobs with schedules, execution order, thread safety, retention policies |
| [ESCALATION.md](docs/ESCALATION.md) | Tiered alert escalation: SLA dictionaries, business hours, dispatch channels, cascade detection, flapping logic |
| [WEBHOOK.md](docs/WEBHOOK.md) | SolarWinds webhook gateway: payload normalization, device classification, resolution detection |
| [FRONTEND.md](docs/FRONTEND.md) | React SPA: component tree, routing, hooks, state management, theme system, WebSocket client |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Docker Compose, environment variables, commands, production considerations, troubleshooting |
| [OPERATIONS_REFERENCE.md](docs/OPERATIONS_REFERENCE.md) | Environment and application settings, service commands, scheduler defaults |
| [MAINTENANCE.md](docs/MAINTENANCE.md) | Release, backup, migration, restore, and recurring maintenance procedures |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Diagnostics for API, worker, database, integration, and UI failures |
| [CODE_REFERENCE.md](docs/CODE_REFERENCE.md) | Source-to-module reference index |
| [DOCUMENTATION_AUDIT.md](docs/DOCUMENTATION_AUDIT.md) | Source-to-documentation audit scope, verified inventories, and observed source-level inconsistencies |
| [IN_CODE_DOCUMENTATION_PLAN.md](docs/IN_CODE_DOCUMENTATION_PLAN.md) | Phased plan and style for future source docstrings and explanatory comments; no code edits are implied |
| [IMPLEMENTATION_PLAN_EFFICIENCY_AND_MIGRATIONS.md](docs/IMPLEMENTATION_PLAN_EFFICIENCY_AND_MIGRATIONS.md) | Current startup migration, dependency, and efficiency implementation plan |
| [IMPLEMENTATION_LOG_EFFICIENCY_AND_MIGRATIONS.md](docs/IMPLEMENTATION_LOG_EFFICIENCY_AND_MIGRATIONS.md) | Dated progress and verification record for the active implementation |

---

## Quick Reference

### Containers

| Service | Tech | Port | Purpose |
|---------|------|------|---------|
| `api` | FastAPI | 8102 -> 8101 | REST + WebSocket |
| `worker` | Python scheduler | — | Background jobs (RSS, scoring, escalation) |
| `webhook` | FastAPI | 8099 -> 8100 | SolarWinds webhook gateway |
| `web` | nginx / Vite | 8503 / 5174 | React SPA / Vite HMR |

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
- `DEFAULT_ADMIN_EMAIL` is optional trusted bootstrap configuration. API, worker, and webhook startup can initialize an existing email-less bootstrap admin; administrator-created display accounts can remain email-less.
- Webhook target: `POST http://host:8099/webhook/solarwinds`

### Risk Levels

`GREEN < BLUE < YELLOW < ORANGE < RED`

### Infrastructure Ontology (7 domains)

| Domain | Examples |
|--------|----------|
| `INTERNET` | VSAT, cellular, SD-WAN, modem, radio, ISP link (`PRIMARY_INTERNET` is a normalized compatibility alias) |
| `COMMS_EQUIPMENT` | Firewall, router, switch, AP, gateway, WLC |
| `POWER_SUPPLIES` | UPS, PDU, ATS, battery, generator, HVAC |
| `RTU` | RTU, remote terminal unit |
| `SCADA` | PLC, meter, substation, relay, SEL |
| `COMPUTE` | VM, host, server, storage, SAN, NAS |
| `FACILITIES` | Physical facility/site infrastructure |

### Permission Strings (must match exactly)

`docs/PERMISSIONS.md` contains the complete catalog. `src/core/permissions.py` is the canonical backend/role-editor catalog; frontend route/tab/action references must match its keys and descriptions. Do not copy a partial grant list into new guides.

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
| `/operational-email` | OperationalEmailPage | `web/src/pages/OperationalEmailPage.tsx` |
| `/settings` | SettingsPage | `web/src/pages/SettingsPage.tsx` |
| `/#/keyword-analysis` | KeywordAnalysisPage | `web/src/pages/KeywordAnalysisPage.tsx` |

## Key Files

| File | Purpose |
|------|---------|
| `src/api/main.py` | FastAPI app entry, router mounting, WebSocket manager |
| `src/api/routes/*.py` | 18 route modules, including permissions, user administration, application settings, and Operational Email |
| `src/services.py` | Central data-access and domain-service module |
| `src/services/aiops_engine.py` | EnterpriseAIOpsEngine — clustering, patient zero, RCA |
| `src/services/logic.py` | HybridScorer — keyword + ML scoring |
| `src/services/categorizer.py` | Article categorization (9 regex categories) |
| `src/services/ioc_extractor.py` | IOC extraction (21 rule types across 5 categories) |
| `src/core/db.py` | SQLite-only engine/session + startup migration/bootstrap entrypoint |
| `src/core/migration_runner.py` | Alembic startup runner and cross-process SQLite migration lock |
| `migrations/schema_v1.py` | Frozen first-revision schema snapshot; keep immutable |
| `migrations/versions/` | Versioned baseline adoption and future schema/data revisions |
| `src/core/bootstrap.py` | Conditional role/admin/feed/keyword/system-config seed data |
| `src/core/operational_email.py` | Operational email template defaults, validation, send history, attachments, and persisted schedule queue |
| `src/core/config.py` | Pydantic settings + logging |
| `src/core/runtime_settings.py` | Live database overrides and environment fallback for notification/Elastic configuration |
| `src/core/llm_providers.py` | Supported LLM provider protocols and endpoint URL construction |
| `src/core/paths.py` | Shared persistent SQLite/data/model paths |
| `src/core/backup_manager.py` | Authenticated encrypted full backups, retention, upload validation, and offline restore |
| `src/core/restore_control.py` | Cross-process maintenance marker, API drain counters, and restore progress state |
| `src/core/ui_restore.py` | UI restore orchestration, writer quiescence, and runtime refresh |
| `src/models/schema.py` | 44 SQLAlchemy models |
| `src/core/permissions.py` | Canonical page, tab, and action permission catalog |
| `src/core/site_contact_validation.py` | Shared server-side validation for optional site contact fields |
| `src/api/routes/settings.py` | Settings reads, including tab-authorized Email Contacts and Network Orders directories |
| `web/src/components/EmailContactsSettingsTab.tsx` | Fiber and ONPAGE email-contact directory editor/read view |
| `web/src/components/NetworkOrdersCircuitsTab.tsx` | A/Z circuit and network-order directory editor/read view |
| `src/core/arkansas_coverage.py` | Projected 50-mile Arkansas-border buffer, NWS geocode matching, and CAP active-time filtering |
| `src/core/scheduler_registry.py` | Scheduler defaults, bounds, timezone, and startup policy |
| `src/scheduler.py` | Background job orchestrator and frequency controls |
| `src/webhook_listener.py` | SolarWinds webhook gateway (port 8100) |
| `src/utils/llm.py` | LLM interaction (OpenAI/Ollama), map-reduce brief pipeline |
| `src/utils/mailer.py` | SMTP email sending |
| `src/api/routes/operational_email.py` | Operational Email page API with blanket page authorization |
| `src/utils/risk_alert.py` | Risk level change detection + alerting |
| `web/src/components/UsersRolesTab.tsx` | User directory, invitation, display-account, and role management |
| `web/src/components/SiteContactsDialog.tsx` | Administrator editor and client-side validation for site contacts |
| `web/src/components/ApplicationSettingsTab.tsx` | Risk scoring, scheduler, and global application settings |
| `web/src/components/OperationalIntegrationSettings.tsx` | Notification destinations and Elastic settings editor |
| `web/src/components/ConusMap.tsx` | Local contiguous-US MapLibre basemap shared by operational map views |
| `web/src/pages/DashboardPage.tsx` | Dashboard with brief generation progress polling |
| `web/src/pages/OperationalEmailPage.tsx` | Operational email templates, composition, attachments, schedule manager, and history |

## Scheduler Jobs

| Job | Interval | Description |
|-----|----------|-------------|
| NWS Active Alerts | 1 min | One combined Arkansas + all six bordering-state NWS poll, CAP lifecycle reconcile |
| RSS Feed Fetch | 5 min | Async RSS ingestion → score → categorize → extract IOCs → dedup |
| Article Enrichment | 3 min | Full-content extraction for high-score articles |
| Maintenance Expiry | 5 min | Clear site maintenance after its ETR |
| Crime Fetch | 10 min | Crime API data + perimeter alert dispatch |
| Regional Hazards | 7 min | SPC outlooks, USGS earthquakes, wildfire data, site intersections |
| Cloud Outages | 8 min | Cloud provider status |
| Telemetry Sync | 6 min | ORNL power, RIPE BGP visibility, and IODA ISP outages |
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
| Encrypted Database Backup | Sunday 00:00 America/Chicago | Full SQLite + model snapshot; retain latest three scheduled backups |
| Daily Fusion Report | 06:00 America/Chicago | Generate and store the previous day's report |
| Daily Email Brief | 07:00 America/Chicago | Email unified brief to recipients |
| Operational Email Queue | 1 min | Persistent one-time/daily/weekly message delivery; cannot be disabled |

## Critical Context

- **Keywords must be seeded for scorer**: bootstrap seeds 70 keywords. Startup rescoring is opt-in via `RESCORE_ON_STARTUP=true`; ordinary startup does not rescore the corpus.
- **compile-map response format**: `[processed_geo, {}, diagnostics, toggled_affected_sites, master_affected_sites, analytics]` — the frontend consumes the six positions by index.
- **Web container has source mount with hot reload** in dev mode: changes to `web/` files reflected instantly via Vite HMR.
- **Brief generation_id persisted in sessionStorage**: survives SPA navigation; polling resumes on return.
- **Current implementation branch:** `dev`, as directed for Operational Email and the Settings reference-directory work. Keep these changes on `dev`; synchronize elsewhere only after a later user request.

## What's Been Done (Changelog)

### Encrypted Full Backup and Restore
- Full SQLite online snapshots include every database table and the persisted ML model artifact when present; `.env` secrets remain separate.
- Packages use authenticated AES-256-GCM encryption, checksums, a versioned manifest, and bounded upload/restore validation.
- Manual and pre-restore safety backups are retained independently and labeled separately; scheduled backups run Sundays at midnight Central and retain the latest three.
- Restore can run from the UI through coordinated API/worker/webhook maintenance, with an offline CLI fallback, pre-restore safety backup, migration checks, atomic DB/model replacement, and rollback handling.
- Restored sessions and outstanding registration/reset/recovery-email links are invalidated while request/audit history remains.
- Administrator APIs/UI manage manual backups, downloads, validated staging, and coordinated UI restore; successful restore clears staged packages, while `scripts/restore_backup.py` remains the offline fallback.
- ML artifacts now persist under `/app/data/models/ml_model.pkl` and are atomically written by training.

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
- Soft delete/restore via `is_deleted`; the current API does not store a deletion-reason field
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
- Map health colors reflect unresolved alert state: green when no unresolved issues remain, including acknowledged alerts; Down / Action Required is the initial active-alert state; Needs Dispatch is an explicit persisted workflow selection. Maintenance is a thicker blue outline/annotation and does not mask active alert colors; co-located sites use compact offsets and connector spokes without red alert pulses.
- Authorized users can manually mark a site Up, which resolves all unresolved site alerts and clears stale Needs Dispatch state; maintenance metadata remains separate.
- Window-fill fullscreen (CSS fixed positioning)
- Auto-clear investigating transition guard
- Maintenance can be cleared from the site dialog with no active incident; the clear removes stale ETR/reason data. Existing ETR expiry remains active.
- Save-site race condition fixed (sequential mutations)
- UTC date rollover maintenance wipe fixed

### RCA Tracking Display
- `status_modified_by`, `status_modified_at` on `MonitoredLocation`
- Tracking info in correlation cards, maintenance banner, site dialog, map popups

### Tiered Alert Escalation
- 1-min loop, P1-P5 SLA, business hours (M-F 0600-2000 Central)
- Dual SLA dictionaries (day shift vs after hours)
- On-call paging (NOC / ITNETWORK based on device type)
- Same-node flapping protection; a suppressed node does not consume unrelated site alerts
- Cascade detection (sibling alert priority escalation)
- Routine one-hour after-hours site cooldown leaves suppressed alerts pending; eligible P1 site tickets/pages can bypass it, with page delivery deduplicated per active node incident

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
