# Changelog — NOC Intelligence Fusion Center

All notable changes for the `architecture/monolith-to-decoupled` branch are documented here.

---

## v2.0.0 — 2026-07-01

### Overview

Complete architectural rewrite from a monolithic Streamlit application to a decoupled FastAPI + React SPA. This release represents the culmination of all porting, fixing, and aligning work to match and exceed the functionality of the original `main` branch.

### Architecture Change

- **Before**: Single-process Streamlit app (`src/app.py`) with embedded caching
- **After**: Decoupled 4-service architecture:
  - `api` — FastAPI REST + WebSocket on port 8101
  - `worker` — Background scheduler (10 jobs)
  - `webhook` — ITSM gateway on port 8100
  - `web` — nginx-served React SPA on port 5173

### New Features

#### AIOps Root Cause Analysis
- Full `EnterpriseAIOpsEngine` correlation engine with 7-domain ontology
- Supreme Patient Zero algorithm using topological tier scoring
- Fleet outage detection for carrier-wide events
- Chronic insights generation (60-day trend analysis)
- Per-site root cause calculation with weather/cloud/BGP context
- Maintenance auto-clear: expired ETR dates automatically unset during analysis
- SLA/P1-P5 priority mapping from max alert level
- In-memory investigation lock state (survives page refreshes)
- `POST /rca/investigate` — deduplicated site investigation locking

#### Tiered Alert Escalation Engine
- 24/7 automated RCA ticketing with P1-P5 SLA enforcement
- Business hours detection (day shift vs. after-hours)
- Dual dispatch paths: tickets only (day) + notifications + on-page (after-hours)
- Cascade detection: higher-priority alerts override dispatch target
- Node flapping protection via cooldown timer
- Site-level on-page mute (1-hour suppression after escalation)
- Smart on-call routing: NOC vs. ITNetwork for SWF devices
- Configurable via environment: `REMEDYFORCE_TICKET_EMAIL`, `NOC_NOTIFY_EMAIL`, `NOC_ONPAGE_EMAIL`, `ITNETWORK_ONPAGE_EMAIL`

#### Email Dispatch
- `POST /rca/send-ticket` — manual dispatch with SMTP email
- Ticket text includes priority, district, SLA target, patient zero, and dynamic alert details
- `POST /email/send` — generic email sending endpoint
- `POST /email/broadcast-brief` — daily unified brief broadcast
- `POST /dashboard/generate-brief` — on-demand brief generation
- Unified brief email formatting with CIS alert level names (aligned with main)

#### RBAC System
- Role-based access control with page-level, tab-level, and action-level permissions
- Backend `require_action(action)` FastAPI dependency for critical endpoints
- Frontend permission gating via `user.allowed_actions` array
- Granular permission strings: `Action: Dispatch RCA Tickets`, `Action: Manage Site Maintenance`, etc.
- Custom role creation via Settings UI
- Geographic site type restrictions

#### Shift Logbook
- Two-column layout with entry form and explorer
- Day/week calendar navigation with independent explorer state
- Soft delete support (`PATCH /entries/{id}` with `is_deleted`)
- Auto-assign shift from user profile
- AI-powered summary generation (`POST /logbook/generate-summary`)
- Role-based entry visibility enforcement

#### Article Intelligence Pipeline
- Hybrid scoring engine: keyword matching (70 seeded keywords) + ML classification
- 8-category regex classification (Cyber, ICS/OT, Cloud, Weather, etc.)
- Autonomous IOC extraction: IPv4, SHA256, domains, URLs, CVE IDs, MITRE ATT&CK
- Article deduplication: exact link + near-duplicate title (SequenceMatcher >85%)
- Pagination with independent per-tab page tracking, category filter, and page size control
- Rescoring: `rescore_all_articles()` re-scores every article using current keywords

#### Geospatial Regional Grid
- Deck.gl interactive map with SPC, NWS, USGS overlays
- PDS (Particularly Dangerous Situation) detection in NWS alerts
- `_precompute_geo_matrix` — Shapely point-in-polygon intersection calculations
- Executive Dashboard tab with infrastructure exposure analytics
- compile-map response includes `[layers, viewState, diagnostics, toggled_affected, master_affected, analytics]`

#### Webhook Enhancement
- Alert level normalization: extracts `Alert_Level` → `Normalized_Alert_Level`
- `AlertName` added to event_type extraction chain
- Device classification into 5 ontology domains via keyword fingerprints
- Resolution detection with word-boundary regex

#### Frontend
- React 18 + TypeScript + Vite SPA with 9 pages, 5 components, 6 utility modules
- deck.gl geospatial visualization with MapLibre dark basemaps
- 6 visual themes (Standard, NOC Terminal, High Contrast, Cyberpunk, Solarized Dark, Midnight Ocean)
- WebSocket real-time updates with exponential-backoff reconnection
- Browser notifications for CRITICAL/HIGH severity alerts
- Central timezone display throughout all UI components
- Loading states, error handling, and responsive layout

### Bug Fixes

#### AIOps RCA
- Blank popup screen: fixed lat/lon extraction from site data
- Popup save/dispatch/maintenance: changed from query params to JSON `Body(...)`
- Permission gating: dispatch behind `Action: Dispatch RCA Tickets`, maintenance behind `Action: Manage Site Maintenance`
- Colors: green when no active alerts, only color when alerts present
- Site type filtering and reliable color assignment
- Window-fill fullscreen via MapContainer

#### Dispatch & Ticketing
- Indentation bug: dispatch logic nested under `if_cascade` — non-cascade tickets not sent
- Manual dispatch email format matched to auto-scheduler same subject, body wrapper, plain text
- Ticket generation: uses cluster data for dynamic domains, trigger time, and alert details
- `generate_rca_ticket_text` — replicated from main with proper formatting
- District line added to ticket text

#### Email
- Correct `/email/send` field mapping (raw data vs. structured fields)
- Dashboard dispatch/brief routes corrected
- Unified brief formatting restored with CIS alert level names and Cyber Security Director line

#### Database
- DB pool exhaustion: switched to `NullPool` for SQLite to avoid `QueuePool` contention
- `alerted_eq_ids` column race condition: run ALTER TABLE early with OperationalError fallback
- SQLite performance: pragmas for synchronous, journal_mode=WAL, cache_size

#### Regional Grid
- Weather/site intersection fixed with proper GeoJSON parsing
- Tooltips respect toggle state for SPC/NWS/USGS layers
- Earthquake tooltip enhanced with depth and time
- Earthquake email alert deduplication

#### Dashboard
- Internal risk display: fixed dashes showing for empty data
- Missing assets tab in settings restored
- Blank screen on login for single-page users: redirect to first allowed page
- All frontend times converted to America/Chicago

#### Articles
- Category filter: was hardcoded to "All" — wired `cat_filter` query param to `get_paginated_articles()`
- Page clamping, total/total_pages in UI, independent per-tab page tracking
- Search page size dropdown functional
- 70 default keywords seeded + `rescore_all_articles()` on init

#### Feeds
- CISA Advisories feed URL: `feed.xml` (404) → `all.xml` (works)
- Google Cloud outage date filtering: added `days_back` parameter
- RSS deduplication: exact link + near-duplicate title removal
- Stale broken CISA feed entry removed from DB

#### General
- ML training UI: correct field names, Loader2 spinner, hot-reload scorer after API retrain
- LLM test-connection endpoint and button added
- Brief generation endpoints fixed with loading animations
- Extensive SMTP and general logging across all modules
- Nginx production config: allow `10.0.0.0/8` subnet, test.weasts.net host

### Scheduler Changes

#### Interval Adjustments (Aligned to Main)

| Job | Old Interval | New Interval |
|-----|-------------|-------------|
| Internal Risk | 6 hours | **1 hour** |
| Unified Brief | 2 hours | **30 minutes** |
| Tiered Alert Escalation | — | **1 minute** (new) |
| Daily Email Brief | — | **07:00 CST** (new) |

#### New Jobs Added
- `job_tiered_alert_escalation` — 24/7 RCA ticketing (every 1 minute)
- `job_daily_email_unified_brief` — daily SMTP brief distribution (07:00 CST)
- Article deduplication runs after every feed fetch cycle

#### Boot Sequence
All jobs execute immediately on container start in deterministic order: Escalation → CISA KEV → Hazards → Clouds → BGP → Crime → RSS → Internal Risk → Unified Brief

### Database Changes

#### New Columns
| Table | Column | Purpose |
|-------|--------|---------|
| `solarwinds_alerts` | `is_ticketed` | Track auto-escalation ticketing |
| `monitored_locations` | `last_auto_ticket` | Last automatic ticket timestamp |
| `monitored_locations` | `last_escalation_ticket` | Site-level on-page mute |
| `monitored_locations` | `last_auto_dispatch` | Last automatic dispatch timestamp |
| `monitored_locations` | `last_escalation_dispatch` | Last escalation dispatch timestamp |
| `monitored_locations` | `status_modified_by` | Username of last status modifier |
| `monitored_locations` | `status_modified_at` | Last status modification time |

#### Seeded Data
- 70 default NOC/cybersecurity keywords with weights
- 12 default RSS feed sources (active)
- Admin + analyst roles with full permissions
- Admin (admin/admin123) and analyst (analyst/analyst123) users
- Default system configuration with AI/SMTP placeholders

### Documentation

- **89 file docs**: Enterprise-grade function-by-function documentation in `Documentation/`
- **ARCHITECTURE.md**: Full system architecture, route reference, scheduler jobs, RBAC, engine ontology, deployment
- **docs/ directory**: GETTING_STARTED.md, USER_GUIDE.md, DEPLOYMENT.md
- **AGENTS.md**: Comprehensive agent instructions for future work
- **CHANGELOG.md**: Complete release notes (this file)
- **README.md**: Updated with current status and architecture

### Known Issues

- Production web container lacks source volume mount — all frontend changes require `docker compose up --build -d --force-recreate web`
- Regional grid frontend accesses `compileResponse[3]` and `compileResponse[4]` — fragile array index pattern
- Keywords must be seeded for scorer — rebuild API container after DB reset
- Domain names must be consistent: engine, webhook, and conditionals use exact ontology names
- `web` container has no source mount — rebuild after frontend changes

### Credits

- Primary code generation: Google Gemini 2.5 Pro
- Supplementary refactoring, bug resolution, feature porting, and documentation: Anthropic Claude-powered agent (OpenCode/big-pickle)
- System architecture, feature requirements, NOC workflow methodologies, security policy, and orchestration: Human engineer
