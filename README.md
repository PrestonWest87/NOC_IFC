# NOC Intelligence Fusion Center

The NOC Intelligence Fusion Center (IFC) is an operations and intelligence workspace for Network Operations Centers. It brings cyber threat intelligence, infrastructure alerts, weather, physical security events, vulnerability data, telemetry, and internal asset risk into one place so operators can understand what is happening, determine what matters, and respond consistently.

The project is designed for teams that need more than a feed reader or a monitoring console. It connects outside intelligence to the organization’s own sites and assets, correlates related alerts, calculates risk, produces operational briefings, and supports the handoff from detection to investigation, dispatch, and reporting.

## What It Does

The IFC continuously follows an ingest, analyze, respond, and communicate workflow:

1. Collects information from configured external sources and internal integrations.
2. Cleans, categorizes, scores, deduplicates, and stores the information.
3. Connects related cyber, infrastructure, environmental, and physical events.
4. Highlights risk to sites, services, equipment, and critical assets.
5. Gives operators tools to investigate, acknowledge, dispatch, document, and report.
6. Sends scheduled briefs and operational notifications to the appropriate recipients.

## Who It Is For

- NOC analysts monitoring live infrastructure and external threats.
- Shift leads preparing handoffs and daily operational summaries.
- Incident responders investigating infrastructure or cyber events.
- Operations managers reviewing risk, trends, assets, and service impact.
- Administrators managing users, permissions, sites, feeds, AI, email, and system settings.

## Main Workspace Areas

### Global Dashboards

Provides the high-level operating picture, including operational metrics, global risk, internal asset risk, threat trends, and the Unified Brief. This is the best starting point for a shift lead or manager who needs the current situation before opening individual events.

### Threat Telemetry

Collects and organizes RSS and OSINT articles, CISA Known Exploited Vulnerabilities, cloud provider outages, and nearby crime incidents. Analysts can filter, search, pin, provide feedback on, and review scored intelligence.

### Regional Grid

Maps monitored sites against weather and environmental conditions. It combines National Weather Service alerts, NOAA/SPC outlooks, USGS earthquakes, wildfire information, and other regional hazard data with site locations and districts.

### Threat Hunting

Provides an IOC matrix, article search, OSINT pivots, a hunt builder, and Elastic SIEM support. Extracted indicators can be reviewed in context and used to pivot into additional intelligence sources.

### Keyword Analysis

Explains how the intelligence corpus is being scored and categorized. Operators can review keyword weights, trigger frequency, score contribution, article categories, score distributions, keyword timelines, category/keyword relationships, and the articles behind a match. Authorized users can also recategorize the stored article corpus.

The page is available at `/#/keyword-analysis` and requires the `Keyword Analysis` page permission. Recategorization additionally requires `Action: Trigger AI Functions`.

### AIOps RCA

Correlates SolarWinds and operational alerts by site and device type. The correlation engine identifies likely root causes, patient-zero candidates, fleet-wide outages, cascades, chronic patterns, and P1-P5 response priorities. Analysts can investigate, acknowledge, dispatch, manage maintenance windows, generate tickets, and review situation reports.

### Shift Logbook

Captures shift activity and handoff notes. Entries can be reviewed by day or period, summarized with AI, and retained as an operational record. Soft deletion preserves the audit context while removing an entry from normal views.

### Reporting

Generates daily fusion reports, custom intelligence reports, shared report-library entries, and email broadcasts. The Unified, Global Threat, and Internal Asset Risk briefs combine multiple data domains instead of presenting isolated feed summaries.

### Settings and Administration

Administrators can manage:

- Users, roles, page permissions, action permissions, and site-type access.
- Monitored locations, districts, priorities, and maintenance information.
- Hardware and software asset inventories.
- RSS and intelligence sources.
- Keyword weights and scoring behavior.
- AI/LLM and SMTP settings.
- Themes, profiles, backups, restore operations, and controlled maintenance actions.

## How Information Is Connected

The IFC uses a common infrastructure vocabulary for correlation:

| Domain | Examples |
|---|---|
| `PRIMARY_INTERNET` | VSAT, cellular, SD-WAN, modem, radio, ISP links |
| `COMMS_EQUIPMENT` | Firewalls, routers, switches, gateways, wireless equipment |
| `POWER_SUPPLIES` | UPS, PDU, ATS, batteries, generators, HVAC controls |
| `RTU` | Remote terminal units and field controllers |
| `SCADA` | PLCs, meters, substations, relays, and control systems |
| `COMPUTE` | Servers, virtual machines, storage, SAN, NAS, and hosts |
| `FACILITIES` | Access control, cameras, buildings, and physical systems |

This classification lets the system compare alerts across sites and infrastructure layers. For example, multiple communications alerts at several sites may indicate a provider or fleet outage rather than unrelated local failures.

## Information Sources

The system can use the following source categories:

- RSS and Atom cybersecurity, news, and threat-intelligence feeds.
- CISA Known Exploited Vulnerabilities.
- SolarWinds Orion webhook alerts.
- National Weather Service and NOAA/SPC hazard data.
- USGS earthquake data.
- Wildfire and regional geospatial sources.
- Cloud provider status pages.
- BGP, routing, and network telemetry sources.
- Elasticsearch events for SIEM-oriented workflows.
- Crime and perimeter data near monitored sites.
- Hardware and software asset inventories.
- OpenAI-compatible or local LLM providers configured in Settings.
- SMTP for reports, alerts, tickets, and notifications.

External source availability varies. A source can be temporarily blocked, unavailable, rate-limited, or return no new records without indicating that the IFC itself is down.

## Runtime Overview

The project runs as a Docker Compose stack:

```text
Analyst browser
      |
      v
React web workspace :8501
      |
      +---- REST API and WebSocket :8101
      |             |
      |             v
      |       Shared database
      |
      +---- Worker: scheduled collection, scoring, briefs, escalation

SolarWinds Orion ---> Webhook gateway :8100 ---> Shared database
```

| Service | Purpose | Host port |
|---|---|---:|
| `api` | REST API, authentication, health checks, and live WebSocket updates | 8101 |
| `worker` | Scheduled ingestion, enrichment, scoring, reports, maintenance, and escalation | None |
| `webhook` | SolarWinds request validation and alert processing | 8100 |
| `web` | Production React workspace served by nginx | 8501 |
| `web-dev` | Optional Vite development workspace with hot reload | 5173 |

The default database is SQLite stored in `./data`. PostgreSQL is supported for deployments that need multiple instances or higher concurrency.

## Quick Start

### Requirements

- Docker Engine 24 or newer is recommended.
- Docker Compose v2 is recommended.
- At least 4 GB of available memory is recommended for a small deployment.
- Outbound access to configured data sources is required for ingestion.
- An LLM provider is optional, but required for AI-generated briefs and summaries.

### Start the Production-Style Stack

```bash
cp .env.example .env
```

Set `DEFAULT_ADMIN_PASSWORD` in `.env` before the first startup. Then build and start the services:

```bash
docker compose up --build -d
```

Open `http://localhost:8501` and sign in as `admin` using the configured password.

Verify the deployment:

```bash
docker compose ps
curl http://localhost:8101/health
curl http://localhost:8101/ready
curl http://localhost:8100/health
```

### Start Development Mode

Development mode starts a Vite workspace with hot reload on port `5173`:

```bash
docker compose --profile dev up --build -d
```

The production web container is still exposed on port `8501`; the `web-dev` container is available on port `5173`.

## Initial Configuration

The complete environment template is [`.env.example`](./.env.example). The most important values are:

| Setting | Why it matters |
|---|---|
| `DATABASE_URL` | Selects the SQLite or PostgreSQL database. |
| `DEFAULT_ADMIN_PASSWORD` | Creates the first administrator when the database has no users. |
| `CORS_ORIGINS` | Controls which browser origins may call the API. |
| `RISK_ALERT_RECIPIENTS` | Enables risk and daily brief recipients. |
| `REMEDYFORCE_TICKET_EMAIL` | Required for tiered escalation ticket dispatch. |
| `NOC_NOTIFY_EMAIL` | Receives after-hours NOC notifications. |
| `NOC_ONPAGE_EMAIL` | Receives after-hours paging for NOC/SWF device categories. |
| `ITNETWORK_ONPAGE_EMAIL` | Receives after-hours paging for network and other device categories. |
| `WEBHOOK_HMAC_SECRET` | Enables signed SolarWinds webhook validation when configured. |
| `ELASTIC_URL`, `ELASTIC_API_KEY` | Enable Elastic-backed telemetry workflows. |
| `DEMO_SEED_DATA` | Adds synthetic assets for disposable demonstrations. Keep false in production. |

SMTP and LLM provider details are configured in the Settings page under the AI & SMTP area and stored in the application configuration. They are not additional `SMTP_*` or `LLM_API_URL` environment variables in the current runtime.

## Automated Operations

The worker runs scheduled jobs without requiring an analyst to trigger each collection manually:

| Activity | Frequency |
|---|---:|
| Alert escalation | Every 1 minute |
| Article enrichment | Every 3 minutes |
| RSS ingestion | Every 5 minutes |
| Maintenance expiry checks | Every 5 minutes |
| Telemetry sync | Every 6 minutes |
| Regional hazards | Every 7 minutes |
| Cloud status | Every 8 minutes |
| Crime data | Every 10 minutes |
| Rolling shift summary | Every 30 minutes |
| Database maintenance | Every 60 minutes |
| Internal risk snapshot | Every 2 hours |
| Internal asset brief | Every 3 hours |
| Unified brief | Every 6 hours |
| CISA KEV sync | Every 7 hours |
| Global Threat Brief | Daily at 02:00 |
| Daily email brief | 07:00 Central time |
| ML retraining | Sunday at 02:00 |

The scheduler prevents the same job from overlapping with itself and limits concurrent scheduled work. External errors are logged and do not intentionally stop the scheduler loop.

## Alerting and Response

Tiered escalation uses Central Time business hours, Monday through Friday from 06:00 to 20:00. It considers:

- P1-P5 priority and response windows.
- Day-shift versus after-hours routing.
- Cascade and fleet-outage context.
- Repeated node flapping and cooldown windows.
- Site maintenance and temporary mute state.
- Ticket, notification, and on-page destinations.

The system does not dispatch tickets unless `REMEDYFORCE_TICKET_EMAIL` is configured. Email delivery also requires a valid, enabled SMTP configuration in Settings.

## Authentication and Permissions

Users authenticate with database-backed session tokens. The system is not using JWT authentication. Access is controlled with:

- Page permissions for workspace areas.
- Tab permissions for dashboard and settings sections.
- Action permissions for operations such as dispatching RCA tickets.
- Allowed site types for facility-level access.

Important permission strings are exact and case-sensitive:

- `Action: Dispatch RCA Tickets`
- `Action: Manage Site Maintenance`
- `Tab: Settings -> Internal Assets`
- `Tab: Dashboards -> Unified Brief`

The frontend hides unavailable areas, but the backend also checks protected operations.

## SolarWinds Webhook

Configure SolarWinds or another compatible ITSM source to send:

```text
POST http://<host>:8100/webhook/solarwinds
Content-Type: application/json
```

The gateway validates request size and, when configured, HMAC signatures and timestamps. It extracts device and alert fields, classifies the device into the shared infrastructure domains, detects resolution messages, and stores the alert for correlation.

Basic connectivity check:

```bash
curl http://localhost:8100/health
```

## Common Operator Commands

```bash
# View service state

# Follow individual service logs

# Restart one service

# Rebuild the frontend

# Check API and database readiness
curl http://localhost:8101/health
curl http://localhost:8101/ready
```

Before database maintenance or a reset, create a verified backup. Do not remove the database as a first troubleshooting step.

## Security and Deployment Guidance

- Keep `.env` out of version control.
- Set a unique administrator password before first boot.
- Restrict `CORS_ORIGINS` to approved browser origins.
- Restrict port `8100` to approved webhook senders.
- Keep ports `8100` and `8101` off the public internet unless protected by a firewall and reverse proxy.
- Use HTTPS through a reverse proxy for production access.
- Use PostgreSQL for multi-instance or high-concurrency deployments.
- Back up the database before migrations, restores, or destructive administrative actions.
- Treat LLM, SMTP, Elastic, and webhook credentials as operational secrets.

## Documentation Map

The detailed documentation is organized under [`docs/`](./docs/):

| Need | Guide |
|---|---|
| Install and configure | [Getting Started](./docs/GETTING_STARTED.md) |
| Deploy and harden | [Deployment](./docs/DEPLOYMENT.md) |
| Understand the system | [Architecture](./docs/ARCHITECTURE.md) |
| Use the workspace | [User Guide](./docs/USER_GUIDE.md) |
| Review REST endpoints | [API Reference](./docs/API.md) |
| Understand data storage | [Database Schema](./docs/DATABASE_SCHEMA.md) |
| Understand scheduled work | [Scheduler](./docs/SCHEDULER.md) |
| Change frequencies and settings | [Operations Reference](./docs/OPERATIONS_REFERENCE.md) |
| Diagnose problems | [Troubleshooting](./docs/TROUBLESHOOTING.md) |
| Follow ingestion and trigger flows | [Data Flows](./docs/DATA_FLOWS.md), [Trigger Flows](./docs/TRIGGER_ACTION_FLOWS.md) |
| Find function-level detail | [Code Reference](./docs/CODE_REFERENCE.md) |
| Review changes | [Changelog](./CHANGELOG.md) |

`docs/` is the only documentation root. The `docs/reference/` tree contains detailed module, service, worker, frontend, and configuration references.

## Current Operational Note

The Elastic cache route currently has a naming mismatch between the API route and the worker export. The application documents this limitation in [API.md](./docs/API.md) and [Troubleshooting](./docs/TROUBLESHOOTING.md); the rest of the Elastic worker remains active and should not be removed.

## AI-Generated Project Disclaimer

Please note that this project—including its core logic, UI components, and documentation—was written by an AI coding agent through OpenCode (also available via the OpenCode GitHub App).

The code generation heavily leveraged the Big Pickle model and OpenAI's GPT-5.6 Luna (Medium). While the output has been reviewed by a human, the reviewer considers themselves a novice at best. Please deploy and use this codebase with caution, review critical security paths manually, and be aware that the AI may have introduced unoptimized patterns, hallucinations, or unintended bugs.

## License

See [LICENSE](./LICENSE).
