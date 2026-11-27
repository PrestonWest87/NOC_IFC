# Operations and Configuration Quick Reference

This is the fast lookup for the default C# dev-c stack. Scheduler definitions live in `src/NocIfc.Application/Features/Settings/SchedulerSettingsCommands.cs` and run in `src/NocIfc.Worker/SchedulerWorker.cs`; the ignored Python Compose backup retains its own scheduler/configuration references.

## Service Commands

```bash
docker compose up --build -d
docker compose --profile dev up --build -d
docker compose ps
docker compose logs -f api
docker compose logs -f worker
docker compose logs -f webhook
docker compose logs -f web
docker compose restart api
docker compose up --build -d --force-recreate web
curl -fsS http://localhost:8101/health
curl -fsS http://localhost:8101/ready
```

## Ports

| Port | Service | Check |
|---:|---|---|
| 8100 | C# webhook (container 8100) | `curl http://localhost:8100/health` |
| 8101 | C# API and WebSocket (container 8101) | `/health`, `/ready`, `/ws?token=...` |
| 8501 | Production web (container 5173) | Browser or `curl` |
| 5173 | Vite dev web (container 5173) | Browser when `dev` profile is active |

The default C# Compose project is named `noc-ifc-dev-c`, uses `./data-dev-c`, and attaches containers to Docker's built-in `bridge` network without allocating a new subnet. Its host ports match the main Compose mapping. Nginx and Vite route to the API through the `noc-ifc-dev-c-api` host-gateway alias. The ignored local `docker-compose.yml` remains the older Python backup using `./data-dev`.

## Operational Email

For linked Fiber Maintenance Complete messages, the Network Orders/Circuit IDs and paired A/Z locations carry into the composer and close-out body. Network-order/circuit identifiers are bold in the sent HTML alternative; the plain-text version is retained.

For Fiber Outage, ONPAGE, linked outage messages, and grouped Fiber Maintenance Start/Complete notices, a BCC recipient receives circuit/network-order details only for circuits mapped to that recipient's Fiber-contact company. Other BCC recipients receive one circuit-free copy per send occurrence, with the rest of the message retained and active Global From in To.

All outbound email uses the saved active sender selected in Settings > AI & SMTP. The existing SMTP relay and Gmail profile are stored side by side; changing the selector affects new messages across alerts, reports, recovery mail, and Operational Email. Gmail uses `smtp.gmail.com:587` with STARTTLS and OAuth2 XOAUTH2; configure an OAuth client and refresh token with `https://mail.google.com/`. Save the profile before sending a test email. The page grant controls Operational Email access; only administrators can edit shared template defaults or signatures. Fiber Outage without configured circuits defaults To to Global From; selecting circuits fans out one message per company with mapped Fiber contacts in To, Global From in Cc, and only that company's circuit subset. Fiber Maintenance uses the same company-specific To routing, with administrator/per-message Cc, and each circuit ID is shown beside its A/Z locations on a separate line, including in linked Maintenance Start/Complete notices. Both templates schedule with the same company split. Fiber contact BCC pickers are available on Fiber Outage and Fiber Outage Resolution, but mapped To contacts are not automatically added to BCC; manual BCC recipients carry into linked messages. Grouped sources appear once in selectors, and linked outage updates/resolutions or maintenance start/completion send once per successfully delivered source company. Fiber contact names/phones are not autofilled into message text. Fiber Outage requires a manually entered nearest-crossroads Location and optional Network Orders/Circuit IDs; selecting a circuit does not replace the Location. Fiber Outage ONPAGE sends ONPAGE contacts to To and Global From on Cc; After-Hours ONPAGE remains To-only. Planned maintenance windows use `MM/DD/YY HH:MM AM/PM` followed by the current CST/CDT label; other date/time fields use that format and include a timezone suffix where their template includes one. Recurring schedules use `America/Chicago` and follow daylight-saving changes.

The Morning Report takes `SystemConfig.rolling_summary` (the latest Global Dashboard shift analysis) at delivery time and sends the stored text without a generated report header or executive-summary wrapper. Fiber outage follow-ups and resolution emails require a successfully sent Fiber Outage or Fiber Outage ONPAGE source record; grouped Fiber Outage sources are listed once and fan out per company that received a successful original delivery. Maintenance Start and Maintenance Complete link to a successfully sent Maintenance Notification or Fiber Maintenance Notification, inheriting its details and recipients; grouped Fiber Maintenance sources fan out per successful company delivery. Both support administrator-configured, sender-editable default Cc. Admin-managed signatures are optional and captured in message/schedule snapshots; deactivating a signature does not change existing scheduled sends or delivery history.

Settings > Email Contacts contains separate Fiber company and ONPAGE department directories. Settings > Network Orders & Circuits contains ordered A/Z location, circuit/network-order ID, company, and reciprocal associated-circuit mappings. Users with the matching Settings tab grant can export these directories to CSV; network-order exports include semicolon-separated associated IDs. Selecting a circuit in Operational Email includes its immediate associations only; associations of auto-included circuits are not traversed. Each directory supports CSV imports; merge/update is the default and replace-all mode is explicit. Changes are administrator-only and audited without including row values in audit details.

Fiber Outage ONPAGE adds optional free-text Rcount, Maps URL, and Closest Hand Hole details. Follow-up and resolution messages no longer prompt for current status.

## Environment Variables

The rows below are a selected operations quick reference, not a complete variable inventory. Use [`.env.example`](../.env.example) and the [environment source reference](reference/config/env_example.md) for the full list, defaults, and readers.

| Variable | Default | Change when |
|---|---|---|
| `DATABASE_URL` | SQLite in `/app/data` | Selecting the shared SQLite database file |
| `DEMO_SEED_DATA` | `false` | Only for disposable demonstrations |
| `DEFAULT_ADMIN_PASSWORD` | empty | Setting the first admin password before first boot |
| `DEFAULT_ADMIN_EMAIL` | empty | Providing a trusted bootstrap recovery/reviewer mailbox; can initialize an existing email-less bootstrap admin on API/worker startup |
| `LOG_LEVEL` | `INFO` | Increasing diagnostic detail (`DEBUG`) or reducing noise |
| `RISK_ALERT_RECIPIENTS` | empty | Enabling risk and daily brief recipients |
| `REMEDYFORCE_TICKET_EMAIL` | empty | Escalation ticket destination |
| `NOC_NOTIFY_EMAIL` | empty | After-hours NOC notifications |
| `NOC_ONPAGE_EMAIL` | empty | After-hours NOC paging |
| `ITNETWORK_ONPAGE_EMAIL` | empty | After-hours IT/network paging |
| `CRIME_ALERT_SMS`, `CRIME_ALERT_EMAIL` | empty | Enabling perimeter alert destinations |
| `ELASTIC_URL`, `ELASTIC_API_KEY` | empty / empty | Enabling Elastic telemetry from an endpoint reachable by the containers |
| `WEBHOOK_HMAC_SECRET` | empty | Enabling SolarWinds signature validation |
| `WEBHOOK_SIGNATURE_HEADER` | `X-SolarWinds-Signature` | Matching sender header name |
| `WEBHOOK_TIMESTAMP_HEADER` | `X-SolarWinds-Timestamp` | Matching sender timestamp header name |
| `WEBHOOK_REPLAY_WINDOW_SECONDS` | `300` | Tightening or relaxing replay protection |
| `WEBHOOK_MAX_BODY_BYTES` | `1048576` | Accommodating larger or rejecting oversized webhook bodies |
| `WEBSOCKET_MAX_MESSAGE_BYTES` | `65536` | Changing WebSocket input limits |
| `ALLOW_PRIVATE_LLM_ENDPOINTS` | `false` | Allowing private endpoints for generic OpenAI-compatible connection tests; Ollama/vLLM local provider selections support validated private targets |
| `CORS_ORIGINS` | localhost origins | Restricting browser origins |
| `ALLOW_UNSIGNED_WEBHOOKS` | `false` | Temporary controlled migration only; do not enable by default |
| `PUBLIC_APP_URL` | `http://localhost:8501` | Registration links or externally advertised URLs |
| `NWS_API_USER_AGENT` | `NOC-IFC/2.0 (https://test.weasts.net)` | Identifying NWS API client; set a deployed URL, with `DEFAULT_ADMIN_EMAIL` appended when configured |
| `REGISTRATION_INVITE_TTL_HOURS` | `72` | Changing invite expiration |
| `RESCORE_ON_STARTUP` | `false` if absent | Explicitly rescoring all existing articles during startup |

These environment values remain supported as fallback runtime configuration. A database value saved in Settings > Application Settings > Notification destinations and Elastic integration takes precedence; an explicit blank disables an optional destination/integration, and “Reset to environment” restores fallback behavior. Values are read dynamically by API and worker processes. The `.env.example` deliberately contains a change-me placeholder for `DEFAULT_ADMIN_PASSWORD`; replace it before first startup.

## Frequency Controls

The C# registry in `SchedulerSettingsCommands.Registry` defines these 21 defaults; a user with scheduler-management permission may save a different validated value in Settings > Application Settings. The ignored Python backup retains its separate `src/core/scheduler_registry.py`. NWS alert polling and the operational email queue are fixed at one minute and cannot be disabled.

| Behavior | C# registry key | Current value |
|---|---|---:|
| RSS fetch | `rss_fetch` | 5 minutes |
| Enrichment | `article_enrichment` | 3 minutes |
| Maintenance expiry | `maintenance_expiry` | 5 minutes |
| NWS active alerts | `nws_alerts` | 1 minute (fixed; cannot be disabled) |
| Regional hazards | `regional_hazards` | 7 minutes |
| Crime | `crime_fetch` | 10 minutes |
| Cloud | `cloud_outages` | 8 minutes |
| Telemetry | `telemetry_sync` | 6 minutes |
| Elastic cache sync | `elastic_sync` | 6 minutes |
| Escalation | `tiered_alert_escalation` | 1 minute (cannot be disabled; 1–5 minute bound) |
| Database maintenance | `database_maintenance` | 60 minutes |
| Internal risk | `internal_risk` | 2 hours |
| Rolling shift summary | `rolling_summary` | 30 minutes |
| Internal asset brief | `internal_brief` | 3 hours |
| Unified brief | `unified_brief` | 6 hours |
| KEV | `cisa_kev` | 7 hours |
| Global brief | `global_brief` | Daily 02:00 America/Chicago |
| Daily Fusion report | `daily_fusion_report` | Daily 06:00 America/Chicago |
| Daily email | `daily_email_brief` | Daily 07:00 America/Chicago |
| Operational email queue | `operational_email_queue` | 1 minute (cannot be disabled) |
| Encrypted database backup | `database_backup` | Sunday 00:00 America/Chicago (cannot be disabled) |

The WebSocket dashboard broadcaster is independent of the scheduler and broadcasts every 10 seconds while clients are connected.

## Application-Level Controls (legacy Python source paths)

These persisted controls are managed through Settings. The source paths below describe the legacy Python backup; C# dev-c ports are tracked in `README_DEV_C.md`.

- Keyword weights: `Keyword.weight`; validated by the keyword routes and applied by `KeywordScorer`.
- Scoring mode and CIS overrides: `scoring_mode`, criticality/lethality overrides, and risk offsets.
- LLM provider/model/context: `SystemConfig` LLM fields; `src/utils/llm.py` applies context-window limits.
- Notification destinations and Elastic URL/key/TLS/query bounds: Settings > Application Settings; null overrides use the matching environment value.
- SMTP host, port, credentials, sender, and recipients: `SystemConfig`; `src/utils/mailer.py` sends messages.
- Active SMTP profile and Gmail OAuth credentials: `SystemConfig`; `src/core/email_settings.py` selects a profile, `src/core/gmail_oauth.py` refreshes access tokens, and `POST /admin/config/test-email` validates saved delivery.
- RSS sources: `FeedSource` rows managed from Settings.

## Safe Database Actions

Create and verify an encrypted full SQLite backup through Settings > Backup & Restore before destructive work. New packages include all database tables; legacy optional classifier artifacts are validated but ignored on restore. `.env` secrets remain separate. Restore uses the coordinated maintenance-window procedure in [Maintenance](MAINTENANCE.md#restore-and-disaster-recovery). The legacy Settings JSON exports cover only supported application-model subsets and are not full database backups. C# services require the host-side Alembic migration to complete before startup; only the legacy Python backup runs migrations at startup.
