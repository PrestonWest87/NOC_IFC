# Operations and Configuration Quick Reference

This is the fast lookup for operators and maintainers. Environment defaults are defined in `src/core/config.py` and `.env.example`; supported scheduler jobs/defaults/bounds are defined in `src/core/scheduler_registry.py`, persisted settings are reloaded by `src/scheduler.py`, and application settings are exposed through the Settings UI.

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
| 8100 | Webhook | `curl http://localhost:8100/health` |
| 8101 | API and WebSocket | `/health`, `/ready`, `/ws?token=...` |
| 8501 | Production web | Browser or `curl` |
| 5173 | Dev web | Browser when `dev` profile is active |

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
| `ALLOW_PRIVATE_LLM_ENDPOINTS` | `false` | Allowing a private/local LLM endpoint after security review |
| `CORS_ORIGINS` | localhost origins | Restricting browser origins |
| `ALLOW_UNSIGNED_WEBHOOKS` | `false` | Temporary controlled migration only; do not enable by default |
| `PUBLIC_APP_URL` | `http://localhost:8501` | Registration links or externally advertised URLs |
| `REGISTRATION_INVITE_TTL_HOURS` | `72` | Changing invite expiration |
| `RESCORE_ON_STARTUP` | `false` if absent | Explicitly rescoring all existing articles during startup |

These defaults describe runtime configuration when a variable is unset. The `.env.example` deliberately contains a change-me placeholder for `DEFAULT_ADMIN_PASSWORD`; replace it before first startup.

## Frequency Controls

The values below are registry defaults for all 20 jobs; a user with scheduler-management permission may save a different validated value in Settings > Application Settings. `src/core/scheduler_registry.py` is the source of truth.

| Behavior | Source location | Current value |
|---|---|---:|
| RSS fetch | `JOB_REGISTRY["rss_fetch"]` | 5 minutes |
| Enrichment | `JOB_REGISTRY["article_enrichment"]` | 3 minutes |
| Maintenance expiry | `JOB_REGISTRY["maintenance_expiry"]` | 5 minutes |
| Hazards | `JOB_REGISTRY["regional_hazards"]` | 7 minutes |
| Crime | `JOB_REGISTRY["crime_fetch"]` | 10 minutes |
| Cloud | `JOB_REGISTRY["cloud_outages"]` | 8 minutes |
| Telemetry | `JOB_REGISTRY["telemetry_sync"]` | 6 minutes |
| Elastic cache sync | `JOB_REGISTRY["elastic_sync"]` | 6 minutes |
| Escalation | `JOB_REGISTRY["tiered_alert_escalation"]` | 1 minute (cannot be disabled; 1–5 minute bound) |
| Database maintenance | `JOB_REGISTRY["database_maintenance"]` | 60 minutes |
| Internal risk | `JOB_REGISTRY["internal_risk"]` | 2 hours |
| Rolling shift summary | `JOB_REGISTRY["rolling_summary"]` | 30 minutes |
| Internal asset brief | `JOB_REGISTRY["internal_brief"]` | 3 hours |
| Unified brief | `JOB_REGISTRY["unified_brief"]` | 6 hours |
| KEV | `JOB_REGISTRY["cisa_kev"]` | 7 hours |
| Global brief | `JOB_REGISTRY["global_brief"]` | Daily 02:00 America/Chicago |
| Daily Fusion report | `JOB_REGISTRY["daily_fusion_report"]` | Daily 06:00 America/Chicago |
| Daily email | `JOB_REGISTRY["daily_email_brief"]` | Daily 07:00 America/Chicago |
| ML retraining | `JOB_REGISTRY["ml_retrain"]` | Sunday 02:00 America/Chicago |
| Encrypted database backup | `JOB_REGISTRY["database_backup"]` | Sunday 00:00 America/Chicago (cannot be disabled) |

The WebSocket dashboard broadcaster is independent of the scheduler and broadcasts every 10 seconds while clients are connected.

## Application-Level Controls

Change these through the Settings UI or the corresponding `SystemConfig` fields, not by adding environment variables that the code does not read:

- Keyword weights: `Keyword.weight`; validated by the keyword routes and applied by `HybridScorer`.
- Scoring mode and CIS overrides: `scoring_mode`, criticality/lethality overrides, and risk offsets.
- LLM provider/model/context: `SystemConfig` LLM fields; `src/utils/llm.py` applies context-window limits.
- SMTP host, port, credentials, sender, and recipients: `SystemConfig`; `src/utils/mailer.py` sends messages.
- RSS sources: `FeedSource` rows managed from Settings.

## Safe Database Actions

Create and verify an encrypted full SQLite backup through Settings > Backup & Restore before destructive work. Packages include all database tables and the trained model when present; `.env` secrets remain separate. Restore uses the offline maintenance-window procedure in [Maintenance](MAINTENANCE.md#restore-and-disaster-recovery). The legacy Settings JSON exports cover only supported application-model subsets and are not full database backups. Schema migrations run automatically at backend startup; conditional bootstrap data preserves existing keyword weights and custom role grants.
