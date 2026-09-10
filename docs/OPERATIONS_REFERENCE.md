# Operations and Configuration Quick Reference

This is the fast lookup for operators and maintainers. Environment defaults are defined in `src/core/config.py` and `.env.example`; scheduler timing is defined in `src/scheduler.py`; application settings are stored in `SystemConfig` and exposed through the Settings UI.

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

| Variable | Default | Change when |
|---|---|---|
| `DATABASE_URL` | SQLite in `/app/data` | Selecting PostgreSQL or another persistent database |
| `DEMO_SEED_DATA` | `false` | Only for disposable demonstrations |
| `DEFAULT_ADMIN_PASSWORD` | empty | Setting the first admin password before first boot |
| `LOG_LEVEL` | `INFO` | Increasing diagnostic detail (`DEBUG`) or reducing noise |
| `RISK_ALERT_RECIPIENTS` | empty | Enabling risk and daily brief recipients |
| `REMEDYFORCE_TICKET_EMAIL` | empty | Escalation ticket destination |
| `NOC_NOTIFY_EMAIL` | empty | After-hours NOC notifications |
| `NOC_ONPAGE_EMAIL` | empty | After-hours NOC paging |
| `ITNETWORK_ONPAGE_EMAIL` | empty | After-hours IT/network paging |
| `CRIME_ALERT_SMS`, `CRIME_ALERT_EMAIL` | empty | Enabling perimeter alert destinations |
| `ELASTIC_URL`, `ELASTIC_API_KEY` | local URL / empty | Enabling Elastic telemetry |
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

## Frequency Controls

| Behavior | Source location | Current value |
|---|---|---:|
| RSS fetch | `src/scheduler.py`, `schedule.every(5).minutes` | 5 minutes |
| Enrichment | `src/scheduler.py`, `schedule.every(3).minutes` | 3 minutes |
| Hazards | `src/scheduler.py`, `schedule.every(7).minutes` | 7 minutes |
| Crime | `src/scheduler.py`, `schedule.every(10).minutes` | 10 minutes |
| Cloud | `src/scheduler.py`, `schedule.every(8).minutes` | 8 minutes |
| Telemetry | `src/scheduler.py`, `schedule.every(6).minutes` | 6 minutes |
| Escalation | `src/scheduler.py`, `schedule.every(1).minutes` | 1 minute |
| Internal risk | `src/scheduler.py`, `schedule.every(2).hours` | 2 hours |
| Brief generation | `src/scheduler.py`, `schedule.every(3/6).hours` | 3/6 hours by brief |
| KEV | `src/scheduler.py`, `schedule.every(7).hours` | 7 hours |
| Daily email | `src/scheduler.py`, `07:00 America/Chicago` | Daily |
| WebSocket broadcast | `src/api/main.py`, `asyncio.sleep(10)` | 10 seconds |

## Application-Level Controls

Change these through the Settings UI or the corresponding `SystemConfig` fields, not by adding environment variables that the code does not read:

- Keyword weights: `Keyword.weight`; validated by the keyword routes and applied by `HybridScorer`.
- Scoring mode and CIS overrides: `scoring_mode`, criticality/lethality overrides, and risk offsets.
- LLM provider/model/context: `SystemConfig` LLM fields; `src/utils/llm.py` applies context-window limits.
- SMTP host, port, credentials, sender, and recipients: `SystemConfig`; `src/utils/mailer.py` sends messages.
- RSS sources: `FeedSource` rows managed from Settings.

## Safe Database Actions

```bash
docker compose exec api python -c "from src.core.db import init_db; init_db()"
docker compose exec api python -c "from src.services import export_backup; export_backup('/app/data/backup.json')"
```

Do not delete the database or run destructive admin actions without a verified backup. `init_db()` is additive but startup seed logic can update roles and add defaults.
