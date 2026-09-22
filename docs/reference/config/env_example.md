# `.env.example` Environment Reference

**Path:** `.env.example`

This file is the complete template for environment variables used by the current Python runtime. Copy it to `.env`; Docker injects it into `api`, `worker`, and `webhook`. The frontend-only `VITE_API_URL` values are defined in `docker-compose.yml`.

| Variable | Default in template | Read by | Purpose |
|---|---|---|---|
| `DATABASE_URL` | SQLite container path `/app/data/noc_fusion.db` | `src.core.config` | SQLAlchemy database URL; Docker maps `/app/data` to repository `./data` |
| `DEMO_SEED_DATA` | `false` | `src.core.config` | Enable synthetic asset seed data |
| `DEFAULT_ADMIN_PASSWORD` | change-me placeholder | `src.core.db` | Initial admin password when the database has no users |
| `LOG_LEVEL` | `INFO` | `src.core.config` | Python logging threshold |
| `RISK_ALERT_RECIPIENTS` | empty | scheduler/config | Risk and daily brief recipients |
| `REMEDYFORCE_TICKET_EMAIL` | empty | scheduler | Required ticket destination for escalation |
| `NOC_NOTIFY_EMAIL` | empty | scheduler/infra worker | After-hours NOC notification |
| `NOC_ONPAGE_EMAIL` | empty | scheduler | After-hours NOC paging for SWF/fiber devices |
| `ITNETWORK_ONPAGE_EMAIL` | empty | scheduler | After-hours IT/network paging |
| `ELASTIC_URL` | `https://localhost:9200` | `src.core.config` | Elasticsearch endpoint |
| `ELASTIC_API_KEY` | empty | `src.core.config` | Elasticsearch credential |
| `ELASTIC_VERIFY_CERTS` | `true` | `src.core.config` | Verify Elasticsearch TLS certificates |
| `ELASTIC_CA_CERTS` | empty | `src.core.config` | Optional CA bundle path |
| `ELASTIC_REQUEST_TIMEOUT` | `15` | `src.core.config` | Elasticsearch request timeout in seconds |
| `ELASTIC_MAX_RESULTS` | `500` | `src.core.config` | Maximum results per Elastic query page |
| `CRIME_ALERT_SMS` | empty | `src.core.config` | Crime SMS gateway destination |
| `CRIME_ALERT_EMAIL` | empty | `src.core.config` | Crime email destination |
| `WEBHOOK_HMAC_SECRET` | empty | `src.core.config`/webhook | Shared SolarWinds signing secret |
| `WEBHOOK_SIGNATURE_HEADER` | `X-SolarWinds-Signature` | webhook | Signature header name |
| `WEBHOOK_TIMESTAMP_HEADER` | `X-SolarWinds-Timestamp` | webhook | Replay timestamp header name |
| `WEBHOOK_REPLAY_WINDOW_SECONDS` | `300` | webhook | Accepted timestamp age |
| `WEBHOOK_MAX_BODY_BYTES` | `1048576` | webhook | Maximum request body size |
| `WEBSOCKET_MAX_MESSAGE_BYTES` | `65536` | API | Maximum client WebSocket message |
| `ALLOW_PRIVATE_LLM_ENDPOINTS` | `false` | LLM route | Permit private LLM endpoint URLs |
| `CORS_ORIGINS` | localhost web origins | API | Comma-separated browser origin allowlist |
| `ALLOW_UNSIGNED_WEBHOOKS` | `false` | webhook | Controlled unsigned-webhook migration exception |
| `PUBLIC_APP_URL` | `http://localhost:8501` | admin routes | Registration link base URL |
| `REGISTRATION_INVITE_TTL_HOURS` | `72` | admin routes | Default invite lifetime |
| `RESCORE_ON_STARTUP` | `false` | `src.core.db` | Explicitly rescore all existing articles at startup; direct environment control, not a `Settings` field |

## Security

Never commit `.env`. Replace all development defaults before production deployment. SMTP and LLM provider credentials are application settings stored in `SystemConfig`, not additional environment variables in the current runtime.
