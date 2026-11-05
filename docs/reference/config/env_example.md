# `.env.example` Environment Reference

**Path:** `.env.example`

This file is the complete template for environment variables used by the current Python runtime. Copy it to `.env`; Docker injects it into `api`, `worker`, and `webhook`. The frontend-only `VITE_API_URL` values are defined in `docker-compose.yml`.

| Variable | Default in template | Read by | Purpose |
|---|---|---|---|
| `DATABASE_URL` | SQLite container path `/app/data/noc_fusion.db` | `src.core.config` | SQLAlchemy database URL; Docker maps `/app/data` to repository `./data`. `src/core/config.py` supplies this same default when unset, although `.env.example` currently labels it required. |
| `DEMO_SEED_DATA` | `false` | `src.core.config` | Enable synthetic asset seed data |
| `DEFAULT_ADMIN_PASSWORD` | change-me placeholder | `src.core.bootstrap` | Initial admin password when the database has no users |
| `DEFAULT_ADMIN_EMAIL` | empty | `src.core.config`, `src.core.bootstrap` | Trusted verified bootstrap mailbox; can initialize an existing email-less bootstrap administrator on API/worker startup |
| `LOG_LEVEL` | `INFO` | `src.core.config` | Python logging threshold |
| `RISK_ALERT_RECIPIENTS` | empty | runtime settings resolver | Fallback for risk and daily brief recipients; UI database override takes precedence |
| `REMEDYFORCE_TICKET_EMAIL` | empty | `src.core.config` / runtime settings resolver | Fallback ticket destination for escalation |
| `NOC_NOTIFY_EMAIL` | empty | `src.core.config` / runtime settings resolver | Fallback NOC notification destination |
| `NOC_ONPAGE_EMAIL` | empty | `src.core.config` / runtime settings resolver | Fallback NOC on-page destination for SWF/fiber devices |
| `ITNETWORK_ONPAGE_EMAIL` | empty | `src.core.config` / runtime settings resolver | Fallback IT/network on-page destination |
| `ELASTIC_URL` | empty | `src.core.config` / runtime settings resolver | Fallback Elasticsearch endpoint reachable from API/worker containers; empty disables sync |
| `ELASTIC_API_KEY` | empty | `src.core.config` / runtime settings resolver | Fallback Elasticsearch credential |
| `ELASTIC_VERIFY_CERTS` | `true` | `src.core.config` / runtime settings resolver | Fallback TLS certificate verification setting |
| `ELASTIC_CA_CERTS` | empty | `src.core.config` / runtime settings resolver | Fallback CA bundle path |
| `ELASTIC_REQUEST_TIMEOUT` | `15` | `src.core.config` / runtime settings resolver | Fallback Elasticsearch request timeout in seconds |
| `ELASTIC_MAX_RESULTS` | `500` | `src.core.config` / runtime settings resolver | Fallback maximum results per Elastic query page |
| `CRIME_ALERT_SMS` | empty | `src.core.config` / runtime settings resolver | Fallback crime SMS gateway destination |
| `CRIME_ALERT_EMAIL` | empty | `src.core.config` / runtime settings resolver | Fallback crime email destination |
| `WEBHOOK_HMAC_SECRET` | empty | `src.core.config`/webhook | Shared SolarWinds signing secret |
| `WEBHOOK_SIGNATURE_HEADER` | `X-SolarWinds-Signature` | webhook | Signature header name |
| `WEBHOOK_TIMESTAMP_HEADER` | `X-SolarWinds-Timestamp` | webhook | Replay timestamp header name |
| `WEBHOOK_REPLAY_WINDOW_SECONDS` | `300` | webhook | Accepted timestamp age |
| `WEBHOOK_MAX_BODY_BYTES` | `1048576` | webhook | Maximum request body size |
| `WEBSOCKET_MAX_MESSAGE_BYTES` | `65536` | API | Maximum client WebSocket message |
| `ALLOW_PRIVATE_LLM_ENDPOINTS` | `false` | LLM route | Permit private targets for generic OpenAI-compatible provider tests; selected Ollama/vLLM providers can use validated local targets |
| `CORS_ORIGINS` | localhost web origins | API | Comma-separated browser origin allowlist |
| `ALLOW_UNSIGNED_WEBHOOKS` | `false` | webhook | Controlled unsigned-webhook migration exception |
| `PUBLIC_APP_URL` | `http://localhost:8501` | admin routes | Registration link base URL |
| `NWS_API_USER_AGENT` | `NOC-IFC/2.0 (https://test.weasts.net)` | `src.core.config`, `src.workers.infra_worker`, `src.services` | Identifies NWS API requests; configure the deployed public URL, with the bootstrap admin email appended when set |
| `REGISTRATION_INVITE_TTL_HOURS` | `72` | admin routes | Default invite lifetime |
| `BACKUP_ENCRYPTION_ACTIVE_KEY_ID` | `primary` | `src.core.backup_manager` | Active key ID for new encrypted full backups |
| `BACKUP_ENCRYPTION_KEYS` | empty | `src.core.backup_manager` | JSON map of 32-byte hex backup keys; never commit or include in backup packages |
| `BACKUP_MAX_BYTES` | `10737418240` | `src.core.backup_manager` | Maximum encrypted backup/upload size; default 10 GiB, maximum 100 GiB |
| `RESCORE_ON_STARTUP` | `false` | `src.core.bootstrap` | Explicitly rescore all existing articles at startup; direct environment control, not a `Settings` field |

## Security

Never commit `.env`. Replace all development defaults before production deployment. SMTP, LLM provider, and Elastic API credentials may be stored as ordinary fields in `SystemConfig`; the live SQLite database does not apply field-level encryption. The UI never returns stored API keys. Encrypted backup packages protect their database snapshot, while `.env` and environment-only secrets remain external. Keep backup encryption keys separate from the database volume and retain old key IDs until backups using them are retired. Saved operational integration settings are shared dynamically by API and worker; null database overrides use the environment value.
