# `.env.example` Environment Reference

**Path:** `.env.example`

This is the environment template for the active C# API, Worker, and Webhook plus host-side offline migration/backup tools. Copy it to `.env`; Compose injects values into backend containers. Frontend-only `VITE_API_URL` values are defined in `compose.dev-c.yaml`.

| Variable | Default in template | Read by | Purpose |
|---|---|---|---|
| `DATABASE_URL` | SQLite container path `/app/data/noc_fusion.db` | C# hosts; host migration tools | Shared SQLite file; Compose maps `/app/data` to isolated `./data-dev-c` |
| `DEMO_SEED_DATA` | `false` | Offline bootstrap | Enable synthetic asset seed data only for disposable databases |
| `DEFAULT_ADMIN_PASSWORD` | change-me placeholder | Offline bootstrap | Initial admin password when preparing a fresh database |
| `DEFAULT_ADMIN_EMAIL` | empty | Offline bootstrap | Trusted verified mailbox for the initial administrator |
| `RISK_ALERT_RECIPIENTS` | empty | C# runtime settings | Fallback for risk and daily brief recipients; database override takes precedence |
| `REMEDYFORCE_TICKET_EMAIL` | empty | C# runtime settings | Fallback ticket destination for escalation |
| `NOC_NOTIFY_EMAIL` | empty | C# runtime settings | Fallback NOC notification destination |
| `NOC_ONPAGE_EMAIL` | empty | C# runtime settings | Fallback NOC on-page destination |
| `ITNETWORK_ONPAGE_EMAIL` | empty | C# runtime settings | Fallback IT/network on-page destination |
| `ELASTIC_URL`, `ELASTIC_API_KEY` | empty | C# runtime settings | Elastic endpoint and credential; blank URL disables sync |
| `ELASTIC_VERIFY_CERTS` | `true` | C# runtime settings | Fallback TLS certificate verification setting |
| `ELASTIC_CA_CERTS` | empty | C# runtime settings | Fallback CA bundle path |
| `ELASTIC_REQUEST_TIMEOUT` | `15` | C# runtime settings | Fallback Elasticsearch request timeout in seconds |
| `ELASTIC_MAX_RESULTS` | `500` | C# runtime settings | Fallback maximum results per Elastic query page |
| `CRIME_ALERT_SMS`, `CRIME_ALERT_EMAIL` | empty | C# runtime settings | Fallback crime alert destinations |
| `WEBHOOK_HMAC_SECRET` | empty | C# Webhook | Shared SolarWinds signing secret |
| `WEBHOOK_SIGNATURE_HEADER` | `X-SolarWinds-Signature` | C# Webhook | Signature header name |
| `WEBHOOK_TIMESTAMP_HEADER` | `X-SolarWinds-Timestamp` | C# Webhook | Replay timestamp header name |
| `WEBHOOK_REPLAY_WINDOW_SECONDS` | `300` | C# Webhook | Accepted timestamp age |
| `WEBHOOK_MAX_BODY_BYTES` | `1048576` | C# Webhook | Maximum request body size |
| `WEBSOCKET_MAX_MESSAGE_BYTES` | `65536` | C# API | Maximum client WebSocket message |
| `ALLOW_PRIVATE_LLM_ENDPOINTS` | `false` | C# LLM settings | Permit private targets for generic OpenAI-compatible connection tests; selected Ollama/vLLM providers can use validated local targets |
| `CORS_ORIGINS` | `http://localhost:8501,http://localhost:5173` | C# API | Comma-separated browser origin allowlist |
| `ALLOW_UNSIGNED_WEBHOOKS` | `false` | C# Webhook | Controlled unsigned-webhook migration exception |
| `PUBLIC_APP_URL` | `http://localhost:8501` | C# API | Registration link base URL |
| `NWS_API_USER_AGENT` | `NOC-IFC/2.0 (https://test.weasts.net)` | C# Worker | Identifies NWS requests; configure the deployed public URL and optional contact |
| `REGISTRATION_INVITE_TTL_HOURS` | `72` | C# API | Default invite lifetime |
| `BACKUP_ENCRYPTION_ACTIVE_KEY_ID` | `primary` | C# backup service; offline tools | Active key ID for new encrypted full backups |
| `BACKUP_ENCRYPTION_KEYS` | empty | C# backup service; offline tools | JSON map of 32-byte hex backup keys; never commit or include in backup packages |
| `BACKUP_MAX_BYTES` | `10737418240` | C# backup service; offline tools | Maximum encrypted backup/upload size; default 10 GiB, maximum 100 GiB |

## Security

Never commit `.env`. Replace all development defaults before production deployment. SMTP, LLM provider, and Elastic API credentials may be stored as ordinary fields in `SystemConfig`; the live SQLite database does not apply field-level encryption. The UI never returns stored API keys. Encrypted backup packages protect their database snapshot, while `.env` and environment-only secrets remain external. Keep backup encryption keys separate from the database volume and retain old key IDs until backups using them are retired. Saved operational integration settings are shared dynamically by the C# API and Worker; null database overrides use the environment value.
