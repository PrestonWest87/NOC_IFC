# NOC Intelligence Fusion Center — Enterprise Deployment Guide

## 1. Prerequisites

| Requirement | Details |
|-------------|---------|
| Docker Engine | v24.0+ with Docker Compose v2 (`docker compose`) |
| Git | v2.30+ for repository cloning |
| RAM | Minimum 2 GB available (4 GB+ recommended for production) |
| Disk | Minimum 10 GB free (20 GB+ recommended for data retention) |
| LLM Endpoint | Optional OpenAI-compatible or local Ollama endpoint; required only for AI-generated features |
| Network | Ports 8100, 8101, 8501 (production) or 5173 (dev) must be available |

Verify prerequisites:

```bash
docker --version          # Docker version 24.0+
docker compose version    # Docker Compose v2
git --version             # git version 2.30+
```

---

## 2. Quick Start

```bash
git clone <repository-url>
cd NOC_IFC

# Create environment file from template
cp .env.example .env      # Edit with your configuration (see Section 4)

# Build and start all services
docker compose up --build -d

# Verify services are running
docker compose ps

# Test API health
curl http://localhost:8101/health
```

Once running, access the UI at `http://localhost:8501`. Log in as `admin` using the value configured in `DEFAULT_ADMIN_PASSWORD`.

---

## 3. Docker Services

### api — FastAPI REST + WebSocket

| Property | Value |
|----------|-------|
| Dockerfile | Project root (`./Dockerfile`) |
| Base image | `python:3.11-slim` |
| Command | `uvicorn src.api.main:app --host 0.0.0.0 --port 8101` |
| Port | `8101` |
| Volumes | `./data:/app/data` |
| Environment | `.env` file |
| WebSocket | `ws://localhost:8101/ws` |

### worker — Background Scheduler

| Property | Value |
|----------|-------|
| Dockerfile | Project root (`./Dockerfile`) |
| Base image | `python:3.11-slim` |
| Command | `python -u src/scheduler.py` |
| Port | None (internal only) |
| Volumes | `./data:/app/data` |
| Memory limit | 1.5 GB |
| Environment | `.env` file |

Runs all scheduled jobs: RSS feed fetch, crime data, hazard monitoring, cloud outage tracking, CISA KEV updates, internal risk assessments, unified brief generation, DB maintenance, ML retraining, and tiered alert escalation.

### webhook — SolarWinds Gateway

| Property | Value |
|----------|-------|
| Dockerfile | Project root (`./Dockerfile`) |
| Base image | `python:3.11-slim` |
| Command | `python -u src/webhook_listener.py` |
| Port | `8100` |
| Volumes | `./data:/app/data` |
| Environment | `.env` file |

Receives SolarWinds alerts at `POST http://localhost:8100/webhook/solarwinds`.

### web — Production Frontend (nginx)

| Property | Value |
|----------|-------|
| Dockerfile | `web/Dockerfile` (multi-stage: `node:22-alpine` build + `nginx:alpine` serve) |
| Port | `8501` → internal `5173` |
| Env | `VITE_API_URL=http://localhost:8101` |
| Depends on | `api` |
| Static build | No HMR; rebuild required for frontend changes |

### web-dev — Development Frontend (Vite, profile: dev)

| Property | Value |
|----------|-------|
| Image | `node:22-alpine` |
| Command | `sh ./dev-entrypoint.sh` |
| Port | `5173` |
| Env | `VITE_API_URL=http://api:8101` |
| Volumes | `./web:/app` and a persistent `node_modules` volume (hot reload via Vite HMR) |
| Profile | `dev` — activated via `docker compose --profile dev up` |

---

## 4. Environment Variables (.env)

Create `.env` from the template and configure as needed. `.env.example` and [the environment reference](reference/config/env_example.md) are the authoritative exhaustive variable list and source mapping; the table below is a selected deployment quick reference. `VITE_API_URL` is configured in Compose, not in the Python `.env` settings.

```bash
cp .env.example .env
```

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | `sqlite:////app/data/noc_fusion.db` | Shared SQLite database file; non-SQLite URLs are rejected |
| `DEMO_SEED_DATA` | No | `false` | Seed synthetic hardware/software assets; use only in disposable environments |
| `DEFAULT_ADMIN_PASSWORD` | First boot | `.env.example` contains a change-me placeholder; runtime default is empty | Creates the initial admin only when no users exist and the value is non-empty; replace the placeholder before startup |
| `DEFAULT_ADMIN_EMAIL` | Optional | (empty) | Trusted verified recovery/notification address for the bootstrap administrator; can initialize an existing email-less bootstrap admin at API/worker startup |
| `LOG_LEVEL` | No | `INFO` | Python log threshold |
| `RISK_ALERT_RECIPIENTS` | For alerts | (empty) | Comma-separated email addresses for risk alerts |
| `REMEDYFORCE_TICKET_EMAIL` | For RCA | (empty) | Email target for RCA ticket dispatch |
| `NOC_NOTIFY_EMAIL` | For after-hours | (empty) | NOC team notification email |
| `NOC_ONPAGE_EMAIL` | For after-hours | (empty) | NOC on-call paging email |
| `ITNETWORK_ONPAGE_EMAIL` | For after-hours | (empty) | IT Network on-call paging email |
| `CRIME_ALERT_SMS` | For crime alerts | (empty) | SMS gateway email for crime notifications |
| `CRIME_ALERT_EMAIL` | For crime alerts | (empty) | Email destination for crime notifications |
| `ELASTIC_URL` | Optional | (empty) | Elasticsearch endpoint reachable from API/worker containers; blank disables sync |
| `ELASTIC_API_KEY` | Optional | (empty) | Elasticsearch read-only API key |
| `ELASTIC_VERIFY_CERTS` | No | `true` | Verify Elasticsearch TLS certificates |
| `ELASTIC_CA_CERTS` | No | (empty) | Optional CA bundle path for Elasticsearch |
| `ELASTIC_REQUEST_TIMEOUT` | No | `15` | Elasticsearch request timeout in seconds |
| `ELASTIC_MAX_RESULTS` | No | `500` | Maximum results per Elastic query page |
| `WEBHOOK_HMAC_SECRET` | Optional | (empty) | Shared secret for signed SolarWinds requests |
| `WEBHOOK_SIGNATURE_HEADER` | No | `X-SolarWinds-Signature` | Webhook signature header |
| `WEBHOOK_TIMESTAMP_HEADER` | No | `X-SolarWinds-Timestamp` | Webhook timestamp header |
| `WEBHOOK_REPLAY_WINDOW_SECONDS` | No | `300` | Accepted webhook timestamp age |
| `WEBHOOK_MAX_BODY_BYTES` | No | `1048576` | Maximum webhook body size |
| `WEBSOCKET_MAX_MESSAGE_BYTES` | No | `65536` | Maximum WebSocket client message |
| `ALLOW_PRIVATE_LLM_ENDPOINTS` | No | `false` | Permit private LLM endpoint URLs |
| `CORS_ORIGINS` | No | localhost origins | Comma-separated allowed browser origins |
| `ALLOW_UNSIGNED_WEBHOOKS` | No | `false` | Controlled webhook migration exception |
| `PUBLIC_APP_URL` | No | `http://localhost:8501` | Registration link base URL |
| `REGISTRATION_INVITE_TTL_HOURS` | No | `72` | Registration invite lifetime |
| `BACKUP_ENCRYPTION_ACTIVE_KEY_ID` | For backups | `primary` | Key ID used for newly created encrypted full backups |
| `BACKUP_ENCRYPTION_KEYS` | For backups | (empty) | JSON map of key IDs to 32-byte hex keys; required to create, validate, or restore packages |
| `BACKUP_MAX_BYTES` | No | `10737418240` | Maximum encrypted backup/upload size in bytes (10 GiB default, 100 GiB maximum) |
| `RESCORE_ON_STARTUP` | No | `false` | Full article rescore during startup |

Create a random backup key with `python -c 'import secrets; print(secrets.token_hex(32))'`, then set `BACKUP_ENCRYPTION_KEYS` to a JSON object such as `{"primary":"<64-hex-character-key>"}`. Keep this secret outside the backup directory and deployment host; losing it makes the encrypted backups unreadable. Retain old key IDs in the JSON map through the lifetime of backups encrypted with them. Full encrypted packages are stored at `./data/backups`, on the shared persistent volume; copy/download them to off-host storage for disaster recovery. `.env` and environment-only credentials are never packaged.

**Example production `.env`:**

```bash
DATABASE_URL=sqlite:////app/data/noc_fusion.db
RISK_ALERT_RECIPIENTS=noc-manager@example.com,soc@example.com
REMEDYFORCE_TICKET_EMAIL=tickets@example.com
NOC_NOTIFY_EMAIL=noc-team@example.com
NOC_ONPAGE_EMAIL=noc-oncall@example.com
ITNETWORK_ONPAGE_EMAIL=network-oncall@example.com
CRIME_ALERT_SMS=gateway@sms-provider.com
DEFAULT_ADMIN_PASSWORD=Ch@ng3M3!nPr0d
```

---

## 5. Commands Reference

### Production Build and Run

```bash
docker compose up --build -d
```

### Development Mode (Hot Reload)

```bash
docker compose --profile dev up --build -d
```

### View Logs

```bash
docker compose logs -f api       # API + WebSocket logs
docker compose logs -f worker    # Scheduler logs
docker compose logs -f web       # Frontend (nginx, no HMR)
docker compose logs -f webhook   # Webhook listener logs
docker compose logs -f           # All services
```

### Restart Services

```bash
docker compose restart api                           # API only
docker compose restart worker                        # Worker only
docker compose restart                               # All services
```

### Rebuild a Single Service

```bash
docker compose up --build -d --force-recreate api   # API
docker compose up --build -d --force-recreate web    # Frontend
docker compose up --build -d --force-recreate worker # Worker
```

### Frontend Standalone Dev (Without Docker)

```bash
cd web
npm ci
npm run dev
```

### Service Status

```bash
docker compose ps               # List running services
docker compose stats            # Live resource usage
```

### Database Operations

```bash
# Shell into API container
docker compose exec api bash

# Migrations are checked automatically before backend services start.
docker compose restart api worker webhook
```

---

## 6. Production Considerations

### Database

- SQLite is the supported application database. API, worker, and webhook containers must share the configured database file.
- Startup checks the Alembic revision and applies pending migrations before the service accepts work. Back up the database before upgrades (see Section 7).
- Pre-Alembic application schemas are upgraded additively when they match the documented compatibility map. Unknown missing columns and invalid legacy data stop startup before the revision is recorded; see [Migration Compatibility](MIGRATION_COMPATIBILITY.md) for the tested boundary and recovery procedure.

### Reverse Proxy and TLS

Deploy nginx or similar reverse proxy in front of the application:

```nginx
server {
    listen 443 ssl http2;
    server_name noc.example.com;

    ssl_certificate     /etc/letsencrypt/live/noc.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/noc.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8501;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws {
        proxy_pass http://127.0.0.1:8101;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400;
    }

    location /api {
        proxy_pass http://127.0.0.1:8101;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name noc.example.com;
    return 301 https://$server_name$request_uri;
}
```

### Resource Limits

The worker service has a 1.5 GB memory limit by default. For production, consider adding limits to other services:

```yaml
services:
  api:
    deploy:
      resources:
        limits:
          memory: 2G
  worker:
    deploy:
      resources:
        limits:
          memory: 1.5G
```

### Logging and Monitoring

- Configure external log aggregation (ELK, Datadog, Splunk)
- Monitor container health via `docker compose ps` or Docker healthchecks
- Set up alerting on API `/health` endpoint
- Track database size growth over time

### Secrets Management

- Use Docker secrets or an external vault for sensitive values
- SMTP credentials and LLM API keys may be stored as ordinary fields in the live SQLite `SystemConfig` row; they are not field-level encrypted at rest.
- Encrypted full-backup packages protect the database snapshot, but do not include `.env` or environment-only secrets.
- Restrict access to the SQLite data volume and `.env`, and use host-level disk encryption or an external secret store where required by policy.

---

## 7. Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Network                           │
│                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │   api    │◄───│   web    │    │ webhook  │              │
│  │  :8101   │    │  :5173   │    │  :8100   │              │
│  └────┬─────┘    └──────────┘    └──────────┘              │
│       │                                                     │
│  ┌────┴─────┐         ┌──────────┐                         │
│  │  worker  │         │ web-dev  │ (dev profile only)      │
│  │  :???    │         │  :5173   │                         │
│  └──────────┘         └──────────┘                         │
└─────────────────────────────────────────────────────────────┘

External Access:
  localhost:8501  → web (production, nginx static)
  localhost:5173  → web-dev (development, Vite HMR)
  localhost:8101  → api (FastAPI + WebSocket)
  localhost:8100  → webhook (SolarWinds gateway)
  ws://localhost:8101/ws → WebSocket real-time updates
```

**SolarWinds Integration:**

```
SolarWinds → POST http://<host>:8100/webhook/solarwinds → webhook service → database
```

All containers communicate on the same Docker bridge network. Internal service-to-service communication uses container names (e.g., `http://api:8101`).

---

## 8. Security Notes

| Area | Current behavior | Production consideration |
|------|------------------|--------------------------|
| REST authentication | `authentication_middleware` protects `/api/v1/*` except the explicit login, registration/recovery, health, and readiness routes. Bearer tokens are preferred; query tokens remain for compatibility. | Configure the reverse proxy and access logs so session tokens are not recorded from legacy query-string clients. |
| Authorization | Route dependencies enforce page, tab, action, administrator, and site-type grants. The canonical permission catalog is `src/core/permissions.py`. | Keep role grants least-privilege and verify any custom roles after upgrades. |
| Administrative routes | Legacy `/admin/*` routes require the administrator role; newer user and application settings routes use their specific permissions. | Do not expose backend ports directly to untrusted networks. |
| CORS | `CORS_ORIGINS` is an explicit origin list; the default allows the local production and development frontends. | Set only the deployed frontend origin(s). |
| WebSocket | Requires a session token and AIOps page/Active Board access; sessions and permissions are revalidated, and site data is filtered. | Prefer TLS (`wss://`) through a reverse proxy and restrict direct access to port 8101. |
| SolarWinds webhook | HMAC and timestamp/replay checks are supported. Unsigned requests are rejected unless `ALLOW_UNSIGNED_WEBHOOKS=true`. | Configure a strong `WEBHOOK_HMAC_SECRET`; keep the unsigned exception disabled. |
| SMTP/LLM credentials | SMTP passwords and LLM keys may be stored in `SystemConfig`; the live SQLite columns are not field-level encrypted. Full backup packages encrypt the database snapshot; `.env` and environment secrets stay external. | Protect the SQLite volume and backups. Define secret rotation and external secret-management requirements for the customer environment. |
| Request limits | The webhook and WebSocket have configured size limits. There is no general API rate limiter; the database-upload endpoint currently reads its upload into memory. | Add route-level rate limits and bounded upload handling before exposing the service to broad or untrusted networks. |
| Transport | Compose publishes the API, webhook, and web ports; TLS termination is not built into the stack. | Terminate HTTPS at a trusted reverse proxy and apply firewall rules to limit source networks. |

Set `DEFAULT_ADMIN_PASSWORD` before first boot; there is no guaranteed hard-coded production password. Review `CORS_ORIGINS`, TLS, network exposure, credential handling, and backup protection as part of each deployment.

---

## 9. Troubleshooting

| Symptom | Likely Cause | Resolution |
|---------|-------------|-----------|
| Database migration failure | Unsupported schema state or invalid legacy data | Preserve the database, read the reported missing-column/duplicate-data details, and follow [Migration Compatibility](MIGRATION_COMPATIBILITY.md); do not edit `alembic_version` or drop columns |
| LLM timeout / errors | Wrong endpoint or model | Verify LLM endpoint URL and API key in Settings > AI & SMTP |
| WebSocket not connecting | API container issue or port conflict | Check `docker compose logs api` for startup errors |
| Emails not sending | SMTP misconfiguration | Verify SMTP settings in Settings > AI & SMTP |
| No articles / feeds | Scheduler not running or no sources | Check `docker compose logs worker`; add RSS sources in Settings |
| Scores all zero | Keywords not seeded | Check API/worker startup logs; conditional keyword seeding runs after migrations |
| Frontend blank screen | Build cache issue | `docker compose up --build -d --force-recreate web` |
| Webhook returns 500 | Invalid SolarWinds payload | Check payload format matches expected schema |
| Worker memory spike | Large feed batch | Increase memory limit or reduce `chunk_size` |
| Port conflict on 8101 | Another process using port | `lsof -i :8101` to identify and stop conflicting process |
| Required table/column missing | Migration failed or legacy schema is inconsistent | Back up the database, inspect startup migration logs, resolve the reported issue, and restart the backend |

**Log locations:**

```bash
# All service logs
docker compose logs api worker webhook web

# Last 100 lines
docker compose logs --tail=100 api

# Follow logs in real time
docker compose logs -f api worker
```

---

## Appendix: Upgrade Procedure

```bash
# 1. Create a manual encrypted full backup in Settings > Backup & Restore.
#    Download/copy it to protected off-host storage and verify the file exists.

# 2. Pull latest code
git pull origin <branch>

# 3. Rebuild and restart all services
docker compose up --build -d

# 4. Verify deployment
docker compose ps
curl http://localhost:8101/health
docker compose logs --tail=30 worker
```

The weekly encrypted full backup is scheduled for Sunday 00:00 `America/Chicago` and the latest three scheduled copies are retained. Manual snapshots are not automatically pruned. Restore is a maintenance-window operation; follow the staged offline procedure in [Maintenance](MAINTENANCE.md#restore-and-disaster-recovery). Settings JSON exports are partial migration tools, not a substitute for an encrypted full backup.

**Post-upgrade checklist:**

- Verify API health endpoint returns 200
- Check worker logs for scheduler job initialization
- Confirm WebSocket connects in browser (developer console)
- Test a SolarWinds webhook POST
- Verify frontend loads and login works
