# NOC Intelligence Fusion Center — Enterprise Deployment Guide

## 1. Prerequisites

| Requirement | Details |
|-------------|---------|
| Docker Engine | v24.0+ with Docker Compose v2 (`docker compose`) |
| Git | v2.30+ for repository cloning |
| RAM | Minimum 2 GB available (4 GB+ recommended for production) |
| Disk | Minimum 10 GB free (20 GB+ recommended for data retention) |
| LLM Endpoint | Optional OpenAI-compatible or local Ollama endpoint; required only for AI-generated features |
| Network | C# dev-c host ports 8100, 8101, 8501, and optionally 5173 must be available |

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

# Prepare a fresh dev-c SQLite database (requires DEFAULT_ADMIN_PASSWORD in .env)
uv sync --project tools/offline-python --locked --python 3.11
uv run --project tools/offline-python --locked python tools/offline-python/prepare_dev_c_database.py

# Build and start the C# services
DEV_C_UID="$(id -u)" DEV_C_GID="$(id -g)" docker compose up --build -d

# Verify services are running
docker compose ps

# Test API readiness
curl http://localhost:8101/ready
```

On `dev-c`, access the UI at `http://localhost:8501` locally or `http://<server-ip>:8501` from the LAN. The default tracked `compose.yaml` selects the C# stack (`noc-ifc-dev-c`) and isolated `./data-dev-c` storage. Log in as `admin` using the local value configured in `DEFAULT_ADMIN_PASSWORD`. The ignored `docker-compose.yml` is preserved as a legacy Python backup.

---

## 3. Docker Services

### Current C# dev-c services

The default `compose.yaml` includes `compose.dev-c.yaml` and builds four separate runtime images. The stack uses Docker's built-in `bridge`; the web proxy reaches the API through a host-gateway alias, while the database bind mount is shared only by the three backend processes.

| Service | Runtime target | Host → container | Storage |
|---------|----------------|------------------|---------|
| `api` | `deploy/Dockerfile.backend` target `api` (.NET 10) | `8101` → `8101` (all host interfaces) | `./data-dev-c:/app/data` |
| `worker` | `deploy/Dockerfile.backend` target `worker` (.NET 10) | Internal only | `./data-dev-c:/app/data` |
| `webhook` | `deploy/Dockerfile.backend` target `webhook` (.NET 10) | `8100` → `8100` (all host interfaces) | `./data-dev-c:/app/data` |
| `web` | `web/Dockerfile` (React + Nginx) | `8501` → `5173` (all host interfaces) | None |
| `web-dev` (`dev` profile) | `node:22-alpine` with Vite HMR | `5173` → `5173` (all host interfaces) | Source mount and npm volume |

API readiness is `http://localhost:8101/ready`; webhook liveness is `http://localhost:8100/health`. The API, Worker, and Webhook do not run schema migrations on startup: prepare/migrate the SQLite database with `tools/offline-python/` first. `data-dev-c` is ignored by Git and Docker build contexts.

### Legacy Python backup services

The remaining tables in this section describe the ignored local `docker-compose.yml` backup. To run it intentionally, pass `-f docker-compose.yml`; do not use its ports or commands as the `dev-c` defaults.

#### api — FastAPI REST + WebSocket

| Property | Value |
|----------|-------|
| Dockerfile | Project root (`./Dockerfile`) |
| Base image | `python:3.11-slim` |
| Command | `uvicorn src.api.main:app --host 0.0.0.0 --port 8101` |
| Port | host `8102` → container `8101` |
| Volumes | `./data-dev:/app/data` |
| Environment | `.env` file |
| WebSocket | `ws://localhost:8102/ws` |

#### worker — Background Scheduler

| Property | Value |
|----------|-------|
| Dockerfile | Project root (`./Dockerfile`) |
| Base image | `python:3.11-slim` |
| Command | `python -u src/scheduler.py` |
| Port | None (internal only) |
| Volumes | `./data-dev:/app/data` |
| Memory limit | 1.5 GB |
| Environment | `.env` file |

Runs all 21 registry-managed background jobs. The complete schedules, startup-run policy, and non-disableable jobs are maintained in [Scheduler and Background Jobs](SCHEDULER.md).

#### webhook — SolarWinds Gateway

| Property | Value |
|----------|-------|
| Dockerfile | Project root (`./Dockerfile`) |
| Base image | `python:3.11-slim` |
| Command | `python -u src/webhook_listener.py` |
| Port | host `8099` → container `8100` |
| Volumes | `./data-dev:/app/data` |
| Environment | `.env` file |

Receives SolarWinds alerts at `POST http://localhost:8099/webhook/solarwinds`.

#### web — Production Frontend (nginx)

| Property | Value |
|----------|-------|
| Dockerfile | `web/Dockerfile` (multi-stage: `node:22-alpine` build + `nginx:alpine` serve) |
| Port | host `8503` → internal `5173` |
| Env | Compose declares `VITE_API_URL=http://noc-ifc-dev-api:8102`; the static bundle does not consume it, and Nginx uses this host-gateway alias |
| Depends on | `api` healthy |
| Static build | No HMR; rebuild required for frontend changes |

#### web-dev — Development Frontend (Vite, profile: dev)

| Property | Value |
|----------|-------|
| Image | `node:22-alpine` |
| Command | `sh ./dev-entrypoint.sh` |
| Port | host `5174` → container `5173` |
| Env | `VITE_API_URL=http://noc-ifc-dev-api:8102` for the running Vite development proxy |
| Volumes | `./web:/app` and a persistent `node_modules` volume (hot reload via Vite HMR) |
| Profile | `dev` — adds the Vite service; production `web` remains running. Use host port 5174 for HMR. |

---

## 4. Environment Variables (.env)

Create `.env` from the template and configure as needed. `.env.example` and [the environment reference](reference/config/env_example.md) are the authoritative exhaustive variable list and source mapping; the table below is a selected deployment quick reference. Production web traffic is same-origin through Nginx; the C# dev-c and legacy Python Vite services each receive their own `VITE_API_URL` in Compose.

```bash
cp .env.example .env
```

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | No | `sqlite:////app/data/noc_fusion.db` | Optional path override for the shared SQLite database file; non-SQLite URLs are rejected |
| `DEMO_SEED_DATA` | No | `false` | Seed synthetic hardware/software assets; use only in disposable environments |
| `DEFAULT_ADMIN_PASSWORD` | First boot | `.env.example` contains a change-me placeholder; runtime default is empty | Creates the initial admin only when no users exist and the value is non-empty; replace the placeholder before startup |
| `DEFAULT_ADMIN_EMAIL` | Optional | (empty) | Trusted verified recovery/notification address for the bootstrap administrator; can initialize an existing email-less bootstrap admin at API/worker startup |
| `LOG_LEVEL` | No | `INFO` | Legacy Python backup log threshold |
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
| `ALLOW_PRIVATE_LLM_ENDPOINTS` | No | `false` | Permit private targets for generic OpenAI-compatible connection tests; selected Ollama/vLLM providers can use validated local endpoints |
| `CORS_ORIGINS` | No | localhost origins | Comma-separated allowed browser origins |
| `ALLOW_UNSIGNED_WEBHOOKS` | No | `false` | Controlled webhook migration exception |
| `PUBLIC_APP_URL` | No | `http://localhost:8501` | Registration link base URL for the C# default stack |
| `NWS_API_USER_AGENT` | No | `NOC-IFC/2.0 (https://test.weasts.net)` | Identifying User-Agent for centralized NWS API requests; set the deployed public URL, and `DEFAULT_ADMIN_EMAIL` is appended as contact when configured |
| `REGISTRATION_INVITE_TTL_HOURS` | No | `72` | Registration invite lifetime |
| `BACKUP_ENCRYPTION_ACTIVE_KEY_ID` | For backups | `primary` | Key ID used for newly created encrypted full backups |
| `BACKUP_ENCRYPTION_KEYS` | For backups | (empty) | JSON map of key IDs to 32-byte hex keys; required to create, validate, or restore packages |
| `BACKUP_MAX_BYTES` | No | `10737418240` | Maximum encrypted backup/upload size in bytes (10 GiB default, 100 GiB maximum) |
| `RESCORE_ON_STARTUP` | No | `false` | Full article rescore during startup |

The notification-destination and Elastic variables above remain environment fallbacks. Their editable database overrides are available in **Settings > Application Settings > Notification destinations and Elastic integration** and are shared dynamically by the API and worker. Blank optional destinations disable them; reset removes the override and uses the environment value. Elastic API keys are never returned by the settings API. Local AI providers are selected in **Settings > AI & SMTP**; use endpoints reachable from the API container (for example, a Docker service name or the host gateway).

Create a random backup key with `python -c 'import secrets; print(secrets.token_hex(32))'`, then set `BACKUP_ENCRYPTION_KEYS` to a JSON object such as `{"primary":"<64-hex-character-key>"}`. Keep this secret outside the backup directory and deployment host; losing it makes the encrypted backups unreadable. Retain old key IDs in the JSON map through the lifetime of backups encrypted with them. Full encrypted packages for the default C# dev-c project are stored at `./data-dev-c/backups`; the legacy Python backup uses `./data-dev/backups`. Copy/download packages to off-host storage for disaster recovery. `.env` and environment-only credentials are never packaged.

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

### C# dev-c Build and Run

```bash
docker compose up --build -d
```

### C# Development Mode (Vite HMR)

```bash
DEV_C_UID="$(id -u)" DEV_C_GID="$(id -g)" docker compose --profile dev up --build -d
```

The optional `web-dev` container is available on host port 5173; the static production `web` remains on 8501.

### Legacy Python Backup

```bash
docker compose -p noc-ifc-dev --profile dev -f docker-compose.yml up --build -d
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
# Shell into the C# API container
docker compose exec api sh

# C# backends require the host-side migration/bootstrap to reach head first.
docker compose restart api worker webhook
```

---

## 6. Production Considerations

### Database

- SQLite is the supported application database. API, worker, and webhook containers must share the configured database file.
- C# API, Worker, and Webhook require Alembic head `20261125_0025` and do not migrate at startup. Run the pinned host-side migration/bootstrap before starting them, and take a backup before upgrading. The legacy Python backup applies migrations during startup.
- Pre-Alembic application schemas are upgraded additively when they match the documented compatibility map. Unknown missing columns and invalid legacy data stop startup before the revision is recorded; see [Migration Compatibility](MIGRATION_COMPATIBILITY.md) for the tested boundary and recovery procedure.

### Reverse Proxy and TLS

For the C# stack, web port 8501 is published on host interfaces for this dev environment. For protected deployments, place nginx or a similar trusted reverse proxy in front of it; the bundled Nginx already proxies `/api/` and `/ws` to the API:

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
        proxy_pass http://127.0.0.1:8501/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400;
    }

    location /api {
        proxy_pass http://127.0.0.1:8501/api;
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

The legacy Python backup uses the older `8503` web and `8102` API ports; it is not the default Compose stack.

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
- SMTP credentials, Gmail OAuth client secrets/refresh tokens, LLM API keys, and Elastic API keys may be stored as ordinary fields in the live SQLite `SystemConfig` row; they are not field-level encrypted at rest. The settings APIs do not return stored secrets. Migration `20261112_0014` clears the retired Gmail App Password field.
- Encrypted full-backup packages protect the database snapshot, but do not include `.env` or environment-only secrets.
- Restrict access to the SQLite data volume and `.env`, and use host-level disk encryption or an external secret store where required by policy.

---

## 7. Network Architecture

### C# dev-c default

Browser traffic enters the Nginx frontend on localhost port 8501. Nginx proxies `/api/` and `/ws` through the Docker host-gateway alias to API port 8101. SolarWinds requests target localhost port 8100; API, Worker, and Webhook share `./data-dev-c`. Optional Vite HMR uses localhost port 5173.

### Legacy Python backup

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Network                           │
│                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │   api    │◄───│   web    │    │ webhook  │              │
│  │  :8102   │    │  :5173   │    │  :8100   │              │
│  └────┬─────┘    └──────────┘    └──────────┘              │
│       │                                                     │
│  ┌────┴─────┐         ┌──────────┐                         │
│  │  worker  │         │          │                         │
│  │  :???    │         │  :5173   │                         │
│  └──────────┘         └──────────┘                         │
└─────────────────────────────────────────────────────────────┘

External Access (legacy Python backup):
  localhost:8503 → web (production, nginx static)
  localhost:5174 → web-dev (development, Vite HMR)
  localhost:8102 → api (FastAPI + WebSocket)
  localhost:8099 → webhook (SolarWinds gateway)
  ws://localhost:8102/ws → WebSocket real-time updates
```

**SolarWinds Integration:**

```
SolarWinds → POST http://<host>:8099/webhook/solarwinds → legacy Python webhook → database
C# SolarWinds → POST http://localhost:8100/webhook/solarwinds → C# webhook → `data-dev-c`
```

All default C# containers attach to Docker's built-in bridge network without allocating another subnet. The web container reaches the API through the `noc-ifc-dev-c-api` host-gateway alias; API, Worker, and Webhook share SQLite through `./data-dev-c`. The ignored Python backup uses separate host ports and `./data-dev`.

---

## 8. Security Notes

| Area | Current behavior | Production consideration |
|------|------------------|--------------------------|
| REST authentication | `authentication_middleware` protects `/api/v1/*` except the explicit login, registration/recovery, health, and readiness routes. Bearer tokens are preferred; query tokens remain for compatibility. | Configure the reverse proxy and access logs so session tokens are not recorded from legacy query-string clients. |
| Authorization | Backend authorization enforces page, tab, action, administrator, and site-type grants. The shared catalog is `contracts/permission_catalog.json`; Python and C# adapters consume it. | Keep role grants least-privilege and verify any custom roles after upgrades. |
| Administrative routes | Legacy `/admin/*` routes require the administrator role; newer user and application settings routes use their specific permissions. | Do not expose backend ports directly to untrusted networks. |
| CORS | `CORS_ORIGINS` is an explicit origin list; the default allows the local production and development frontends. | Set only the deployed frontend origin(s). |
| WebSocket | Requires a session token and AIOps page/Active Board access; sessions and permissions are revalidated, and site data is filtered. | Prefer TLS (`wss://`) through a reverse proxy and restrict direct access to host port 8101. |
| SolarWinds webhook | HMAC and timestamp/replay checks are supported. Unsigned requests are rejected unless `ALLOW_UNSIGNED_WEBHOOKS=true`. | Configure a strong `WEBHOOK_HMAC_SECRET`; keep the unsigned exception disabled. |
| SMTP/LLM/Elastic credentials | SMTP passwords and LLM/Elastic API keys may be stored in `SystemConfig`; the live SQLite columns are not field-level encrypted. Full backup packages encrypt the database snapshot; `.env` and environment secrets stay external. | Protect the SQLite volume and backups. Define secret rotation and external secret-management requirements for the customer environment. |
| Request limits | The webhook and WebSocket have configured size limits. There is no general API rate limiter; the database-upload endpoint currently reads its upload into memory. | Add route-level rate limits and bounded upload handling before exposing the service to broad or untrusted networks. |
| Transport | The C# dev Compose publishes main-compatible API/webhook/web ports on all host interfaces; TLS termination is not built in. | Restrict these development ports to trusted LAN clients with host firewall rules; terminate HTTPS before broader exposure. |
| Frontend source-IP rule | `web/nginx.conf` contains `allow 10.0.0.0/8` for workspace requests but no `deny all`; this is not an allowlist and does not block unmatched client addresses. | Enforce the intended source-network restriction at the host firewall or trusted upstream proxy. |

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
| Port conflict on 8101 | Another process using the C# API port | `lsof -i :8101` to identify the process; the Python backup uses 8102 |
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
