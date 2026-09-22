# NOC Intelligence Fusion Center — Enterprise Deployment Guide

## 1. Prerequisites

| Requirement | Details |
|-------------|---------|
| Docker Engine | v24.0+ with Docker Compose v2 (`docker compose`) |
| Git | v2.30+ for repository cloning |
| RAM | Minimum 2 GB available (4 GB+ recommended for production) |
| Disk | Minimum 10 GB free (20 GB+ recommended for data retention) |
| LLM Endpoint | OpenAI API key or local Ollama instance |
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
| Dockerfile | `web/Dockerfile` (multi-stage: `node:20-alpine` build + `nginx:alpine` serve) |
| Port | `8501` → internal `5173` |
| Env | `VITE_API_URL=http://localhost:8101` |
| Depends on | `api` |
| Static build | No HMR; rebuild required for frontend changes |

### web-dev — Development Frontend (Vite, profile: dev)

| Property | Value |
|----------|-------|
| Image | `node:20-alpine` |
| Command | `sh -c "npm ci && npm run dev -- --host 0.0.0.0"` |
| Port | `5173` |
| Env | `VITE_API_URL=http://api:8101` |
| Volumes | `./web:/app` (hot reload via Vite HMR) |
| Profile | `dev` — activated via `docker compose --profile dev up` |

---

## 4. Environment Variables (.env)

Create `.env` from the template and configure as needed:

```bash
cp .env.example .env
```

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | `sqlite:////app/data/noc_fusion.db` | SQLite (default) or PostgreSQL connection string |
| `DEMO_SEED_DATA` | No | `false` | Seed synthetic hardware/software assets; use only in disposable environments |
| `DEFAULT_ADMIN_PASSWORD` | First boot | (empty) | Initial admin password when no users exist |
| `LOG_LEVEL` | No | `INFO` | Python log threshold |
| `RISK_ALERT_RECIPIENTS` | For alerts | (empty) | Comma-separated email addresses for risk alerts |
| `REMEDYFORCE_TICKET_EMAIL` | For RCA | (empty) | Email target for RCA ticket dispatch |
| `NOC_NOTIFY_EMAIL` | For after-hours | (empty) | NOC team notification email |
| `NOC_ONPAGE_EMAIL` | For after-hours | (empty) | NOC on-call paging email |
| `ITNETWORK_ONPAGE_EMAIL` | For after-hours | (empty) | IT Network on-call paging email |
| `CRIME_ALERT_SMS` | For crime alerts | (empty) | SMS gateway email for crime notifications |
| `CRIME_ALERT_EMAIL` | For crime alerts | (empty) | Email destination for crime notifications |
| `ELASTIC_URL` | Optional | `https://localhost:9200` | Elasticsearch endpoint |
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
| `RESCORE_ON_STARTUP` | No | `false` | Full article rescore during startup |

**Example production `.env`:**

```bash
DATABASE_URL=postgresql://noc_user:secure_password@postgres:5432/noc_fusion
RISK_ALERT_RECIPIENTS=noc-manager@example.com,soc@example.com
REMEDYFORCE_TICKET_EMAIL=tickets@example.com
NOC_NOTIFY_EMAIL=noc-team@example.com
NOC_ONPAGE_EMAIL=noc-oncall@example.com
ITNETWORK_ONPAGE_EMAIL=network-oncall@example.com
CRIME_ALERT_SMS=gateway@sms-provider.com
DEFAULT_ADMIN_PASSWORD=Ch@ng3M3!nPr0d
```

**PostgreSQL URL format:**

```
postgresql://username:password@hostname:5432/database_name
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

# Reinitialize database (caution: destructive)
docker compose exec api python -c "from src.core.db import init_db; init_db()"
```

---

## 6. Production Considerations

### Database

- **Use PostgreSQL** instead of SQLite for multi-instance or high-concurrency deployments
- SQLite uses `NullPool` to avoid `QueuePool` contention — acceptable for single-instance only
- Configure automated backups (see Section 7)

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
- SMTP credentials are stored in the `SystemConfig` database table (encrypted at rest)
- LLM API keys are stored in environment variables and `SystemConfig`

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

| Area | Status | Notes |
|------|--------|-------|
| Authentication | Token-based per endpoint | No global auth middleware |
| Admin endpoints | Unprotected | Assumed internal network access only |
| RCA dispatch | Permission-gated | Requires `Action: Dispatch RCA Tickets` |
| CORS | Permissive | Allows all origins by default; restrict in `main.py` for production |
| SMTP credentials | Database-stored | `SystemConfig` table, not in env vars |
| API keys | Env vars + DB | LLM keys in `.env` and `SystemConfig` |
| Initial password | `DEFAULT_ADMIN_PASSWORD` | Set before first boot; never rely on a hard-coded password |
| WebSocket | No auth | Connects without authentication |

**Recommended hardening:**

1. Restrict CORS `allow_origins` in `src/api/main.py` to your domain
2. Add HMAC signature verification to the webhook endpoint
3. Implement API rate limiting via middleware
4. Use firewall rules to limit port access by source IP
5. Enable HTTPS via reverse proxy — never expose services on plain HTTP

---

## 9. Troubleshooting

| Symptom | Likely Cause | Resolution |
|---------|-------------|-----------|
| DB pool exhaustion | SQLite `QueuePool` contention | Already mitigated with `NullPool`; switch to PostgreSQL for high concurrency |
| LLM timeout / errors | Wrong endpoint or model | Verify LLM endpoint URL and API key in Settings > AI & SMTP |
| WebSocket not connecting | API container issue or port conflict | Check `docker compose logs api` for startup errors |
| Emails not sending | SMTP misconfiguration | Verify SMTP settings in Settings > AI & SMTP |
| No articles / feeds | Scheduler not running or no sources | Check `docker compose logs worker`; add RSS sources in Settings |
| Scores all zero | Keywords not seeded | Run `init_db()` or rebuild API container (keywords seed on startup) |
| Frontend blank screen | Build cache issue | `docker compose up --build -d --force-recreate web` |
| Webhook returns 500 | Invalid SolarWinds payload | Check payload format matches expected schema |
| Worker memory spike | Large feed batch | Increase memory limit or reduce `chunk_size` |
| Port conflict on 8101 | Another process using port | `lsof -i :8101` to identify and stop conflicting process |
| `init_db()` missing tables | Schema migration needed | Run `docker compose exec api python -c "from src.core.db import init_db; init_db()"` |

**Log locations:**

```bash
# All service logs
docker compose logs api | worker | webhook | web

# Last 100 lines
docker compose logs --tail=100 api

# Follow logs in real time
docker compose logs -f api worker
```

---

## Appendix: Upgrade Procedure

```bash
# 1. Backup database
docker compose exec api python -c "
from src.services import export_backup
export_backup('/app/data/pre-upgrade-backup.json')
"

# 2. Pull latest code
git pull origin <branch>

# 3. Rebuild and restart all services
docker compose up --build -d

# 4. Verify deployment
docker compose ps
curl http://localhost:8101/health
docker compose logs --tail=30 worker
```

**Post-upgrade checklist:**

- Verify API health endpoint returns 200
- Check worker logs for scheduler job initialization
- Confirm WebSocket connects in browser (developer console)
- Test a SolarWinds webhook POST
- Verify frontend loads and login works
