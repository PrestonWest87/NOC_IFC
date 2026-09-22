# NOC Intelligence Fusion Center — Getting Started Guide

## Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Docker Engine | v20.10.0 | v24.0+ |
| Docker Compose | v2.0.0 | v2.20+ |
| RAM | 4 GB | 8 GB |
| Disk (SSD) | 10 GB | 15 GB |
| CPU Cores | 2 | 4 |
| OS | Linux (recommended), macOS, Windows WSL2 | Linux x86_64 |

---

## Quick Start (5 Minutes)

### 1. Clone and Configure

```bash
git clone <repository-url> noc-ifc
cd noc-ifc
cp .env.example .env
```

Edit `.env` and set at minimum:

```bash
DATABASE_URL=sqlite:////app/data/noc_fusion.db
```

### 2. Build and Launch

```bash
docker compose up --build -d
```

This starts 4 services:
- **`api`** — FastAPI backend on port 8101
- **`worker`** — Background scheduler for data ingestion
- **`webhook`** — Webhook gateway on port 8100
- **`web`** — React frontend exposed on port 8501 (container port 5173)

### 3. Access the Application

Open **http://localhost:8501** in your browser.

Set `DEFAULT_ADMIN_PASSWORD` in `.env` before first startup. The database creates the `admin` user only when no users exist and this value is non-empty. There is no guaranteed hard-coded default password and no automatic analyst-user seed in the current runtime.

### 4. Verify It's Running

```bash
# Check all containers are up
docker compose ps

# Check API health
curl http://localhost:8101/health

# Check worker logs (data ingestion should start immediately)
docker compose logs -f worker

# View frontend logs
docker compose logs -f web
```

---

## Development Setup

For hot-reload development:

```bash
docker compose --profile dev up --build -d
```

The `dev` profile starts a `web-dev` container with Vite's HMR (Hot Module Replacement) instead of the production nginx build. Frontend changes are picked up instantly via a volume mount.

### Standalone Frontend Development

```bash
cd web
npm install
npm run dev
```

This starts Vite dev server on port 5173 with proxy configuration for `/api` → `http://localhost:8101` and `/ws` → `ws://localhost:8101`.

---

## Environment Configuration

The checked-in `.env.example` is the complete environment template. The API, worker, and webhook load `.env` through Docker Compose. The frontend uses the `VITE_API_URL` value defined in `docker-compose.yml`; it is not read by the Python settings class.

### Required Variables

| Variable | Example | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:////app/data/noc_fusion.db` | Database connection string. Use `postgresql://user:pass@host:5432/db` for PostgreSQL. |

### Optional Variables

| Variable | Purpose | Required For |
|----------|---------|-------------|
| `CORS_ORIGINS` | Comma-separated browser origins | CORS allowlist |
| `RISK_ALERT_RECIPIENTS` | Comma-separated email list for risk alerts | Email risk notifications |
| `REMEDYFORCE_TICKET_EMAIL` | Primary ticket destination | Tiered alert escalation engine |
| `NOC_NOTIFY_EMAIL` | NOC notification email (after hours) | After-hours notifications |
| `NOC_ONPAGE_EMAIL` | On-page destination for NOC devices | Smart on-call paging |
| `ITNETWORK_ONPAGE_EMAIL` | On-page destination for IT/Network devices | Smart on-call paging |
| `ELASTIC_URL` | Elasticsearch connection URL | Elastic SIEM integration |
| `ELASTIC_API_KEY` | Elasticsearch API key | Elastic SIEM integration |
| `ELASTIC_VERIFY_CERTS` | `true` | Verify Elasticsearch TLS certificates |
| `ELASTIC_CA_CERTS` | Empty | Optional CA bundle path for Elasticsearch |
| `ELASTIC_REQUEST_TIMEOUT` | `15` | Elasticsearch request timeout in seconds |
| `ELASTIC_MAX_RESULTS` | `500` | Maximum results per Elastic query page |
| `DEMO_SEED_DATA` | `true` only for disposable demos | Synthetic asset seed data |
| `DEFAULT_ADMIN_PASSWORD` | Initial admin password | First boot when no users exist |
| `LOG_LEVEL` | `INFO` | Python log threshold |
| `CRIME_ALERT_SMS` | SMS gateway address | Crime notifications |
| `CRIME_ALERT_EMAIL` | Email address | Crime notifications |
| `WEBHOOK_HMAC_SECRET` | Shared signing secret | Signed SolarWinds webhooks |
| `WEBHOOK_SIGNATURE_HEADER` | `X-SolarWinds-Signature` | Webhook signature header name |
| `WEBHOOK_TIMESTAMP_HEADER` | `X-SolarWinds-Timestamp` | Webhook timestamp header name |
| `WEBHOOK_REPLAY_WINDOW_SECONDS` | `300` | Webhook replay protection window |
| `WEBHOOK_MAX_BODY_BYTES` | `1048576` | Maximum webhook request body |
| `WEBSOCKET_MAX_MESSAGE_BYTES` | `65536` | Maximum client WebSocket message |
| `ALLOW_PRIVATE_LLM_ENDPOINTS` | `false` | Permit private LLM endpoint URLs |
| `ALLOW_UNSIGNED_WEBHOOKS` | `false` | Controlled webhook migration exception |
| `PUBLIC_APP_URL` | `http://localhost:8501` | Registration link base URL |
| `REGISTRATION_INVITE_TTL_HOURS` | `72` | Registration invite lifetime |
| `RESCORE_ON_STARTUP` | `false` | Full article rescore during startup |

### SMTP Configuration

Configure SMTP and LLM settings in the Settings page (AI & SMTP tab) or directly in the database `system_config` table. These are application settings, not environment variables in the current runtime:

| Field | Example |
|-------|---------|
| SMTP Server | `smtp.office365.com` |
| SMTP Port | `587` |
| SMTP Username | `noc@aecc.com` |
| SMTP Password | (app password) |
| SMTP Sender | `noc@aecc.com` |
| SMTP Recipient | `team@aecc.com` |

### LLM Configuration

Configure AI in the Settings page (AI & SMTP tab):

| Field | Example |
|-------|---------|
| LLM Endpoint | `https://api.openai.com/v1` |
| LLM API Key | `sk-...` |
| LLM Model | `gpt-4o-mini` |
| Active | Toggle on |

---

## Docker Commands Reference

### Service Management

| Command | Description |
|---------|-------------|
| `docker compose up --build -d` | Build and start all services (production) |
| `docker compose --profile dev up --build -d` | Start with Vite HMR (development) |
| `docker compose down` | Stop all services |
| `docker compose restart api` | Restart API only |
| `docker compose restart worker` | Restart scheduler only |

### Logs

| Command | Description |
|---------|-------------|
| `docker compose logs -f api` | Follow API logs |
| `docker compose logs -f worker` | Follow scheduler logs |
| `docker compose logs -f webhook` | Follow webhook gateway logs |
| `docker compose logs -f web` | Follow frontend/nginx logs |
| `docker compose logs --tail=200` | View last 200 lines of all services |

### Rebuilds

| Command | Description |
|---------|-------------|
| `docker compose up --build -d api` | Rebuild API after backend code changes |
| `docker compose up --build -d --force-recreate web` | Rebuild frontend (production) after frontend changes |
| `docker compose restart web` | Refresh nginx DNS cache after API restart |

### Database

| Command | Description |
|---------|-------------|
| `docker compose down && rm data/noc_fusion.db && docker compose up --build -d` | Full database reset (re-seeds on startup) |
| `docker compose exec api python -c "from src.core.db import init_db; init_db()"` | Re-seed database without restart |

---

## Webhook Configuration

Configure your ITSM monitoring tool to send alerts:

```
POST http://<your-host>:8100/webhook/solarwinds
Content-Type: application/json
```

The webhook listener accepts SolarWinds-style JSON payloads, normalizes them, and persists alerts for AIOps correlation. Supported field mappings are documented in the Webhook section of ARCHITECTURE.md.

### Testing the Webhook

```bash
curl -X POST http://localhost:8100/webhook/solarwinds \
  -H "Content-Type: application/json" \
  -d '{
    "Node_Details": {
      "NodeName": "RTR-AECCORP-01",
      "IP_Address": "10.0.0.1"
    },
    "severity": "CRITICAL",
    "Alert_Level": "P1",
    "AlertName": "Node Down"
  }'
```

---

## Troubleshooting

### Container Won't Start

```bash
# Check container logs
docker compose logs api

# Check for port conflicts
lsof -i :8101
lsof -i :5173

# Verify .env exists
ls -la .env
```

### No Data Appearing

```bash
# Check scheduler is running
docker compose logs -f worker

# Verify feeds are active (check Settings > RSS Sources)
# The boot sequence runs all jobs immediately on startup

# Check database exists
ls -la data/noc_fusion.db
```

### Database Errors

```bash
# Reset database
docker compose down
rm -f data/noc_fusion.db
docker compose up --build -d

# Or re-seed without data loss
docker compose exec api python -c "
from src.core.db import init_db
init_db()
print('Database re-seeded successfully')
"
```

### WebSocket Not Connecting

```bash
# Verify API is running
curl http://localhost:8101/health

# Check for proxy configuration in nginx/vite
# Production: nginx.conf proxies /ws to http://api:8101
# Dev: vite.config.ts proxies /ws to ws://localhost:8101
```

### Frontend Shows Blank Screen

```bash
# Check browser console for errors
# For production container, rebuild after frontend changes:
docker compose up --build -d --force-recreate web

# For dev profile, the volume mount picks up changes automatically
```

---

## Security Notes

1. **Change default credentials immediately** in production:
   - Login as admin, navigate to Settings > Users & Roles
   - Change the admin password
   - Create individual user accounts

2. **Network isolation**: The webhook port (8100) and API port (8101) should not be exposed to the public internet. Only port 8501 (production frontend) should be publicly accessible.

3. **Secrets management**: Session tokens are database-backed, while integration settings are supplied through the supported environment variables and Settings UI. Keep `.env` out of version control and use a secret manager in production.

4. **HTTPS**: Use a reverse proxy (nginx, Caddy, Traefik) for TLS termination in production.

5. **Database**: Default SQLite is suitable for evaluation. For production, use PostgreSQL with proper backup procedures.
