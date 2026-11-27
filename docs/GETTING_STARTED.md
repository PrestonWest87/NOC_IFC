# NOC Intelligence Fusion Center — Getting Started Guide

On `dev-c`, the tracked `compose.yaml` starts the C# backend by default and includes `compose.dev-c.yaml`. The ignored local `docker-compose.yml` remains the Python backup.

## Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Docker Engine | v24.0+ | Latest supported release |
| Docker Compose | v2.20+ | Latest supported release |
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

Edit `.env` and replace the `DEFAULT_ADMIN_PASSWORD` placeholder before continuing. The database preparation step creates the initial administrator.

### 2. Build and Launch

```bash
uv sync --project tools/offline-python --locked --python 3.11
uv run --project tools/offline-python --locked python tools/offline-python/prepare_dev_c_database.py
DEV_C_UID="$(id -u)" DEV_C_GID="$(id -g)" \
docker compose up --build -d
```

The setup command creates only a fresh `./data-dev-c` database and refuses to overwrite an existing one. The default Compose project is `noc-ifc-dev-c`:
- **`api`** — C# REST/WebSocket backend on host port 8101 (container port 8101)
- **`worker`** — C# background scheduler
- **`webhook`** — C# SolarWinds gateway on host port 8100 (container port 8100)
- **`web`** — React frontend exposed on host port 8501 (container port 5173)

### 3. Access the Application

Open **http://localhost:8501** locally or **http://<server-ip>:8501** from the LAN.

`DEFAULT_ADMIN_EMAIL` is optional; it bootstraps a verified recovery/reviewer address. If the bootstrap admin already exists without a verified email, configuring this value and restarting the API or worker will attach and verify it; a matching pending initial recovery-email request will be completed. The database creates the `admin` user only when no users exist and the password value is non-empty. There is no guaranteed hard-coded default password.

### 4. Verify It's Running

```bash
# Check all containers are up
docker compose ps

# Check API readiness
curl http://localhost:8101/ready

# Check worker logs (data ingestion should start immediately)
docker compose logs -f worker

# View frontend logs
docker compose logs -f web
```

---

## Development Setup

For containerized Vite hot reload alongside the production web service:

```bash
DEV_C_UID="$(id -u)" DEV_C_GID="$(id -g)" docker compose --profile dev up --build -d
```

Open `http://localhost:5173`; the production `web` service remains available on host port 8501.

### Standalone Frontend Development

```bash
cd web
npm ci
npm run dev
```

This starts Vite on port 5173 with `/api` and `/ws` proxied to the C# API at `http://localhost:8101`.

---

## Environment Configuration

The checked-in `.env.example` is the complete environment template, and [the environment reference](reference/config/env_example.md) maps each variable to its reader and purpose. The API, worker, and webhook load `.env` through Docker Compose. The `web-dev` Vite server uses the Compose `VITE_API_URL` value for its development proxy; production serves a static bundle and proxies same-origin `/api/` and `/ws` requests through Nginx. The following optional list is a quick selection, not an exhaustive inventory.

### Database Variable

| Variable | Example | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:////app/data/noc_fusion.db` | Optional override for the default shared SQLite database file used by the API, worker, and webhook. |

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
| `DEFAULT_ADMIN_EMAIL` | Optional trusted bootstrap email for the administrator | Recovery and account-review notifications; can initialize an existing email-less bootstrap admin at startup |
| `LOG_LEVEL` | `INFO` | Python log threshold |
| `BACKUP_ENCRYPTION_ACTIVE_KEY_ID` | `primary` | Active key ID for full encrypted database backups; set with `BACKUP_ENCRYPTION_KEYS` to enable backups |
| `BACKUP_ENCRYPTION_KEYS` | Empty | JSON key-ID map of 32-byte hex encryption keys; keep outside the repository and retain old keys until matching backups expire |
| `BACKUP_MAX_BYTES` | `10737418240` | Maximum encrypted full-backup and restore-upload size in bytes |
| `CRIME_ALERT_SMS` | SMS gateway address | Crime notifications |
| `CRIME_ALERT_EMAIL` | Email address | Crime notifications |
| `WEBHOOK_HMAC_SECRET` | Shared signing secret | Signed SolarWinds webhooks |
| `WEBHOOK_SIGNATURE_HEADER` | `X-SolarWinds-Signature` | Webhook signature header name |
| `WEBHOOK_TIMESTAMP_HEADER` | `X-SolarWinds-Timestamp` | Webhook timestamp header name |
| `WEBHOOK_REPLAY_WINDOW_SECONDS` | `300` | Webhook replay protection window |
| `WEBHOOK_MAX_BODY_BYTES` | `1048576` | Maximum webhook request body |
| `WEBSOCKET_MAX_MESSAGE_BYTES` | `65536` | Maximum client WebSocket message |
| `ALLOW_PRIVATE_LLM_ENDPOINTS` | `false` | Permit private LLM targets for generic OpenAI-compatible tests; explicit Ollama/vLLM provider selections support validated local endpoints |
| `ALLOW_UNSIGNED_WEBHOOKS` | `false` | Controlled webhook migration exception |
| `PUBLIC_APP_URL` | `http://localhost:8501` | Registration link base URL |
| `REGISTRATION_INVITE_TTL_HOURS` | `72` | Registration invite lifetime |
| `RESCORE_ON_STARTUP` | `false` | Full article rescore during startup |

### SMTP Configuration

Configure SMTP and LLM settings in the Settings page (AI & SMTP tab). Choose an OpenAI-compatible, Ollama OpenAI-compatible, Ollama native, or vLLM provider. The connection test uses the selected protocol. Local model URLs must be reachable from the API container; use the Docker service name or host gateway instead of container-local `localhost`.

The SMTP Broadcast panel stores the existing relay and a Gmail/Google Workspace profile side by side. Choose the active sender, save, and send a test email. Gmail uses `smtp.gmail.com:587` with STARTTLS and OAuth 2.0 XOAUTH2; no account password or App Password is used. The existing SMTP profile remains available for switching back.

### Gmail OAuth Setup

1. In Google Cloud Console, configure the OAuth consent screen and create a **Web application** OAuth client. Add `https://developers.google.com/oauthplayground` as an authorized redirect URI. For Workspace, use an internal app where possible and ask the Workspace administrator to trust the client and allow the Gmail scope if policy requires it.
2. To obtain a refresh token, open the [Google OAuth 2.0 Playground](https://developers.google.com/oauthplayground/), enable **Use your own OAuth credentials**, and enter the OAuth client ID/secret. Add the scope `https://mail.google.com/`, request offline access, authorize the sending account, exchange the authorization code, and copy the returned refresh token. The OAuth client must allow the Playground redirect URI `https://developers.google.com/oauthplayground`.
3. In Settings > AI & SMTP, enter the Gmail account address, OAuth client ID, client secret, and refresh token. Set the optional From address, enable Gmail, select it as the active sender, save, and send a test email.

The client secret and refresh token are write-only in IFC settings. The API exchanges the refresh token for a short-lived access token when it sends mail. If Google or Workspace revokes the grant, generate a new refresh token and replace it in Settings.

For long-term use, configure the OAuth consent screen for the intended audience. Google OAuth apps left in External/Testing status can receive refresh tokens that expire after seven days for Gmail scopes; Workspace internal apps or properly published/verified apps avoid relying on a temporary test grant.

Configure alert destinations and Elastic settings in Settings > Application Settings > Notification destinations and Elastic integration. These values are stored in the shared `SystemConfig` row and apply to the API and worker without a restart. The environment variables listed above remain supported as defaults until a database override is saved; “Reset to environment” removes overrides. The Elastic API key is write-only in the UI. SMTP and LLM settings remain application settings in `SystemConfig`:

| Field | Example |
|-------|---------|
| SMTP Server | `smtp.office365.com` |
| SMTP Port | `587` |
| SMTP Username | `noc@aecc.com` |
| SMTP Password | (existing relay credential, if required; Gmail uses OAuth instead) |
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
| `uv run --project tools/offline-python --locked python tools/offline-python/prepare_dev_c_database.py` | Create and seed a fresh `data-dev-c` database; refuses to overwrite existing SQLite files and requires `DEFAULT_ADMIN_PASSWORD` |
| `DATABASE_URL="sqlite:////absolute/path/data-dev-c/noc_fusion.db" uv run --project tools/offline-python --locked python -c 'from src.core.db import init_db; init_db()'` | Apply host-side migrations/bootstrap to an existing dev-c database after taking a backup |
| `docker compose restart api worker webhook` | Restart C# services after migration; they check for Alembic head `20261125_0025` but do not migrate at startup |

---

## Webhook Configuration

Configure your ITSM monitoring tool to send signed alerts to the default C# gateway:

```
POST http://<your-host>:8100/webhook/solarwinds
Content-Type: application/json
```

The C# gateway accepts signed SolarWinds-style JSON payloads, normalizes them, and persists alerts for AIOps correlation. `WEBHOOK_HMAC_SECRET` is required unless `ALLOW_UNSIGNED_WEBHOOKS=true`; unsigned requests otherwise receive 503. See [Webhook Gateway](WEBHOOK.md) for payload mappings and signature format. The Python backup still listens on host port 8099 when explicitly selected with `-f docker-compose.yml`.

### Testing the Webhook

Use a SolarWinds sender configured with the same `WEBHOOK_HMAC_SECRET`, or run the signature and persistence fixtures in `qa/NocIfc.Api.Tests/WebhookGatewayTests.cs`. Do not enable unsigned requests on a network-facing webhook.

---

## Troubleshooting

### Container Won't Start

```bash
# Check container logs
docker compose logs api

# Check for C# dev-c port conflicts
lsof -i :8101
lsof -i :8100
lsof -i :8501
lsof -i :5173

# Verify .env exists
ls -la .env
```

### No Data Appearing

```bash
# Check scheduler is running
docker compose logs -f worker

# Verify feeds are active (check Settings > RSS Sources)
# Only scheduler registry entries marked startup_run run at boot; the rest wait for their configured schedule.
# See SCHEDULER.md for the current startup-run list and schedule defaults.

# Check isolated C# database exists
ls -la data-dev-c/noc_fusion.db
```

### Database Errors

```bash
# Preserve the database and inspect the migration failure first.
docker compose logs --tail=300 api
docker compose logs --tail=300 worker
docker compose logs --tail=300 webhook

# C# services do not apply migrations on restart. After resolving the issue:
DATABASE_URL="sqlite:////absolute/path/data-dev-c/noc_fusion.db" uv run --project tools/offline-python --locked python -c 'from src.core.db import init_db; init_db()'
docker compose restart api worker webhook
```

Do not delete the database to recover a migration error. Full reset is destructive and only appropriate when all application data may be discarded; create a verified backup first. For older schema support and fail-closed migration behavior, see [Migration Compatibility](MIGRATION_COMPATIBILITY.md).

### WebSocket Not Connecting

```bash
# Verify API is running
curl http://localhost:8101/health

# Check for proxy configuration in nginx/vite
# Production: Nginx proxies /ws through the C# API host-gateway alias at port 8101
# Standalone Vite: vite.config.ts proxies /ws to ws://localhost:8101
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

2. **Network isolation**: The dev-c ports match main and are LAN-published for testing. Keep them on a trusted development network and do not expose them publicly.

3. **Secrets management**: Session tokens are database-backed, while integration settings are supplied through the supported environment variables and Settings UI. Keep `.env` out of version control and use a secret manager in production.

4. **HTTPS**: Use a reverse proxy (nginx, Caddy, Traefik) for TLS termination in production.

5. **Database**: The application uses SQLite. Back up the shared database file before upgrades or restores.
