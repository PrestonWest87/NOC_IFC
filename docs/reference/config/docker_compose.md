# docker-compose.yml — Multi-Service Orchestration

**Path:** `docker-compose.yml`

## Purpose

Defines five services (`api`, `worker`, `webhook`, `web`, `web-dev`) that constitute the NOC Intelligence Fusion Center platform. Uses a shared Python image for backend services and a multi-stage Node/Nginx build for the frontend. The `web-dev` service is profile-gated for hot-reload development.

The dev branch sets the Compose project name to `noc-ifc-dev`, publishes distinct host ports, mounts `./data-dev`, and attaches containers to Docker's built-in `bridge` network instead of allocating a new subnet.

## Services

### `api` — FastAPI REST + WebSocket Server

| Key | Value | Description |
|-----|-------|-------------|
| `build.context` | `.` | Project root as build context. |
| `build.dockerfile` | `Dockerfile` | Uses main Python Dockerfile. |
| `command` | `uvicorn src.api.main:app --host 0.0.0.0 --port 8101` | Launches FastAPI via Uvicorn. Listens on all interfaces port 8101. |
| `network_mode` | `bridge` | Uses Docker's existing built-in bridge network; no new subnet is allocated. |
| `ports` | `"8102:8101"` | Maps dev host port 8102 (one above main API 8101) to container port 8101. |
| `env_file` | `.env` | Loads environment variables from `.env` at project root. |
| `volumes` | `./data-dev:/app/data` | Mounts storage isolated from the existing instance. |
| `healthcheck` | `GET /ready` every 30 seconds | Checks both the API process and database readiness; health becomes ready after the 20-second start period and configured retries. |
| `deploy.resources.limits` | `1.0` CPU, `768M` | Compose resource limits for the API container. |

### `worker` — Background Scheduler

| Key | Value | Description |
|-----|-------|-------------|
| `build.context` | `.` | Project root as build context. |
| `build.dockerfile` | `Dockerfile` | Uses main Python Dockerfile. |
| `command` | `python -u src/scheduler.py` | Runs the scheduler with unbuffered output (`-u`). |
| `network_mode` | `bridge` | Uses Docker's built-in bridge network. |
| `env_file` | `.env` | Environment from `.env`. |
| `volumes` | `./data-dev:/app/data` | Persistent dev data mount. |
| `deploy.resources.limits.memory` | `1.5G` | Caps worker container memory. Prevents runaway jobs from exhausting host memory. |
| `depends_on` | `api` with `condition: service_healthy` | Waits for API readiness before starting the worker. |
| `deploy.resources.limits.cpus` | `2.0` | Compose worker CPU limit. |

### `webhook` — SolarWinds Webhook Gateway

| Key | Value | Description |
|-----|-------|-------------|
| `build.context` | `.` | Project root as build context. |
| `build.dockerfile` | `Dockerfile` | Uses main Python Dockerfile. |
| `command` | `python -u src/webhook_listener.py` | Runs the webhook listener with unbuffered output. |
| `network_mode` | `bridge` | Uses Docker's built-in bridge network. |
| `ports` | `"8099:8100"` | Maps dev host port 8099 (one below main webhook 8100) to container port 8100. |
| `env_file` | `.env` | Environment from `.env`. |
| `volumes` | `./data-dev:/app/data` | Persistent dev data mount. |
| `healthcheck` | `GET /health` every 30 seconds | Confirms the webhook HTTP server is live. |
| `deploy.resources.limits` | `0.5` CPU, `384M` | Compose resource limits for the webhook container. |

### `web` — Frontend Production (Nginx)

| Key | Value | Description |
|-----|-------|-------------|
| `build.context` | `./web` | Web subdirectory as build context. |
| `build.dockerfile` | `Dockerfile` | Uses the multi-stage web Dockerfile. |
| `network_mode` | `bridge` | Uses Docker's built-in bridge network. |
| `ports` | `"8503:5173"` | Maps the dev Nginx web container to host port 8503. |
| `environment.VITE_API_URL` | `http://noc-ifc-dev-api:8102` | The static bundle does not consume this runtime variable; Nginx proxies `/api/` and `/ws` through this unique host-gateway alias. |
| `extra_hosts` | `noc-ifc-dev-api:host-gateway` | Resolves the API host port without depending on the existing project's `api` DNS alias. |
| `depends_on` | `api` with `condition: service_healthy` | Waits for API readiness before starting the production web container. |
| `healthcheck` | `GET /health` every 30 seconds | Checks the Nginx static server. |
| `deploy.resources.limits` | `0.25` CPU, `128M` | Compose resource limits for the production web container. |

### `web-dev` — Frontend Development (Hot Reload)

| Key | Value | Description |
|-----|-------|-------------|
| `profiles` | `["dev"]` | **Profile-gated.** Only starts when explicitly activated with `--profile dev`. |
| `image` | `node:22-alpine` | Uses the public Node image directly (no build step). |
| `working_dir` | `/app` | Container working directory. |
| `command` | `sh ./dev-entrypoint.sh` | Reuses the named dependency volume; reruns `npm ci` only when the lockfile hash changes, then starts Vite. |
| `network_mode` | `bridge` | Uses the built-in Docker bridge network. |
| `ports` | `"5174:5173"` | Maps HMR host port 5174 (one above main Vite port 5173) to container port 5173. |
| `environment.VITE_API_URL` | `http://noc-ifc-dev-api:8102` | Read by Vite through the unique host-gateway alias to the dev API host port. |
| `extra_hosts` | `noc-ifc-dev-api:host-gateway` | Resolves the API host port without colliding with the existing `api` service alias. |
| `depends_on` | `api` | Ensures API starts first. |
| `volumes` | `./web:/app`, `web_dev_node_modules:/app/node_modules` | Source changes trigger HMR while the separate named volume preserves container-installed dependencies. |

## Environment Configuration

All backend services source environment variables from the project root `.env` file via `env_file: .env`. The `web-dev` service reads its inline `VITE_API_URL` at Vite-server startup to configure its `/api` and `/ws` development proxies. The production `web` service also declares that variable, but its already-built static bundle and Nginx proxy do not read it at container runtime.

Key environment variable consumed:

| Variable | Used By | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | api, worker, webhook | SQLite database file shared by the backend services on isolated `./data-dev` storage. Startup migrations run before application work. |
| `RISK_ALERT_RECIPIENTS` | api, worker | Fallback recipients for risk alerts; database overrides are read from shared SQLite at operation time. |
| `REMEDYFORCE_TICKET_EMAIL`, `NOC_*_EMAIL`, `ITNETWORK_ONPAGE_EMAIL` | worker | Environment fallbacks for escalation/wildfire destinations; Application Settings database overrides take precedence. |
| `ELASTIC_*`, `CRIME_ALERT_*` | api, worker | Environment fallbacks for Elastic and crime alerts; Application Settings database overrides take precedence. |
| `WEBHOOK_*` | webhook | HMAC, replay, and body-size controls. |
| `CORS_ORIGINS` | api | Allowed browser origins; defaults include ports 8503, 5174, and standalone Vite port 5173. |
| `PUBLIC_APP_URL`, `REGISTRATION_INVITE_TTL_HOURS` | api | Registration URL (8503 by default) and invite lifetime. |

## Profiles

| Profile | Service | Purpose |
|---------|---------|---------|
| `dev` | `web-dev` | Adds the Vite hot-reload service; it does not remove the production `web` service. Use host port 5174 for HMR. |

Activation:

```bash
# Production mode (default)
docker compose up --build -d

# Development mode with hot reload
docker compose --profile dev up --build -d
```

## Network Topology

Services attach to Docker's built-in `bridge` network. The `web` and `web-dev` containers use the `noc-ifc-dev-api` `/etc/hosts` alias supplied by `host-gateway`, avoiding service-name collisions with the existing instance:

- `http://noc-ifc-dev-api:8102` — used by Vite and Nginx to reach the dev API through the host gateway

## Volume Mounts

| Host Path | Container Path | Services | Purpose |
|-----------|---------------|----------|---------|
| `./data-dev` | `/app/data` | api, worker, webhook | Dev SQLite DB, cached data, and model artifacts; separate from existing `./data` |
| `./web` | `/app` | web-dev | Frontend source for Vite HMR |
