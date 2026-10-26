# docker-compose.yml — Multi-Service Orchestration

**Path:** `docker-compose.yml`

## Purpose

Defines five services (`api`, `worker`, `webhook`, `web`, `web-dev`) that constitute the NOC Intelligence Fusion Center platform. Uses a shared Python image for backend services and a multi-stage Node/Nginx build for the frontend. The `web-dev` service is profile-gated for hot-reload development.

## Services

### `api` — FastAPI REST + WebSocket Server

| Key | Value | Description |
|-----|-------|-------------|
| `build.context` | `.` | Project root as build context. |
| `build.dockerfile` | `Dockerfile` | Uses main Python Dockerfile. |
| `command` | `uvicorn src.api.main:app --host 0.0.0.0 --port 8101` | Launches FastAPI via Uvicorn. Listens on all interfaces port 8101. |
| `ports` | `"8101:8101"` | Maps host port 8101 to container port 8101. |
| `env_file` | `.env` | Loads environment variables from `.env` at project root. |
| `volumes` | `./data:/app/data` | Mounts persistent storage. |
| `healthcheck` | `GET /ready` every 30 seconds | Checks both the API process and database readiness; health becomes ready after the 20-second start period and configured retries. |
| `deploy.resources.limits` | `1.0` CPU, `768M` | Compose resource limits for the API container. |

### `worker` — Background Scheduler

| Key | Value | Description |
|-----|-------|-------------|
| `build.context` | `.` | Project root as build context. |
| `build.dockerfile` | `Dockerfile` | Uses main Python Dockerfile. |
| `command` | `python -u src/scheduler.py` | Runs the scheduler with unbuffered output (`-u`). |
| `env_file` | `.env` | Environment from `.env`. |
| `volumes` | `./data:/app/data` | Persistent data mount. |
| `deploy.resources.limits.memory` | `1.5G` | Caps worker container memory. Prevents runaway jobs from exhausting host memory. |
| `depends_on` | `api` with `condition: service_healthy` | Waits for API readiness before starting the worker. |
| `deploy.resources.limits.cpus` | `2.0` | Compose worker CPU limit. |

### `webhook` — SolarWinds Webhook Gateway

| Key | Value | Description |
|-----|-------|-------------|
| `build.context` | `.` | Project root as build context. |
| `build.dockerfile` | `Dockerfile` | Uses main Python Dockerfile. |
| `command` | `python -u src/webhook_listener.py` | Runs the webhook listener with unbuffered output. |
| `ports` | `"8100:8100"` | Maps host port 8100 to container port 8100. |
| `env_file` | `.env` | Environment from `.env`. |
| `volumes` | `./data:/app/data` | Persistent data mount. |
| `healthcheck` | `GET /health` every 30 seconds | Confirms the webhook HTTP server is live. |
| `deploy.resources.limits` | `0.5` CPU, `384M` | Compose resource limits for the webhook container. |

### `web` — Frontend Production (Nginx)

| Key | Value | Description |
|-----|-------|-------------|
| `build.context` | `./web` | Web subdirectory as build context. |
| `build.dockerfile` | `Dockerfile` | Uses the multi-stage web Dockerfile. |
| `ports` | `"8501:5173"` | Maps host port 8501 to container port 5173. |
| `environment.VITE_API_URL` | `http://localhost:8101` | Declared on the running container, but the built static frontend/Nginx does not consume this runtime variable; Nginx proxies `/api/` and `/ws` to `http://api:8101`. |
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
| `ports` | `"5173:5173"` | Maps host port 5173 to container port 5173. |
| `environment.VITE_API_URL` | `http://api:8101` | Read by the running Vite dev server to target the Docker-internal `api` service hostname. |
| `depends_on` | `api` | Ensures API starts first. |
| `volumes` | `./web:/app`, `web_dev_node_modules:/app/node_modules` | Source changes trigger HMR while the separate named volume preserves container-installed dependencies. |

## Environment Configuration

All backend services source environment variables from the project root `.env` file via `env_file: .env`. The `web-dev` service reads its inline `VITE_API_URL` at Vite-server startup to configure its `/api` and `/ws` development proxies. The production `web` service also declares that variable, but its already-built static bundle and Nginx proxy do not read it at container runtime.

Key environment variable consumed:

| Variable | Used By | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | api, worker, webhook | SQLite database file shared by all backend services. Startup migrations run before application work. |
| `RISK_ALERT_RECIPIENTS` | api, worker, webhook | Comma-separated email recipients for risk alerts. |
| `WEBHOOK_*` | webhook | HMAC, replay, and body-size controls. |
| `CORS_ORIGINS` | api | Allowed browser origins. |
| `PUBLIC_APP_URL`, `REGISTRATION_INVITE_TTL_HOURS` | api | Registration URL and invite lifetime. |

## Profiles

| Profile | Service | Purpose |
|---------|---------|---------|
| `dev` | `web-dev` | Adds the Vite hot-reload service; it does not remove the production `web` service. Use host port 5173 for the dev frontend. |

Activation:

```bash
# Production mode (default)
docker compose up --build -d

# Development mode with hot reload
docker compose --profile dev up --build -d
```

## Network Topology

All services share the default Docker Compose network (bridge). Internal DNS resolution uses service names:

- `http://api:8101` — used by the `web-dev` Vite proxy and production Nginx `/api/` and `/ws` upstreams

## Volume Mounts

| Host Path | Container Path | Services | Purpose |
|-----------|---------------|----------|---------|
| `./data` | `/app/data` | api, worker, webhook | Persistent SQLite DB, cached data |
| `./web` | `/app` | web-dev | Frontend source for Vite HMR |
