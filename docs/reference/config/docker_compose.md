# docker-compose.yml — Multi-Service Orchestration

**Path:** `/home/weast/docker/NOC_IFC/docker-compose.yml`

## Purpose

Defines five services (`api`, `worker`, `webhook`, `web`, `web-dev`) that constitute the NOC Intelligence Fusion Center platform. Uses a shared Python image for backend services and a multi-stage Node/Nginx build for the frontend. The `web-dev` service is profile-gated for hot-reload development.

## Services

### `api` — FastAPI REST + WebSocket Server

| Key | Value | Description |
|-----|-------|-------------|
| `build.context` | `.` | Project root as build context. |
| `build.dockerfile` | `Dockerfile` | Uses main Python Dockerfile. |
| `command` | `uvicorn src.api.main:app --host 0.0.0.0 --port 8101 --reload` | Launches FastAPI via Uvicorn with hot-reload. Listens on all interfaces port 8101. |
| `ports` | `"8101:8101"` | Maps host port 8101 to container port 8101. |
| `env_file` | `.env` | Loads environment variables from `.env` at project root. |
| `volumes` | `./src:/app/src`, `./data:/app/data` | Mounts source and data directories for live code reload and persistent storage. |

### `worker` — Background Scheduler

| Key | Value | Description |
|-----|-------|-------------|
| `build.context` | `.` | Project root as build context. |
| `build.dockerfile` | `Dockerfile` | Uses main Python Dockerfile. |
| `command` | `python -u src/scheduler.py` | Runs the scheduler with unbuffered output (`-u`). |
| `env_file` | `.env` | Environment from `.env`. |
| `volumes` | `./src:/app/src`, `./data:/app/data` | Source and data mounts. |
| `deploy.resources.limits.memory` | `1G` | Caps worker container at 1 GB of RAM. Prevents runaway jobs from exhausting host memory. |

### `webhook` — SolarWinds Webhook Gateway

| Key | Value | Description |
|-----|-------|-------------|
| `build.context` | `.` | Project root as build context. |
| `build.dockerfile` | `Dockerfile` | Uses main Python Dockerfile. |
| `command` | `python -u src/webhook_listener.py` | Runs the webhook listener with unbuffered output. |
| `ports` | `"8100:8100"` | Maps host port 8100 to container port 8100. |
| `env_file` | `.env` | Environment from `.env`. |
| `volumes` | `./src:/app/src`, `./data:/app/data` | Source and data mounts. |

### `web` — Frontend Production (Nginx)

| Key | Value | Description |
|-----|-------|-------------|
| `build.context` | `./web` | Web subdirectory as build context. |
| `build.dockerfile` | `Dockerfile` | Uses the multi-stage web Dockerfile. |
| `ports` | `"5173:5173"` | Maps host port 5173 to container port 5173. |
| `environment.VITE_API_URL` | `http://localhost:8101` | Injected at build time for API proxy target. Points to host-localhost (not Docker network), since in production the browser connects to the host. |
| `depends_on` | `api` | Ensures the API container starts before the web container (best-effort — does not wait for readiness). |

### `web-dev` — Frontend Development (Hot Reload)

| Key | Value | Description |
|-----|-------|-------------|
| `profiles` | `["dev"]` | **Profile-gated.** Only starts when explicitly activated with `--profile dev`. |
| `image` | `node:20-alpine` | Uses the public Node image directly (no build step). |
| `working_dir` | `/app` | Container working directory. |
| `command` | `sh -c "npm ci && npm run dev -- --host 0.0.0.0"` | Installs dependencies and starts Vite dev server on all interfaces. |
| `ports` | `"5173:5173"` | Maps host port 5173 to container port 5173. |
| `environment.VITE_API_URL` | `http://api:8101` | Injected at build time. Points to the Docker-internal `api` service hostname. |
| `depends_on` | `api` | Ensures API starts first. |
| `volumes` | `./web:/app` | Mounts the entire web directory — source changes trigger instant Vite hot-module replacement. |

## Environment Configuration

All backend services source environment variables from the project root `.env` file via `env_file: .env`. The frontend services use inline `environment:` blocks for `VITE_API_URL` since Vite only embeds variables prefixed with `VITE_` at build time.

Key environment variable consumed:

| Variable | Used By | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | api, worker, webhook | SQLAlchemy database connection string. |
| `RISK_ALERT_RECIPIENTS` | api, worker, webhook | Comma-separated email recipients for risk alerts. |

## Profiles

| Profile | Service | Purpose |
|---------|---------|---------|
| `dev` | `web-dev` | Enables Vite hot-reload dev server. Starts `web-dev` instead of `web`. |

Activation:

```bash
# Production mode (default)
docker compose up --build -d

# Development mode with hot reload
docker compose --profile dev up --build -d
```

## Network Topology

All services share the default Docker Compose network (bridge). Internal DNS resolution uses service names:

- `http://api:8101` — used by `web-dev` Vite proxy and `web` Nginx proxy
- `http://localhost:8101` — used by production `web` Nginx proxy (browser-side)

## Volume Mounts

| Host Path | Container Path | Services | Purpose |
|-----------|---------------|----------|---------|
| `./src` | `/app/src` | api, worker, webhook | Live source code (hot-reload) |
| `./data` | `/app/data` | api, worker, webhook | Persistent SQLite DB, cached data |
| `./web` | `/app` | web-dev | Frontend source for Vite HMR |
