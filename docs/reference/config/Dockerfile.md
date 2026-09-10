# Dockerfile — API/Worker/Webhook Build

**Path:** `/home/weast/docker/NOC_IFC/Dockerfile`

## Purpose

Single-stage Python production image used by the `api`, `worker`, and `webhook` services in `docker-compose.yml`. Installs system-level PostgreSQL client libraries, pip dependencies, and bundles the entire application source.

## Directives

| Directive | Value | Description |
|-----------|-------|-------------|
| `FROM` | `python:3.11-slim` | Base image — Debian slim variant with Python 3.11. Minimal footprint for production. |
| `WORKDIR` | `/app` | Working directory inside the container. All subsequent commands and `COPY` destinations resolve relative to this path. |
| `RUN` | `apt-get update && apt-get install -y libpq-dev gcc && rm -rf /var/lib/apt/lists/*` | Installs `libpq-dev` (PostgreSQL client headers, required by `psycopg2`) and `gcc` (C compiler for building native extensions). Removes apt cache to reduce layer size. |
| `COPY` | `requirements.txt .` | Copies only `requirements.txt` first to leverage Docker layer caching — rebuilds only when dependencies change. |
| `RUN` | `pip install --no-cache-dir -r requirements.txt` | Installs all Python packages. `--no-cache-dir` disables pip cache to reduce image size. |
| `COPY` | `. .` | Copies the entire project source (excluding items in `.dockerignore`, if present). |
| `ENV` | `PYTHONPATH=/app` | Ensures Python can resolve imports from `/app` as the root package directory. Required for `from src.api.main import app` to work at runtime. |

## Dependencies

- **`requirements.txt`** — Pinned and unpinned Python packages installed during build.
- **`src/`** — Application source code mounted as a volume at runtime for live-reload in development; baked into the image at build time for production.
- **OS packages:** `libpq-dev`, `gcc` — required at build time for compiling `psycopg2` against `libpq`. Only `libpq` is needed at runtime.

## Usage

Referenced by three services in `docker-compose.yml`:

| Service | Command | Role |
|---------|---------|------|
| `api` | `uvicorn src.api.main:app --host 0.0.0.0 --port 8101 --reload` | FastAPI REST + WebSocket server on port 8101 |
| `worker` | `python -u src/scheduler.py` | Background scheduler for data ingestion jobs |
| `webhook` | `python -u src/webhook_listener.py` | SolarWinds webhook gateway on port 8100 |

Build invocation:

```bash
docker compose build api
docker compose build worker
docker compose build webhook
```

All three use `context: .` (the project root) with this Dockerfile.
