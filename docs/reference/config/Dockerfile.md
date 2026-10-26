# Dockerfile — API/Worker/Webhook Build

**Path:** `Dockerfile`

## Purpose

Single-stage Python production image used by the `api`, `worker`, and `webhook` services in `docker-compose.yml`. Installs SQLite-compatible Python dependencies and bundles the application source.

## Directives

| Directive | Value | Description |
|-----------|-------|-------------|
| `FROM` | `python:3.11-slim` | Base image — Debian slim variant with Python 3.11. Minimal footprint for production. |
| `WORKDIR` | `/app` | Working directory inside the container. All subsequent commands and `COPY` destinations resolve relative to this path. |
| `ENV` | `PYTHONDONTWRITEBYTECODE=1`, `PYTHONUNBUFFERED=1`, `PYTHONPATH=/app` | Prevents bytecode writes in the image, streams log output, and makes `/app` the Python import root. |
| `RUN` | `apt-get update && apt-get install -y gosu && rm -rf /var/lib/apt/lists/*` | Installs `gosu` to drop container privileges. Runtime packages use prebuilt wheels, so a compiler and PostgreSQL client libraries are not installed. |
| `COPY` | `requirements.txt requirements.lock ./` | Copies direct requirements and the resolved Python lock before source to leverage Docker layer caching. |
| `RUN` | `pip install --disable-pip-version-check --require-hashes -r requirements.lock` with a BuildKit pip-cache mount | Installs pinned runtime packages with artifact hashes while reusing downloaded wheels across rebuilds. The cache mount is not stored in the image. |
| `COPY` | `. .` | Copies project runtime source while `.dockerignore` excludes local data/backups/models, Markdown documentation, dependencies, and the legacy generated `src/ml_model.pkl` artifact. |
| `COPY` / `RUN` | `docker-entrypoint.sh` | Adds the runtime entrypoint, which repairs `/app/data` ownership and drops privileges to `appuser` through `gosu`. |

## Dependencies

- **`requirements.txt`** — Direct Python runtime requirements.
- **`requirements.lock`** — Transitive, version-pinned, hash-checked runtime resolution used by the image build.
- **`src/`** — Application source baked into the shared backend image. Compose does not mount backend source at runtime; API/worker/webhook code changes require rebuilding those services.
- **OS packages:** `gosu`; no compiler or PostgreSQL client libraries are installed.

## Usage

Referenced by three services in `docker-compose.yml`:

| Service | Command | Role |
|---------|---------|------|
| `api` | `uvicorn src.api.main:app --host 0.0.0.0 --port 8101` | FastAPI REST + WebSocket server on port 8101 |
| `worker` | `python -u src/scheduler.py` | Background scheduler for data ingestion jobs |
| `webhook` | `python -u src/webhook_listener.py` | SolarWinds webhook gateway on port 8100 |

Build invocation:

```bash
docker compose build api
docker compose build worker
docker compose build webhook
```

All three use `context: .` (the project root) with this Dockerfile.
