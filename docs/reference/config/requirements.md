# Python Dependencies

**Direct runtime manifest:** `requirements.txt`

**Resolved runtime lock:** `requirements.lock`
**Test manifest:** `requirements-test.txt` (adds HTTPX2 for FastAPI's `TestClient` after the runtime lock)

The Python image installs only runtime dependencies. The test manifest adds a pinned HTTPX2 version for FastAPI's `TestClient`; install it after `requirements.lock` when preparing a test environment.

| Package | Why it is required |
|---|---|
| `alembic>=1.13,<2` | Versioned SQLite schema migrations, checked at service startup. |
| `sqlalchemy` | ORM, schema metadata, sessions, and SQLite engine. |
| `fastapi` | REST API and SolarWinds webhook application. |
| `uvicorn[standard]` | ASGI server, WebSocket support, and optimized HTTP/event-loop extras. |
| `python-multipart>=0.0.20` | Admin database-upload endpoint. |
| `pydantic-settings` | Typed application settings. |
| `python-dotenv` | Explicit `.env` loading in `src/core/config.py`. |
| `feedparser` | RSS/Atom parsing in feed and cloud-status workers. |
| `schedule` | Dynamic in-process background job scheduler. |
| `requests` | Synchronous external API and LLM calls. |
| `aiohttp` | Concurrent asynchronous RSS fetching. |
| `trafilatura` | Article full-text extraction. |
| `shapely` | Regional polygon, point, and geometry operations. |
| `scikit-learn` | ML article scoring and scheduled model training. |
| `joblib` | Persisting and loading the trained model. |
| `elasticsearch>=8.0.0,<9.0.0` | Production Elastic telemetry/search integration; retained in the standard image. Tests mock the client or leave `ELASTIC_URL` blank. |
| `rapidfuzz` | Native title-similarity ratio used by article deduplication. |
| `bcrypt==4.1.2` | Password hashing. |

Removed unused direct requirements: PostgreSQL's `psycopg2-binary`, `beautifulsoup4`, `aiofiles`, `openai`, and `google-generativeai`. LLM calls use `requests` with the configured compatible endpoint, not provider SDKs. Pandas was removed after active regional, AIOps, settings, and model-training code was converted to records, counters, and Python lists. `pydeck` was not a declared dependency; its unreferenced legacy rendering helpers were removed.

## Installing dependencies

```bash
# Runtime image / production environment
pip install --require-hashes -r requirements.lock

# Development and tests
pip install -r requirements-test.txt
```

Regenerate the hash-pinned runtime lock after changing direct requirements:

```bash
uv pip compile requirements.txt --python-version 3.11 --universal --generate-hashes -o requirements.lock
```

`Dockerfile` installs the lock with hash checking and uses a BuildKit pip cache mount. Keep `requirements.txt` and `requirements.lock` synchronized in the same change.
