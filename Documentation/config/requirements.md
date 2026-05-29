# requirements.txt — Python Dependencies

**Path:** `/home/weast/docker/NOC_IFC/requirements.txt`

## Purpose

Declares all Python third-party packages required by the backend services (API, Worker, Webhook). Installed via `pip install --no-cache-dir -r requirements.txt` during the Docker build.

## Packages

### Database & ORM

| Package | Version | Purpose |
|---------|---------|---------|
| `psycopg2-binary` | Latest | PostgreSQL adapter for SQLAlchemy. Binary wheel — no build-time dependency on `libpq-dev`. Used when `DATABASE_URL` points to PostgreSQL. |
| `sqlalchemy` | Latest | SQLAlchemy ORM and Core — database models, session management, query building. Used by `src/core/db.py` and all route modules. |

### Web Framework & Server

| Package | Version | Purpose |
|---------|---------|---------|
| `fastapi` | Latest | Modern async Python web framework. Powers both the REST API (`src/api/main.py`) and the webhook gateway (`src/webhook_listener.py`). |
| `uvicorn[standard]` | Latest | ASGI server for FastAPI. `[standard]` extras include `uvloop` and `httptools` for better performance. Used by `api` (port 8101) and `webhook` (port 8100) services. |
| `aiohttp` | Latest | Async HTTP client/server library. Used for outbound HTTP requests (RSS fetching, API calls to external services). |
| `aiofiles` | Latest | Async file I/O. Used for non-blocking file reads/writes. |
| `pydantic-settings` | Latest | Pydantic-based settings management with `.env` file support. Backs `src/core/config.py`. |

### Data Processing

| Package | Version | Purpose |
|---------|---------|---------|
| `pandas` | Latest | DataFrame library for data manipulation, aggregation, and analytics. Used by the AIOps engine, reporting, and regional grid analytics. |
| `shapely` | Latest | Geometric objects and operations (points, polygons, intersections). Used for geospatial computations in the regional grid. |
| `scikit-learn` | Latest | ML library — TF-IDF vectorization, clustering, and classification for article categorization and threat scoring. |
| `joblib` | Latest | Model persistence (save/load trained scikit-learn models). |
| `rapidfuzz` | Latest | Fast string matching (fuzzywuzzy replacement). Used for near-duplicate article detection (SequenceMatcher alternative) and IOC fuzzy matching. |

### RSS & Web Scraping

| Package | Version | Purpose |
|---------|---------|---------|
| `feedparser` | Latest | RSS/Atom feed parser. Used by the scheduler to fetch and parse cybersecurity news feeds. |
| `beautifulsoup4` | Latest | HTML/XML parser. Used for web scraping and cleaning HTML content from feeds. |
| `requests` | Latest | Synchronous HTTP library. Used in scripts and utility functions. |

### WebSockets

| Package | Version | Purpose |
|---------|---------|---------|
| `fastapi` | (listed above) | FastAPI includes built-in WebSocket support. |
| `aiohttp` | (listed above) | Async HTTP — also used as WebSocket client. |

### AI / LLM Integration

| Package | Version | Purpose |
|---------|---------|---------|
| `openai` | Latest | OpenAI API client. Used by `src/utils/llm.py` for GPT-based report generation and threat analysis. |
| `google-generativeai` | Latest | Google Generative AI (Gemini) client. Alternative LLM provider in `src/utils/llm.py`. |

### Scheduling

| Package | Version | Purpose |
|---------|---------|---------|
| `schedule` | Latest | In-process job scheduler. Drives `src/scheduler.py` — periodic RSS fetches, crime data pulls, cloud outage checks, database maintenance, and ML retraining. |

### Security & Auth

| Package | Version | Purpose |
|---------|---------|---------|
| `bcrypt==4.1.2` | `==4.1.2` (pinned) | Password hashing. Version pinned to 4.1.2 for stable bcrypt compatibility. Used for user authentication. |

### Search

| Package | Version | Purpose |
|---------|---------|---------|
| `elasticsearch>=8.0.0,<9.0.0` | `>=8.0.0,<9.0.0` (range) | Elasticsearch client for full-text search capabilities. Version range allows any 8.x release but prevents 9.x breaking changes. |

### Environment & Config

| Package | Version | Purpose |
|---------|---------|---------|
| `python-dotenv` | Latest | Loads `.env` files into `os.environ`. Used as a fallback or alongside `pydantic-settings`. |

### Legacy / Monolith Remnants

| Package | Version | Purpose |
|---------|---------|---------|
| `streamlit` | Latest | Streamlit framework. **Legacy dependency** — the monolith was a Streamlit app. The refactored architecture uses FastAPI + React, but Streamlit remains in requirements (possibly for utility scripts or fallback). |
| `streamlit-autorefresh` | Latest | Streamlit auto-refresh component. **Legacy dependency** — companion to Streamlit, retained for compatibility. |

## Dependency Graph

```
web framework        → fastapi, uvicorn[standard], aiohttp, aiofiles
database             → sqlalchemy, psycopg2-binary, pydantic-settings
data science         → pandas, scikit-learn, joblib, shapely, rapidfuzz
scheduling           → schedule
rss/scraping         → feedparser, beautifulsoup4, requests
ai/llm               → openai, google-generativeai
security             → bcrypt==4.1.2
search               → elasticsearch>=8.0.0,<9.0.0
env                  → python-dotenv
legacy               → streamlit, streamlit-autorefresh
```

## Versioning Strategy

| Style | Examples | Risk |
|-------|----------|------|
| No pin (latest) | `sqlalchemy`, `pandas` | Accepts any version. May break on major releases. |
| Caret/compatible range | `elasticsearch>=8.0.0,<9.0.0` | Allows minor/patch upgrades within major version. |
| Exact pin | `bcrypt==4.1.2` | No automatic upgrades — deliberate version lock. |

For reproducible builds, Docker uses `pip install --no-cache-dir -r requirements.txt` which resolves unversioned packages to whatever is latest at build time. For stricter reproducibility, consider generating a `requirements-lock.txt` or using `pip freeze`.

## Usage

```bash
# During Docker build (automated)
pip install --no-cache-dir -r requirements.txt

# Local development (in a virtualenv)
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
