# Core Configuration Module

**File:** `src/core/config.py`

Provides application-wide configuration loading from environment variables and standardized logging setup. Uses Pydantic's `BaseSettings` for validation and `.env` file support.

---

## Class: `Settings`

Pydantic `BaseSettings` subclass that loads and validates all environment-driven configuration for the NOC Fusion application.

### Purpose
Centralized, typed configuration container that reads from environment variables (`.env` file) and exposes all tunable parameters.

### Configuration Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `database_url` | `str` | `sqlite:////app/data/noc_fusion.db` | SQLAlchemy database connection string. Supports any SQLAlchemy-compatible backend (SQLite, PostgreSQL, etc.). |
| `elastic_url` | `str` | `https://localhost:9200` | Elasticsearch endpoint URL for SIEM event queries. |
| `elastic_api_key` | `str` | `your_read_only_api_key` | API key for authenticating against the Elasticsearch instance. |
| `crime_alert_sms` | `str \| None` | `None` | Phone number or SMS gateway for crime alert notifications. |
| `crime_alert_email` | `str \| None` | `None` | Email address for crime alert notifications. |
| `risk_alert_recipients` | `str` | `""` | Comma-separated list of email recipients for risk alert notifications. |

### Inner Class: `Config`

| Attribute | Value | Description |
|-----------|-------|-------------|
| `env_file` | `".env"` | Path to the `.env` file for local overrides. |
| `extra` | `"ignore"` | Silently ignore any extra fields in the environment not defined in the model. |

### Flow
1. `load_dotenv()` is called at module import time to populate `os.environ` from `.env`.
2. `Settings()` constructor reads from environment variables, applying defaults where values are missing.
3. The singleton `settings` instance is created at module level.

### Dependencies
- `pydantic_settings.BaseSettings` — validation and env-file loading.
- `dotenv.load_dotenv` — loads `.env` file into the process environment.

---

## Module-Level Constants

| Constant | Source | Type | Description |
|----------|--------|------|-------------|
| `DATABASE_URL` | `settings.database_url` | `str` | Database connection URL used by SQLAlchemy engine. |
| `ELASTIC_URL` | `settings.elastic_url` | `str` | Elasticsearch endpoint URL. |
| `ELASTIC_API_KEY` | `settings.elastic_api_key` | `str` | Elasticsearch API key. |
| `CRIME_ALERT_SMS` | `settings.crime_alert_sms` | `str \| None` | SMS gateway for crime alerts. |
| `CRIME_ALERT_EMAIL` | `settings.crime_alert_email` | `str \| None` | Email for crime alerts. |
| `RISK_ALERT_RECIPIENTS` | `settings.risk_alert_recipients` | `str` | Risk alert email recipients. |

These are convenience aliases extracted once at import time so that other modules can `from src.core.config import DATABASE_URL` directly.

---

## Function: `setup_logging(level=logging.INFO)`

### Purpose
Configures the root Python logger with a standardized format and stdout handler. Intended to be called once at application startup.

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `level` | `int` | `logging.INFO` | Logging threshold level (e.g., `logging.INFO`, `logging.DEBUG`). |

### Returns
`None`

### Raises
None.

### Flow
1. Calls `logging.basicConfig()` with:
   - Level set to the provided `level`.
   - Format string: `"%(asctime)s [%(levelname)s] %(name)s: %(message)s"`.
   - Date format: `"%H:%M:%S"` (hours:minutes:seconds).
   - Single `StreamHandler` writing to `sys.stdout`.
   - `force=True` to override any pre-existing logger configuration.

### Dependencies
- `logging` — standard library logging.
- `sys` — for `sys.stdout` stream.
