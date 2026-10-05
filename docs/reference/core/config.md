# Core Configuration Module

**File:** `src/core/config.py`

Loads typed environment configuration with Pydantic Settings, imports `.env` values with `python-dotenv`, exposes a small set of compatibility aliases, and configures stdout logging.

## `Settings(BaseSettings)`

| Field | Type | Default | Purpose |
|---|---|---|---|
| `database_url` | `str` | `sqlite:////app/data/noc_fusion.db` | SQLAlchemy database URL. |
| `demo_seed_data` | `bool` | `False` | Enables synthetic asset seeds for disposable demonstrations. |
| `log_level` | `str` | `INFO` | Declared logging setting; `setup_logging()` also reads `LOG_LEVEL` directly when no level is supplied. |
| `elastic_url` | `str` | `""` | Elasticsearch endpoint; a blank value disables Elastic sync. |
| `elastic_api_key` | `str` | `""` | Optional Elasticsearch API key. |
| `elastic_verify_certs` | `bool` | `True` | Verify TLS certificates for Elasticsearch. |
| `elastic_ca_certs` | `str \| None` | `None` | Optional CA bundle path. |
| `elastic_request_timeout` | `float` | `15.0` (greater than 0, at most 120) | Elasticsearch request timeout in seconds. |
| `elastic_max_results` | `int` | `500` (greater than 0, at most 5000) | Maximum result count for Elastic queries. |
| `crime_alert_sms` | `str \| None` | `None` | Crime SMS gateway destination. |
| `crime_alert_email` | `str \| None` | `None` | Crime email destination. |
| `risk_alert_recipients` | `str` | `""` | Comma-separated risk/daily-brief recipients. |
| `webhook_hmac_secret` | `str \| None` | `None` | SolarWinds signing secret. |
| `webhook_signature_header` | `str` | `X-SolarWinds-Signature` | Signature header name. |
| `webhook_timestamp_header` | `str` | `X-SolarWinds-Timestamp` | Replay timestamp header name. |
| `webhook_replay_window_seconds` | `int` | `300` | Accepted webhook timestamp age. |
| `webhook_max_body_bytes` | `int` | `1048576` | Maximum webhook request body. |
| `websocket_max_message_bytes` | `int` | `65536` | Maximum client WebSocket message. |
| `allow_private_llm_endpoints` | `bool` | `False` | Allows private LLM endpoint URLs when true. |
| `cors_origins` | `str` | `http://localhost:8501,http://localhost:5173` | Comma-separated CORS origin list. |
| `allow_unsigned_webhooks` | `bool` | `False` | Explicit migration exception for unsigned webhook requests. |
| `public_app_url` | `str` | `http://localhost:8501` | Base URL used for registration links. |
| `default_admin_email` | `str` | Empty | Optional verified email for the bootstrap admin/recovery reviewer. |
| `registration_invite_ttl_hours` | `int` | `72` | Default registration invite lifetime. |
| `backup_encryption_keys` | `str` | `""` | JSON map of backup key IDs to 32-byte hexadecimal keys. |
| `backup_encryption_active_key_id` | `str` | `primary` | Key ID selected for new encrypted backups. |
| `backup_max_bytes` | `int` | `10737418240` (greater than 0, at most 107374182400) | Maximum encrypted backup/upload size in bytes. |

### Pydantic configuration

The nested `Config` sets `env_file = ".env"` and `extra = "ignore"`. `load_dotenv()` runs at import time before the singleton `settings = Settings()` is created. Pydantic maps environment names to lowercase field names case-insensitively.

## Module-Level Aliases

The module exports these aliases for older imports:

`DATABASE_URL`, `ELASTIC_URL`, `ELASTIC_API_KEY`, `CRIME_ALERT_SMS`, `CRIME_ALERT_EMAIL`, and `RISK_ALERT_RECIPIENTS`.

Other settings must be read from the `settings` singleton.

## `setup_logging(level=None)`

Configures the root logger with `logging.basicConfig(..., force=True)`:

- When `level` is not `None`, uses the supplied logging level.
- When `level` is `None`, reads `LOG_LEVEL` from the process environment and uppercases it.
- Invalid level names fall back to `logging.WARNING`.
- Writes to `sys.stdout` using `%(asctime)s [%(levelname)s] %(name)s: %(message)s`.
- Uses `%H:%M:%S` timestamps.

The API, worker, and webhook call this during startup. Repeated calls replace the prior root logger configuration because `force=True` is intentional.
