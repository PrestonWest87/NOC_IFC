# .env.example — Environment Variable Template

**Path:** `/home/weast/docker/NOC_IFC/.env.example`

## Purpose

Template file documenting required environment variables. Users copy this to `.env` (which is gitignored) and populate with real values.

## Variables

### `DATABASE_URL`

| Property | Value |
|----------|-------|
| **Required** | Yes |
| **Type** | `string` |
| **Default** | `sqlite:////app/data/noc_fusion.db` (assumed — not declared in example) |
| **Example** | `DATABASE_URL=sqlite:////app/data/noc_fusion.db` |
| **Example (PostgreSQL)** | `DATABASE_URL=postgresql://user:password@host:5432/noc_fusion` |

**Description:** SQLAlchemy database connection string. Determines which database engine and path the application uses.

- **SQLite (default):** `sqlite:////app/data/noc_fusion.db` — file-based, no separate server required. The database file lives at the path `/app/data/noc_fusion.db` inside the container, mapped to `./data/` on the host via Docker volume.
- **PostgreSQL:** `postgresql://user:password@host:5432/noc_fusion` — requires a running PostgreSQL server. Install `psycopg2-binary` (already in `requirements.txt`) and set the connection string accordingly.

### `RISK_ALERT_RECIPIENTS`

| Property | Value |
|----------|-------|
| **Required** | Yes (if using risk alerts) |
| **Type** | `string` |
| **Default** | None |
| **Example** | `RISK_ALERT_RECIPIENTS=admin@example.com,soc@example.com` |

**Description:** Comma-separated list of email recipients for automated risk alert notifications. When the risk assessment engine detects conditions exceeding a configurable threshold, an email alert is sent to every address in this list.

## Usage

```bash
# Copy the template
cp .env.example .env

# Edit with your values
vim .env

# .env is automatically loaded by docker-compose (env_file: .env)
# and by python-dotenv (imported in src/core/config.py)
```

## Security

`.env` is listed in `.gitignore` to prevent accidental commit of secrets. Never commit database credentials, API keys, or email server passwords to version control.

## Consumed By

| Service | File | How |
|---------|------|-----|
| api, worker, webhook | `docker-compose.yml` | `env_file: .env` — injected as container environment variables |
| All Python services | `src/core/config.py` | `pydantic-settings` reads `DATABASE_URL`, email config, and other env vars at startup |
