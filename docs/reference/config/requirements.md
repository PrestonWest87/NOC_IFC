# Host-Side Python Tooling

There is no Python application runtime or root `requirements.txt` on `dev-c`. Python is retained only for Alembic migrations, fresh-database bootstrap, offline backup conversion/recovery, and route-contract comparison.

**Manifest:** `tools/offline-python/pyproject.toml`

**Lock:** `tools/offline-python/uv.lock`
**Python:** 3.11

The locked tool dependencies are Alembic, SQLAlchemy, Pydantic Settings, python-dotenv, bcrypt, and cryptography. Install the isolated host environment with:

```bash
uv sync --project tools/offline-python --locked --python 3.11
```

Commands are documented in [Getting Started](../../GETTING_STARTED.md), [Maintenance](../../MAINTENANCE.md), and `README_DEV_C.md`. The tool directory is excluded from backend image builds.
