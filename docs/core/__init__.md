# Core Package

**Directory:** `src/core/`

Contains foundational infrastructure modules for the NOC Fusion Center application:

- **`config.py`** — Environment-based configuration via Pydantic `BaseSettings` and standardized logging setup.
- **`db.py`** — SQLAlchemy engine, session factory, database initialization (schema, migrations, seeding), and FastAPI dependency injection.
