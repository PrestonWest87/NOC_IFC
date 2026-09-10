# Models Package

**Directory:** `src/models/`

Contains SQLAlchemy ORM model definitions for all database entities.

- **`__init__.py`** — Re-exports all model classes from `schema.py`.
- **`schema.py`** — Defines 27 database models (tables) covering: users, roles, articles, RSS feeds, keywords, CVEs, alerts, locations, hazards, outages, assets, risk snapshots, incidents, caches, and more.
