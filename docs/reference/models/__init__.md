# Models Package

**Directory:** `src/models/`

Contains SQLAlchemy ORM model definitions for all database entities.

- **`__init__.py`** — Re-exports all model classes from `schema.py`.
- **`schema.py`** — Defines 35 mapped database models (tables), including display/individual users, email-change and reset-review workflows, audit events, scheduler job settings, and operational intelligence entities.
