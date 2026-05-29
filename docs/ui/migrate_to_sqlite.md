# Module: `src/migrate_to_sqlite.py`

## Overview

One-shot database migration script that transfers all data from a PostgreSQL source database to a SQLite destination database. Creates the schema on the SQLite side, then iterates over all tables defined in the SQLAlchemy `Base` metadata and copies rows.

---

## Module-Level Execution Flow

**Purpose:** Script entrypoint - performs the full migration from PostgreSQL to SQLite.

**Flow:**
1. Defines PostgreSQL source URL (`postgresql://admin:adminpass@db:5432/rss_db`).
2. Defines SQLite destination URL (`sqlite:////app/data/noc_fusion.db`).
3. Creates SQLAlchemy engines for both databases.
4. Ensures the `/app/data` directory exists.
5. Creates all tables on the SQLite engine using `Base.metadata.create_all()`.
6. Iterates over every table in `Base.metadata.tables`:
   - Deletes existing rows from the SQLite table (for idempotency).
   - Selects all rows from the PostgreSQL source.
   - Converts each row to a dict using `row._mapping`.
   - Inserts the dicts into SQLite using `table.insert()`.
   - Logs the row count for each table.
7. Prints completion message.

**Dependencies:**
| Module | Usage |
|--------|-------|
| `os` | Directory creation |
| `sqlalchemy.create_engine` | Database connection |
| `src.database.Base` | SQLAlchemy metadata with all table definitions |

**Raises:** Exception if database connections fail or SQL execution errors occur (not caught).
