# Enterprise Architecture & Functional Specification: `src/migrate_to_sqlite.py`

## 1. Executive Overview

The `src/migrate_to_sqlite.py` module is a **one-shot data migration utility** that transfers all application state from a running PostgreSQL database into a self-contained SQLite file. Designed for edge-compute scenarios where the system transitions from a full PostgreSQL deployment to a lightweight, zero-configuration SQLite instance.

---

## 2. Configuration

| Parameter | Value | Description |
|-----------|-------|-------------|
| `PG_URL` | `postgresql://admin:adminpass@db:5432/rss_db` | Source PostgreSQL connection |
| `SQLITE_URL` | `sqlite:////app/data/noc_fusion.db` | Destination SQLite file |

---

## 3. Execution Flow

1. **Connect to PostgreSQL** — Creates SQLAlchemy engine from `PG_URL`
2. **Connect to SQLite** — Creates destination DB file (auto-creates `/app/data` directory)
3. **Build Schema** — Calls `Base.metadata.create_all()` to create all tables in SQLite
4. **Transfer Data** — Iterates through all tables in `Base.metadata.tables`:
   - Wipes existing auto-generated data in SQLite
   - Fetches all rows from PostgreSQL
   - Converts to dictionaries via `row._mapping`
   - Bulk-inserts to SQLite
5. **Reports Status** — Prints row counts per table

---

## 4. Usage

```bash
# Run inside the worker container after PostgreSQL is running
docker compose exec worker python src/migrate_to_sqlite.py

# Or run directly if PostgreSQL is accessible
python src/migrate_to_sqlite.py
```

## 5. Prerequisites

- PostgreSQL source must be running and accessible at `db:5432`
- Destination SQLite path must be writable (`/app/data`)
- All SQLAlchemy models must be importable (via `src.database`)

---

## 6. API Citations

- **SQLAlchemy:** https://docs.sqlalchemy.org/
- **PostgreSQL Connection Strings:** https://docs.sqlalchemy.org/en/20/dialects/postgresql.html
