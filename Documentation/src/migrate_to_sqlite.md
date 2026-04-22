# Enterprise Architecture & Functional Specification: `src/migrate_to_sqlite.py`

## 1. Executive Overview

The `src/migrate_to_sqlite.py` module is a **data migration utility** that transfers all data from a PostgreSQL source database to a SQLite destination file. It is designed for edge-compute scenarios where the system migrates from a full PostgreSQL deployment to a lightweight SQLite instance.

---

## 2. Configuration

### Database URLs

| Parameter | Value | Description |
|-----------|-------|-------------|
| `PG_URL` | `postgresql://admin:adminpass@db:5432/rss_db` | Source PostgreSQL |
| `SQLITE_URL` | `sqlite:////app/data/noc_fusion.db` | Destination SQLite |

**Note:** These are hardcoded for the Docker Compose environment. Modify directly for other migrations.

---

## 3. Execution Flow

### Main Block (Lines 11-41)

The script executes as a standalone utility (not an importable module):

1. **Connect to PostgreSQL** - Creates SQLAlchemy engine from `PG_URL`
2. **Connect to SQLite** - Creates destination DB file (auto-creates `/app/data` directory)
3. **Build Schema** - Calls `Base.metadata.create_all()` to create all tables
4. **Transfer Data** - Iterates through all tables in `Base.metadata.tables`:
   - Wipes any auto-generated data in SQLite first
   - Fetches all rows from PostgreSQL
   - Converts to dictionaries and bulk-inserts to SQLite
5. **Reports Status** - Prints row counts per table

---

## 4. Migration Log Example

```
 Connecting to Postgres source...
 Connecting to SQLite destination...
 Building schema...
 Transferring data...
  Table: users...
   [OK] 42 rows transferred.
  Table: roles...
   [OK] 8 rows transferred.
  Table: articles...
   [OK] 1,547 rows transferred.
  ...
  Done! Data safely written to /app/data/noc_fusion.db
```

---

## 5. Usage

```bash
# Run inside the worker container after PostgreSQL is running
docker compose exec worker python src/migrate_to_sqlite.py

# Or run directly if PostgreSQL is accessible
python src/migrate_to_sqlite.py
```

---

## 6. Prerequisites

- PostgreSQL source must be running and accessible at `db:5432`
- Destination SQLite path must be writable (`/app/data`)
- All SQLAlchemy models must be importable (via `src.database`)

---

## 7. API Citations

- **SQLAlchemy:** https://docs.sqlalchemy.org/
- **PostgreSQL Connection Strings:** https://docs.sqlalchemy.org/en/20/dialects/postgresql.html
- **SQLite in Docker:** https://github.com/boot5c5c/docs/blob/main/Boot%20User%20Manual%20-%20SQLite%20in%20Docker.md