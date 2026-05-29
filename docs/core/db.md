# Core Database Module

**File:** `src/core/db.py`

Provides the SQLAlchemy engine, session factory, database initialization (schema creation, migrations, defaults seeding), and a FastAPI-compatible dependency injection helper.

---

## Module-Level Objects

### `engine`

SQLAlchemy `Engine` instance created with the configured `DATABASE_URL`. For SQLite, it passes `connect_args={"check_same_thread": False, "timeout": 30}` to allow cross-thread access and a 30-second connection timeout.

### `SessionLocal`

`sessionmaker` bound to `engine`, configured with `autocommit=False` and `autoflush=False`. Used as the session factory throughout the application.

---

## Event Listener: `set_sqlite_pragma`

### Purpose
SQLAlchemy event listener attached to the engine's `"connect"` event. Executes performance-optimizing PRAGMA statements on every new SQLite connection.

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `dbapi_connection` | `object` | The raw DBAPI connection object (e.g., `sqlite3.Connection`). |
| `connection_record` | `object` | The connection record from SQLAlchemy's connection pool. |

### Returns
`None`

### Raises
None.

### Flow
1. Obtains a cursor from the raw connection.
2. Executes five PRAGMA statements in sequence:
   - `journal_mode=WAL` — enables Write-Ahead Logging for better concurrent reads.
   - `synchronous=NORMAL` — reduces fsync calls for improved write performance.
   - `cache_size=-16000` — sets page cache to 16 MB (negative = kibibytes).
   - `temp_store=MEMORY` — stores temporary tables/indexes in memory.
   - `mmap_size=268435456` — enables memory-mapped I/O with 256 MB limit.
3. Closes the cursor.

### Dependencies
- `sqlalchemy.event` — for `@event.listens_for` decorator.
- SQLite `DBAPI` — the PRAGMA statements are SQLite-specific.

---

## Generator: `get_db()`

### Purpose
FastAPI dependency generator that yields a database session and ensures it is closed after the request completes.

### Parameters
None.

### Yields
| Type | Description |
|------|-------------|
| `sqlalchemy.orm.Session` | A new `SessionLocal` instance. |

### Raises
None.

### Flow
1. Creates a new `SessionLocal()` session.
2. `yield`s the session to the caller (FastAPI route handler).
3. In the `finally` block, closes the session, releasing the connection back to the pool.

### Dependencies
- `SessionLocal` — session factory defined in this module.

---

## Function: `init_db()`

### Purpose
Comprehensive database initialization routine. Creates all tables from SQLAlchemy ORM models, applies schema migrations for columns added after initial deployment, seeds default roles, an admin user, RSS feed sources, and scoring keywords, then triggers article rescoring.

### Parameters
None.

### Returns
`None`

### Raises
None. All exceptions are caught, logged, and suppressed to make initialization resilient to partial failures.

### Flow

#### Phase 1 — Random Sleep
Sleeps a random interval between 0.1 and 1.5 seconds to stagger initialization when multiple processes start simultaneously.

#### Phase 2 — Schema Creation
Calls `Base.metadata.create_all(bind=engine)` to create all tables defined in model classes. Errors are logged but do not halt execution.

#### Phase 3 — Schema Migrations (Idempotent `ALTER TABLE`)
Each migration is wrapped in a `try/except` block that silently passes on failure (column already exists). Executed with `AUTOCOMMIT` isolation level:

1. `roles` → add `allowed_site_types` (JSON)
2. `solarwinds_alerts` → add `is_dispatched` (BOOLEAN, default 0)
3. `monitored_locations` → add `district` (VARCHAR, default `'Central'`)
4. `shift_logs` → add `author_role` (VARCHAR, default `'analyst'`)
5. `system_config` → add `baseline_override_cyber` and `baseline_override_phys` (FLOAT, default 0.0)
6. `monitored_locations` → add `under_maintenance`, `maintenance_etr`, `maintenance_reason`
7. Create `user_weather_prefs` table if not exists, with index on `username`
8. `shift_logs` → add `is_deleted` (BOOLEAN, default 0)
9. `system_config` → add `unified_brief`, `unified_brief_time`
10. `users` → add `default_shift` (VARCHAR, default `'No Shift'`)
11. `crime_incidents` → add `is_alert_dispatched` (BOOLEAN, default 0)
12. `system_config` → add `last_global_risk`, `last_internal_risk`, `last_risk_alert_time`, `sys_countermeasures`, `net_countermeasures`
13. `solarwinds_alerts` → add `is_ticketed`; `monitored_locations` → add `last_auto_ticket`, `last_escalation_ticket`, `last_auto_dispatch`, `last_escalation_dispatch`, `status_modified_by`, `status_modified_at`

#### Phase 4 — Roles and Admin User Seeding
Opens a `SessionLocal` session:

1. Defines `all_pages` — list of 8 top-level navigation page names.
2. Defines `all_actions` — list of 38 granular action/tab permission strings.
3. **Admin Role**: Creates or updates a role named `"admin"` with all pages and all actions.
4. **Analyst Role**: Creates or updates a role named `"analyst"` with all pages except `"Settings & Admin"` and all actions.
5. **Admin User**: If no users exist, creates the default `"admin"` user with:
   - Username: `admin`
   - Password: `admin123` (bcrypt-hashed with generated salt)
   - Role: `admin`
   - Full name: `"Preston"`
   - Job title: `"Network Operations Analyst"`
   - Contact info: `"NOC Desk"`
6. Commits the transaction. On error, rolls back and logs.

#### Phase 5 — RSS Feed Sources Seeding
Opens a separate `SessionLocal` session. Inserts 7 default RSS feed sources if they do not already exist (checked by URL):

| URL | Name |
|-----|------|
| `https://feeds.feedburner.com/TheHackersNews` | The Hacker News |
| `https://krebsonsecurity.com/feed/` | Krebs on Security |
| `https://www.bleepingcomputer.com/feed/` | BleepingComputer |
| `https://feeds.a.dj.com/rss/RSSWorldNews.xml` | WSJ World News |
| `https://www.cisa.gov/cybersecurity-advisories/all.xml` | CISA Advisories |
| `https://www.darkreading.com/rss.xml` | Dark Reading |
| `https://therecord.media/feed/` | The Record |

Logs the count of newly added feeds.

#### Phase 6 — Keywords Seeding
Opens a separate `SessionLocal` session. Inserts 70 default scoring keywords with weights if they do not already exist (checked by word). Keywords cover:

- **Threat types**: ransomware, breach, zero-day, exploit, malware, ddos, phishing, backdoor, trojan, spyware, wiper, botnet, C2 infrastructure
- **Attack techniques**: lateral movement, privilege escalation, data exfiltration, supply chain, RCE
- **Tools/Frameworks**: Cobalt Strike, Log4j, Log4Shell, SolarWinds
- **Threat actors/groups**: LockBit, BlackCat, Clop, AlphV, Conti, APT, nation-state
- **Organizations**: CISA, FBI, NSA, NATO
- **Topics**: disinformation, deepfake, AI/ML, drones/UAVs, military, defense, critical infrastructure, power grid, energy, financial, cryptocurrency
- **Network/infrastructure**: BGP, submarine cable, outage, degraded, disruption

Logs the count of newly added keywords.

#### Phase 7 — Article Rescoring
Imports `rescore_all_articles` from `src.services` and calls it to re-score all existing articles against the newly seeded keywords. Logs the number of rescored articles.

### Dependencies

| Dependency | Usage |
|------------|-------|
| `sqlalchemy` (`create_engine`, `text`, `event`) | Engine creation, raw SQL execution |
| `sqlalchemy.orm.sessionmaker` | Session factory |
| `src.models.Base` | Declarative base for `create_all` |
| `src.core.config.DATABASE_URL` | Database connection string |
| `src.models.schema.Role`, `User`, `FeedSource`, `Keyword` | ORM models for seeding |
| `bcrypt` | Password hashing for default admin user |
| `src.services.rescore_all_articles` | Article rescoring after keyword seeding |
| `logging` | Error/warning logging |
| `time`, `random` | Staggered sleep |
