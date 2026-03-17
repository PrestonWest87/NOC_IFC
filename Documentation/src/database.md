# Enterprise Architecture & Data Dictionary: `src/database.py`

*(Note: We covered the architecture for `database.py` earlier in our session, but here is the formalized, comprehensive enterprise documentation based on the exact code you just provided to ensure your project documentation is complete.)*

## 1. Executive Overview

The `src/database.py` module is the **Data Persistence and ORM Foundation** of the Intelligence Fusion Center (IFC). It leverages SQLAlchemy to map Python objects to relational database tables. The architecture is designed to be highly portable, seamlessly transitioning between a lightweight, file-based **SQLite** database (ideal for Dockerized/edge deployments) and an enterprise **PostgreSQL** cluster.

It defines the entirety of the application's schema—encompassing Identity and Access Management (IAM), raw threat intelligence, infrastructure telemetry, and AIOps correlation states—and provides a self-healing bootstrap sequence (`init_db`) to seed initial requirements.

---

## 2. Engine Architecture & Connection Management

The database engine dynamically configures its connection pooling and threading behavior based on the detected database dialect via the `DATABASE_URL` environment variable.

### 2.1 SQLite Mode (Edge/Container Default)
* **Trigger:** `DATABASE_URL.startswith("sqlite")`
* **Configuration:** `connect_args={"check_same_thread": False}`
* **Purpose:** This is a critical configuration for Streamlit. Streamlit and background worker scripts (like `scheduler.py`) spawn multiple threads. Disabling the `check_same_thread` constraint prevents SQLite from throwing `ProgrammingError` exceptions when a background thread writes to the database while the UI thread is reading from it.

### 2.2 PostgreSQL Mode (Enterprise Scale)
* **Trigger:** Any non-SQLite URI.
* **Configuration:** `pool_size=20, max_overflow=30, pool_pre_ping=True, pool_recycle=3600`
* **Purpose:** Establishes a robust connection pool. `pool_pre_ping` ensures connections are alive before handing them to the application (preventing "MySQL has gone away" style errors), and `pool_recycle` prevents stale connections from lingering indefinitely.

### 2.3 Transaction Management
* **`SessionLocal`**: A `sessionmaker` configured with `autocommit=False` and `autoflush=False`. This enforces strict ACID compliance across the application, requiring developers to explicitly call `session.commit()` to persist state changes, allowing safe rollbacks via `session.rollback()` in the event of worker failures.

---

## 3. Object-Relational Mapping (ORM) Models

The schema is divided into distinct operational domains, all inheriting from SQLAlchemy's `declarative_base()`.

### 3.1 Identity & Access Management (RBAC)
* **`User`**: Stores operator credentials with `bcrypt` encrypted passwords (`password_hash`). Manages UI sessions via `session_token` and stores user metadata (`full_name`, `job_title`).
* **`Role`**: Dictates application permissions. Employs `JSON` columns (`allowed_pages`, `allowed_actions`) to grant granular access to main dashboard tabs and specific interaction buttons (e.g., pinning, training ML).

### 3.2 Threat Intelligence & OSINT
* **`Article`**: The core repository for parsed RSS feeds. Stores raw text (`summary`, `title`), contextual metadata (`source`, `category`, `score`), JSON arrays of `keywords_found`, and LLM-generated summaries (`ai_bluf`). Integrates a `human_feedback` integer for reinforcement learning.
* **`FeedSource` & `Keyword`**: Configuration tables defining the RSS URLs to poll and the weighted vocabulary used to score threat severity.
* **`ExtractedIOC`**: Stores specific Indicators of Compromise (IPs, Domains, SHA256 hashes) extracted from high-scoring articles via Regex, linking back to the parent `article_id`.
* **`CveItem`**: A localized mirror of the CISA Known Exploited Vulnerabilities catalog.

### 3.3 Infrastructure & Telemetry Status
* **`MonitoredLocation`**: Represents the physical geofenced NOC sites (Datacenters, Branches). Stores exact `lat`/`lon` coordinates, routing `priority`, and caches the `current_spc_risk` (Severe weather threat level).
* **`RegionalHazard` & `RegionalOutage`**: Tracks physical threats (NWS/SPC weather polygons) and major ISP/Power grid failures. Includes a `radius_km` field to calculate geospatial intersection with `MonitoredLocations`.
* **`CloudOutage` & `BgpAnomaly`**: Tracks unresolved global SaaS/IaaS degradation (e.g., AWS, Azure) and internet routing disruptions affecting tracked ASNs.

### 3.4 AIOps & Incident Correlation
* **`SolarWindsAlert`**: The primary ingestion table for external ITSM/NMS webhooks. Stores the original JSON (`raw_payload`), maps the alert to a physical site (`mapped_location`), and tracks the AI correlation state (`is_correlated`, `ai_root_cause`).
* **`TimelineEvent`**: A specialized chronological audit log feeding the live RCA dashboard. Tracks alerts, AI decisions, and system events.
* **`NodeAlias`**: A Machine Learning translation table mapping raw, unstandardized device strings (`node_pattern`) to formal location names (`mapped_location_name`), alongside an AI `confidence_score`.

### 3.5 System Configuration & Output
* **`SystemConfig`**: A singleton table managing global variables. Stores LLM API keys/endpoints, internal `tech_stack` context, and SMTP server credentials for automated broadcasting.
* **`SavedReport` & `DailyBriefing`**: Archives of ad-hoc intelligence reports generated by analysts and automated, AI-synthesized daily operational summaries.

---

## 4. Database Bootstrap & Seeding (`init_db`)

The `init_db()` function is a self-healing initialization sequence executed at application startup.

### 4.1 Schema Generation & Migration Fallback
1.  **Creation:** Utilizes `Base.metadata.create_all(bind=engine)` to automatically generate the full schema if it does not exist.
2.  **Dialect Failsafe:** It includes a list of raw SQL strings (`ALTER TABLE`, `CREATE INDEX`) traditionally used for PostgreSQL schema evolution. However, the script intelligently checks `if not DATABASE_URL.startswith("sqlite"):` before attempting to execute them. This prevents syntax crashes in SQLite while maintaining backward compatibility for Postgres deployments.

### 4.2 Application Seeding (Zero-Config Setup)
To prevent lockout on a fresh deployment, the script checks the database state and automatically seeds essential data:
1.  **Roles:** Generates the `admin` (access to all pages/actions) and `analyst` (restricted pages) roles, populating their JSON permission arrays dynamically from hardcoded lists.
2.  **Master User:** If the `User` table is entirely empty, it generates a default administrator account (`admin` / `admin123`) to guarantee immediate system access.
