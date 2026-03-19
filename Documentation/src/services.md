# Enterprise Architecture & Functional Specification: `src/services.py`

## 1. Executive Overview

The `src/services.py` module is the **Data Access and Abstraction Layer (DAL)** for the Intelligence Fusion Center (IFC). 

Introduced during the refactoring to a strict Service-Oriented Architecture (SOA), this module is the exclusive bridge between the database (SQLAlchemy models) and the presentation layer (`app.py`). It encapsulates all database transactions, connection pooling, complex business logic, and memory caching. By isolating these operations, the architecture ensures that UI threads remain lightweight, prevents connection pool exhaustion, and enables seamless data mocking for future unit testing.

---

## 2. Core Architecture: The `DotDict` Translation Pattern

One of the primary challenges of abstracting SQLAlchemy from Streamlit is that SQLAlchemy ORM objects are intrinsically tied to their underlying database `Session`. If `app.py` receives a raw ORM object and the session closes, any attempt to access its attributes will throw a `DetachedInstanceError`.

### `DotDict` and `to_dotdict(obj)`
* **Mechanism:** The module implements a custom `DotDict` class that inherits from Python's native `dict` but overrides `__getattr__` to allow dot-notation access (e.g., `user.username` instead of `user["username"]`).
* **Execution:** Every fetch function (e.g., `get_user_by_username`, `get_cached_locations`) queries the database, extracts the values from the ORM object's columns, constructs a `DotDict`, and immediately closes the session.
* **Benefit:** `app.py` receives a pure, detached Python dictionary that *behaves* exactly like an ORM object, eliminating state-management crashes in the UI entirely.

---

## 3. High-Velocity Memory Caching (The `@st.cache_data` Fleet)

To protect the SQLite/PostgreSQL backend from the high read-volume of the SOC Wall Monitors (which refresh every 60 seconds), the service layer implements aggressive, Time-To-Live (TTL) memory caching.

* **`get_cached_config()` (TTL: 300s):** Caches the `SystemConfig` table. Prevents the app from querying the database for LLM API keys on every single page re-render.
* **`get_cached_locations()` (TTL: 600s):** Caches the `MonitoredLocation` coordinate data, capped at `max_entries=1`. Because NOC locations rarely change, this saves massive I/O overhead during the geospatial intersection algorithms.
* **`get_cached_geojson()` (TTL: 120s):** Caches the live NOAA SPC and NWS API responses. *Critical for external rate-limiting.* Without this, a 5-user dashboard would hit the US Government APIs 5 times per minute, risking IP blacklisting.
* **`get_ar_counties_mapping()` (TTL: 86400s):** Caches the static GitHub GeoJSON file for Arkansas county boundaries for 24 hours.

---

## 4. Identity & Access Management (IAM)

This cluster manages secure authentication and Role-Based Access Control.
* **`authenticate_user(username, password)`:** Opens a transient DB session, verifies the `bcrypt` password hash, mints a new UUID `session_token`, commits it, and returns the sanitized user object.
* **`update_user_profile(...)`:** Securely validates the operator's old password before allowing an update to their new password or contact info.
* **`create_role(...)` & `update_role(...)`:** Translates the UI's multi-select arrays of allowed pages/actions into JSON strings and commits them to the `roles` table.

---

## 5. Threat Intelligence & Telemetry Fetchers

These functions abstract the complex `.filter()` and `.order_by()` SQLAlchemy chains away from the frontend.

* **`get_paginated_articles(feed_type, cat_filter, page, ...)`:** * Calculates total items and total pages. 
    * Applies `offset()` and `limit()` mathematically based on the current page size.
    * Dynamically swaps `order_by()` logic (e.g., ordering Live feeds chronologically, but ordering Deep Search feeds by `score.desc()`).
* **`get_iocs(days_back=3)`:** Executes a relational join to fetch both the `ExtractedIOC` artifact and its parent `Article.link` so operators can pivot to the source intel.
* **`get_aiops_dashboard_data()`:** A master fetcher that hits four distinct tables simultaneously (`SolarWindsAlert`, `TimelineEvent`, `RegionalOutage`, `NodeAlias`) to populate the entire AIOps view in a single lifecycle.

---

## 6. Geospatial Intersections & NWS Analytics

The heaviest computational logic in the system is centralized here.

### 6.1 `process_nws_alerts(data, selected_events, is_oos)`
* **Memory Optimization:** Rather than storing the entire massive, multi-megabyte GeoJSON payload in the Streamlit UI state, this function strips out the bloat. It builds a "Micro-Feature" dictionary containing only the `geometry`, severity color codes, and pre-compiled `shapely` objects.
* **County-to-Polygon Fallback:** If an NWS alert fails to provide geometric coordinates (which occasionally happens), the function intercepts the text `areaDesc` (e.g., "Pulaski County; Saline County"). It cross-references these strings against the `get_ar_counties_mapping()` cache to artificially stitch the missing polygons back together, ensuring the map always renders accurately.

### 6.2 `calculate_site_intersections(map_df, active_polygons)`
* Iterates over every monitored IT facility.
* Executes `site_pt.within(p["shape"])` against every active severe weather polygon.
* Generates two distinct data outputs: `toggled_affected_sites` (for the map UI based on current visual filters) and `master_affected_sites` (for the Executive Broadcast logic).

---

## 7. Administrative & Destructive Failsafes

### `nuke_tables(model_names)`
* **The Problem:** Executing raw SQL `TRUNCATE CASCADE` commands works flawlessly in PostgreSQL but throws fatal syntax errors in SQLite.
* **The Cross-Dialect Solution:** This function accepts an array of model string names (e.g., `["CloudOutage", "MonitoredLocation"]`). It maps the string to the actual ORM Model class and executes a pure SQLAlchemy `db.query(Model).delete(synchronize_session=False)`. This ensures that a "Factory Reset" from the UI executes safely regardless of the underlying database engine.
