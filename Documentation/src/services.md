# Enterprise Architecture & Functional Specification: `src/services.py`

## 1. Executive Overview

The `src/services.py` module operates as the **Data Access and Abstraction Layer (DAL)** for the Intelligence Fusion Center (IFC). 

Engineered to enforce a strict **Service-Oriented Architecture (SOA)**, this module acts as the exclusive bridge between the backend database (SQLAlchemy models) and the presentation layer (`src/app.py`). It encapsulates all database transactions, connection pooling, heavy Pandas DataFrame manipulations, and memory caching. By isolating these operations, the architecture ensures the Streamlit UI threads remain lightweight, prevents connection pool exhaustion, and securely handles the complex calculations required by the new **Internal Asset Risk Matrix**, **AI Shift Logbook**, and **Global Fleet Detection** engines.

---

## 2. Core Architecture: The Translation Pattern

A primary challenge of abstracting SQLAlchemy from a live-refreshing Streamlit UI is that SQLAlchemy ORM objects are intrinsically tied to their underlying database `Session`. If the UI receives a raw ORM object and the session closes, accessing its attributes throws a fatal `DetachedInstanceError`.

### `DotDict` and `to_dotdict(obj)`
* **Mechanism:** The module implements a custom `DotDict` class that inherits from Python's native `dict` but overrides `__getattr__` to allow dot-notation access (e.g., `user.username` instead of `user["username"]`).
* **Execution:** Every fetch function (e.g., `get_user_by_username`, `get_shift_logs`) opens a transient database transaction, extracts the values from the ORM object's columns, constructs a `DotDict`, and immediately closes the session.
* **Architectural Benefit:** The frontend receives a pure, detached Python dictionary that behaves identically to an ORM object, eliminating state-management crashes and database locking issues during rapid UI auto-refreshes.

---

## 3. High-Velocity Memory Caching & Pre-Computation

To protect the backend from the high read-volume of SOC Wall Monitors (which auto-refresh every 5 to 60 seconds) and heavy geospatial math, the service layer implements aggressive, Time-To-Live (TTL) memory caching via `@st.cache_data`.

* **`get_cached_config()` & `get_cached_locations()`:** Caches global variables, API keys, and thousands of IT facility coordinates to prevent endless database I/O overhead.
* **`get_cached_geojson()` (TTL: 120s):** Directly reads pre-fetched SPC and NWS JSON payloads from the `GeoJsonCache` table rather than hitting external APIs. This completely protects NOAA endpoints from rate-limiting bans while ensuring the map engine renders instantly.
* **`compile_regional_grid_map(...)`:** Separates CPU-heavy parsing from UI rendering. It parses massive JSON feeds, calculates intersections, and builds complex Shapely/PyDeck map layers, returning ready-to-render objects directly to the Streamlit UI.

---

## 4. Executive Dashboards & Internal Asset Risk

This section handles the deterministic scoring, data synthesis, and integration with the organization's internal hardware footprint.

### `get_executive_grid_intel(active_warn_count, recent_crimes)`
* **Data Aggregation:** Queries the database for 48-hour Cyber OSINT, physical threats, 14-day ICS advisories, CISA KEVs, and active perimeter incidents.
* **CIS-Aligned Scoring Engine:** Evaluates active threats against a 14-day dynamically rolling baseline. Calculates a `unified_risk` mapping to standard MS-ISAC operational tiers: **GREEN, BLUE, YELLOW, ORANGE, RED**.

### `generate_and_save_internal_risk_snapshot()`
* **Purpose:** An optimization function designed to run in the background (or forced via the UI) to prevent calculating massive join queries during a live dashboard load.
* **Execution:** Cross-references thousands of `HardwareAsset` and `SoftwareAsset` rows against the active `CveItem` (KEV) database and 72-hour `ExtractedIOC` threat telemetry. It tallies "At-Risk" assets and produces a hardened `InternalRiskSnapshot` JSON payload that the UI queries to render the 14-day deviation trend graph.

---

## 5. Shift Logbook & RCA Ticket Dispatch

Manages the tactical operational workflows, bridging the gap between passive telemetry monitoring and active human response.

### `get_shift_logs` & `save_shift_log`
* **Role-Bound Isolation:** Extracts and saves tactical running notes explicitly bound to the operator's `author_role` (e.g., TOC vs. NOC) and shift period (Morning/Evening). Filters out entries flagged with `is_deleted` for standard users, while allowing Admins full audit visibility.

### `set_site_maintenance(site_name, is_maint, etr_date, reason)`
* Allows operators to directly mutate the `MonitoredLocation` maintenance flags. When active, this forces the `app.py` UI to silence AIOps correlation alarms for that facility and explicitly displays the estimated time of restoration (ETR) on the Active Board.

### `set_cluster_dispatch(alert_ids, is_dispatched)`
* Tracks the operational lifecycle of a network outage. Once an operator clicks "Dispatch Ticket," this service updates the `is_dispatched` flag for all raw `SolarWindsAlert` records inside that specific cluster, visually checking off the incident on the active board to prevent duplicate efforts.

---

## 6. Geospatial Intersections & Bounding Box Engine

The heaviest computational logic involving Shapely geometries and NWS API routing resides here.

### `process_nws_alerts(data, selected_events, is_oos)`
* **Micro-Feature Optimization:** Strips multi-megabyte GeoJSON bloat. It injects predefined RGBA severity colors directly into the remaining "Micro-Features" before passing them to the PyDeck map.

### `calculate_site_intersections(map_df, master_polygons)`
* **Lightning-Fast Pre-Check Math:** Before executing CPU-intensive point-in-polygon math (`site_pt.within(shape)`), the algorithm extracts the strict min/max boundaries of every weather polygon (`p['bounds']`). 
* **Execution:** It runs a pure float-math evaluation (`minx <= lon <= maxx`). If the facility is not inside the rough square of the storm, it completely skips the expensive Shapely math. This architectural optimization allows the system to evaluate thousands of IT locations against national weather systems instantly without UI latency.

---

## 7. Administrative & Destructive Failsafes

### `recategorize_all_articles()`
* **Retroactive Maintenance:** Iterates over every historical article in the database and re-runs the text through the `categorize_text` regex engine. Ensures that if the taxonomy is updated, old intelligence is instantly realigned to the new domains.

### `nuke_crime_data()`, `nuke_weather_data()`, & `nuke_tables(model_names)`
* **The Cross-Dialect Solution:** Executing raw SQL `TRUNCATE CASCADE` commands works in PostgreSQL but throws fatal syntax errors in SQLite. This function accepts an array of model string names, maps them to the actual ORM classes, and executes a pure SQLAlchemy `.delete()`.
* **Kill-Switch Operations:** Allows administrators in the UI's "Danger Zone" to instantly purge corrupted NOAA/SPC geometry caches or Local CAD data without rebooting the Docker containers, forcing a clean data pull on the next scheduler tick.
