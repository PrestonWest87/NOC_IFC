# Enterprise Architecture & Functional Specification: `src/services.py`

## 1. Executive Overview

The `src/services.py` module operates as the **Data Access and Abstraction Layer (DAL)** for the Intelligence Fusion Center (IFC). 

Engineered to enforce a strict Service-Oriented Architecture (SOA), this module is the exclusive bridge between the backend database (SQLAlchemy models) and the presentation layer (`src/app.py`). It encapsulates all database transactions, connection pooling, heavy Pandas DataFrame manipulations, and memory caching. By isolating these operations, the architecture ensures the Streamlit UI threads remain lightweight, prevents connection pool exhaustion, and securely handles the new Executive Threat Matrix, Shift Logbook routing, and high-speed PyDeck geospatial math.

---

## 2. Core Architecture: The Translation Pattern

A primary challenge of abstracting SQLAlchemy from Streamlit is that SQLAlchemy ORM objects are intrinsically tied to their underlying database `Session`. If the UI receives a raw ORM object and the session closes, accessing its attributes throws a fatal `DetachedInstanceError`.

### `DotDict` and `to_dotdict(obj)`
* **Mechanism:** The module implements a custom `DotDict` class that inherits from Python's native `dict` but overrides `__getattr__` to allow dot-notation access (e.g., `user.username` instead of `user["username"]`).
* **Execution:** Every fetch function (e.g., `get_user_by_username`, `get_shift_logs`) opens a transient database transaction, extracts the values from the ORM object's columns, constructs a `DotDict`, and immediately closes the session.
* **Architectural Benefit:** The frontend receives a pure, detached Python dictionary that behaves identically to an ORM object, eliminating state-management crashes and database locking issues during rapid UI auto-refreshes.

---

## 3. High-Velocity Memory Caching & Pre-Computation

To protect the backend from the high read-volume of SOC Wall Monitors (which auto-refresh frequently) and heavy geospatial math, the service layer implements aggressive, Time-To-Live (TTL) memory caching via `@st.cache_data`.

* **`get_cached_config()` & `get_cached_locations()`:** Caches API keys, overrides, and critical IT facility coordinates to prevent endless database I/O overhead.
* **`get_cached_geojson()` (TTL: 120s):** Directly reads pre-fetched SPC and NWS JSON payloads from the `GeoJsonCache` database table. This protects external NOAA APIs from rate-limiting bans while feeding the map engine.
* **`get_regional_counties_mapping()` (TTL: 86400s):** Fetches the master US County GeoJSON and explicitly filters for regional FIPS codes (AR, LA, MO, MS, OK, TN, TX). This provides offline, strict boundary mapping for alert generation.
* **`_precompute_geo_matrix()` (TTL: 150s):** The module separates CPU-heavy parsing from UI rendering. It parses massive JSON feeds, builds complex Shapely objects, and calculates intersections ONCE, storing the ready-to-render map layers in memory. 

---

## 4. Executive Dashboard & Multi-Domain Synthesis

This section handles the deterministic scoring and synthesis of intelligence for executive leadership.

### `get_executive_grid_intel(active_warn_count, recent_crimes)`
* **Data Aggregation:** Queries the database for 48-hour Cyber OSINT, physical threats, 14-day ICS advisories, CISA KEVs, and active perimeter incidents.
* **Geopolitical Noise Reduction:** Applies strict keyword heuristics to filter out generic news (e.g., "election", "missile") while boosting intelligence containing BES (Bulk Electric System) terms.
* **FBI UCR Taxonomy (Physical):** Categorizes local incidents natively into "Crimes Against Persons," "Crimes Against Property," or "Crimes Against Society," dynamically altering the physical threat weight based on violence proximity.
* **CIS-Aligned Scoring Engine:** Evaluates active exploits against a 14-day dynamically rolling baseline (or administrative `baseline_override` inputs). Calculates a `unified_risk` mapping to standard MS-ISAC operational tiers: **GREEN, BLUE, YELLOW, ORANGE, RED**.

### `generate_outlook_html_report(intel)`
* Translates the synthesized `unified_risk` and AI briefings into a highly formatted, inline-CSS HTML email template designed specifically to render correctly in Microsoft Outlook, delegating to `mailer.py` for dispatch.

---

## 5. Geospatial Intersections & The Bounding Box Engine

The heaviest computational logic involving Shapely geometries and NWS API routing resides here.

### `process_nws_alerts(data, selected_events, is_oos)`
* **Strict Border Enforcement:** Intercepts the NWS `SAME` codes (six-digit geocodes). By extracting the final five digits as standard FIPS codes, it explicitly routes warnings strictly to the Arkansas [AR] feed (State FIPS '05') or the Out-of-State [OOS] feed, guaranteeing UI segregation.
* **Micro-Feature Optimization:** Strips multi-megabyte GeoJSON bloat, injecting predefined RGBA severity colors directly into the remaining "Micro-Features" before passing them to the frontend.

### `calculate_site_intersections(map_df, master_polygons)`
* **Lightning-Fast Pre-Check Math:** Before executing CPU-intensive point-in-polygon math (`site_pt.within(shape)`), the algorithm extracts the strict min/max boundaries of every weather polygon (`p['bounds']`). 
* **Execution:** It runs a pure float-math evaluation (`minx <= lon <= maxx`). If the facility is not inside the rough square of the storm, it completely skips the expensive Shapely math. This architectural optimization allows the system to process thousands of locations instantly without UI lag.

### `get_infrastructure_analytics(map_df, master_affected_sites)`
* Utilizes Pandas to build real-time exposure analytics (`priority_risk_matrix`, `district_risk_matrix`) correlating facility criticality (P1-P4) directly with explicit hazard severities (e.g., Tornado Warnings, SPC High Risks).

---

## 6. AIOps RCA Engine & Maintenance Controls

### `set_site_maintenance(site_name, is_maint, etr_date, reason)`
* Allows NOC/TOC operators to silence correlation alarms on physical facilities undergoing planned work by directly mutating the `MonitoredLocation` maintenance flags.

### `generate_global_sitrep(sys_config_dict)`
* **Orchestration:** Initializes the `EnterpriseAIOpsEngine` and feeds it all active, un-correlated `SolarWindsAlert` objects alongside live weather, cloud, and BGP telemetry to identify "Patient Zero".
* **AI Over-Watch:** Passes the deterministic report to the LLM to generate a strict, 2-sentence executive summary appended to the top of the SitRep.

### `generate_rca_ticket_text(site, data, priority, patient_zero, root_cause)`
* Automates ITSM operational workflows. Translates the deeply nested, correlated Incident Object directly into formatted, ITSM-ready text utilized by the frontend to dispatch RemedyForce email tickets instantly.

---

## 7. Administrative & Destructive Failsafes

### `recategorize_all_articles()`
* **Retroactive Maintenance:** Iterates over every historical article in the database and re-runs the text through the `categorize_text` regex engine. Ensures that if the taxonomy is updated, old intelligence is instantly realigned to the new domains.

### `nuke_weather_data()` & `nuke_tables(model_names)`
* **The Cross-Dialect Solution:** Executing raw SQL `TRUNCATE CASCADE` commands works in PostgreSQL but throws fatal syntax errors in SQLite. This function accepts an array of model string names, maps them to the actual ORM classes, and executes a pure SQLAlchemy `.delete()`. 
* **Operational Failsafe:** `nuke_weather_data` acts as a kill-switch to purge both the `RegionalHazard` and `GeoJsonCache` tables and forces all location risks back to "None", ensuring corrupted or stalled NOAA API data can be flushed instantly without rebooting the Docker containers.
