# Enterprise Architecture & Functional Specification: `src/services.py`

## 1. Executive Overview

The `src/services.py` module operates as the **Data Access and Abstraction Layer (DAL)** for the Intelligence Fusion Center (IFC). 

Engineered to enforce a strict Service-Oriented Architecture (SOA), this module is the exclusive bridge between the backend database (SQLAlchemy models) and the presentation layer (`src/app.py`). It encapsulates all database transactions, connection pooling, heavy Pandas DataFrame manipulations, and memory caching. By isolating these operations, the architecture ensures the Streamlit UI threads remain lightweight, prevents connection pool exhaustion, and securely handles the new Executive Dashboard and Crime Intelligence synthesis logic.

---

## 2. Core Architecture: The Translation Pattern

A primary challenge of abstracting SQLAlchemy from Streamlit is that SQLAlchemy ORM objects are intrinsically tied to their underlying database `Session`. If the UI receives a raw ORM object and the session closes, accessing its attributes throws a fatal `DetachedInstanceError`.

### `DotDict` and `to_dotdict(obj)`
* **Mechanism:** The module implements a custom `DotDict` class that inherits from Python's native `dict` but overrides `__getattr__` to allow dot-notation access (e.g., `user.username` instead of `user["username"]`).
* **Execution:** Every fetch function (e.g., `get_user_by_username`, `get_cached_locations`) opens a transient database transaction, extracts the values from the ORM object's columns, constructs a `DotDict`, and immediately closes the session.
* **Architectural Benefit:** The frontend receives a pure, detached Python dictionary that behaves identically to an ORM object, eliminating state-management crashes and database locking issues during UI re-renders.

---

## 3. High-Velocity Memory Caching

To protect the backend from the high read-volume of SOC Wall Monitors (which auto-refresh frequently), the service layer implements aggressive, Time-To-Live (TTL) memory caching via `@st.cache_data`.

* **`get_cached_config()` (TTL: 300s):** Caches the `SystemConfig` table, preventing the application from querying the database for LLM API keys on every single page re-render.
* **`get_cached_locations()` (TTL: 600s):** Caches the `MonitoredLocation` coordinate data. Because NOC locations rarely change, this saves massive I/O overhead during complex geospatial intersection algorithms.
* **`get_cached_geojson()` (TTL: 120s):** Caches the live NOAA SPC and NWS API responses. This is critical for external rate-limiting; without it, multiple active dashboards would hammer US Government APIs, risking IP blacklisting.
* **`get_ar_counties_mapping()` (TTL: 86400s):** Caches static GeoJSON files representing state county boundaries for 24 hours to support offline geometric fallback mapping.

---

## 4. Executive Dashboard & Crime Intelligence Integration

This section handles the synthesis of multi-domain intelligence for executive leadership.

### `get_executive_grid_intel(active_warn_count, recent_crimes)`
* **Data Aggregation:** Queries the database for 48-hour Cyber OSINT, 48-hour Physical OSINT, 14-day ICS-CERT advisories, and 168-hour active Crime Incidents.
* **Noise Reduction:** Applies strict keyword heuristics to filter out geopolitical noise (e.g., "election", "troop") from cyber and physical intelligence arrays, isolating only threats relevant to Bulk Electric System (BES) infrastructure.
* **Scoring Matrix:** Calculates an independent `cyber_score` and `physical_score` based on threat volume and severity. It then calculates a overarching `unified_risk` (HIGH, MEDIUM, LOW).

### `generate_outlook_html_report(intel)` & `send_executive_report(...)`
* **Formatting:** Translates the synthesized `unified_risk` into a highly formatted, inline-CSS HTML email template designed specifically to render correctly in Microsoft Outlook.
* **Dispatch:** Hands the payload directly to `src.mailer.send_alert_email` for immediate autonomous broadcast to executive distribution lists.

---

## 5. Geospatial Intersections & Threat Telemetry

The heaviest computational logic involving Shapely geometries and external API routing resides here.

### `process_nws_alerts(data, selected_events, is_oos)`
* **Memory Optimization:** Rather than storing massive, multi-megabyte GeoJSON payloads in the UI state, this function strips out the bloat. It builds a "Micro-Feature" dictionary containing only the geometry, severity color codes, and pre-compiled `shapely` objects.
* **County-to-Polygon Fallback:** If an NWS alert fails to provide geometric coordinates, the function intercepts the text `areaDesc` (e.g., "Pulaski County"). It cross-references these strings against the cached county mapping to artificially stitch the missing polygons back together, ensuring the map always renders.

### `get_active_wildfires()`
* **ArcGIS Integration:** Executes targeted REST queries against the National Interagency Fire Center (NIFC) database.
* **Filtration:** Drops prescribed burns (RX), 100% contained fires, and fires under 0.1 acres, converting the remaining critical hazards into map-ready GeoJSON features.

### `calculate_site_intersections` & `get_infrastructure_analytics`
* Iterates over every monitored IT facility using Pandas DataFrames.
* Executes point-in-polygon math (`site_pt.within(p["shape"])`) against active severe weather and wildfire geometries to generate immediate blast-radius analytics.

---

## 6. AIOps Root Cause Analysis (RCA) Engine Support

### `generate_global_sitrep(sys_config_dict)`
* **Orchestration:** Initializes the `EnterpriseAIOpsEngine` and feeds it all active, un-correlated `SolarWindsAlert` objects alongside live weather, cloud, and BGP telemetry.
* **Synthesis:** Compiles the deterministic calculations (Patient Zero, Blast Radius, Cascade Delay) into a structured Markdown report.
* **AI Over-Watch:** Passes the deterministic report to the LLM via `call_llm` to generate a strict, 2-sentence executive summary appended to the top of the SitRep.

---

## 7. Administrative & Destructive Failsafes

### `recategorize_all_articles()`
* **Purpose:** A retroactive maintenance function.
* **Execution:** Iterates over every historical article in the database and re-runs the text through the `categorize_text` regex engine. This ensures that if the taxonomy is updated, old intelligence is instantly realigned to the new organizational domains.

### `nuke_tables(model_names)`
* **The Cross-Dialect Solution:** Executing raw SQL `TRUNCATE CASCADE` commands works in PostgreSQL but throws fatal syntax errors in SQLite. This function accepts an array of model string names, maps them to the actual ORM classes, and executes a pure SQLAlchemy `.delete(synchronize_session=False)`. This ensures that a "Factory Reset" triggered from the UI Danger Zone executes safely regardless of the underlying database deployment.
