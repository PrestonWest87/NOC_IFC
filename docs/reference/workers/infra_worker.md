# Infra Worker Module

**File:** `src/workers/infra_worker.py`

## Overview

Ingests regional infrastructure hazard data from three federal sources: the Storm Prediction Center (SPC) convective outlooks, National Weather Service (NWS) active alerts, and USGS earthquake feeds. Caches GeoJSON data for map visualisation, persists structured hazard records, and triggers email alerts when earthquakes are detected within proximity of monitored sites.

---

## Constants

### `CENTRAL_TZ` (`ZoneInfo`)

`America/Chicago` timezone for local time display in alert bodies.

### `SPC_URLS` (`dict[str, str]`)

Three SPC convective outlook GeoJSON URLs (day 1, day 2, day 3).

### `USGS_BOUNDS` (`dict[str, dict]`)

Bounding boxes for USGS earthquake queries:
- `"ar"`: Arkansas region (`[33.0, 36.5, -94.5, -89.6]`)
- `"oos"`: Out-of-state region (`[33.0, 37.5, -95.5, -89.0]`)

---

## Functions

### `save_geojson_to_db(session: Session, feed_name: str, data: dict) -> None`

- **Purpose:** Upsert raw GeoJSON data into the `GeoJsonCache` table for later retrieval by the frontend map layer.
- **Parameters:**
  - `session` (`sqlalchemy.orm.Session`): Active database session.
  - `feed_name` (`str`): Unique cache key (e.g. `"spc_day1"`, `"nws_ar"`, `"usgs_ar"`).
  - `data` (`dict`): GeoJSON data structure to cache.
- **Returns:** `None`
- **Raises:** None.
- **Flow:**
  1. Query `GeoJsonCache` by `feed_name`.
  2. If exists: update `data` and set `updated_at` to `UTC now`.
  3. If not exists: insert new `GeoJsonCache` row.
  4. (Session is **not** committed here; caller commits.)
- **Dependencies:** `src.models.schema.GeoJsonCache`

### `fetch_spc_outlooks() -> None`

- **Purpose:** Download day 1, 2, and 3 SPC convective outlook GeoJSON files and cache them in `GeoJsonCache`.
- **Parameters:** None
- **Returns:** `None`
- **Raises:** None (exceptions are caught, logged, and the session is rolled back).
- **Flow:**
  1. Open a database session.
  2. For each SPC URL:
     a. HTTP GET with a `Mozilla/5.0` User-Agent (15 s timeout).
     b. On 200 OK: call `save_geojson_to_db()` with the JSON response.
     c. On failure: log HTTP error.
  3. Commit the session.
  4. On exception: rollback and log.
- **Dependencies:**
  - `requests` - HTTP client
  - `src.core.db.SessionLocal` - SQLAlchemy session factory
  - `src.models.schema.GeoJsonCache` - ORM model

### `fetch_nws_alerts_for_region(area_str: str, feed_name: str) -> None`

- **Purpose:** Fetch active NWS alerts for a given US-state area code and persist as `RegionalHazard` records.
- **Parameters:**
  - `area_str` (`str`): NWS API area parameter (e.g. `"AR"`, `"OK,MS,MO"`).
  - `feed_name` (`str`): Cache key for the raw GeoJSON response.
- **Returns:** `None`
- **Raises:** None (exceptions are caught, logged, and the session is rolled back).
- **Flow:**
  1. Open a database session.
  2. GET `https://api.weather.gov/alerts/active?area={area_str}` (15 s timeout).
  3. If 200 OK:
     a. Cache full GeoJSON via `save_geojson_to_db()`.
     b. Iterate `features`:
        i.   Extract `properties.id` (or generate UUID).
        ii.  Query `RegionalHazard` by `hazard_id`.
        iii. If exists: update `updated_at`.
        iv.  If new: insert `RegionalHazard` with `event`, `severity`, `headline`, `description`, `areaDesc`.
     c. Commit; log added/updated counts.
  4. On failure: log HTTP or exception error.
- **Dependencies:**
  - `requests` - HTTP client
  - `uuid` - fallback ID generation
  - `src.core.db.SessionLocal` - SQLAlchemy session factory
  - `src.models.schema.RegionalHazard`, `GeoJsonCache` - ORM models
  - `datetime`

### `fetch_usgs_earthquakes(area_key: str, feed_name: str) -> None`

- **Purpose:** Fetch earthquake events of magnitude >= 2.0 from the last 7 days within a defined bounding box and cache the GeoJSON.
- **Parameters:**
  - `area_key` (`str`): Key into `USGS_BOUNDS` (`"ar"` or `"oos"`).
  - `feed_name` (`str`): Cache key for the GeoJSON response.
- **Returns:** `None`
- **Raises:** None (exceptions are caught, logged, and the session is rolled back).
- **Flow:**
  1. Look up bounding box from `USGS_BOUNDS`.
  2. Build USGS FDSN query URL with `starttime`, `minmagnitude=2.0`, and bounding box limits.
  3. Open session; HTTP GET (20 s timeout).
  4. If 200 OK: cache GeoJSON via `save_geojson_to_db()`; commit.
  5. On failure: log HTTP or exception error.
- **Dependencies:**
  - `requests` - HTTP client
  - `src.core.db.SessionLocal` - SQLAlchemy session factory
  - `src.models.schema.GeoJsonCache` - ORM model
  - `datetime`

### `haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float`

- **Purpose:** Calculate the great-circle distance in miles between two coordinates using the Haversine formula.
- **Parameters:**
  - `lat1` (`float`): Latitude of point 1 (degrees).
  - `lon1` (`float`): Longitude of point 1 (degrees).
  - `lat2` (`float`): Latitude of point 2 (degrees).
  - `lon2` (`float`): Longitude of point 2 (degrees).
- **Returns:** `float` - Distance in statute miles (Earth radius = 3959 mi).
- **Raises:** None.
- **Flow:** Standard Haversine computation: radians conversion, delta, `sin^2`, `asin`, `R * c`.
- **Dependencies:** `math`

### `check_earthquake_proximity(equake_data: dict, distance_miles: int = 50) -> None`

- **Purpose:** Check each earthquake in a GeoJSON feature collection against all monitored sites with valid coordinates. If any site is within the threshold distance, send an email alert.
- **Parameters:**
  - `equake_data` (`dict`): USGS GeoJSON feature collection.
  - `distance_miles` (`int`, optional): Proximity threshold in miles. Defaults to `50`.
- **Returns:** `None`
- **Raises:** None.
- **Flow:**
  1. Return early if `equake_data` is empty or has no `features`.
  2. Query all `MonitoredLocation` rows with non-null `lat`/`lon`.
  3. For each earthquake feature with `mag >= 2.5`:
     a. Extract coordinates, magnitude, place, time, depth.
     b. For each site:
        i.   Compute distance via `haversine_distance()`.
        ii.  If within threshold, append alert dict.
  4. If alerts exist:
     a. Retrieve alert recipients via `get_alert_recipients()`.
     b. Build email body via `build_eq_alert_email_body()`.
     c. Send alert via `send_alert()`.
     d. Log the alert event.
- **Dependencies:**
  - `src.utils.risk_alert.send_alert`, `get_alert_recipients`, `build_eq_alert_email_body`
  - `src.core.db.SessionLocal`
  - `src.models.schema.MonitoredLocation`
  - `datetime`, `zoneinfo`

### `fetch_regional_hazards() -> None`

- **Purpose:** Main entry point. Orchestrates all regional hazard data ingestion in sequence: SPC outlooks, NWS alerts (AR and tri-state), USGS earthquakes (AR and out-of-state), and earthquake proximity checks.
- **Parameters:** None
- **Returns:** `None`
- **Raises:** None (all sub-calls are internally guarded).
- **Flow:**
  1. Call `fetch_spc_outlooks()`.
  2. Call `fetch_nws_alerts_for_region("AR", "nws_ar")`.
  3. Call `fetch_nws_alerts_for_region("OK,MS,MO", "nws_oos")`.
  4. Call `fetch_usgs_earthquakes("ar", "usgs_ar")`.
  5. Call `fetch_usgs_earthquakes("oos", "usgs_oos")`.
  6. Open session; load cached USGS data for both regions.
  7. Call `check_earthquake_proximity()` for each region's data.
  8. Run `gc.collect()`.
- **Dependencies:** All functions in this module; `gc` for garbage collection.
