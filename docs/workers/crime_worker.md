# Crime Worker Module

**File:** `src/workers/crime_worker.py`

## Overview

Polls the Little Rock (AR) police dispatch CAD (Computer-Aided Dispatch) feed, geocodes incident addresses via the ArcGIS World Geocoding Service, classifies incidents by severity/category, and persists `CrimeIncident` records to the database. Also prunes records older than 7 days and dispatches perimeter crime alerts when new incidents are detected.

---

## Module-Level State

### `GEO_CACHE` (`dict`)

In-memory cache mapping raw address strings to `(lat, lon, is_approximate)` tuples to avoid redundant geocoding calls.

---

## Functions

### `calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float`

- **Purpose:** Calculate the great-circle distance in miles between two geographic coordinates using the Haversine formula.
- **Parameters:**
  - `lat1` (`float`): Latitude of the first point in degrees.
  - `lon1` (`float`): Longitude of the first point in degrees.
  - `lat2` (`float`): Latitude of the second point in degrees.
  - `lon2` (`float`): Longitude of the second point in degrees.
- **Returns:** `float` - Distance in statute miles (Earth radius = 3958.8 mi).
- **Raises:** None.
- **Flow:**
  1. Convert all four coordinates to radians.
  2. Compute delta-lat and delta-lon.
  3. Apply Haversine formula: `a = sin(dlat/2)^2 + cos(lat1)*cos(lat2)*sin(dlon/2)^2`.
  4. `c = 2 * asin(sqrt(a))`.
  5. Return `R * c`.
- **Dependencies:** `math`

### `geocode_address_arcgis(address: str, hq_lat: float, hq_lon: float, region: str = "Little Rock, AR") -> tuple[float, float, bool]`

- **Purpose:** Geocode a street address using the ArcGIS World Geocoding Service. Falls back to a randomised jitter around the headquarters coordinates when the service is unavailable or returns no candidates.
- **Parameters:**
  - `address` (`str`): Raw address string from the CAD feed.
  - `hq_lat` (`float`): Headquarters latitude for fallback jitter centre.
  - `hq_lon` (`float`): Headquarters longitude for fallback jitter centre.
  - `region` (`str`, optional): Geographic context appended to the address string. Defaults to `"Little Rock, AR"`.
- **Returns:** `tuple[float, float, bool]` - `(latitude, longitude, is_approximate)`. `is_approximate` is `True` when the geocode score is below 75 or a fallback jitter was used.
- **Raises:** None (all exceptions are silently caught; fallback is always returned).
- **Flow:**
  1. Check `GEO_CACHE`; return cached result if present.
  2. Clean the address (replace `/` with `and`, remove `BLK`/`BLOCK`, normalise whitespace).
  3. Call ArcGIS `findAddressCandidates` endpoint (5 s timeout).
  4. If a candidate exists:
     a. Extract `(y, x)` coordinates.
     b. Set `is_approx = score < 75`.
     c. Cache and return.
  5. On failure or empty response:
     a. Generate random jitter within ~0.5-1 mile of HQ.
     b. Cache with `is_approx = True` and return.
- **Dependencies:**
  - `requests` - HTTP client
  - `random`, `math` - jitter generation
  - Module-level `GEO_CACHE`

### `fetch_live_crimes() -> None`

- **Purpose:** Main entry point. Polls the Little Rock Police Department CAD event feed, geocodes and classifies each incident, persists new records in batches, prunes expired records, and dispatches perimeter alerts.
- **Parameters:** None
- **Returns:** `None`
- **Raises:** None (top-level exceptions are caught and logged).
- **Flow:**
  1. POST to the LR CAD endpoint (15 s timeout).
  2. Parse JSON response.
  3. Set HQ coordinates (`34.6755, -92.3235`) and 7-day cutoff.
  4. For each entry:
     a. Extract `typeDescription`, `location`, `dispatchDate`.
     b. Skip if date is empty or older than 7 days.
     c. Geocode via `geocode_address_arcgis()`.
     d. Compute distance from HQ via `calculate_distance()`.
     e. Build deduplication hash: `LR_{date}_{md5(location)[:6]}`.
     f. Classify category/severity by keyword matching:
        - `ARSON/EXPLOSIVE/TERROR/SABOTAGE/SHOOTING` -> Critical Infrastructure Threat / Critical
        - `THEFT/BURGLARY/ROBBERY/BREAKING` -> Asset/Copper Theft Risk / High
        - `ASSAULT/BATTERY/HOMICIDE/WEAPON/SHOTS` -> Violent Proximity Threat / High
        - `VANDALISM/TRESPASS/PROWLER/DISTURBANCE/SUSPICIOUS` -> Perimeter Breach/Vandalism / Medium
        - Default -> General Police Activity / Low
     g. Append `CrimeIncident` to batch.
  5. Flush batch every 100 records (deduplicate by `id`).
  6. After all batches, purge records older than 7 days.
  7. If new incidents were added, call `dispatch_perimeter_crime_alerts()`.
- **Dependencies:**
  - `requests` - HTTP client
  - `hashlib` - deduplication hash
  - `src.core.db.SessionLocal` - SQLAlchemy session factory
  - `src.models.schema.CrimeIncident` - ORM model
  - `src.services.dispatch_perimeter_crime_alerts` - alert dispatch
  - `math`, `random`, `datetime`
