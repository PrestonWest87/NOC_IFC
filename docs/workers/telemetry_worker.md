# Telemetry Worker Module

**File:** `src/workers/telemetry_worker.py`

## Overview

Ingests multi-domain telemetry data from three external sources: ORNL ODIN power outage data, RIPE RIS BGP routing visibility, and IODA (Internet Outage Detection and Analysis) ISP outage alerts. Persists structured `RegionalOutage` and `BgpAnomaly` records for the regional grid and threat telemetry dashboards.

---

## Constants

### `AR_COUNTY_COORDS` (`dict[str, tuple[float, float]]`)

Coordinates for 9 Arkansas counties used to geolocate power outages.

### `HEADERS` (`dict[str, str]`)

HTTP request headers including a modern Chrome User-Agent, `Accept: application/json`, and `Connection: keep-alive`.

---

## Functions

### `fetch_ornl_odin_power() -> None`

- **Purpose:** Query the ORNL OpenDataSoft ODIN real-time power outage API for Arkansas records with >100 customers affected, and upsert into `RegionalOutage` as `outage_type="Power"`.
- **Parameters:** None
- **Returns:** `None`
- **Raises:** None (exceptions are caught, logged, and the session is rolled back).
- **Flow:**
  1. Open a database session.
  2. HTTP GET the ORNL ODIN API (20 s timeout) with a filter for `state:Arkansas`.
  3. If 200 OK:
     a. Delete all existing `RegionalOutage` rows where `provider == "ORNL ODIN"`.
     b. For each result record:
        i.   Extract county name and `customers_out` count.
        ii.  Skip if `customers_out <= 100`.
        iii. Look up coordinates from `AR_COUNTY_COORDS` (fallback: `34.8, -92.2`).
        iv.  Estimate radius: `10.0 + (out_count / 1000)` km.
        v.   Insert `RegionalOutage` with `is_resolved=False`.
     c. Commit.
     d. Log sync complete.
  4. On failure: rollback and log error.
- **Dependencies:**
  - `requests` - HTTP client
  - `src.core.db.SessionLocal` - SQLAlchemy session factory
  - `src.models.schema.RegionalOutage` - ORM model

### `fetch_bgp_anomalies() -> None`

- **Purpose:** Query the RIPE RIS routing status API for each monitored ASN and detect BGP visibility drops with a risk score above 0.5.
- **Parameters:** None
- **Returns:** `None`
- **Raises:** None (exceptions are caught, logged, and the session is rolled back).
- **Flow:**
  1. Open a database session.
  2. Load `SystemConfig` to get `monitored_asns` (comma-separated list).
  3. Return early if no ASNs configured.
  4. For each ASN (strip `AS` prefix):
     a. GET `https://stat.ripe.net/data/routing-status/data.json?resource={clean_asn}` (20 s timeout).
     b. If 200 OK:
        i.   Extract IPv4 `visibility.risk` score.
        ii.  If `risk > 0.5`:
             - Check if an unresolved `BgpAnomaly` already exists for this ASN.
             - If not, insert with `event_type="BGP Visibility Drop"` and `is_resolved=False`.
  5. Commit.
  6. Log sync complete.
  7. On failure: rollback and log error.
- **Dependencies:**
  - `requests` - HTTP client
  - `src.core.db.SessionLocal` - SQLAlchemy session factory
  - `src.models.schema.BgpAnomaly`, `SystemConfig` - ORM models

### `fetch_ioda_isp_outages() -> None`

- **Purpose:** Query the Georgia Tech IODA API for active ISP outage alerts affecting Arkansas (by region) and each monitored ASN (by ASN entity), and persist as `RegionalOutage` records with `outage_type="ISP"`.
- **Parameters:** None
- **Returns:** `None`
- **Raises:** None (exceptions are caught, logged, and the session is rolled back).
- **Flow:**
  1. Open a database session.
  2. Compute epoch timestamps: `now` and `now - 12 hours`.
  3. Delete all existing `RegionalOutage` rows where `provider == "IODA"`.
  4. **Arkansas region query:**
     a. GET `?entityType=region&entityCode=US-AR&from={past}&until={now}`.
     b. For each alert: insert `RegionalOutage` with `lat=34.8, lon=-92.2, radius_km=200`.
  5. **Per-ASN queries (if configured):**
     a. Load `SystemConfig.monitored_asns`.
     b. For each ASN: GET `?entityType=asn&entityCode={asn}&from={past}&until={now}`.
     c. For each alert: insert `RegionalOutage` with `lat=34.8, lon=-92.2, radius_km=300`.
  6. Commit; log total alert count.
  7. On failure: rollback and log error.
- **Dependencies:**
  - `requests` - HTTP client
  - `time` - epoch timestamp generation
  - `src.core.db.SessionLocal` - SQLAlchemy session factory
  - `src.models.schema.RegionalOutage`, `SystemConfig` - ORM models

### `run_telemetry_sync() -> None`

- **Purpose:** Main entry point. Invokes all three telemetry ingestion pipelines in sequence.
- **Parameters:** None
- **Returns:** `None`
- **Raises:** None (all sub-calls are internally guarded).
- **Flow:**
  1. Call `fetch_ornl_odin_power()`.
  2. Call `fetch_bgp_anomalies()`.
  3. Call `fetch_ioda_isp_outages()`.
  4. Log `"Multi-Domain Telemetry Sync Complete."`.
- **Dependencies:** All functions in this module.
