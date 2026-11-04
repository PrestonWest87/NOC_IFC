# Infra Worker Module

**File:** `src/workers/infra_worker.py`

## Overview

The module fetches SPC outlooks and USGS earthquakes on the slower `regional_hazards` job, and exposes a separate `fetch_nws_alerts()` job that polls one combined NWS alert endpoint every 60 seconds. It persists provider health, current CAP lifecycle fields, and GeoJSON; earthquake and WFCA fire proximity checks remain worker-side.

NWS alert coverage starts with Arkansas and extends 50 miles outward into all six Arkansas neighbors: Louisiana, Texas, Mississippi, Missouri, Oklahoma, and Tennessee. `src.core.arkansas_coverage` creates the distance buffer from county geometry in a local azimuthal-equidistant projection. Alert polygons and county UGC/SAME geocodes are checked against that corridor. Unresolved zone-only alerts are retained as an explicit state-level fallback.

## Constants

| Name | Purpose |
|---|---|
| `CENTRAL_TZ` | America/Chicago timestamps in proximity-email bodies |
| `NWS_ACTIVE_FEED` | Raw combined NWS snapshot key, `nws_region` |
| `NWS_ACTIVE_URL` | One `/alerts/active?area=AR,LA,TX,MS,MO,OK,TN` request |
| `USGS_BOUNDS` | Conservative fallback query envelopes if county geometry cannot be loaded; normal requests use projected Arkansas/border bounds |

## Fetch and lifecycle functions

### `save_geojson_to_db(session, feed_name, data, duration_ms=None) -> None`

Upserts a successful provider payload and records its last attempt/success, HTTP status, content timestamp, and feature count. It does not commit; the caller controls the transaction.

### `_record_geojson_failure(session, feed_name, error, http_status=None, duration_ms=None) -> None`

Records attempt/error metadata without replacing the provider's last good GeoJSON payload or successful timestamp.

### `fetch_spc_outlooks() -> dict`

Fetches SPC Day 1–3 categorical outlooks concurrently (15-second per-request timeout). Each layer reports `ok` or `error`; failed layers preserve prior successful data.

### `fetch_nws_alerts() -> dict`

Makes at most one NWS request per 60 seconds across the worker and manual-sync path. The request identifies the application with `NWS_API_USER_AGENT`, sends `If-None-Match`/`If-Modified-Since` when returned by NWS, and does not retry immediately on errors. A persisted `Retry-After` defers future attempts.

- A `200` response atomically stores the raw source snapshot, derives active `nws_ar` and `nws_oos` display collections, and reconciles normalized alert rows.
- A `304` refreshes source-verification time without replacing the cached body.
- A failure retains last-good data and records status/error/duration.
- CAP `expires` deactivates messages at the provider expiry. CAP Update/Cancel `references` mark prior IDs superseded/cancelled. Successful snapshots mark missing IDs inactive.
- Expected event-ending time (`ends`/`eventEndingTime`) is stored separately from CAP expiry.
- The provider request covers `AR,LA,TX,MS,MO,OK,TN`; regional display filters select alert geometry intersecting Arkansas or the outward 50-mile buffer. County/zone fallbacks include a precision marker.

### `fetch_usgs_earthquakes(area_key, feed_name) -> dict`

Fetches the previous seven days of M2.0+ events. Normal query bounds come from the same Arkansas coverage geometry, and returned points are filtered into either Arkansas or its outside border strip. Static conservative bounds are used only if boundary geometry is unavailable. Earthquake notification still uses a separate M2.5 threshold and 50-mile site proximity.

### `fetch_regional_hazards() -> dict`

Runs SPC and both USGS queries concurrently, then evaluates earthquake and WFCA wildfire proximity. It no longer polls NWS; the NWS feed has its own minute job. Returns per-feed results and an overall `ok`/`partial_failure` status for manual synchronization.

## Geometry and proximity helpers

- `haversine_distance(lat1, lon1, lat2, lon2)` returns great-circle miles.
- `check_earthquake_proximity(equake_data, distance_miles=50)` emails only new M2.5+ events within the site threshold and persists alerted event IDs.
- `check_wildfire_proximity(distance_miles=5)` uses WFCA incidents/perimeters, preserves the small-fire one-mile rule, and suppresses duplicate notifications.

The WFCA display service uses the same 50-mile projected corridor; its source freshness and last-good fallback are returned in the payload metadata.
