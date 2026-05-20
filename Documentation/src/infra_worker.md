# Enterprise Architecture & Functional Specification: `src/infra_worker.py`

## 1. Executive Overview

The `src/infra_worker.py` module serves as the **Physical Infrastructure & Environmental Telemetry Engine** for the Intelligence Fusion Center. It ingests live meteorological data from government APIs, utilizes advanced geospatial mathematics via the `shapely` library, and monitors seismic activity via USGS.

It has been expanded to ingest **USGS Earthquake Data** and cache all raw GeoJSON geometry (SPC outlooks, NWS alerts, USGS quakes) into the database for instant UI rendering.

---

## 2. Core Data Sources & Upstream APIs

### 2.1 Storm Prediction Center (SPC) Convective Outlooks
| Feed | Endpoint | Purpose |
|------|----------|---------|
| Day 1 | `day1otlk_cat.nolyr.geojson` | Current day severe thunderstorm/tornado risk |
| Day 2 | `day2otlk_cat.nolyr.geojson` | +24 hour forecast |
| Day 3 | `day3otlk_cat.nolyr.geojson` | +48 hour forecast |

### 2.2 NWS Active Warnings API
- **Endpoint:** `https://api.weather.gov/alerts/active?area={area_str}`
- **Primary Region:** Arkansas (`AR`)
- **Out-of-State Region:** Oklahoma, Mississippi, Missouri (`OK,MS,MO`)

### 2.3 USGS Earthquake API
- **Endpoint:** `https://earthquake.usgs.gov/fdsnws/event/1/query`
- **Parameters:** Magnitude >= 2.0, 7-day lookback, geofenced to Arkansas region bounds

---

## 3. Geospatial Processing Engine

### `fetch_spc_outlooks()`
Downloads Day 1, Day 2, and Day 3 SPC convective outlook GeoJSON and caches each to the `GeoJsonCache` table via `save_geojson_to_db()`.

### `fetch_nws_alerts_for_region(area_str, feed_name)`
1. Queries NWS API for active alerts
2. Saves raw GeoJSON to `GeoJsonCache` for UI rendering
3. Parses features into `RegionalHazard` records with upsert logic (UUID fallback for missing NWS IDs)

### `save_geojson_to_db(session, feed_name, data)`
Upserts GeoJSON cache into the database for instant UI map rendering without re-fetching external APIs.

---

## 4. Seismic Monitoring

### `fetch_usgs_earthquakes(area_key, feed_name)`
Queries USGS for earthquakes >= 2.0 magnitude within the last 7 days, geofenced to predefined USGS bounds for Arkansas (`ar`) and out-of-state (`oos`) regions. Caches results to `GeoJsonCache`.

### `check_earthquake_proximity(equake_data, distance_miles=50)`
Cross-references earthquake epicenters against all monitored NOC facility locations. If a quake >= 2.5 magnitude is within 50 miles of a facility, triggers an alert via `risk_alert.send_alert()` using `build_eq_alert_email_body()`.

### `haversine_distance(lat1, lon1, lat2, lon2)`
Calculates great-circle distance in miles between two lat/lon points.

---

## 5. System Integration

### `fetch_regional_hazards()`
Master wrapper that executes the full pipeline:
1. Fetch SPC Day 1-3 outlooks
2. Fetch NWS alerts for Arkansas
3. Fetch NWS alerts for out-of-state region
4. Fetch USGS earthquakes for Arkansas
5. Fetch USGS earthquakes for out-of-state
6. Check earthquake proximity to monitored sites
7. Run garbage collection

---

## 6. Complete Function Reference

| Function | Signature | Purpose |
|----------|-----------|---------|
| `log_print` | `(msg) -> None` | Timestamped logging to stdout |
| `save_geojson_to_db` | `(session, feed_name, data) -> None` | Upsert GeoJSON to cache |
| `fetch_spc_outlooks` | `() -> None` | Fetch Day 1-3 SPC convective outlooks |
| `fetch_nws_alerts_for_region` | `(area_str, feed_name) -> None` | Fetch NWS alerts for region |
| `fetch_usgs_earthquakes` | `(area_key, feed_name) -> None` | Fetch USGS earthquake data |
| `haversine_distance` | `(lat1, lon1, lat2, lon2) -> float` | Distance in miles |
| `check_earthquake_proximity` | `(equake_data, distance_miles) -> None` | Earthquake proximity alerting |
| `fetch_regional_hazards` | `() -> None` | Master wrapper function |

### Constants

| Constant | Type | Description |
|----------|------|-------------|
| `USGS_BOUNDS` | `dict` | `ar` and `oos` geographic bounds |
| `CENTRAL_TZ` | `ZoneInfo` | America/Chicago timezone |

---

## 7. API Citations

| API / Service | Purpose | Documentation |
|---------------|---------|---------------|
| NWS API | Weather alerts | https://www.weather.gov/api/ |
| SPC | Storm predictions | https://www.spc.noaa.gov/ |
| USGS | Earthquakes | https://earthquake.usgs.gov/ |
| Requests | HTTP client | https://docs.python-requests.org/ |
