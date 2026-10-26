# Route module: `src.api.routes.regional`

Prefix: `/api/v1/regional`. All routes require page permission `Regional Grid`; tab and manual-sync grants are listed per endpoint.

## Data and map endpoints

| Method/path | Additional grant | Behavior |
|---|---|---|
| `GET /locations` | Any Regional Grid tab | Returns cached locations. Non-administrators receive only rows whose `loc_type` is in their site-type grants. |
| `GET /geojson` | Any map, executive, hazard, weather-log, or Atmos tab | Returns `spc_day1`, `spc_day2`, `spc_day3`, `nws_ar`, `nws_oos`, `usgs_ar`, `usgs_oos`, and per-feed freshness `meta`. |
| `GET /wildfires` | `Tab: Regional Grid -> Geospatial Map` | Returns WFCA incident, reported perimeter, and recent satellite-footprint data (or an empty-list fallback on a source-level failure). See `API.md` for geographic and small-fire filters. |
| `POST /compile-map` | Any Regional Grid tab | Compiles site/hazard intersections and analytics. Body accepts `toggles`, `selected_events`, and `map_df`; legacy `spc_data`, `ar_data`, `oos_data`, `usgs_ar_data`, and `usgs_oos_data` remain accepted. If no legacy GeoJSON is supplied, the service uses its coherent cached snapshot. Non-admin site rows are filtered to allowed names; a row set without a recognized site-name column is discarded. |
| `GET /weather-alerts-log` | `Tab: Regional Grid -> Weather Alerts Log` | Returns persisted NWS alert details and USGS earthquake entries from cached GeoJSON. |
| `GET /site-types` | Page `Regional Grid` | Returns the default site types merged with distinct database `MonitoredLocation.loc_type` values. |

### Positional `POST /compile-map` response

This API intentionally returns a six-element JSON array consumed by index in `RegionalGridPage.tsx`:

```text
[processed_geo, {}, map_diagnostics, toggled_affected_sites,
 master_affected_sites, analytics]
```

`processed_geo` contains the processed AR/OOS warning/watch FeatureCollections; the second position is an empty view-state object. Preserve this order if changing the API or frontend.

## Atmos Weather endpoints

| Method/path | Grant | Parameters/body |
|---|---|---|
| `GET /weather-prefs` | `Tab: Regional Grid -> Atmos Weather` | Uses the authenticated user's username; no username query is accepted. |
| `POST /weather-prefs` | Atmos Weather tab | JSON array of subscribed alert-type strings; username is taken from the session. |
| `GET /forecast?lat=34.8&lon=-92.2` | Atmos Weather tab | Returns the NWS forecast for the supplied coordinates. Defaults to the sample Little Rock coordinates. |

## Manual synchronization

`POST /sync-hazards` requires one of Geospatial Map, Executive Dash, or Hazard Analytics plus `Action: Manually Sync Data`. It calls `fetch_regional_hazards()`, clears GeoJSON/freshness/intersection/wildfire caches, and returns success. Worker failure returns HTTP 502.
