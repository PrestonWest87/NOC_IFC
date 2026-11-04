# Route module: `src.api.routes.regional`

Prefix: `/api/v1/regional`. All routes require page permission `Regional Grid`; tab and manual-sync grants are listed per endpoint.

## Data and map endpoints

| Method/path | Additional grant | Behavior |
|---|---|---|
| `GET /locations` | Any Regional Grid tab | Returns cached locations. Non-administrators receive only rows whose `loc_type` is in their site-type grants. |
| `GET /geojson?layers=...&bbox=...` | Any map, executive, hazard, weather-log, or Atmos tab | Optional comma-separated `layers` limits which collections transfer; `layers=summary` returns only active NWS event names/metadata; optional WGS84 viewport `bbox` limits returned features. Omitted `layers` preserves the all-layer response. |
| `GET /wildfires?bbox=...` | `Tab: Regional Grid -> Geospatial Map` | Returns cached WFCA incidents, reported perimeters, estimated satellite footprints, and freshness metadata, optionally scoped to the WGS84 viewport. Source failures retain the last successful payload when available. |
| `POST /compile-map` | Any Regional Grid tab | Compiles selected site/hazard intersections. Body accepts `toggles`, `selected_events`, `map_df`, optional `viewport_bounds`, and `include_analytics`; legacy raw GeoJSON fields remain accepted. Non-admin site rows are filtered to allowed names and viewport before compilation. |
| `GET /weather-alerts-log` | `Tab: Regional Grid -> Weather Alerts Log` | Returns current NWS alerts and USGS earthquake entries. NWS records past CAP `expires` are excluded; expected event-ending time remains a separate field. |
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

`POST /sync-hazards` requires one of Geospatial Map, Executive Dash, or Hazard Analytics plus `Action: Manually Sync Data`. It calls the one-request NWS poll and the slower SPC/USGS/WFCA job, clears derived caches, and returns per-feed outcomes. NWS requests made within 60 seconds or within `Retry-After` are reported as deferred without another upstream call; provider failures return HTTP 502 with feed results.
