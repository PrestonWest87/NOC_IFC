# Module: `src.api.routes.regional`

Regional grid and geospatial data routes for monitored locations, weather overlays (SPC, NWS, USGS), infrastructure analytics, and hazard synchronization. Prefix: `/api/v1/regional`.

---

## Endpoint: `GET /locations`

### Purpose
Returns all cached monitored site locations.

### Parameters
None.

### Returns
List of location objects with lat/lon, type, district, priority, etc.

### Raises
None.

### Flow
Direct delegation to `svc.get_cached_locations()`.

### Dependencies
- `src.services.get_cached_locations()`

---

## Endpoint: `GET /geojson`

### Purpose
Returns all cached GeoJSON layers for weather and geological hazards (SPC day 1/2/3, NWS alerts/river, USGS earthquakes/river).

### Parameters
None.

### Returns
```json
{
  "spc_day1": {...},
  "spc_day2": {...},
  "spc_day3": {...},
  "nws_ar": {...},
  "nws_oos": {...},
  "usgs_ar": {...},
  "usgs_oos": {...}
}
```

### Raises
None.

### Flow
1. Calls `svc.get_cached_geojson()` which returns a 7-tuple.
2. Destructures into named keys and returns as JSON.

### Dependencies
- `src.services.get_cached_geojson()`

---

## Endpoint: `POST /compile-map`

### Purpose
Compiles the regional map data by precomputing a geo-spatial matrix, applying toggle filters, and building analytics. This is the core map data compilation endpoint.

### Parameters
| Parameter | Type               | Description                                          |
|-----------|--------------------|------------------------------------------------------|
| `data`    | `dict[str, Any]`   | JSON body with toggles, SPC/NWS/USGS data, and events.|

#### Body Fields
| Field               | Type      | Default | Description                               |
|---------------------|-----------|---------|-------------------------------------------|
| `toggles`           | `dict`    | `{}`    | Visibility toggles for hazard layers.     |
| `spc_data`          | `object`  | `None`  | SPC storm prediction data.                |
| `ar_data`           | `object`  | `None`  | NWS area river data.                      |
| `oos_data`          | `object`  | `None`  | NWS out-of-service river data.            |
| `usgs_ar_data`      | `object`  | `None`  | USGS area river data.                     |
| `usgs_oos_data`     | `object`  | `None`  | USGS out-of-service river data.           |
| `selected_events`   | `list`    | `[]`    | Currently selected event types.           |
| `map_df`            | `list`    | `[]`    | Raw map dataframe rows (list of dicts).   |

### Returns
```json
[
  [],                              // placeholder for layers (populated client-side)
  {},                              // placeholder for viewState (populated client-side)
  [...],                           // map_diagnostics
  [...],                           // toggled_affected_sites
  [...],                           // master_affected_sites
  { ... }                          // analytics_serialized
]
```

### Raises
None.

### Flow
1. Extracts toggle states, hazard data objects, selected events, and raw map dataframe from the request body.
2. Converts `raw_map_df` list to a `pandas.DataFrame` (or empty DataFrame if not provided).
3. Calls `svc._precompute_geo_matrix()` to compute the geo-spatial intersection matrix.
4. Iterates over `master_affected_sites` from the cache, applying toggle visibility rules:
   - `SPC:` prefix → `spc` toggle.
   - `Wildfire Risk:` prefix → `fire_risk` toggle.
   - `Active Wildfire:` prefix → `active_wildfires` toggle.
   - `EQ (` prefix → `earthquakes` toggle.
   - `[OOS]` prefix → `oos` toggle.
   - `[AR]` prefix → `warn` or `watch` toggle based on severity.
5. Builds `toggled_affected_sites` dict with deduplicated hazards per site, then converts to list with `Intersecting Hazards` string.
6. Calls `svc.get_infrastructure_analytics()` with the map DataFrame and master affected sites.
7. Serializes analytics DataFrames to JSON-compatible dicts (converts to lists of records).
8. Returns a 6-element list: `[layers, viewState, diagnostics, toggled_affected_sites, master_affected_sites, analytics]`.

### Dependencies
- `pandas`
- `src.services._precompute_geo_matrix()`
- `src.services.get_infrastructure_analytics()`

---

## Endpoint: `GET /weather-prefs`

### Purpose
Returns a user's weather alert preferences.

### Parameters
| Parameter  | Type   | Default | Description                     |
|------------|--------|---------|---------------------------------|
| `username` | `str`  | `""`    | Username to query preferences for.|

### Returns
User weather preferences object.

### Raises
None.

### Flow
Direct delegation to `svc.get_user_weather_prefs()`.

### Dependencies
- `src.services.get_user_weather_prefs()`

---

## Endpoint: `POST /weather-prefs`

### Purpose
Sets a user's weather alert preferences.

### Parameters
| Parameter  | Type        | Default | Description                           |
|------------|-------------|---------|---------------------------------------|
| `username` | `str`       | `""`    | Username to set preferences for.      |
| `alerts`   | `list[str]` | `[]`    | List of alert types to subscribe to.  |

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Direct delegation to `svc.set_user_weather_prefs()`.

### Dependencies
- `src.services.set_user_weather_prefs()`

---

## Endpoint: `GET /forecast`

### Purpose
Returns the NWS forecast for a given latitude/longitude coordinate.

### Parameters
| Parameter | Type    | Default  | Description                     |
|-----------|---------|----------|---------------------------------|
| `lat`     | `float` | `34.8`   | Latitude of the location.       |
| `lon`     | `float` | `-92.2`  | Longitude of the location.      |

### Returns
NWS forecast data object.

### Raises
None.

### Flow
Direct delegation to `svc.get_nws_forecast()`.

### Dependencies
- `src.services.get_nws_forecast()`

---

## Endpoint: `GET /weather-alerts-log`

### Purpose
Returns a compiled log of all active weather alerts from NWS and USGS.

### Parameters
None.

### Returns
Weather alerts log object.

### Raises
None.

### Flow
1. Retrieves all cached GeoJSON data via `svc.get_cached_geojson()`.
2. Extracts AR, OOS, and USGS data.
3. Delegates to `svc.get_weather_alerts_log()` with the extracted data.

### Dependencies
- `src.services.get_cached_geojson()`
- `src.services.get_weather_alerts_log()`

---

## Endpoint: `GET /site-types`

### Purpose
Returns all distinct site/facility types defined in the system.

### Parameters
None.

### Returns
List of site type strings.

### Raises
None.

### Flow
Direct delegation to `svc.get_all_site_types()`.

### Dependencies
- `src.services.get_all_site_types()`

---

## Endpoint: `POST /sync-hazards`

### Purpose
Manually triggers a synchronous fetch of regional hazard data from external weather services.

### Parameters
None.

### Returns
```json
{
  "status": "ok" | "error",
  "message": "<description>"
}
```

### Raises
None.

### Flow
1. Imports `fetch_regional_hazards` from `src.workers.infra_worker`.
2. Calls the fetch function.
3. Clears the cached GeoJSON.
4. Returns success, or catches any exception and returns an error message.

### Dependencies
- `src.workers.infra_worker.fetch_regional_hazards()`
- `src.services.get_cached_geojson.clear()` (LRU cache clear)
