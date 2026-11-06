# Arkansas Regional Coverage and CAP Filtering

**File:** `src/core/arkansas_coverage.py`

Builds the projected geography used to filter National Weather Service alerts and
regional points to Arkansas and the 50-mile border corridor across Louisiana,
Texas, Mississippi, Missouri, Oklahoma, and Tennessee. The module also parses
CAP timing and alert geocodes. It does not persist data; the regional worker and
services own caching and database updates.

## Scope and geometry

| Constant | Value | Purpose |
|---|---:|---|
| `BUFFER_MILES` | `50.0` | Default outward buffer from Arkansas |
| `NEIGHBOR_STATE_CODES` | `LA`, `TX`, `MS`, `MO`, `OK`, `TN` | Neighbor-state strip |
| `REQUEST_STATE_CODES` | `AR` plus the six neighbors | State codes queried from NWS |
| `METERS_PER_MILE` | `1609.344` | Converts the buffer to projected meters |

`build_arkansas_coverage(counties, buffer_miles=BUFFER_MILES)` accepts the
county-geometry mapping returned by `src.services.get_regional_counties_mapping()`.
It unions valid Arkansas county geometries, chooses a local azimuthal-equidistant
projection centered on the state's representative point, buffers in meters, and
subtracts Arkansas to produce the neighbor strip. It also retains county
geometries and WGS84 bounds for later point, alert, and provider-query checks.
It raises `ValueError` when no valid Arkansas county geometry is available.

`get_arkansas_coverage()` lazily loads the shared county mapping and memoizes one
coverage object with an LRU cache. Clear that cache if the source county geometry
is replaced at runtime.

## `ArkansasCoverage`

The immutable dataclass stores the projected Arkansas polygon, full buffer, and
neighbor strip; original WGS84 geometry; county polygons; coordinate
transformers; and WGS84 bounds.

- `project(geometry)` transforms a WGS84 Shapely geometry into the local metric
  projection.
- `includes_point(longitude, latitude, scope="border")` tests a WGS84 point.
  `scope="arkansas"` tests Arkansas only, `scope="border"` tests only the
  outward neighbor strip, and other scope values test the complete buffered
  region.
- `contains_alert(feature)` returns `(scope, precision)`, where scope is
  `arkansas`, `border`, or `None`. It tries valid alert geometry first, then
  county FIPS values from SAME/UGC geocodes, then state codes. If the geometry
  is absent and no usable geocode resolves the area, it preserves the alert as
  `border` with `unresolved_state_fallback` precision rather than dropping it.
  Resolved fallback precision is marked `county_geocode` or `state_fallback`;
  intersecting shapes are marked `alert_geometry`.

## CAP timestamps and regional splitting

`parse_nws_datetime(value)` parses ISO timestamps as UTC; timestamps without an
offset are treated as UTC. Invalid or empty values return `None`.

- `is_unexpired_alert(feature, now=None)` rejects CAP `Cancel` messages and
  messages whose `expires` time has passed. A missing `expires` value does not
  expire the message.
- `is_current_alert(feature, now=None)` additionally rejects messages whose
  `effective` time is in the future. CAP event-ending time is not used as the
  message-expiry cutoff.
- `filter_current_alerts(collection, now=None)` returns a filtered
  `FeatureCollection` without mutating the cached provider payload.
- `split_alerts_for_region(data, now=None)` filters expired/cancelled messages,
  classifies the rest using `contains_alert()`, and returns Arkansas and border
  `FeatureCollection` objects plus counts, precision totals, border-state codes,
  and buffer distance. It uses `is_unexpired_alert()`; callers that need to
  exclude future-effective messages should use the current-alert filter as well.

## Geocode helpers

- `alert_county_fips(properties)` extracts county FIPS codes from NWS SAME and
  county UGC values.
- `alert_state_codes(properties)` extracts state abbreviations from SAME/UGC
  geocodes.
- `_code_values(value)` accepts scalar or list-like geocode values and splits
  comma/semicolon-delimited strings.

The worker request cadence, last-good cache behavior, CAP lifecycle persistence,
and provider health reporting are documented in
[`workers/infra_worker.md`](../workers/infra_worker.md) and
[`DATA_FLOWS.md`](../../DATA_FLOWS.md#7-regional-weather-fire-and-telemetry).
