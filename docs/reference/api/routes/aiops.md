# Module: `src.api.routes.aiops`

AIOps (Artificial Intelligence for IT Operations) routes for dashboard data, global situational reports, monitored sites, and alert acknowledgment. Prefix: `/api/v1/aiops`.

---

## Endpoint: `GET /dashboard`

### Purpose
Returns the AIOps dashboard data including active alerts, timeline events, and grid state.

### Parameters
None.

### Returns
```json
{
  "alerts": [...],
  "events": [...],
  "grid": [...]
}
```

### Raises
None.

### Flow
Calls `svc.get_aiops_dashboard_data()` which returns a 3-tuple destructured into alerts, events, and grid.

### Dependencies
- `src.services.get_aiops_dashboard_data()`

---

## Endpoint: `GET /sitrep`

### Purpose
Generates and returns a global situational report based on current system configuration.

### Parameters
None (uses `db: Session` via `Depends(get_db)`).

### Returns
```json
{
  "report": "<generated SITREP text>"
}
```

### Raises
None.

### Flow
1. Opens a database session via `Depends(get_db)`.
2. Queries the first `SystemConfig` record.
3. Extracts `is_active`, `llm_endpoint`, `llm_api_key`, `llm_model_name` into a config dict.
4. Calls `svc.generate_global_sitrep()` with the config dict.
5. Returns the generated report.

### Dependencies
- `src.core.db.get_db`
- `src.services.SystemConfig` (model)
- `src.services.generate_global_sitrep()`

---

## Endpoint: `GET /sites`

### Purpose
Returns all monitored locations/sites with their basic properties.

### Parameters
None (uses `db: Session` via `Depends(get_db)`).

### Returns
```json
[
  {
    "id": <int>,
    "name": "...",
    "lat": <float>,
    "lon": <float>,
    "type": "...",
    "district": "...",
    "priority": <int>,
    "under_maintenance": true | false
  },
  ...
]
```

### Raises
None.

### Flow
1. Opens a database session via `Depends(get_db)`.
2. Queries all `MonitoredLocation` records.
3. Maps each site to a sanitized dict.
4. Returns the list.

### Dependencies
- `src.core.db.get_db`
- `src.models.schema.MonitoredLocation`

---

## Endpoint: `PATCH /sites/{site_id}/acknowledge`

### Purpose
Acknowledges all unresolved, non-correlated alerts associated with a specific site.

### Parameters
| Parameter  | Type  | Description                          |
|------------|-------|--------------------------------------|
| `site_id`  | `int` | Site ID (path parameter).            |

### Returns
```json
{ "status": "acknowledged" }
```

### Raises
None.

### Flow
1. Opens a database session via `Depends(get_db)`.
2. Queries all `SolarWindsAlert` records that are not correlated and not resolved.
3. Collects their IDs.
4. Calls `svc.acknowledge_cluster()` with the list of alert IDs.
5. Returns acknowledgment status.

### Dependencies
- `src.core.db.get_db`
- `src.models.schema.SolarWindsAlert`
- `src.services.acknowledge_cluster()`
