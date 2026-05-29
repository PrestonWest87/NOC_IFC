# Module: `src.api.routes.rca`

Root Cause Analysis (RCA) routes for AIOps alert clustering, fleet outage detection, root cause calculation, site maintenance, dispatching, and situation reporting. Prefix: `/api/v1/rca`.

---

## Function: `require_action(action: str)`

### Purpose
Factory function that returns a FastAPI `Depends` dependency callable. The returned checker validates that the requesting user's token grants a specific action permission.

### Parameters
| Parameter | Type   | Description                              |
|-----------|--------|------------------------------------------|
| `action`  | `str`  | The action string to check (e.g., `"Action: Dispatch RCA Tickets"`).|

### Returns
| Type       | Description                                                      |
|------------|------------------------------------------------------------------|
| `callable` | A `checker` function with signature `(token: str = Query("")) -> User`. |

### Raises
- `HTTPException 401` — if the token is invalid or not provided.
- `HTTPException 403` — if the user's `allowed_actions` does not include the required action.

### Flow
1. `checker` reads the `token` query parameter.
2. Looks up the user via `svc.get_user_by_token(token)`.
3. If no user, raises 401.
4. If the required action is not in `user.allowed_actions`, raises 403.
5. Returns the user object.

### Dependencies
- `src.services.get_user_by_token()`

---

## Endpoint: `GET /dashboard`

### Purpose
Returns the AIOps dashboard data including active alerts, timeline events, grid state, and all monitored locations.

### Parameters
None.

### Returns
```json
{
  "alerts": [...],
  "events": [...],
  "grid": [...],
  "locations": [...]
}
```

### Raises
None.

### Flow
1. Calls `svc.get_aiops_dashboard_data()` for alerts, events, grid.
2. Calls `svc.get_cached_locations()` for all monitored locations.
3. Combines into a single response.

### Dependencies
- `src.services.get_aiops_dashboard_data()`
- `src.services.get_cached_locations()`

---

## Endpoint: `POST /analyze`

### Purpose
Performs a full RCA analysis cycle: clusters alerts by site, identifies fleet outages, calculates root cause per site with contextual weather/cloud/BGP data, and generates chronic insights.

### Parameters
None.

### Returns
```json
{
  "clustered": {...},
  "fleet_outages": [...],
  "root_cause": {...},
  "chronic_insights": [...],
  "events": [...]
}
```

### Raises
None.

### Flow
1. Retrieves active alerts, events, and grid data from the dashboard.
2. Instantiates `EnterpriseAIOpsEngine`.
3. Calls `engine.analyze_and_cluster(alerts)` to group alerts by site.
4. Calls `engine.identify_fleet_outages(clustered)` to detect fleet-wide communication/power failures.
5. Queries active `CloudOutage`, `RegionalHazard`, and `BgpAnomaly` records from the database.
6. Iterates over each clustered site, calling `engine.calculate_root_cause()` with contextual data.
7. Calls `engine.generate_chronic_insights()` for chronic pattern analysis.
8. Returns all results in a single response.

### Dependencies
- `src.services.get_aiops_dashboard_data()`
- `src.services.aiops_engine.EnterpriseAIOpsEngine`
- `src.models.schema.CloudOutage`, `RegionalHazard`, `BgpAnomaly`
- `src.core.db.SessionLocal`

---

## Endpoint: `POST /acknowledge`

### Purpose
Acknowledges a set of alerts by their IDs, removing them from the active alert board.

### Parameters
| Parameter    | Type        | Description                           |
|--------------|-------------|---------------------------------------|
| `alert_ids`  | `list[int]` | JSON body array of alert IDs.         |

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Delegates to `svc.acknowledge_cluster()`.

### Dependencies
- `src.services.acknowledge_cluster()`

---

## Endpoint: `POST /dispatch`

### Purpose
Sets the dispatch status for a set of alerts. Requires `Action: Dispatch RCA Tickets` permission.

### Parameters
| Parameter | Type               | Description                               |
|-----------|--------------------|-------------------------------------------|
| `data`    | `dict`             | JSON body with `alert_ids` and `is_dispatched`. |

### Returns
```json
{ "status": "ok" }
```

### Raises
- `HTTPException 401` — not authenticated.
- `HTTPException 403` — missing `Action: Dispatch RCA Tickets`.

### Flow
Guarded by `Depends(require_action("Action: Dispatch RCA Tickets"))`. Delegates to `svc.set_cluster_dispatch()`.

### Dependencies
- `src.services.set_cluster_dispatch()`
- `require_action()`

---

## Endpoint: `POST /site-maintenance`

### Purpose
Sets or clears maintenance mode for a monitored site, with optional ETR (Estimated Time to Resolve) and reason. Requires `Action: Manage Site Maintenance` permission.

### Parameters
| Parameter | Type               | Description                                          |
|-----------|--------------------|------------------------------------------------------|
| `data`    | `dict`             | JSON body with site_name, is_maint, etr, and reason. |

#### Body Fields
| Field       | Type      | Default | Description                             |
|-------------|-----------|---------|-----------------------------------------|
| `site_name` | `str`     | `""`    | Name of the monitored site.             |
| `is_maint`  | `bool`    | `False` | Whether to enable or disable maintenance.|
| `etr`       | `str`     | `None`  | ISO 8601 ETR datetime string.           |
| `reason`    | `str`     | `""`    | Maintenance reason.                     |

### Returns
```json
{ "status": "ok" }
```

### Raises
- `HTTPException 401` — not authenticated.
- `HTTPException 403` — missing `Action: Manage Site Maintenance`.

### Flow
1. Guarded by `Depends(require_action("Action: Manage Site Maintenance"))`.
2. Parses `etr` from ISO 8601 string to `datetime` if provided.
3. Delegates to `svc.set_site_maintenance()`.

### Dependencies
- `src.services.set_site_maintenance()`
- `require_action()`

---

## Endpoint: `POST /generate-ticket`

### Purpose
Generates a formatted RCA ticket text string for a given site, priority, patient zero, and root cause description.

### Parameters
| Parameter       | Type   | Default | Description                          |
|-----------------|--------|---------|--------------------------------------|
| `site`          | `str`  | `""`    | Site name.                           |
| `priority`      | `str`  | `"P3"`  | Priority level (P1-P5).              |
| `patient_zero`  | `str`  | `""`    | Patient-zero device/node name.       |
| `root_cause`    | `str`  | `""`    | Root cause description.              |

### Returns
```json
{
  "ticket": "<formatted ticket text>"
}
```

### Raises
None.

### Flow
Delegates to `svc.generate_rca_ticket_text()`.

### Dependencies
- `src.services.generate_rca_ticket_text()`

---

## Endpoint: `GET /sitrep`

### Purpose
Returns a global situational report (SITREP) generated from the current system configuration and AIOps data.

### Parameters
None.

### Returns
```json
{
  "report": "<generated SITREP text>"
}
```

### Raises
None.

### Flow
1. Opens a database session and retrieves the first `SystemConfig` row.
2. Extracts key fields into a config dict.
3. Delegates to `svc.generate_global_sitrep()`.

### Dependencies
- `src.services.generate_global_sitrep()`
- `src.models.schema.SystemConfig`
- `src.core.db.SessionLocal`

---

## Endpoint: `POST /sitrep`

### Purpose
Performs actions related to the situational report, such as refreshing the rolling summary, generating scoring rationale, or running a security audit.

### Parameters
| Parameter | Type               | Description                                   |
|-----------|--------------------|-----------------------------------------------|
| `data`    | `dict[str, Any]`   | JSON body with `action` and optional payload. |

#### Body Fields
| Field    | Type               | Default | Description                              |
|----------|--------------------|---------|------------------------------------------|
| `action` | `str`              | `""`    | One of: `refresh_briefing`, `scoring_rationale`, `security_audit`. |
| `intel`  | `dict`             | `{}`    | Intel data for scoring rationale action. |

### Returns
Varies by action:
- `refresh_briefing` — result of `svc.trigger_rolling_summary()`.
- `scoring_rationale` — result of `svc.trigger_scoring_rationale()`.
- `security_audit` — `{"status": "ok", "report": "<audit>"}`.
- Unknown action — `{"status": "error", "message": "Unknown action: <action>"}`.

### Raises
None.

### Flow
1. Extracts `action` from the request body.
2. Routes to the appropriate handler based on action string:
   - `refresh_briefing`: calls `svc.trigger_rolling_summary()`.
   - `scoring_rationale`: extracts `intel` and calls `svc.trigger_scoring_rationale()`.
   - `security_audit`: queries the last 50 `CveItem` records and calls `cross_reference_cves()` from `src.utils.llm`.
   - Default: logs a warning and returns an error response.

### Dependencies
- `src.services.trigger_rolling_summary()`
- `src.services.trigger_scoring_rationale()`
- `src.utils.llm.cross_reference_cves()`
- `src.models.schema.CveItem`
- `src.core.db.SessionLocal`

---

## Endpoint: `POST /clear-events`

### Purpose
Clears all timeline events from the AIOps dashboard.

### Parameters
None.

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Delegates to `svc.clear_timeline_events()`.

### Dependencies
- `src.services.clear_timeline_events()`

---

## Endpoint: `POST /nuke-alerts`

### Purpose
Deletes all active (non-acknowledged) alerts from the system.

### Parameters
None.

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Delegates to `svc.nuke_active_alerts()`.

### Dependencies
- `src.services.nuke_active_alerts()`

---

## Endpoint: `POST /resolve-alert`

### Purpose
Resolves a specific alert by alert ID or by node name.

### Parameters
| Parameter   | Type   | Default | Description                          |
|-------------|--------|---------|--------------------------------------|
| `alert_id`  | `int`  | `0`     | ID of the alert to resolve.          |
| `node_name` | `str`  | `""`    | Node name to resolve alerts for.     |

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Delegates to `svc.resolve_alert()`.

### Dependencies
- `src.services.resolve_alert()`
