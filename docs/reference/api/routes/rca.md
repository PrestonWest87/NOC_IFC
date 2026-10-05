# Module: `src.api.routes.rca`

Root Cause Analysis (RCA) routes for AIOps alert clustering, fleet outage detection, root cause calculation, site maintenance, dispatching, investigation state management, and situation reporting. Prefix: `/api/v1/rca`.

---

## Module-Level State

```python
INVESTIGATING_SITES = set()  # In-memory set of site names under investigation
```

This process-local set survives browser page refreshes but resets when the API process restarts. `GET /dashboard` returns investigation state only for sites visible to the caller (all sites for administrators); `POST /investigate` changes a site in the set.

---

## Function: `require_action(action: str)`

### Purpose
Wrapper around `src.api.auth_guard.require_action`. The shared request middleware/dependency resolves the bearer session (retaining legacy query-token compatibility), then the returned dependency checks the authenticated user's action/tab grant.

### Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| `action` | `str` | The action string to check (e.g., `"Action: Dispatch RCA Tickets"`). |

### Returns
| Type | Description |
|------|-------------|
| `callable` | A dependency that receives the authenticated user from `get_current_user` and returns it when authorized. |

### Raises
- `HTTPException 401` — if the token is invalid or not provided.
- `HTTPException 403` — if the user's `allowed_actions` does not include the required action.

### Flow
1. The shared auth guard resolves the request session.
2. Checks the required action against the user's grants (administrators use the full-access override).
3. Returns the authenticated user or raises a structured 401/403 response.

### Dependencies
- `src.services.get_user_by_token()`

---

## Endpoint: `GET /dashboard`

### Purpose
Requires the AIOps RCA page and Active Board tab. Returns dashboard alerts, timeline events, grid, locations, and investigation state filtered to the caller's allowed site types. Administrators receive the full site set.

### Parameters
None.

### Returns
```json
{
  "alerts": [...],
  "events": [...],
  "grid": [...],
  "locations": [...],
  "investigating_sites": ["SiteName", ...]
}
```

### Dependencies
- `src.services.get_aiops_dashboard_data()`
- `src.services.get_cached_locations()`
- Module-level `INVESTIGATING_SITES` set

---

## Endpoint: `POST /analyze`

### Purpose
Requires the AIOps RCA page, Active Board tab, and `Action: Run RCA Analysis`. Performs a full RCA analysis cycle on the caller's permitted alert/site data, identifies fleet outages, and calculates root cause with weather/cloud/BGP context. Chronic insights are returned only to users with access to all site types.

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

### Flow
1. Retrieves active alerts, events, and grid data, then filters them to the caller's site-type scope.
2. Instantiates `EnterpriseAIOpsEngine`.
3. Calls `engine.analyze_and_cluster(alerts)` to group alerts by site.
4. Calls `engine.identify_fleet_outages(clustered)` to detect fleet-wide communication/power failures.
5. Queries active `CloudOutage`, `RegionalHazard`, and `BgpAnomaly` records.
6. Iterates over each clustered site, calling `engine.calculate_root_cause()` with contextual data.
7. Calls `engine.generate_chronic_insights()` for 60-day trend analysis only when the caller has access to all site types.
8. Returns all results.

### Dependencies
- `src.services.get_aiops_dashboard_data()`
- `src.services.aiops_engine.EnterpriseAIOpsEngine`
- `src.models.schema.CloudOutage`, `RegionalHazard`, `BgpAnomaly`
- `src.core.db.SessionLocal`

---

## Endpoint: `POST /acknowledge`

### Purpose
Requires the AIOps RCA page, Active Board tab, and `Action: Acknowledge RCA Alerts`. Acknowledges a set of alerts by their IDs using the authenticated user's name, verifies access to all affected sites, and schedules a WebSocket update.

### Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| `alert_ids` | `list[int]` | JSON body array of alert IDs to acknowledge. |

### Returns
```json
{ "status": "ok" }
```

### Flow
1. Calls `svc.ensure_user_can_access_alerts(user, alert_ids)` and returns a site-scope 403 if needed.
2. Delegates to `svc.acknowledge_cluster(alert_ids, username=user.username)`.
3. Schedules `{"type": "RCA_UPDATE"}` through FastAPI `BackgroundTasks`.

### Dependencies
- `src.services.acknowledge_cluster()`
- `src.api.main.manager`

---

## Endpoint: `POST /dispatch`

### Purpose
Requires the AIOps RCA page, Active Board tab, and `Action: Dispatch RCA Tickets`. Sets the dispatch status for a set of accessible alerts and triggers a WebSocket update.

### Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | `dict` | JSON body with `alert_ids` (list[int]) and `is_dispatched` (bool). |

### Returns
```json
{ "status": "ok" }
```

### Raises
- `HTTPException 401` — not authenticated.
- `HTTPException 403` — missing `Action: Dispatch RCA Tickets`.

### Flow
1. Guarded by `Depends(require_action("Action: Dispatch RCA Tickets"))`.
2. Verifies access to every alert's site, then calls `svc.set_cluster_dispatch(alert_ids, is_dispatched, dispatched_by=user.username)`.
3. Broadcasts RCA_UPDATE via WebSocket.

### Dependencies
- `src.services.set_cluster_dispatch()`
- `require_action()`
- `src.api.main.manager`

---

## Endpoint: `POST /site-maintenance`

### Purpose
Sets or clears maintenance mode for an accessible monitored site, with optional ETR (Estimated Time to Resolve) and reason. Requires the AIOps RCA page, Active Board tab, and `Action: Manage Site Maintenance`. Tracks `status_modified_by` and `status_modified_at`.

### Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | `dict` | JSON body with `site_name`, `is_maint`, `etr`, `reason`. |

#### Body Fields
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `site_name` | `str` | `""` | Name of the monitored site. |
| `is_maint` | `bool` | `False` | Whether to enable or disable maintenance. |
| `etr` | `str` | `None` | ISO 8601 ETR datetime string. |
| `reason` | `str` | `""` | Maintenance reason. |

### Returns
```json
{ "status": "ok" }
```

### Raises
- `HTTPException 401` — not authenticated.
- `HTTPException 403` — missing `Action: Manage Site Maintenance`.

### Flow
1. Requires the Active Board tab and `Action: Manage Site Maintenance`, then validates site-type access.
2. Parses `etr` from ISO 8601 string to `datetime` if provided.
3. Delegates to `svc.set_site_maintenance(site_name, is_maint, etr_date, reason, modified_by=user.username)`.
4. Broadcasts RCA_UPDATE via WebSocket.

### Dependencies
- `src.services.set_site_maintenance()`
- `require_action()`
- `src.api.main.manager`

---

## Endpoint: `POST /investigate`

### Purpose
Locks or unlocks an accessible site for investigation by adding/removing it from the in-memory `INVESTIGATING_SITES` set. Requires the AIOps RCA page, the Active Board tab, and `Action: Dispatch RCA Tickets`.

### Parameters
JSON body:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `site` | `str` | `""` | Site name to toggle investigation state for. |
| `is_investigating` | `bool` | `False` | Whether to lock or unlock investigation. |

### Returns
```json
{ "status": "ok" }
```

### Flow
1. Reads `site` and `is_investigating` from the JSON body.
2. Requires the Active Board tab and `Action: Dispatch RCA Tickets`, then validates site-type access.
3. If `is_investigating`, adds the site to the set; otherwise discards it.
4. Schedules `{"type": "RCA_UPDATE"}` through FastAPI `BackgroundTasks` for WebSocket broadcast.

### Dependencies
- `src.api.main.manager`
- Module-level `INVESTIGATING_SITES`

---

## Endpoint: `POST /generate-ticket`

### Purpose
Generates formatted RCA ticket text for an accessible site. Requires the AIOps RCA page, Active Board tab, and `Action: Dispatch RCA Tickets`.

### Parameters
JSON body:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `site` | `str` | `""` | Site name. |
| `priority` | `str` | `"P3"` | Priority level (P1-P5). |
| `patient_zero` | `str` | `""` | Patient-zero device/node name. |
| `root_cause` | `str` | `""` | Root cause description. |
| `cluster` | `dict` | `{}` | Cluster data (alert details, event type, node info). |

### Returns
```json
{
  "ticket": "<formatted ticket text>"
}
```

### Flow
Delegates to `svc.generate_rca_ticket_text(site, cluster, priority, patient_zero, root_cause)` which generates formatted text including:
- Priority and district header
- Alert details with event types, severity, timestamps
- Patient zero identification
- Root cause description
- Affected device listing

### Dependencies
- `src.services.generate_rca_ticket_text()`

---

## Endpoint: `POST /send-ticket`

### Purpose
Sends a formatted RCA ticket via email. Requires the AIOps RCA page, Active Board tab, and `Action: Dispatch RCA Tickets`, and validates the site and any alert IDs against the caller's site scope.

### Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `site` | `str` | `""` | Site name. |
| `ticket_text` | `str` | `""` | Pre-generated ticket text body. |
| `recipient` | `str` | `"remedyforceworkflow@aecc.com, noc@aecc.com"` | Email recipient(s). |
| `alert_ids` | `list[int]` | `[]` | Alert IDs to mark as dispatched. |
| `priority` | `str` | `"P3"` | Priority level. |
| `district` | `str` | `"Unknown"` | District for the header. |
| `sla` | `str` | `"N/A (Manual Dispatch)"` | SLA target string. |

### Returns
```json
{
  "status": "ok" | "error",
  "message": "<SMTP result message>"
}
```

### Flow
1. Guarded by `Depends(require_action("Action: Dispatch RCA Tickets"))`.
2. Constructs the email body with `*** MANUAL TICKET ***`, the target SLA, and the supplied ticket text.
3. Calls `send_alert_email()` from `src.utils.mailer` with plain text format.
4. If `alert_ids` are provided, marks them as dispatched via `svc.set_cluster_dispatch()` regardless of the mailer's returned success value.
5. Broadcasts RCA_UPDATE via WebSocket.

### Dependencies
- `src.utils.mailer.send_alert_email()`
- `src.services.set_cluster_dispatch()`
- `require_action()`
- `src.api.main.manager`

---

## Endpoint: `GET /sitrep`

### Purpose
Requires the AIOps RCA page, Global Correlation tab, `Action: Generate Reports`, and access to all site types. Returns a global SITREP generated from current configuration and AIOps data.

### Parameters
None.

### Returns
```json
{
  "report": "<generated SITREP text>"
}
```

### Dependencies
- `src.services.generate_global_sitrep()`
- `src.models.schema.SystemConfig`
- `src.core.db.SessionLocal`

---

## Endpoint: `POST /sitrep`

### Purpose
Requires the AIOps RCA page and Global Correlation tab. Each action has its own action permission; scoring rationale and security audit also require access to all site types.

### Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `data` | `dict[str, Any]` | `{}` | JSON body with `action` and optional payload. |

#### Body Fields
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `action` | `str` | `""` | One of: `refresh_briefing`, `scoring_rationale`, `security_audit`. |
| `intel` | `dict` | `{}` | Intel data for scoring rationale action. |

### Returns
Varies by action:
- `refresh_briefing` — result of `svc.trigger_rolling_summary()`.
- `scoring_rationale` — result of `svc.trigger_scoring_rationale()`.
- `security_audit` — `{"status": "ok", "report": "<audit>"}`.
- Unknown action — `{"status": "error", "message": "Unknown action: <action>"}`.

### Dependencies
- `src.services.trigger_rolling_summary()`
- `src.services.trigger_scoring_rationale()`
- `src.utils.llm.cross_reference_cves()`
- `src.models.schema.CveItem`

---

## Endpoint: `POST /clear-events`

### Purpose
Clears all timeline events from the AIOps dashboard. Requires the AIOps RCA page, Danger Zone tab, and `Action: Clear AIOps Data`.

### Parameters
None.

### Returns
```json
{ "status": "ok" }
```

### Dependencies
- `src.services.clear_timeline_events()`

---

## Endpoint: `POST /nuke-alerts`

### Purpose
Deletes all SolarWinds alert records. Requires the AIOps RCA page, Danger Zone tab, and `Action: Clear AIOps Data`.

### Parameters
None.

### Returns
```json
{ "status": "ok" }
```

### Dependencies
- `src.services.nuke_active_alerts()`

---

## Endpoint: `POST /resolve-alert`

### Purpose
Resolves a specific alert selected by `alert_id`. The optional `node_name` appears in the operator timeline message; it is not used to look up the alert. Requires the AIOps RCA page, Active Board tab, and `Action: Acknowledge RCA Alerts`, and verifies site scope.

### Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `alert_id` | `int` | `0` | ID of the alert to resolve. |
| `node_name` | `str` | `""` | Node name included in the operator timeline message. |

### Returns
```json
{ "status": "ok" }
```

### Dependencies
- `src.services.resolve_alert()`
