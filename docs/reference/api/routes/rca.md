# Module: `src.api.routes.rca`

Root Cause Analysis (RCA) routes for AIOps alert clustering, fleet outage detection, root cause calculation, site maintenance, dispatching, investigation state management, and situation reporting. Prefix: `/api/v1/rca`.

---

## Module-Level State

```python
INVESTIGATING_SITES = set()  # In-memory set of site names under investigation
```

This set survives page refreshes but resets on server restart. It is returned in the `/dashboard` response and managed via the `/investigate` endpoint.

---

## Function: `require_action(action: str)`

### Purpose
Factory function that returns a FastAPI `Depends` dependency callable. Validates that the requesting user's token grants a specific action permission.

### Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| `action` | `str` | The action string to check (e.g., `"Action: Dispatch RCA Tickets"`). |

### Returns
| Type | Description |
|------|-------------|
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
Returns the AIOps dashboard data including active alerts, timeline events, grid state, all monitored locations, and the current set of investigating sites.

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

### Flow
1. Retrieves active alerts, events, and grid data from the dashboard.
2. Instantiates `EnterpriseAIOpsEngine`.
3. Calls `engine.analyze_and_cluster(alerts)` to group alerts by site.
4. Calls `engine.identify_fleet_outages(clustered)` to detect fleet-wide communication/power failures.
5. Queries active `CloudOutage`, `RegionalHazard`, and `BgpAnomaly` records.
6. Iterates over each clustered site, calling `engine.calculate_root_cause()` with contextual data.
7. Calls `engine.generate_chronic_insights()` for 60-day trend analysis.
8. Returns all results.

### Dependencies
- `src.services.get_aiops_dashboard_data()`
- `src.services.aiops_engine.EnterpriseAIOpsEngine`
- `src.models.schema.CloudOutage`, `RegionalHazard`, `BgpAnomaly`
- `src.core.db.SessionLocal`

---

## Endpoint: `POST /acknowledge`

### Purpose
Acknowledges a set of alerts by their IDs, removing them from the active alert board. Triggers a WebSocket broadcast to notify all connected clients.

### Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| `alert_ids` | `list[int]` | JSON body array of alert IDs to acknowledge. |

### Returns
```json
{ "status": "ok" }
```

### Flow
1. Delegates to `svc.acknowledge_cluster(alert_ids)`.
2. Broadcasts `{"type": "RCA_UPDATE"}` via WebSocket `manager.broadcast_json()` using `BackgroundTasks`.

### Dependencies
- `src.services.acknowledge_cluster()`
- `src.api.main.manager`

---

## Endpoint: `POST /dispatch`

### Purpose
Sets the dispatch status for a set of alerts. Requires `Action: Dispatch RCA Tickets` permission. Triggers WebSocket broadcast.

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
2. Delegates to `svc.set_cluster_dispatch(alert_ids, is_dispatched)`.
3. Broadcasts RCA_UPDATE via WebSocket.

### Dependencies
- `src.services.set_cluster_dispatch()`
- `require_action()`
- `src.api.main.manager`

---

## Endpoint: `POST /site-maintenance`

### Purpose
Sets or clears maintenance mode for a monitored site, with optional ETR (Estimated Time to Resolve) and reason. Requires `Action: Manage Site Maintenance` permission. Tracks `status_modified_by` and `status_modified_at`.

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
1. Guarded by `Depends(require_action("Action: Manage Site Maintenance"))`.
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
Locks or unlocks a site for investigation by adding/removing it from the in-memory `INVESTIGATING_SITES` set. Requires `Action: Dispatch RCA Tickets` permission.

### Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `site` | `str` | `""` | Site name to toggle investigation state for. |
| `is_investigating` | `bool` | `False` | Whether to lock or unlock investigation. |

### Returns
```json
{ "status": "ok" }
```

### Flow
1. Guarded by `Depends(require_action("Action: Dispatch RCA Tickets"))`.
2. If `is_investigating`, adds site to set; otherwise discards.
3. Broadcasts `{"type": "RCA_UPDATE"}` via WebSocket.

### Dependencies
- `src.api.main.manager`
- Module-level `INVESTIGATING_SITES`

---

## Endpoint: `POST /generate-ticket`

### Purpose
Generates a formatted RCA ticket text string for a given site, priority, patient zero, and root cause description.

### Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `site` | `str` | `""` | Site name. |
| `priority` | `str` | `"P3"` | Priority level (P1-P5). |
| `patient_zero` | `str` | `""` | Patient-zero device/node name. |
| `root_cause` | `str` | `""` | Root cause description. |
| `cluster` | `dict` | `{}` | Cluster data (alert details, event_type, node info). |

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
Sends a formatted RCA ticket via email. Requires `Action: Dispatch RCA Tickets` permission. Marks alerts as dispatched on success.

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
2. Constructs email body with prefix "Automated Comms Outage\n*** MANUAL TICKET ***".
3. Calls `send_alert_email()` from `src.utils.mailer` with plain text format.
4. If `alert_ids` provided, marks them as dispatched via `svc.set_cluster_dispatch()`.
5. Broadcasts RCA_UPDATE via WebSocket.

### Dependencies
- `src.utils.mailer.send_alert_email()`
- `src.services.set_cluster_dispatch()`
- `require_action()`
- `src.api.main.manager`

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

### Dependencies
- `src.services.generate_global_sitrep()`
- `src.models.schema.SystemConfig`
- `src.core.db.SessionLocal`

---

## Endpoint: `POST /sitrep`

### Purpose
Performs actions related to the situational report: refreshing the rolling summary, generating scoring rationale, or running a security audit.

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
Clears all timeline events from the AIOps dashboard.

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
Deletes all active (non-acknowledged) alerts from the system.

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
Resolves a specific alert by alert ID or by node name.

### Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `alert_id` | `int` | `0` | ID of the alert to resolve. |
| `node_name` | `str` | `""` | Node name to resolve alerts for. |

### Returns
```json
{ "status": "ok" }
```

### Dependencies
- `src.services.resolve_alert()`
