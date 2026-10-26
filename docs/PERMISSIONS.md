# Permissions and Authorization

This reference documents the permission contract implemented by `src/core/permissions.py` and enforced by FastAPI route dependencies. Permission names are exact, case-sensitive strings. The API is authoritative; frontend checks control visibility and provide feedback, not security.

## Permission layers

Each role stores three independent grant arrays:

- **Pages** (`allowed_pages`) control route/workspace access.
- **Tabs and actions** (`allowed_actions`) control individual sections and operations. Tab grants use the same storage array as action grants, but have separate `Tab:` keys.
- **Site types** (`allowed_site_types`) limit facility-scoped AIOps data and mutations.

The built-in `admin` and `administrator` role names receive the administrator override in backend permission helpers. Non-administrator roles must carry each applicable grant explicitly. Several legacy `/api/v1/admin/*` routes are administrator-only even when a user has a matching Settings tab grant.

## Page catalog

| Exact page key | Route | Scope |
|---|---|---|
| `Global Dashboards` | `/` | Operational and risk dashboards |
| `Threat Telemetry` | `/threat-telemetry` | RSS, CISA KEV, cloud status, and perimeter crime |
| `Regional Grid` | `/regional-grid` | Regional map, weather, and hazard analytics |
| `Threat Hunting & IOCs` | `/threat-hunting` | IOC search, article pivots, and cached Elastic events |
| `AIOps RCA` | `/aiops-rca` | Infrastructure alerts, correlation, and response |
| `Shift Logbook` | `/shift-logbook` | Shift notes and handoff history |
| `Reporting & Briefings` | `/reporting` | Reports, briefings, and report library |
| `Settings & Admin` | `/settings` | Profile, application settings, and user administration |
| `Keyword Analysis` | `/#/keyword-analysis` | Scoring and category analytics |

## Tab catalog

| Workspace | Exact tab grant | UI tab value |
|---|---|---|
| Dashboards | `Tab: Dashboards -> Operational` | `0` |
| | `Tab: Dashboards -> Global Risk` | `1` |
| | `Tab: Dashboards -> Internal Risk` | `2` |
| | `Tab: Dashboards -> Unified Brief` | `3` |
| Threat Telemetry | `Tab: Threat Telemetry -> RSS Triage` | `0` |
| | `Tab: Threat Telemetry -> CISA KEV` | `1` |
| | `Tab: Threat Telemetry -> Cloud Services` | `2` |
| | `Tab: Threat Telemetry -> Perimeter Crime` | `3` |
| Regional Grid | `Tab: Regional Grid -> Geospatial Map` | `geospatial` |
| | `Tab: Regional Grid -> Executive Dash` | `executive` |
| | `Tab: Regional Grid -> Hazard Analytics` | `hazard` |
| | `Tab: Regional Grid -> Location Matrix` | `matrix` |
| | `Tab: Regional Grid -> Weather Alerts Log` | `alerts` |
| | `Tab: Regional Grid -> Atmos Weather` | `atmos` |
| Threat Hunting | `Tab: Threat Hunting -> Global IOC Matrix` | `ioc` |
| | `Tab: Threat Hunting -> Deep Hunt Builder` | `hunt` |
| | `Tab: Reporting -> Elastic SIEM Report` | `siem` |
| AIOps RCA | `Tab: AIOps RCA -> Active Board` | `0` |
| | `Tab: AIOps RCA -> Predictive Analytics` | `1` |
| | `Tab: AIOps RCA -> Global Correlation` | `2` |
| Shift Logbook | `Tab: Shift Log -> Active Shift` | `active` |
| | `Tab: Shift Log -> History` | `history` |
| Reporting | `Tab: Reporting -> Daily Fusion` | `0` |
| | `Tab: Reporting -> Report Builder` | `1` |
| | `Tab: Reporting -> Shared Library` | `2` |
| Settings | `Tab: Settings -> Facility Locations` | `facilities` |
| | `Tab: Settings -> Internal Assets` | `assets` |
| | `Tab: Settings -> RSS Sources` | `rss` |
| | `Tab: Settings -> ML Training` | `ml` |
| | `Tab: Settings -> AI & SMTP` | `ai-smtp` |
| | `Tab: Settings -> Application Settings` | `application` |
| | `Tab: Settings -> Users & Roles` | `users` |
| | `Tab: Settings -> Backup & Restore` | `backup` |
| | `Tab: Settings -> Danger Zone` | `danger` |

## Action catalog

| Exact action key | Purpose |
|---|---|
| `Action: Pin Articles` | Pin and unpin articles |
| `Action: Boost Threat Score` | Manually adjust an article score |
| `Action: Manually Sync Data` | Trigger supported external data synchronization |
| `Action: Generate Reports` | Generate or regenerate reports and briefs |
| `Action: Generate Risk Snapshot` | Run the internal asset-risk calculation |
| `Action: Run RCA Analysis` | Run root-cause analysis and correlation |
| `Action: Clear AIOps Data` | Delete timeline events or SolarWinds alert data |
| `Action: Dispatch Exec Report` | Send or broadcast reports and briefs; also gates selected report-library operations |
| `Action: Send Email` | Send an arbitrary operational email |
| `Action: Submit Shift Log` | Create, edit, or delete the caller's shift-log entries |
| `Action: Manage Shift Logs` | Edit or delete another user's shift-log entries |
| `Action: Dispatch RCA Tickets` | Change investigation/dispatch workflow and generate or send RCA tickets |
| `Action: Acknowledge RCA Alerts` | Acknowledge or resolve RCA alerts |
| `Action: Manage Site Maintenance` | Change site maintenance state and ETR |
| `Action: Train ML Model` | Run manual model retraining |
| `Action: Adjust Risk Scoring Overrides` | Change risk mode, baselines, overrides, offsets, and countermeasures |
| `Action: Manage Scheduler Settings` | Change validated scheduler timing |
| `Action: Manage Application Settings` | Change global application defaults and failed-login alert settings |
| `Action: Manage Users` | Create and manage individual/display accounts |
| `Action: Manage Roles` | Create roles and edit permission grants |
| `Action: Review Account Recovery Requests` | Approve or deny password-reset requests |
| `Action: Approve Recovery Email Changes` | Approve or deny recovery-email changes |
| `Action: Trigger AI Functions` | **Legacy compatibility grant.** New operations use narrower action grants where available. |

`Action: Trigger AI Functions` remains a recognized legacy key. Current routes still use it for article feedback/BLUF generation, SIEM triage, keyword recategorization, and scoring-rationale actions. It does not replace the narrower `Action: Generate Reports`, email, scheduler, risk, user, or recovery grants.

## Default role behavior

Bootstrap behavior is defined in `src/core/bootstrap.py`:

- **`admin`** receives all page, action, and tab keys plus the current default/database site-type catalog. The runtime administrator override also applies to the `administrator` role name.
- **`analyst`** is seeded with every page except Settings & Admin, the non-Settings operational tab grants, a selected operational action set, and the current site-type catalog. The one-time permission-catalog migration resets the built-in analyst role to this baseline and conservatively replaces the legacy AI grant on other roles; later startups do not union grants.
- **`viewer`** receives Global Dashboards and Regional Grid, with the Operational dashboard and Geospatial Map tabs, and the current site-type catalog.
- **`user-admin`** receives Settings & Admin, the Users & Roles tab, user management, password-reset review, and recovery-email approval grants; it has no site-type grants.

Custom roles are not broadened on normal startup. Role creation validates grants against the current catalog. Delegated role editors cannot grant permissions or site types they do not hold, cannot assign administrator/elevated user-administration roles, and cannot edit the built-in administrator role. Existing legacy site-type grants can be retained or removed during an edit; new site-type grants must be in the live catalog.

## Enforcement by boundary

| Boundary | Enforcement |
|---|---|
| HTTP authentication | Middleware authenticates protected `/api/v1/*` requests from a Bearer token. `token` and `session_token` query parameters remain supported for compatibility. Public auth/recovery, health/readiness, and restore-status routes are explicit exceptions. |
| Page/tab/action | Router and handler dependencies check exact catalog keys. A 401 means no valid active session; a 403 means the session is valid but a required grant is missing. |
| Legacy administrator API | The `/api/v1/admin/*` router requires the built-in administrator role. New delegated user and application-settings routes use finer-grained grants. |
| AIOps site scope | Non-administrators' alert, timeline, grid, location, and WebSocket data are filtered to names whose site type is in `allowed_site_types`. Mutations validate the target site or every alert ID. Global RCA reports require all site types. |
| WebSocket | Requires an active session, `AIOps RCA` page, and `Tab: AIOps RCA -> Active Board`. Sessions/grants are revalidated; client `INVESTIGATING_UPDATE` and `RCA_UPDATE` commands require `Action: Dispatch RCA Tickets`. |
| Role editor | `/permissions/catalog` is available to any authenticated user; user/role administration writes enforce their separate actions and the delegation limits above. |

See [API Reference](API.md) for route-by-route requirements and [User Guide](USER_GUIDE.md) for the end-user view.
