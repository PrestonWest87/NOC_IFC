# Permissions

## Overview

Permission mapping and resolution utilities for tab-level access control. Maps action permission strings (returned by the backend for the authenticated user) to tab identifier keys used by the frontend page components.

---

## Constants

### `TAB_PERMISSION_MAP`

- **Type**: `Record<string, Record<string, string>>`
- **Description**: Maps page keys to a dictionary of `{ action_permission_string: tab_identifier }`. Page-level keys match the page component naming convention. Tab identifiers are used by page components to conditionally render sub-tabs.

| Page Key | Action Permission | Tab Key |
|----------|-----------------|---------|
| `dashboard` | `Tab: Dashboards -> Operational` | `"0"` |
| `dashboard` | `Tab: Dashboards -> Global Risk` | `"1"` |
| `dashboard` | `Tab: Dashboards -> Internal Risk` | `"2"` |
| `dashboard` | `Tab: Dashboards -> Unified Brief` | `"3"` |
| `threatTelemetry` | `Tab: Threat Telemetry -> RSS Triage` | `"0"` |
| `threatTelemetry` | `Tab: Threat Telemetry -> CISA KEV` | `"1"` |
| `threatTelemetry` | `Tab: Threat Telemetry -> Cloud Services` | `"2"` |
| `threatTelemetry` | `Tab: Threat Telemetry -> Perimeter Crime` | `"3"` |
| `regionalGrid` | `Tab: Regional Grid -> Geospatial Map` | `"geospatial"` |
| `regionalGrid` | `Tab: Regional Grid -> Executive Dash` | `"executive"` |
| `regionalGrid` | `Tab: Regional Grid -> Hazard Analytics` | `"hazard"` |
| `regionalGrid` | `Tab: Regional Grid -> Location Matrix` | `"matrix"` |
| `regionalGrid` | `Tab: Regional Grid -> Weather Alerts Log` | `"alerts"` |
| `regionalGrid` | `Tab: Regional Grid -> Atmos Weather` | `"atmos"` |
| `threatHunting` | `Tab: Threat Hunting -> Global IOC Matrix` | `"ioc"` |
| `threatHunting` | `Tab: Threat Hunting -> Deep Hunt Builder` | `"hunt"` |
| `threatHunting` | `Tab: Reporting -> Elastic SIEM Report` | `"siem"` |
| `aiopsRca` | `Tab: AIOps RCA -> Active Board` | `"0"` |
| `aiopsRca` | `Tab: AIOps RCA -> Predictive Analytics` | `"1"` |
| `aiopsRca` | `Tab: AIOps RCA -> Global Correlation` | `"2"` |
| `reporting` | `Tab: Reporting -> Daily Fusion` | `"0"` |
| `reporting` | `Tab: Reporting -> Report Builder` | `"1"` |
| `reporting` | `Tab: Reporting -> Shared Library` | `"2"` |
| `settings` | `Tab: Settings -> Facility Locations` | `"facilities"` |
| `settings` | `Tab: Settings -> Internal Assets` | `"assets"` |
| `settings` | `Tab: Settings -> RSS Sources` | `"rss"` |
| `settings` | `Tab: Settings -> ML Training` | `"ml"` |
| `settings` | `Tab: Settings -> AI & SMTP` | `"ai-smtp"` |
| `settings` | `Tab: Settings -> Users & Roles` | `"users"` |
| `settings` | `Tab: Settings -> Backup & Restore` | `"backup"` |
| `settings` | `Tab: Settings -> Danger Zone` | `"danger"` |

---

## Functions

### `getAllowedTabs(allowedActions, pageKey)`

| Parameter | Type | Description |
|-----------|------|-------------|
| `allowedActions` | `string[] \| undefined` | Array of action permission strings assigned to the current user (from `User.allowed_actions`) |
| `pageKey` | `keyof typeof TAB_PERMISSION_MAP` | The page identifier key (e.g. `"dashboard"`, `"regionalGrid"`) |

- **Returns**: `string[]` — Array of tab key strings the user is permitted to access.
- **Flow**:
  1. Looks up the permission map for the given `pageKey`.
  2. If `allowedActions` is undefined or empty, returns an empty array.
  3. Iterates over the map entries, filtering for actions present in `allowedActions`.
  4. Returns the tab key values of matching entries.
- **Example**:
  ```typescript
  // User has operational and unified brief permissions
  getAllowedTabs(
    ["Tab: Dashboards -> Operational", "Tab: Dashboards -> Unified Brief"],
    "dashboard"
  );
  // Returns: ["0", "3"]
  ```

---

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| None | Standalone utility with no imports |
