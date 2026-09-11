# Module: `web/src/utils/routeConfig.ts`

Defines the frontend page-permission contract.

## `PAGE_PERMISSION_MAP`

Maps route paths to exact backend `allowed_pages` values:

| Route | Permission |
|---|---|
| `/` | `Global Dashboards` |
| `/threat-telemetry` | `Threat Telemetry` |
| `/regional-grid` | `Regional Grid` |
| `/threat-hunting` | `Threat Hunting & IOCs` |
| `/aiops-rca` | `AIOps RCA` |
| `/shift-logbook` | `Shift Logbook` |
| `/reporting` | `Reporting & Briefings` |
| `/settings` | `Settings & Admin` |
| `/keyword-analysis` | `Keyword Analysis` |

## `PAGE_ROUTE_MAP`

Constructed with `Object.fromEntries` by reversing `PAGE_PERMISSION_MAP`. `ProtectedRoute` uses it to send a user without access to the first page they are allowed to view.

Permission spelling is an integration contract. Change the backend role seed, frontend map, and Settings role controls together.
