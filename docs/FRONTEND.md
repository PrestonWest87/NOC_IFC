# Frontend Architecture and Workspace

The frontend is a TypeScript/React single-page application in `web/`. It uses Vite for development/building, HashRouter for client routing, TanStack Query for server state, Zustand for shared realtime UI state, Axios for REST calls, and MapLibre/deck.gl for maps. The source tree is authoritative; detailed source pages are under [`reference/web/`](reference/README.md#frontend).

## Application setup

`web/src/main.tsx` imports the base theme, component styles, and theme overrides; calls `initTheme()` before rendering; and mounts `<App />` in `React.StrictMode`.

`App.tsx` wraps the application with `QueryClientProvider`, `HashRouter`, `AuthProvider`, `ThemeSync`, `RealtimeBridge`, and a page-level error boundary. The shared query defaults are 30-second stale time, no refetch-on-window-focus, refetch-on-reconnect, and one retry. Protected page modules are lazy-loaded under `Suspense`.

## Routes and page access

Routes are hash-based (for example `/#/regional-grid`). The backend page permission strings are the values in `src/core/permissions.py` and `web/src/utils/routeConfig.ts`.

| Hash route | Page | Page grant |
|---|---|---|
| `#/login` | Login | Public |
| `#/register` | Registration invitation | Public |
| `#/forgot-password` | Password reset request | Public |
| `#/reset-password` | Password reset completion | Public token flow |
| `#/verify-email` | Recovery-email verification | Public token flow |
| `#/` | Global Dashboards | `Global Dashboards` |
| `#/threat-telemetry` | Threat Telemetry | `Threat Telemetry` |
| `#/regional-grid` | Regional Grid | `Regional Grid` |
| `#/threat-hunting` | Threat Hunting & IOCs | `Threat Hunting & IOCs` |
| `#/aiops-rca` | AIOps RCA | `AIOps RCA` |
| `#/shift-logbook` | Shift Logbook | `Shift Logbook` |
| `#/reporting` | Reporting & Briefings | `Reporting & Briefings` |
| `#/settings` | Settings & Admin | `Settings & Admin` |
| `#/keyword-analysis` | Keyword Analysis | `Keyword Analysis` |

After successful login, the browser navigates to the first page in `user.allowed_pages` that maps to a frontend route. `ProtectedRoute` checks the exact page grant. A logged-in user lacking a page grant sees an access-denied message inside the normal layout; the guard does not silently log the user out or redirect to another page.

Tabs are filtered by `web/src/utils/permissions.ts`. Some Settings views are self-service: Profile and Theme appear to any authenticated user who can enter Settings. Other Settings tabs require their exact `Tab: Settings -> ...` grant. Individual controls may need a distinct action grant. Server dependencies remain authoritative for all reads/writes. See [`PERMISSIONS.md`](PERMISSIONS.md) and [`API.md`](API.md).

## Authentication and REST client

`AuthContext` keeps the opaque API session token and public user object in `sessionStorage` (`noc_token`, `noc_user`). It refreshes with `GET /auth/me`; a transient network/API error retains the session, while an explicit 401 clears it. Logout requests server revocation and clears the browser state immediately. Recovery-email verification signals a user refresh in the current tab and same-origin tabs.

`web/src/utils/api.ts` creates an Axios client with relative base URL `/api/v1`. Its request interceptor attaches `Authorization: Bearer ...` from session storage. Its response interceptor:

- On 401, clears credentials, emits `noc:unauthorized`, redirects to `#/login`, and rejects the original request.
- On 403, emits `noc:permission-denied`, preserves the session, and exposes the structured permission message to the UI.

Production nginx proxies `/api/` and `/ws` to the API. The Vite dev server proxies the same paths to `VITE_API_URL` (default `http://localhost:8101`; Compose sets `http://api:8101` inside `web-dev`).

## Page guide

### Global Dashboards

Four tabs: Operational Dashboard, Global Risk, Internal Risk, and Unified Brief. Operational Dashboard has Threat Triage, Infrastructure Status, and AI Analysis panels; its subpanel auto-rotates every ten seconds when enabled. Dashboard metrics/article queries poll at 15–300 second intervals according to their data source.

Global Risk displays the executive CIS score, 14-day score trend, evidence, and Global Threat Brief. Internal Risk displays the latest snapshot, history, hardware/software correlations, and Internal Asset Risk Brief. Risk overrides and scheduler forms are in Settings > Application Settings, not on Dashboard. Unified, global, and internal brief generation returns a generation ID; the page polls every two seconds and keeps the ID in `sessionStorage` across SPA navigation. Brief broadcasts require `Action: Dispatch Exec Report`.

### Threat Telemetry

Four tabs: RSS Triage, CISA KEV, Cloud Services, and Perimeter Crime. RSS triage has Pinned, Live, Low, and Search sub-tabs; the page supports pagination, category/search filters, and permission-gated pin/boost/feedback/BLUF actions. KEV, cloud, and crime sync actions require `Action: Manually Sync Data` plus their tab grant. The crime feed is Little Rock CAD data geocoded and measured from the Little Rock headquarters point.

**Category-label compatibility issue:** the page currently offers some legacy category labels that do not exactly equal current categorizer output. The source comparison is detailed in [`DOCUMENTATION_AUDIT.md`](DOCUMENTATION_AUDIT.md#source-level-mismatches-surfaced-during-the-audit); this can affect exact category filtering.

### Regional Grid

Six tabs: Geospatial Overlay, Executive Dashboard, Deep Hazard Analytics, Location Matrix, Weather Alerts Log, and Atmos Weather. The geospatial view combines MapLibre with deck.gl overlays for SPC, NWS, USGS, fire weather, WFCA wildfire incidents/perimeters/estimated FIRMS footprints, and site markers. The API compiles site/hazard intersections and returns a positional six-item response; the frontend reads positions 0, 3, 4, and 5 for processed geometry, toggled affected sites, all affected sites, and analytics. The route's response order is documented in [`ARCHITECTURE.md`](ARCHITECTURE.md#regional-map).

Weather preferences are per authenticated user. Atmos Weather includes site forecast, NWS alert preferences, SPC outlooks, and an embedded radar view. Wildfire footprints are estimated detection geometry and are distinct from reported fire perimeters.

### Threat Hunting & IOCs

Three tabs: Live Global IOC Matrix, Deep Hunt & Detection Builder, and Elastic SIEM Report. The IOC matrix reads extracted indicators for the last three days by default, offers type filtering/CSV export, and includes external pivots for supported hash/IP/domain/CVE/MITRE indicators.

Deep Hunt searches article title, summary, and full content by an OR combination of parsed terms over 1–30 days (the UI offers 7–30 days) and displays up to 15 of at most 30 matches. `buildDetectionPackage()` is a frontend template generator: it excerpts results, extracts CVE-shaped strings, and creates generic Splunk/Elastic query and YARA stub text. It does **not** call an LLM or validate generated detection rules.

Elastic SIEM displays a local cache of high-severity events. Manual synchronization requires the SIEM tab and `Action: Manually Sync Data`; AI triage requires the legacy `Action: Trigger AI Functions` grant and sends at most 50 bounded events.

### AIOps RCA

Visible tabs are Active Board, Patterns, and Global; their catalog grants are `Tab: AIOps RCA -> Active Board`, `... -> Predictive Analytics`, and `... -> Global Correlation`. Dashboard polling is ten seconds when enabled; analysis polling is sixty seconds. AIOps sockets additionally require Active Board access.

The map distinguishes:

- **Up / Clear**: no unresolved alerts.
- **Down / Action Required**: unresolved alert without a later workflow state.
- **Needs Dispatch**, **Investigating**, and **Ticket Dispatched**: workflow annotations for unresolved incidents.
- **Under Maintenance**: independent blue outline; it does not hide green health or an active alert state.

Acknowledgment hides alerts from the uncorrelated alert list but does not resolve them; active issue counts continue to include acknowledged unresolved alerts. Mark Site Up calls `POST /rca/resolve-site`, resolves every unresolved site alert, clears Needs Dispatch and investigation state, and leaves maintenance metadata separate. Site dialogs let authorized users manage investigation, dispatch, Needs Dispatch, and maintenance/ETR. Co-located sites use a stable radial offset with spokes. The unused `AIOpsMap` helper still contains an older map behavior and is not imported by the routed AIOps page.

### Shift Logbook

The Active Shift view includes note entry, recent-day navigation, and report generation. History access enables the independent explorer with search, role/date filters, day/week views, and administrator CSV export. Soft delete/restore stores `is_deleted`; the current API does not collect a deletion reason. A summary uses the selected shift/day/week scope, appends the generated result when requested by the UI, and falls back to a deterministic summary if the LLM does not finish within thirty seconds.

Auto-Draft requires both `AIOps RCA` page access and `Action: Run RCA Analysis`; it fetches the scoped board and analysis and appends the generated incident-duration lines to the unsaved form.

### Reporting & Briefings

Three tabs: Daily Fusion Briefing, Custom Report Builder, Shared Library. Daily Fusion can generate the previous local calendar day's report and broadcast supplied content. The custom builder searches using space/comma/semicolon-separated terms and quoted phrases, selects matching articles or explicit IDs, then starts an asynchronous report generation. The user may save or broadcast the final report. Broadcast recipient lists allow up to 20 comma/semicolon-separated email addresses and reject newlines.

### Keyword Analysis

Five tabs: Overview, Keyword Analysis, Category Breakdown, Timeline, and Cross-Reference. The page reads persisted analytics from `/keyword-analysis/*`; it does not re-run scoring in the browser. Recategorization processes stored articles in server batches and requires the legacy `Action: Trigger AI Functions` grant.

### Settings & Admin

Eleven UI sections: Profile, Theme, Facilities, Internal Assets, RSS Sources, ML Training, AI & SMTP, Application Settings, Users & Roles, Backup & Restore, and Danger Zone. The nine operational Settings sections use tab grants; Profile/Theme are self-service views. Tab visibility does not imply mutation permission.

`UsersRolesTab` handles searchable user directories, invitations, display accounts, roles, account status, session revocation, and reviewed recovery requests. `ApplicationSettingsTab` separates global defaults/failed-login alerting, risk scoring, and scheduler settings by action grant. Backup and destructive controls are shown only for built-in administrators; the legacy JSON and `.db` migration tools are labeled as partial operations.

## Shared components and state

- `Layout` filters sidebar links by page permission and displays the individual-account recovery prompt. Display accounts are exempt.
- `MapContainer` waits for a non-zero size using `ResizeObserver` and implements **window-fill CSS positioning**, not the browser Fullscreen API.
- `ThemeSelector` offers 21 themes, stores the choice in localStorage, and posts it to the signed-in account. `ThemeSync` applies the saved account theme after user refresh.
- `MarkdownContent` renders report/brief Markdown in the application UI.
- Zustand's `useAppStore` holds the latest dashboard push payload, socket state, investigating-site list, and outbound message callback. TanStack Query holds endpoint data and is invalidated/merged by the WebSocket hook.

`useAIOpsWebSocket` uses `ws`/`wss` on the current browser host and places the opaque token in the query string because the browser WebSocket API cannot attach a custom Authorization header. It reconnects with capped exponential backoff unless the server closes with policy code 1008. It handles `dashboard_update`, `INVESTIGATING_UPDATE`, and `RCA_UPDATE`; newly observed CRITICAL/HIGH IDs can trigger browser notifications.

## Timezone and themes

`web/src/utils/timezone.ts` treats server date strings without an explicit offset as UTC and formats in `America/Chicago`. Theme variables are layered across `styles/theme.css`, `themes/themes.css`, and `styles/components.css`; `standard` uses the base palette.

## Development and production build

```bash
cd web
npm ci
npm run dev
npm run build
```

The Vite development server listens on port 5173 and uses polling for Docker file mounts. Production `web/Dockerfile` compiles to `dist/` and serves the static bundle through nginx on container port 5173 (host port 8501). Production frontend changes require rebuilding/recreating `web`.
