# AiopsRcaPage.tsx

AIOps Root Cause Analysis page. Provides three tabs: Active Board (live map + correlation cards), Predictive Analytics & Chronic Degradation, and Deterministic Global Correlation Engine.

---

## Constants

### `INITIAL_VIEW`
- Default deck.gl MapViewState: lat `34.8`, lon `-92.2`, zoom `6`, pitch `0`.

### `RCA_TAB_LABELS`
- Values: `["Active Board", "Patterns", "Global"]`

### Style Constants
- `tabBtn(active)`: Dynamic style for tab buttons with active/inactive state.
- `card`, `inputBase`, `btnBase`, `label`: Shared CSS property objects.

---

## `AiopsRcaPage` (named export)

### Purpose
Main AIOps RCA page with live polling, site status map, alert correlation, chronic degradation analysis, and global sitrep generation.

### Props
None (uses `useAuth` for user context).

### Returns
- Tab navigation with three tabs
- Tab 0: Live map with event log + incident correlation cards
- Tab 1: Predictive analytics with deep analysis runner
- Tab 2: Global correlation engine with sitrep generation

### Flow

#### State Management
| State | Type | Default | Description |
|-------|------|---------|-------------|
| `activeTab` | `number` | `0` | Active tab index |
| `livePolling` | `boolean` | `true` | Enables 5s polling |
| `dispatchChecked` | `Record<string, boolean>` | `{}` | Per-site dispatch checkbox state |
| `ticketExpanded` | `string \| null` | `null` | Site with expanded ticket panel |
| `maintExpanded` | `string \| null` | `null` | Site with expanded maintenance panel |
| `maintForm` | `Record<string, { status, etr, reason }>` | `{}` | Maintenance form data per site |
| `ticketTexts` | `Record<string, string>` | `{}` | Ticket text per site |
| `sitrepReport` | `string \| null` | `null` | Global correlation sitrep report |
| `deepAnalysisRun` | `boolean` | `false` | Whether deep analysis has been triggered |
| `investigatingSites` | `Set<string>` | `new Set()` | Sites marked as investigating |
| `siteDialog` | `object \| null` | `null` | Map popup dialog state |
| `dialogDispatch` | `boolean` | `false` | Dialog dispatch checkbox |
| `dialogStatus` | `string` | `"Investigate/Dispatch"` | Dialog radio selection |
| `dialogEtr` | `string` | today's date | Dialog ETR date |
| `dialogReason` | `string` | `""` | Dialog reason text |

#### Data Queries
| Query Key | Endpoint | Interval | Description |
|-----------|----------|----------|-------------|
| `rca-dashboard` | `GET /rca/dashboard` | 5s (when live) | Current dashboard state |
| `rca-analyze` | `POST /rca/analyze` | 30s (when live) | Root cause analysis |
| `rca-sitrep` | `GET /rca/sitrep` | manual only | Global sitrep |

#### Mutations
| Mutation | Endpoint | Description |
|----------|----------|-------------|
| `ackMutation` | `POST /rca/acknowledge` | Acknowledge alert IDs |
| `dispatchMutation` | `POST /rca/dispatch` | Toggle dispatch state |
| `maintMutation` | `POST /rca/site-maintenance` | Set maintenance state |

#### Tab Content

**Tab 0 — Active Board:**
- Live polling toggle (5s interval for dashboard, 30s for analysis)
- deck.gl map with:
  - Site scatter points color-coded by status (Operational=green, No Dispatch=blue, Dispatched=yellow, Investigating=orange, Action Required=red)
  - Alert pulse layer for sites requiring action
  - Click handler opens site dialog popup
- Event Log sidebar (timestamped event messages)
- Global Fleet Event banner (when fleet outages detected)
- Incident correlation cards per site showing:
  - Priority, site name, alert count
  - Root cause text with patient zero
  - Maintenance banner (when site is under maintenance)
  - Action buttons: Ticket Dispatched checkbox, Draft & Dispatch Ticket, Acknowledge, Maintenance Controls
  - Expanded ticket textarea with dispatch button
  - Expanded maintenance form (status, ETR, reason, save)

**Tab 1 — Patterns (Predictive Analytics):**
- Run Deep Analysis button (triggers `POST /rca/analyze`)
- Results when analysis has been run:
  - Top Offending Nodes table (high-frequency flapping devices)
  - Infrastructure Hotspots table (chronically unstable sites/regions)
  - AI Predictive Maintenance Forecast (string, array, or table format)
- Empty state when analysis hasn't been run

**Tab 2 — Global (Correlation Engine):**
- Run Global Correlation button (triggers `GET /rca/sitrep`)
- Sitrep report display in monospace font
- Broadcast SitRep button (triggers `POST /rca/dispatch`)
- Empty state when correlation hasn't been run

#### Derived Data
- `sites`: Memoized mapping of locations with alert counts, dispatch, and maintenance status.
- `incidentSites`: Unique set of site names from clustered analysis, root cause, and alerts.
- `getRc(site)`: Parses root cause data (array or object format) into structured object with cause, score, priority, evidenceLog, blastRadius, patientZero, cascadeStr.
- `getClusterAlerts(site)`: Returns alerts for a site from clustered data or filtered alerts.
- `chronOffNodes`, `chronHotspots`, `chronForecast`: Extracted from chronic insights data (handles multiple data formats).

#### Handlers
- `handleAcknowledge(site)`: Collects alert IDs for the site and acknowledges them.
- `handleDispatchToggle(site, checked)`: Sets dispatch state for all alerts at the site.
- `handleGenerateTicket(site)`: Generates a ticket via API or falls back to formatted text.
- `openSiteDialog(site)`: Populates the site dialog state from a site object.
- `handleMapClick(info)`: Opens site dialog when a mapped site is clicked.
- `handleSaveSiteDialog()`: Saves dispatch and maintenance changes from the dialog.
- `handleRunDeepAnalysis()`: Triggers analysis refetch and sets state flag.
- `handleRunGlobalCorrelation()`: Triggers sitrep fetch and stores report.
- `saveMaint(site)`: Saves maintenance form data via mutation.
- `mapTooltip(info)`: Returns HTML tooltip for site layer.
- `mapLayers`: Memoized deck.gl layers (sites + alert pulses) with color/size logic.
- `renderChronicTable(data, caption)`: Renders a generic tabular display for chronic insights.

#### Permission Enforcement
- `getAllowedTabs(user?.allowed_actions, "aiopsRca")` filters tabs.
- `canDispatch` = `userAllowedActions.includes("Action: Dispatch RCA Tickets")`.
- `canManageMaint` = `userAllowedActions.includes("Action: Manage Site Maintenance")`.
- Dispatch/Maintenance controls are conditionally rendered based on these permissions.
- `useEffect` enforces tab permissions on changes.

### Dependencies
- `useState`, `useMemo`, `useCallback`, `useEffect` from `react`
- `useQuery`, `useMutation`, `useQueryClient` from `@tanstack/react-query`
- `api` from `../utils/api`
- `useAuth` from `../utils/AuthContext`
- `getAllowedTabs` from `../utils/permissions`
- `MapContainer` from `../components/MapContainer`
- `DeckGL` from `@deck.gl/react`
- `ScatterplotLayer` from `@deck.gl/layers`
- `Map` from `react-map-gl/maplibre`
- `MapViewState` type from `@deck.gl/core`
- `maplibre-gl/dist/maplibre-gl.css`
- `lucide-react` icons (15+ icons)
