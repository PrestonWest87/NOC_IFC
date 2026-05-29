# RegionalGridPage.tsx

Regional Grid & Hazard Analytics page. Provides six tabs: Geospatial Overlay, Executive Dashboard, Deep Hazard Analytics, Location Matrix, Weather Alerts Log, and Atmos Weather. Integrates deck.gl map visualization with NWS, SPC, USGS data layers.

---

## Constants

### `ALL_TABS`
- Purpose: Tab configuration with key, label, and icon.
- Values: `geospatial`, `executive`, `hazard`, `matrix`, `alerts`, `atmos`

### `SIDEBAR_PX`
- Purpose: Width of the geospatial sidebar in pixels.
- Value: `280`

### Style Constants
- `CARD_STYLE`, `CARD_HEADER`, `BTN_PRIMARY`, `BTN_SECONDARY`, `INPUT_STYLE`, `LABEL_STYLE`, `TH_STYLE`, `TD_STYLE` — reusable CSS property objects.

### `SPC_COLORS`
- Maps SPC risk labels to hex colors: `HIGH`, `MDT`, `ENH`, `SLGT`, `MRGL`, `TSTM`, `None`.

### `NWS_COLORS`
- Maps NWS alert types to hex colors: `WARNING`, `WATCH`, `ADVISORY`, `STATEMENT`, `None`.

### `SPC_FILL`
- Maps SPC risk labels to RGBA tuples for GeoJsonLayer fill colors: `TSTM`, `MRGL`, `SLGT`, `ENH`, `MDT`, `HIGH`.

### `INITIAL_VIEW`
- Default MapViewState: lat `34.8`, lon `-92.2`, zoom `5.5`, pitch `0`.

### `TOOLTIP_STYLE`
- Shared tooltip style object for deck.gl tooltips.

---

## `formatDt(s)`

### Purpose
Formats a date string into a human-readable local string.

### Parameters
| Param | Type | Description |
|-------|------|-------------|
| `s` | `string` | ISO date string or "N/A" |

### Returns
Formatted string (e.g. "05/29, 02:30 PM CDT") or "N/A" on failure.

---

## `InfoBox({ type, children })`

### Purpose
Renders a colored information box with a left border accent.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `type` | `"info" \| "success" \| "warning" \| "error"` | Determines border/background/text colors |
| `children` | `React.ReactNode` | Content inside the box |

### Color Mapping
| Type | Border | Background | Text |
|------|--------|------------|------|
| `info` | `--accent-blue` | rgba(59,130,246,0.1) | `#93c5fd` |
| `success` | `--accent-green` | rgba(1,164,109,0.1) | `#6ee7b7` |
| `warning` | `--accent-yellow` | rgba(234,179,8,0.1) | `#fde68a` |
| `error` | `--accent-red` | rgba(239,68,68,0.1) | `#fca5a5` |

---

## `MetricCard({ label, value, sub })`

### Purpose
Displays a metric with a large value, label, and optional subtitle.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `label` | `string` | Metric description |
| `value` | `string \| number` | Primary value |
| `sub` | `string` (optional) | Subtitle below the label |

---

## `RiskBadge({ level })`

### Purpose
Renders a colored risk level badge.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `level` | `string` | Risk level key (e.g. `HIGH`, `WARNING`) |

### Returns
A `<span>` with uppercase styling, letter spacing, and dynamic background/text colors.

---

## `FilterChip({ selected, onClick, label })`

### Purpose
Renders a toggleable filter chip button.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `selected` | `boolean` | Whether chip is active |
| `onClick` | `() => void` | Toggle handler |
| `label` | `string` | Chip label |

---

## `ToggleSwitch({ checked, onChange, label })`

### Purpose
Renders a custom toggle switch with label.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `checked` | `boolean` | Current toggle state |
| `onChange` | `(v: boolean) => void` | Change handler |
| `label` | `string` | Label text |

---

## `RegionalGridPage` (named export)

### Purpose
Main regional grid page coordinating six tabs with map visualization, weather data, and analytics.

### Props
None (uses `useAuth` for user context).

### Returns
A full-page layout with:
- Title header "Regional Grid & Hazard Analytics"
- Tab navigation bar (filtered by permissions)
- Conditional rendering of tab content

### Flow

#### State Management
| State | Type | Default | Description |
|-------|------|---------|-------------|
| `activeTab` | `string` | First allowed tab | Active tab key |
| `expandedSections` | `Record<string, boolean>` | `{}` | Collapsible section states |
| `mapToggles` | `Record<string, boolean>` | all false | Map layer toggle states |
| `showRadarPanel` | `boolean` | `false` | Shows radar iframe panel |
| `selectedEvents` | `string[]` | `[]` | Selected weather event types |
| `selectedTypes` | `string[]` | `[]` | Selected facility types |
| `selectedPrios` | `string[]` | `[]` | Selected priority levels |
| `viewState` | `MapViewState` | `INITIAL_VIEW` | deck.gl view state |
| `briefing` | `string` | Placeholder text | AI-generated briefing |
| `briefLoading` | `boolean` | `false` | Brief generation loading |
| `recipientEmail` | `string` | `""` | SitRep recipient |
| `analystNotes` | `string` | `""` | Analyst notes for sitrep |
| `hazardRecip` | `string` | `""` | Hazard sitrep recipient |
| `selectedAlertIdx` | `number \| null` | `null` | Selected alert index |
| `targetSite` | `string` | `""` | Selected site for forecast |

#### Data Queries
| Query Key | Endpoint | Interval | Description |
|-----------|----------|----------|-------------|
| `regional-locations` | `GET /regional/locations` | 2min | Monitored facility locations |
| `regional-geojson` | `GET /regional/geojson` | 2min | SPC/NWS/USGS GeoJSON |
| `regional-alerts-log` | `GET /regional/weather-alerts-log` | 2min | Weather alerts log |
| `regional-forecast` | `GET /regional/forecast` | 5min | 7-day forecast (enabled by targetSite) |
| `regional-weather-prefs` | `GET /regional/weather-prefs` | once | User weather alert preferences |
| `regional-compile-map` | `POST /regional/compile-map` | 2min | Compiled map layers + analytics |

#### Derived Data
- `mapDf`: Filtered locations by selected types and priorities (via `useMemo`).
- `activeEventTypes`: Unique event types from GeoJSON features (via `useMemo`).
- `compileResponse`: Array `[layers, viewState, diagnostics, toggledAffected, masterAffected, analytics]`.

#### Tab Delegation
Each tab renders a dedicated sub-component:
- `activeTab === "geospatial"` -> `<GeospatialTab>`
- `activeTab === "executive"` -> `<ExecutiveTab>`
- `activeTab === "hazard"` -> `<HazardTab>`
- `activeTab === "matrix"` -> `<MatrixTab>`
- `activeTab === "alerts"` -> `<AlertsTab>`
- `activeTab === "atmos"` -> `<AtmosTab>`

#### Permission Enforcement
- `getAllowedTabs(user?.allowed_actions, "regionalGrid")` filters visible tabs.
- `useEffect` resets active tab if no longer permitted.
- `useEffect` auto-selects all facility types and priorities on first load.
- `useEffect` auto-selects all event types once available.

### Dependencies
- `useState`, `useMemo`, `useCallback`, `useEffect` from `react`
- `useQuery` from `@tanstack/react-query`
- `MapContainer` from `../components/MapContainer`
- `DeckGL` from `@deck.gl/react`
- `ScatterplotLayer`, `GeoJsonLayer`, `BitmapLayer` from `@deck.gl/layers`
- `Map as MapLibreMap` from `react-map-gl/maplibre`
- `MapViewState` type from `@deck.gl/core`
- `recharts` (`PieChart`, `Pie`, `Cell`, `BarChart`, `Bar`, `XAxis`, `YAxis`, `Tooltip`, `ResponsiveContainer`, `CartesianGrid`, `Legend`)
- `lucide-react` icons
- `api` from `../utils/api`
- `useAuth` from `../utils/AuthContext`
- `getAllowedTabs` from `../utils/permissions`

---

## `GeospatialTab({ mapToggles, onToggle, showRadarPanel, setShowRadarPanel, activeEventTypes, selectedEvents, setSelectedEvents, availableTypes, selectedTypes, setSelectedTypes, availablePrios, selectedPrios, setSelectedPrios, mapLayers, viewState, onViewStateChange, toggledAffectedSites })`

### Purpose
Renders the Geospatial Overlay tab with a map sidebar and deck.gl map.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `mapToggles` | `Record<string, boolean>` | Layer toggle states |
| `onToggle` | `(k: string) => void` | Toggle handler |
| `showRadarPanel` | `boolean` | Whether the radar iframe panel is open |
| `setShowRadarPanel` | `(v: boolean) => void` | Radar panel toggle handler |
| `activeEventTypes` | `string[]` | Available weather event types |
| `selectedEvents` | `string[]` | Currently selected event types |
| `setSelectedEvents` | `(v: string[]) => void` | Event type selection handler |
| `availableTypes` | `string[]` | Available facility types |
| `selectedTypes` | `string[]` | Selected facility types |
| `setSelectedTypes` | `(v: string[]) => void` | Facility type selection handler |
| `availablePrios` | `string[]` | Available priority levels |
| `selectedPrios` | `string[]` | Selected priority levels |
| `setSelectedPrios` | `(v: string[]) => void` | Priority selection handler |
| `mapLayers` | `any[]` | deck.gl layer array |
| `viewState` | `MapViewState` | Current map view state |
| `onViewStateChange` | `(v: MapViewState) => void` | View state change handler |
| `toggledAffectedSites` | `any[]` | Sites affected by active layers |

### Internal: `mapTooltip(info)`
Returns HTML tooltip content based on layer ID (spc, ar_warn, wildfires, earthquakes, facilities).

### Internal: `affectedSitesSorted`
Memoized sort of `toggledAffectedSites` by priority then name.

### Returns
Two-column layout:
- **Left sidebar** (280px): Master Layers toggles (Radar, SPC, Warnings, Watches, OOS), Fire Desk toggles (Fire Weather, Wildfires, Earthquakes), Hazard Isolation filter chips, Facility Filters (type/priority multi-select).
- **Main area**: deck.gl map (with optional rainviewer iframe panel) + affected sites table.

### Dependencies
- `MapContainer` from `../components/MapContainer`
- `DeckGL` from `@deck.gl/react`
- `MapLibreMap` from `react-map-gl/maplibre`
- All local components (`ToggleSwitch`, `FilterChip`, `InfoBox`, etc.)

---

## `ExecutiveTab({ analytics, masterAffectedSites, briefing, briefLoading, onGenerateBriefing, recipientEmail, setRecipientEmail, analystNotes, setAnalystNotes, onSendSitrep, expandedSections, toggleSection })`

### Purpose
Executive Dashboard tab showing infrastructure threat KPIs, AI briefing, charts, and broadcast controls.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `analytics` | `any` | Compiled analytics object |
| `masterAffectedSites` | `any[]` | All affected sites |
| `briefing` | `string` | AI-generated briefing text |
| `briefLoading` | `boolean` | Brief loading state |
| `onGenerateBriefing` | `() => void` | Generate briefing handler |
| `recipientEmail` | `string` | SitRep email recipient |
| `setRecipientEmail` | `(v: string) => void` | Email setter |
| `analystNotes` | `string` | Additional notes |
| `setAnalystNotes` | `(v: string) => void` | Notes setter |
| `onSendSitrep` | `() => void` | Send sitrep handler |
| `expandedSections` | `Record<string, boolean>` | Collapsible sections state |
| `toggleSection` | `(k: string) => void` | Section toggle handler |

### Returns
- KPI metric cards (Total Assets, At-Risk Assets, P1 at Risk, Highest Risk)
- AI Executive Weather Briefing box with generate button
- SPC Risk pie chart, NWS Alerts pie chart, At-Risk Assets by District bar chart
- Broadcast form (email + analyst notes + transmit button)
- Raw Matrices expandable section with priority, district, and type risk matrices

### Dependencies
- `recharts` for charts
- `SimpleTable` (local)
- `InfoBox`, `MetricCard` (local)

---

## `SimpleTable({ data })`

### Purpose
Renders a generic data table from an array or object.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `data` | `any` | Array of records or key-value object |

### Returns
A scrollable table with auto-detected column headers, up to 20 rows.

---

## `HazardTab({ masterAffectedSites, hazardRecip, setHazardRecip, onSendHazardSitrep })`

### Purpose
Deep Hazard Analytics tab — deduplicated intersectional dataset of site-hazard pairs.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `masterAffectedSites` | `any[]` | All affected sites |
| `hazardRecip` | `string` | Hazard sitrep recipient email |
| `setHazardRecip` | `(v: string) => void` | Email setter |
| `onSendHazardSitrep` | `() => void` | Send handler |

### Returns
- KPI cards (Total Sites Impacted, P1 Impacts, P2 Impacts, Unique Hazards)
- Complete intersectional dataset table sorted by priority, severity, then name
- Broadcast form for executive HTML SitRep

---

## `MatrixTab({ mapDf })`

### Purpose
Location Matrix tab — table of all tracked facilities with SPC risk.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `mapDf` | `any[]` | Filtered location data |

### Returns
A table sorted by SPC risk order (HIGH to None) then priority.

---

## `AlertsTab({ alertsLog, selectedAlertIdx, setSelectedAlertIdx })`

### Purpose
Weather Alerts Log tab — searchable log of NWS alerts.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `alertsLog` | `any[]` | Raw alert log entries |
| `selectedAlertIdx` | `number \| null` | Currently selected alert index |
| `setSelectedAlertIdx` | `(v: number \| null) => void` | Selection handler |

### Returns
- Alert log table (Event, Severity, Affected Area, Expires, Headline) with click-to-select
- Deep Dive Inspection panel for the selected alert showing full details (Description, Instructions, etc.)

---

## `AtmosTab({ userPrefs, mapDf, geojson, targetSite, setTargetSite, forecast, onSavePrefs })`

### Purpose
Atmos Weather tab — weather alert preferences, site-specific forecast, SPC outlooks, and live radar.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `userPrefs` | `any` | Saved weather alert preferences |
| `mapDf` | `any[]` | Facility location data for site selection |
| `geojson` | `any` | GeoJSON data for alert filtering |
| `targetSite` | `string` | Selected site for forecast |
| `setTargetSite` | `(v: string) => void` | Site selector setter |
| `forecast` | `any` | 7-day forecast data |
| `onSavePrefs` | `(prefs: string[]) => void` | Save preferences handler |

### Returns
- Browser notification enable button
- Alert Preferences filter chips (13 NWS event types)
- Active Watched Alerts panel
- Site-Specific 7-Day Forecast (7-day grid + detailed descriptions toggle)
- Predictive Convective Outlooks (SPC) sub-tabs
- Live Atmospheric Radar (Windy embed iframe)

---

## `SpcOutlookTabs({ geojson })`

### Purpose
Renders tabbed SPC convective outlook maps (Day 1, Day 2, Day 3).

### Props
| Prop | Type | Description |
|------|------|-------------|
| `geojson` | `any` | GeoJSON data with `spc_day1`, `spc_day2`, `spc_day3` |

### Returns
- Three sub-tabs for Day 1/2/3
- deck.gl GeoJsonLayer map of SPC outlook polygons

### Dependencies
- `DeckGL` from `@deck.gl/react`
- `GeoJsonLayer` from `@deck.gl/layers`
- `MapLibreMap` from `react-map-gl/maplibre`

---

## `buildSitrepHtml(analytics, masterAffectedSites, briefing, notes)`

### Purpose
Builds an HTML email body for the Executive SitRep.

### Parameters
| Param | Type | Description |
|-------|------|-------------|
| `analytics` | `any` | Analytics data |
| `masterAffectedSites` | `any[]` | Affected sites |
| `briefing` | `string` | AI briefing text |
| `notes` | `string` | Analyst notes |

### Returns
A formatted HTML string with inline styles.

---

## `buildHazardHtml(masterAffectedSites)`

### Purpose
Builds an HTML email body for the hazard SitRep.

### Parameters
| Param | Type | Description |
|-------|------|-------------|
| `masterAffectedSites` | `any[]` | Affected sites |

### Returns
An HTML string with a table of affected sites sorted by priority and hazard.
