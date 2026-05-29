# DashboardPage.tsx

Global NOC Dashboards — the primary landing page. Provides four tabbed views: Operational Dashboard, Global Risk, Internal Risk, and Unified Brief. Each tab surfaces live metrics from multiple API endpoints.

---

## Constants

### `RISK_COLORS`
- Purpose: Maps risk level strings to hex color codes.
- Type: `Record<string, string>`
- Keys: `GREEN`, `BLUE`, `YELLOW`, `ORANGE`, `RED`

### `RISK_NAMES`
- Purpose: Maps risk level strings to human-readable labels.
- Type: `Record<string, string>`
- Keys: `GREEN` ("GREEN (LOW)"), `BLUE` ("BLUE (GUARDED)"), `YELLOW` ("YELLOW (ELEVATED)"), `ORANGE` ("ORANGE (HIGH)"), `RED` ("RED (SEVERE)")

### `SUB_PANELS`
- Purpose: Labels for the three auto-rotating sub-panels under Operational Dashboard.
- Values: `["Threat Triage", "Infrastructure Status", "AI Analysis"]`

### `DASHBOARD_TABS`
- Purpose: Labels for the four main dashboard tabs.
- Values: `["Operational Dashboard", "Global Risk", "Internal Risk", "Unified Brief"]`

---

## `RiskBadge({ level, size })`

### Purpose
Renders a small colored badge showing the risk level name.

### Props
| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `level` | `string` | — | Risk level key (e.g. "RED", "GREEN") |
| `size` | `"sm" \| "lg"` | `"sm"` | Controls font-size and padding |

### Returns
A `<span>` element with dynamic background color and white text.

### Dependencies
- `RISK_COLORS` (local)

---

## `MetricCard({ label, value, icon })`

### Purpose
Displays a single numeric metric with an optional icon inside a card container.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `label` | `string` | Metric label displayed below the value |
| `value` | `number` | Primary numeric value displayed in large font |
| `icon` | `React.ReactNode` (optional) | Icon component rendered above the value |

### Returns
A styled `div` card with icon, value, and label.

---

## `ScoreBadge({ score })`

### Purpose
Renders a compact numeric score badge with color-coded background.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `score` | `number` | Numeric score (0-100 typical range) |

### Color Mapping
| Range | Color |
|-------|-------|
| >= 80 | `#ef4444` (red) |
| >= 60 | `#f97316` (orange) |
| >= 40 | `#eab308` (yellow) |
| < 40 | `#6b7280` (gray) |

### Returns
A `<span>` with rounded background and white text showing `score.toFixed(0)`.

---

## `TabButton({ active, label, onClick })`

### Purpose
Renders a tab button with active/inactive styling.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `active` | `boolean` | Whether this tab is currently selected |
| `label` | `string` | Tab label text |
| `onClick` | `() => void` | Click handler |

### Returns
A `<button>` with blue background when active, tertiary background when inactive.

---

## `SubTabButton({ active, label, onClick })`

### Purpose
Renders a subtab button with a bottom-border accent for active state.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `active` | `boolean` | Whether subtab is selected |
| `label` | `string` | Subtab label |
| `onClick` | `() => void` | Click handler |

### Returns
A `<button>` with a blue bottom border when active, transparent border when inactive.

---

## `ArticleItem({ article })`

### Purpose
Renders a single article row in the Pinned Intel / Live Feed lists.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `article` | `any` | Article object with fields: `id`, `title`, `link`, `score`, `source`, `category`, `summary`, `ai_bluf` |

### Returns
A `div` containing:
- `ScoreBadge` for the article score
- An external link to the article title
- Source and category metadata
- Truncated summary (120 chars) 
- Truncated AI BLUF (100 chars) in green italic

### Dependencies
- `ScoreBadge` (local)
- `ExternalLink` icon from `lucide-react`

---

## `DashboardPage` (named export)

### Purpose
Main dashboard page component orchestrating four tabs: Operational Dashboard, Global Risk, Internal Risk, and Unified Brief.

### Props
None (uses `useAuth` for user context).

### Returns
A full-page layout with:
- Title header "Global NOC Dashboards"
- Tab navigation bar (filtered by permissions)
- Conditional rendering of tab content based on `tab` state

### Flow

#### State Management
| State | Type | Default | Description |
|-------|------|---------|-------------|
| `tab` | `number` | `0` | Active dashboard tab index |
| `subPanel` | `number` | `0` | Active subtab index |
| `autoRotate` | `boolean` | `true` | Toggles auto-rotation of subtabs |
| `cisLegendOpen` | `boolean` | `false` | Controls CIS Threat Legend modal |
| `scoringOverview` | `string \| null` | `null` | Generated scoring rationale text |
| `scoringOverviewRisk` | `string \| null` | `null` | Risk level when scoring was generated |
| `dispatchEmail` | `string` | `""` | Email address for report dispatch |
| `ubEmail` | `string` | `""` | Email address for unified brief broadcast |
| `forceRefreshKey` | `number` | `0` | Key for forcing sitrep query refetch |

#### Hooks Used
- `useAuth()` for user context and permission checks
- `useState` for all local state
- `useRef` for the auto-rotation interval
- `useEffect` for auto-rotation timer and permission enforcement
- `useQuery` for all data fetching (10 queries)
- `useMutation` for mutations (5 mutations)
- `useQueryClient` for cache invalidation

#### Data Queries (all via `@tanstack/react-query`)
| Query Key | Endpoint | Interval | Description |
|-----------|----------|----------|-------------|
| `dashboard-metrics` | `GET /dashboard/metrics` | 30s | RSS, CVE, hazard, cloud counts |
| `pinned-articles` | `GET /dashboard/pinned-articles` | 30s | Pinned intel articles |
| `live-articles` | `GET /dashboard/live-articles` | 15s | Live article feed |
| `cves-dash` | `GET /threat/cves?limit=15` | 5min | Top CVEs |
| `outages-dash` | `GET /threat/cloud-outages?active_only=true` | 2min | Active cloud outages |
| `hazards-dash` | `GET /dashboard/hazards?limit=15` | 2min | Regional hazards |
| `sitrep-dash` | `GET /rca/sitrep` | 1min | AI shift briefing |
| `executive-intel` | `GET /dashboard/executive-intel` | 1min | Unified risk intelligence |
| `threat-trends` | `GET /dashboard/threat-trends?days=14` | 2min | 14-day CIS trend data |
| `internal-risk` | `GET /dashboard/internal-risk` | 5min | Internal asset risk matrix |
| `internal-risk-history` | `GET /dashboard/internal-risk/history?days=28` | 5min | 28-day internal risk history |
| `sys-config` | `GET /settings/config` | 2min | System configuration (briefs, etc.) |

#### Mutations
| Mutation | Endpoint | On Success |
|----------|----------|------------|
| `refreshBriefingMut` | `POST /rca/sitrep { action: "refresh_briefing" }` | Increments `forceRefreshKey`, invalidates `sys-config` |
| `securityAuditMut` | `POST /rca/sitrep { action: "security_audit" }` | (none) |
| `generateScoringMut` | `POST /dashboard/generate-scoring-rationale` | Sets `scoringOverview` and `scoringOverviewRisk` |
| `generateUnifiedBriefMut` | `POST /dashboard/generate-unified-brief` | Increments `forceRefreshKey`, invalidates `sys-config` |
| `generateInternalMut` | `POST /dashboard/generate-internal-risk` | Calls `refetchInternal()` |

#### Tab Content

**Tab 0 — Operational Dashboard:**
- Four metric cards (RSS, CVEs, Hazards, Cloud Outages)
- Auto-rotate toggle and three sub-panels:
  - *Threat Triage*: Pinned intel + live feed (two-column)
  - *Infrastructure Status*: CISA KEVs, Cloud Outages, Regional Hazards (three-column)
  - *AI Analysis*: Shift briefing text + security auditor button

**Tab 1 — Global Risk:**
- CIS Threat Legend modal
- Executive Grid Threat Matrix with unified risk banner
- 14-day CIS trend line chart (Recharts)
- Physical & perimeter / Cyber & SCADA side-by-side columns
- Dynamic scoring overview generation
- Dispatch intelligence report via email

**Tab 2 — Internal Risk:**
- Internal Asset Risk Dashboard banner with CIS posture
- Three metric cards (Total Assets, OSINT Correlations, Critical Hits)
- Historical threat trend (28-day line chart)
- Hardware and software asset tables

**Tab 3 — Unified Brief:**
- Executive Unified Risk Brief
- Last auto-generated timestamp
- Force refresh button
- Broadcast brief via email

#### Permission Enforcement
- `getAllowedTabs(user?.allowed_actions, "dashboard")` filters which tabs are visible
- `useEffect` resets active tab if the current tab is no longer permitted

### Dependencies
- `useState`, `useEffect`, `useRef` from `react`
- `useQuery`, `useMutation`, `useQueryClient` from `@tanstack/react-query`
- `recharts` (`LineChart`, `Line`, `XAxis`, `YAxis`, `Tooltip`, `ResponsiveContainer`, `CartesianGrid`)
- `lucide-react` icons (15+ icons)
- `api` from `../utils/api`
- `useAuth` from `../utils/AuthContext`
- `getAllowedTabs` from `../utils/permissions`

---

## `SeverityIcon({ severity })`

### Purpose
Renders a color-coded `AlertTriangle` icon based on severity text.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `severity` | `string` | Severity level (e.g. "extreme", "severe", "moderate") |

### Returns
- Red icon for "extreme" or "severe"
- Orange icon for "moderate"
- Gray icon for all other values

### Dependencies
- `AlertTriangle` icon from `lucide-react`

---

## `HardwareSoftwareTable({ data, type, emptyMessage })`

### Purpose
Renders an expandable table of hardware or software assets with OSINT correlation counts and risk indicators.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `data` | `any` | Array or object of asset records |
| `type` | `"hardware" \| "software"` | Determines column layout |
| `emptyMessage` | `string` | Message shown when no assets exist |

### Returns
A collapsible section with:
- Expand/collapse toggled via `expanded` state
- At-risk count badge if any assets have positive OSINT matches
- Warning banner if assets are at risk, or success banner if all clear
- Table with columns varying by type:
  - Hardware: IP Address, Asset Name, Type, OS, OSINT Matches, Risk Score
  - Software: Name, OSINT Matches, Risk Level

### Flow
1. Normalizes `data` into an array (handles both array and object inputs).
2. Filters `atRisk` items where OSINT match count > 0.
3. Renders expandable header with at-risk count badge.
4. When expanded, renders warning/success banners and the full data table.
5. Highlights rows with active OSINT matches using a red-tinted background.

### Dependencies
- `useState` from `react`
- `RiskBadge` (local)
- `ChevronDown`, `ChevronRight` icons from `lucide-react`
