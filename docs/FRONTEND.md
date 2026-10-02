# NOC Intelligence Fusion Center — Frontend Documentation

Enterprise-grade React single-page application for the Network Operations Center Intelligence Fusion Platform. Provides real-time dashboards, threat telemetry, geospatial visualization, AIOps correlation, keyword analysis, and shift management.

Branch: `architecture/monolith-to-decoupled`

---

## Table of Contents

1. [Technology Stack](#1-technology-stack)
2. [Project Structure](#2-project-structure)
3. [Development Setup](#3-development-setup)
4. [Routing & Permissions](#4-routing--permissions)
5. [Page Components](#5-page-components)
6. [Shared Components](#6-shared-components)
7. [Custom Hooks](#7-custom-hooks)
8. [State Management](#8-state-management)
9. [API Client](#9-api-client)
10. [Theme System](#10-theme-system)
11. [Timezone Handling](#11-timezone-handling)
12. [Build & Deployment](#12-build--deployment)

---

## 1. Technology Stack

| Library | Version | Purpose |
|---------|---------|---------|
| React | 18.3.x | UI framework |
| TypeScript | 5.5.x | Static typing |
| Vite | 5.4.x | Build tool & dev server |
| React Router | 7.15.x | Client-side routing (`HashRouter`) |
| TanStack Query | 5.100.x | Server-state management, caching, polling |
| Zustand | 4.5.x | Lightweight client-state store |
| Axios | 1.7.x | HTTP client |
| MapLibre GL | 4.7.x | Vector map rendering |
| @vis.gl/react-maplibre | 8.1.x | MapLibre-only React bindings |
| deck.gl | 9.0.x | Geospatial data overlays |
| Recharts | 3.8.x | Charting library |
| Lucide React | 1.16.x | Icon set |

**Runtime config**: Vite dev server proxies `/api` and `/ws` to the FastAPI backend at `VITE_API_URL` (default `http://localhost:8101`).

---

## 2. Project Structure

```
web/
├── index.html
├── package.json
├── vite.config.ts              # Vite config: proxy, HMR, allowedHosts
├── tsconfig.json
└── src/
    ├── main.tsx                # ReactDOM entry, CSS imports, initTheme()
    ├── App.tsx                 # QueryClientProvider, HashRouter, AuthProvider, routes
     ├── pages/                  # Page components (route targets)
     │   ├── LoginPage.tsx
     │   ├── ForgotPasswordPage.tsx
     │   ├── ResetPasswordPage.tsx
     │   ├── VerifyRecoveryEmailPage.tsx
     │   ├── DashboardPage.tsx
    │   ├── ThreatTelemetryPage.tsx
    │   ├── RegionalGridPage.tsx
    │   ├── ThreatHuntingPage.tsx
    │   ├── AiopsRcaPage.tsx
     │   ├── ShiftLogbookPage.tsx
     │   ├── ReportingPage.tsx
     │   ├── KeywordAnalysisPage.tsx
     │   └── SettingsPage.tsx
    ├── components/             # Shared UI components
    │   ├── Layout.tsx          # Sidebar nav, user info, logout
    │   ├── AIOpsMap.tsx        # Map visualization
    │   ├── MapContainer.tsx    # Fullscreen-capable map wrapper
     │   ├── ThemeSelector.tsx   # Theme picker with 6 presets
     │   ├── UsersRolesTab.tsx   # Searchable account directory and reviewer queues
     │   ├── ApplicationSettingsTab.tsx # Risk controls and dynamic schedules
    ├── hooks/
    │   └── useAIOpsWebSocket.ts  # WebSocket real-time hook
    ├── utils/
    │   ├── api.ts              # Axios instance, interceptors
    │   ├── AuthContext.tsx      # Auth provider, login/logout, permissions
    │   ├── routeConfig.ts      # Route ↔ permission mappings
    │   └── timezone.ts         # America/Chicago formatters
    ├── store/
    │   └── useAppStore.ts      # Zustand global state
    ├── styles/
    │   ├── theme.css           # Base CSS custom properties (:root)
    │   └── components.css      # Component-level styles
    └── themes/
        └── themes.css          # Theme overrides (data-theme selectors)
```

---

## 3. Development Setup

### Prerequisites

- Node.js 18+
- npm or equivalent package manager
- Backend API running on port 8101

### Local Development

```bash
cd web
npm install
npm run dev        # Starts Vite on http://0.0.0.0:5173
```

The Vite dev server (`vite.config.ts:16-26`) proxies:
- `/api/*` → `http://localhost:8101/api/*`
- `/ws` → `ws://localhost:8101/ws`

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_API_URL` | `http://localhost:8101` | Backend API base URL (used in proxy config) |

> **Note**: `VITE_API_URL` is consumed at build time by `vite.config.ts:4`. The Axios client (`utils/api.ts:4`) uses a relative base URL `/api/v1`, relying on the Vite proxy in dev and nginx routing in production.

---

## 4. Routing & Permissions

### Route Definitions

Defined in `src/utils/routeConfig.ts` and wired in `src/App.tsx`:

| Route | Page Component | Permission Key |
|-------|---------------|----------------|
| `/login` | `LoginPage` | None (public) |
| `/forgot-password` | `ForgotPasswordPage` | None (public; generic reviewed request) |
| `/reset-password` | `ResetPasswordPage` | None (public; single-use token required) |
| `/verify-email` | `VerifyRecoveryEmailPage` | None (public; approved verification token required) |
| `/` | `DashboardPage` | `Global Dashboards` |
| `/threat-telemetry` | `ThreatTelemetryPage` | `Threat Telemetry` |
| `/regional-grid` | `RegionalGridPage` | `Regional Grid` |
| `/threat-hunting` | `ThreatHuntingPage` | `Threat Hunting & IOCs` |
| `/aiops-rca` | `AiopsRcaPage` | `AIOps RCA` |
| `/shift-logbook` | `ShiftLogbookPage` | `Shift Logbook` |
| `/reporting` | `ReportingPage` | `Reporting & Briefings` |
| `/keyword-analysis` | `KeywordAnalysisPage` | `Keyword Analysis` |
| `/settings` | `SettingsPage` | `Settings & Admin` |

### Permission Model

`PAGE_PERMISSION_MAP` (`routeConfig.ts:1-10`) maps URL paths to permission strings. `PAGE_ROUTE_MAP` (`routeConfig.ts:12-14`) is the reverse mapping (permission → route).

### ProtectedRoute Guard

`App.tsx:18-29` — `ProtectedRoute` wraps all authenticated pages:

1. If no `user` in `AuthContext`, redirects to `/login`.
2. If the route has a required permission (via `PAGE_PERMISSION_MAP`), checks the user's page grants.
3. If the user lacks access, renders an access-denied explanation and retains the session.
4. Renders children inside `<Layout>` (sidebar navigation), filtering links by page grants.

API endpoints independently enforce page, tab, action, and site-type permissions. The role editor loads the permission catalog from `/permissions/catalog`; sensitive operations such as sending email, generating reports, changing risk overrides, scheduler editing, user administration, and recovery review have separate action grants. API 403s show an access notice without clearing the session; 401s clear the session and return to login.

### HashRouter

The app uses `HashRouter` (`App.tsx:49`), so all routes are hash-based (`/#/threat-telemetry`). This avoids server-side routing configuration and works with the nginx static file server in production.

---

## 5. Page Components

### LoginPage (`src/pages/LoginPage.tsx`)

- Username/password form with `POST /auth/login`.
- Displays a restricted-system notice stating that access is for authorized users and may be monitored, recorded, and audited.
- Provides a generic forgot-password request. Reset links are sent only after a permitted user administrator approves the request.
- On success, stores token and user object in `sessionStorage` via `AuthContext.login()`.
- Redirects to the first page in `user.allowed_pages`, or `/` for admin users.

### DashboardPage (`src/pages/DashboardPage.tsx`)

Four-tab layout:

| Tab | Description |
|-----|-------------|
| **Operational Dashboard** | Real-time alerts, metrics, CIS scoring overview |
| **Global Risk** | Global risk assessment with scoring overrides |
| **Internal Risk** | Internal risk panel with manual/hybrid/auto scoring modes |
| **Unified Brief** | AI-generated briefing with map-reduce pipeline |

Key behaviors:
- **Auto-rotation**: Cycles between Operational Dashboard tabs on a timer.
- **Brief generation**: Triggers `POST /reporting/generate-unified-brief`, then polls `GET /brief-generation-status/{id}` for progress. The `brief_gen_id` persists in `sessionStorage` across tab switches.
- **Scoring overrides**: Forms for global/internal CIS scoring with manual/hybrid/auto modes and C/I/L override columns.
- **Broadcast**: Email button calls `POST /email/broadcast-brief` to distribute the generated brief.

### ThreatTelemetryPage (`src/pages/ThreatTelemetryPage.tsx`)

Four-section layout:

| Section | Data Source | Features |
|---------|------------|----------|
| **RSS Articles** | `GET /threat/articles` | Pagination, category filter, keyword search |
| **CVEs** | `GET /threat/cves` | Table with CISA KEV status badges |
| **Cloud Outages** | `GET /threat/cloud-outages` | Filterable outage table |
| **Crime Incidents** | `GET /threat/crimes` | Map visualization with incident markers |

Manual sync buttons trigger `POST /threat/sync-*` endpoints to force data refresh.

### RegionalGridPage (`src/pages/RegionalGridPage.tsx`)

MapLibre GL-based geospatial view with toggleable overlay layers:

| Layer | Description |
|-------|-------------|
| Radar | Weather radar composite |
| SPC | Storm Prediction Center outlooks |
| NWS Warnings | National Weather Service warnings |
| NWS Watches | National Weather Service watches |
| OOS | Out-of-service site markers |
| Fire | Active fire detections |
| Wildfires | Wildfire perimeter data |
| Earthquake | USGS earthquake events |

Features:
- **Site intersections**: Computes which monitored sites fall within hazard polygons.
- **Analytics dashboard**: Embedded executive dash analytics within the map container.
- **Weather preferences**: User-configurable weather overlay defaults.

### ThreatHuntingPage (`src/pages/ThreatHuntingPage.tsx`)

- **IOC Matrix**: Displays extracted indicators of compromise with pivot links to OSINT sources.
- **Deep Hunt Builder**: Custom query interface for article search with boolean operators.
- **OSINT Pivot**: Integration with external threat intelligence lookups.

### AiopsRcaPage (`src/pages/AiopsRcaPage.tsx`)

Core AIOps correlation and incident response board:

| Feature | Description |
|---------|-------------|
| **Active Alerts Board** | Filterable by `user.allowed_site_types`; color-coded by status |
| **Global Correlation** | Scatterplot visualization of cross-domain alert correlation |
| **Site Dialog** | Detailed per-site view with maintenance controls |
| **Status Tracking** | Investigating → Dispatched → Maintenance state machine |
| **Fullscreen Mode** | CSS fixed-position fullscreen (not Fullscreen API) |

Color logic:
- **Investigating** (transitional, auto-clears on next dashboard update)
- **Dispatched** (manual clear only)
- **Maintenance** (sticky, requires manual clearing)
- **Green** when no active alerts; coloring only applies when alerts are present

### ShiftLogbookPage (`src/pages/ShiftLogbookPage.tsx`)

- **Day-stepper navigation**: Previous/next day controls with date display.
- **Independent explorer tab**: Browse historical entries without affecting the active day view.
- **Soft delete**: Entries can be deleted with a required reason field.
- **Auto-assign shift**: Populates shift from `user.default_shift` (name + title format).
- **LLM summary**: Generates shift summary via backend LLM; falls back to text summary if generation exceeds 30 seconds (prevents 504 timeout).

### ReportingPage (`src/pages/ReportingPage.tsx`)

| Tab | Description |
|-----|-------------|
| **Daily Fusion** | Generate comprehensive daily fusion report |
| **Report Builder** | Custom report with configurable sections |
| **Saved Reports** | Library of previously generated reports |
| **Broadcast** | Email distribution management |

### KeywordAnalysisPage (`src/pages/KeywordAnalysisPage.tsx`)

Protected route: `/keyword-analysis`. The page uses React Query to read persisted article and keyword analytics from `/api/v1/keyword-analysis/*`.

| Tab | Purpose |
|---|---|
| **Overview** | Keyword/article totals, weight ranges, and used/unused keyword counts |
| **Keyword Analysis** | Search and sort keyword weights, trigger counts, and score contribution |
| **Category Breakdown** | Compare category volume and average score over a selected period |
| **Timeline** | Plot article volume, keyword matches, match rate, and average score over time |
| **Cross-Reference** | Compare keyword occurrences across article categories |

The page also supports score-distribution buckets, category details, recent articles for a selected keyword, and an authorized all-article recategorization action. The overview query refreshes every 30 seconds; recategorization requires `Action: Trigger AI Functions`.

### SettingsPage (`src/pages/SettingsPage.tsx`)

Administrative interface with sections:

Tab visibility follows the caller's `Tab: Settings -> ...` grants rather than an administrator-role check. Individual action permissions gate user administration, recovery review, ML training, risk changes, scheduler edits, and other mutations; legacy backup/destructive controls remain administrator-only and display a read-only notice to other tab-authorized users.

| Section | Description |
|---------|-------------|
| **Facilities** | Manage monitored locations and site metadata |
| **Internal Assets** | CSV import for hardware/software asset inventories |
| **RSS Feeds** | Add/remove RSS sources with inline weight editing for keywords |
| **AI/LLM** | Configure LLM connection, model selection, temperature |
| **Users & Roles** | Searchable account directory, email invitations, display accounts, recovery requests, role assignment |
| **Application Settings** | Risk-scoring overrides, bounded scheduler schedules, and global application defaults |
| **Backup & Restore** | Legacy configuration backup, 27-model JSON export/import, and SQLite file data import (not a full database-file swap) |

---

## 6. Shared Components

### Layout (`src/components/Layout.tsx`)

Full-height sidebar navigation:

- **Collapsed/expanded toggle**: Sidebar width transitions between 56px and 230px.
- **Permission-filtered nav**: Only renders nav items where `item.label` is in `user.allowed_pages`.
- **User info panel**: Displays `full_name` and `job_title` (or `role` fallback) at sidebar bottom.
- **Recovery-email prompt**: Individual accounts without an approved recovery email receive a persistent prompt explaining administrator approval and mailbox verification; display accounts are exempt.
- **Logout button**: Calls `AuthContext.logout()`.
- **Lucide icons**: Each nav item has an associated icon (`Activity`, `Globe`, `Crosshair`, `Shield`, `Radio`, `BookOpen`, `FileText`, `Settings`).

### AIOpsMap (`src/components/AIOpsMap.tsx`)

Map visualization component used by `RegionalGridPage` and `AiopsRcaPage`. Renders MapLibre GL map with overlay layers, site markers, and hazard polygons.

### MapContainer (`src/components/MapContainer.tsx`)

Fullscreen-capable wrapper for map components:

- Uses `ResizeObserver` to detect when the container has non-zero dimensions before rendering children (prevents MapLibre initialization errors).
- **Window-fill fullscreen**: Toggles between relative positioning and fixed `100vw × 100vh` overlay with `z-index: 1000`.
- Backdrop click exits fullscreen.

### ThemeSelector (`src/components/ThemeSelector.tsx`)

Theme picker rendering 21 preset buttons:

| Theme ID | Label |
|----------|-------|
| `standard` | Standard (default dark) |
| `noc-terminal` | NOC Terminal (green monochrome) |
| `high-contrast` | High Contrast Dark (yellow on black) |
| `cyberpunk` | Cyberpunk (pink/cyan on purple) |
| `solarized-dark` | Solarized Dark |
| `midnight-ocean` | Midnight Ocean (blue on navy) |
| `arctic-command` | Arctic Command |
| `ember-watch` | Ember Watch |
| `forest-ops` | Forest Ops |
| `amethyst-grid` | Amethyst Grid |
| `slate-steel` | Slate Steel |
| `paper-light` | Paper Light |
| `nordic-frost` | Nordic Frost |
| `dracula-console` | Dracula Console |
| `synthwave` | Synthwave |
| `desert-signal` | Desert Signal |
| `olive-command` | Olive Command |
| `mono-ops` | Monochrome Ops |
| `rose-pine` | Rose Pine |
| `oceanic-teal` | Oceanic Teal |
| `copper-wire` | Copper Wire |

The selector currently exposes 21 themes. It applies the theme via the `data-theme` attribute on `<body>` and saves it to `localStorage` under `noc_theme`. When a user is signed in, selecting a theme also persists it through `POST /api/v1/auth/update-theme`; `ThemeSync` applies the account preference after login.

---

## 7. Custom Hooks

### useAIOpsWebSocket (`src/hooks/useAIOpsWebSocket.ts`)

Manages the persistent WebSocket connection to the backend for users with AIOps RCA page access:

**Connection**:
- Connects to `ws(s)://{host}/ws?token=...` based on current protocol. The backend periodically revalidates the session and filters site data by the user's permitted site types.
- Auto-reconnect with exponential backoff: `min(1000 × 2^attempt, 30000)` ms.

**Message handling**:
- `dashboard_update`: Standard payload with alerts, events, grid data. Stored in Zustand via `setDashboard()`. Triggers critical notification for new `CRITICAL`/`HIGH` severity alerts.
- `INVESTIGATING_UPDATE`: UI state echo — updates `investigatingSites` in Zustand.
- `RCA_UPDATE`: Database resync request — invalidates TanStack Query caches for `rca-dashboard` and `rca-analyze` keys.

**Bidirectional control**:
- Exposes `sendMessage(msg)` globally via Zustand's `setSendMessage()`, allowing any page to broadcast JSON commands over the WebSocket.

**Return value**: `{ data: DashboardPayload | null, connected: boolean }`

---

## 8. State Management

### AuthContext (`src/utils/AuthContext.tsx`)

React Context providing authentication state:

```typescript
interface AuthContextType {
  user: User | null;
  token: string;
  login: (username: string, password: string) => Promise<User>;
  logout: () => void;
  refreshUser: () => Promise<void>;
}
```

- **Persistence**: `user` and `token` stored in `sessionStorage` (keys: `noc_user`, `noc_token`).
- **Auto-refresh**: `refreshUser()` calls `GET /auth/me` on mount to validate/refresh the session.
- **401 handling**: Axios interceptor clears the session and redirects to `#/login` on 401 responses.
- **403 handling**: Keeps the session active and displays an accessible permission-specific notice.

**User interface** (`AuthContext.tsx:4-15`):

```typescript
interface User {
  id?: number;
  username: string;
  full_name?: string;
  job_title?: string;
  contact_info?: string;
  account_type?: "individual" | "display";
  email?: string | null;
  email_verified_at?: string | null;
  recovery_email_status?: string;
  is_active?: boolean;
  created_at?: string | null;
  last_login_at?: string | null;
  last_activity_at?: string | null;
  default_shift?: string;
  role?: string;
  allowed_pages?: string[];      // Page-level permissions
  allowed_actions?: string[];    // Action-level permissions
  allowed_site_types?: string[]; // Site type filter for AIOps
}
```

### TanStack Query

Server-state management for all API data fetching:

- **Cache keys**: Used consistently across components and WebSocket invalidation (e.g., `["rca-dashboard"]`, `["rca-analyze"]`).
- **Polling**: Brief generation status polled with `refetchInterval`.
- **Invalidation**: WebSocket `RCA_UPDATE` messages trigger `queryClient.invalidateQueries()` for affected keys.

### Zustand Store (`src/store/useAppStore.ts`)

Lightweight global store for UI-level state:

```typescript
interface AppState {
  dashboard: DashboardPayload | null;  // Latest WebSocket payload
  connected: boolean;                  // WebSocket connection status
  investigatingSites: string[];        // Sites in investigating state
  sendMessage: (msg: any) => void;     // WebSocket send function
  // Setters...
}
```

- `setInvestigatingSite()`: Toggles site in/out of the investigating list (deduplicates via `Set`).
- `sendMessage`: Injected by `useAIOpsWebSocket` hook; used by pages to broadcast commands.

---

## 9. API Client

### Axios Instance (`src/utils/api.ts`)

```typescript
const api = axios.create({
  baseURL: "/api/v1",
});
```

**Request interceptor** (`api.ts:7-13`):
- Attaches `Authorization: Bearer <token>` from `sessionStorage` to every request.

**Response interceptor** (`api.ts:15-25`):
- On 401: clears `noc_token` and `noc_user` from `sessionStorage`, redirects to `#/login`.
- On 403: retains the session and emits an accessible permission notice with the missing grant.
- All other errors propagate normally.

**Usage pattern**:
```typescript
import api from "../utils/api";

const { data } = await api.get("/dashboard/metrics");
const { data } = await api.post("/auth/login", { username, password });
```

**Production routing**: In production, nginx proxies `/api/v1/*` to the FastAPI backend. The Axios base URL remains relative (`/api/v1`), so no configuration change is needed between environments.

---

## 10. Theme System

### Architecture

Three-layer CSS custom property system:

1. **Base** (`src/styles/theme.css`): `:root` defaults — the standard dark theme.
2. **Overrides** (`src/themes/themes.css`): `[data-theme="..."]` selectors that redefine the same variables.
3. **Components** (`src/styles/components.css`): Component-level styles consuming the variables.

### Variable Reference

**Backgrounds**:
| Variable | Default | Usage |
|----------|---------|-------|
| `--bg-primary` | `#0a0e1a` | Page background |
| `--bg-secondary` | `#111827` | Sidebar, secondary panels |
| `--bg-tertiary` | `#1e293b` | Hover states, nested panels |
| `--bg-card` | `#1a2332` | Card/panel backgrounds |
| `--bg-card-hover` | `#1e293b` | Card hover state |
| `--bg-input` | `#0f172a` | Form input backgrounds |

**Text**:
| Variable | Default | Usage |
|----------|---------|-------|
| `--text-primary` | `#e2e8f0` | Headings, primary content |
| `--text-secondary` | `#94a3b8` | Body text, descriptions |
| `--text-muted` | `#64748b` | Labels, timestamps |

**Borders**:
| Variable | Default | Usage |
|----------|---------|-------|
| `--border-primary` | `#2d3a50` | Card borders, table rules |
| `--border-secondary` | `#1e293b` | Subtle dividers |

**Accent Colors**:
| Variable | Default | Usage |
|----------|---------|-------|
| `--accent-blue` | `#3b82f6` | Primary actions, links |
| `--accent-cyan` | `#06b6d4` | Secondary highlights |
| `--accent-green` | `#01a46d` | Success states |
| `--accent-yellow` | `#eab308` | Warning states |
| `--accent-orange` | `#f97316` | Elevated warnings |
| `--accent-red` | `#ef4444` | Error/critical states |
| `--accent-purple` | `#a855f7` | Special highlights |
| `--accent-pink` | `#ec4899` | Special highlights |

**Risk Level Colors** (CIS-aligned):
| Variable | Default | Risk Level |
|----------|---------|------------|
| `--risk-green` | `#01a46d` | GREEN — Normal |
| `--risk-blue` | `#377fc7` | BLUE — Elevated |
| `--risk-yellow` | `#eab308` | YELLOW — Guarded |
| `--risk-orange` | `#f97316` | ORANGE — High |
| `--risk-red` | `#ef4444` | RED — Severe |

Each risk level also has a `--shade-{color}` variant at 15% opacity for background fills.

**Typography**:
| Variable | Default |
|----------|---------|
| `--font-sans` | `system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif` |
| `--font-mono` | `'Courier New', Courier, monospace` |

**Spacing & Shadows**:
| Variable | Default |
|----------|---------|
| `--radius-sm` | `4px` |
| `--radius-md` | `8px` |
| `--radius-lg` | `12px` |
| `--shadow-sm` | `0 1px 2px rgba(0,0,0,0.3)` |
| `--shadow-md` | `0 4px 6px rgba(0,0,0,0.4)` |
| `--shadow-lg` | `0 10px 25px rgba(0,0,0,0.5)` |

### Theme Overrides

Twenty-one themes are exposed by `ThemeSelector`; the non-standard palettes are defined in `src/themes/themes.css` via `[data-theme="..."]` selectors. The base `standard` palette is defined in `src/styles/theme.css`. The active theme is applied by setting `document.body.setAttribute("data-theme", id)`.

| Theme | Character |
|-------|-----------|
| `standard` | Default dark — no override needed; uses `:root` |
| `noc-terminal` | Green monochrome on black — all colors map to `#00ff00` |
| `high-contrast` | Yellow on black — all colors map to `#FFFF00` |
| `cyberpunk` | Pink/cyan accents on deep purple |
| `solarized-dark` | Solarized palette — muted earth tones |
| `midnight-ocean` | Blue/cyan accents on deep navy |
| `arctic-command` | Arctic Command |
| `ember-watch` | Ember Watch |
| `forest-ops` | Forest Ops |
| `amethyst-grid` | Amethyst Grid |
| `slate-steel` | Slate Steel |
| `paper-light` | Paper Light |
| `nordic-frost` | Nordic Frost |
| `dracula-console` | Dracula Console |
| `synthwave` | Synthwave |
| `desert-signal` | Desert Signal |
| `olive-command` | Olive Command |
| `mono-ops` | Monochrome Ops |
| `rose-pine` | Rose Pine |
| `oceanic-teal` | Oceanic Teal |
| `copper-wire` | Copper Wire |

---

## 11. Timezone Handling

### Centralized Utilities (`src/utils/timezone.ts`)

All timestamps are displayed in **America/Chicago** timezone. The module provides:

| Function | Returns | Example Output |
|----------|---------|----------------|
| `formatInChicago(d, options?, fallback?)` | Full datetime string | `Jun 30, 2026, 10:35 PM` |
| `formatDateInChicago(d, fallback?)` | Date only | `Jun 30, 2026` |
| `formatTimeInChicago(d, fallback?)` | Time only | `10:35 PM` |
| `formatShortInChicago(d, fallback?)` | Short datetime | `Jun 30, 2026, 10:35 PM` |
| `chicagoDateString(d?)` | ISO date string | `2026-06-30` |
| `chicagoNow()` | Current time in Chicago | `Date` object |

### UTC Handling

The `ensureUtcDate()` helper (`timezone.ts:21-29`) addresses a critical issue: naive datetime strings from SQLite (e.g., `"2026-06-30T22:35:00"`) lack timezone indicators. Without the `Z` suffix, JavaScript would interpret them as local system time rather than UTC.

The function appends `Z` to any datetime string that lacks a timezone marker (`Z` or `±HH:MM` offset), forcing UTC interpretation before converting to America/Chicago for display.

---

## 12. Build & Deployment

### Development

```bash
cd web && npm run dev    # Vite dev server with HMR on port 5173
```

HMR is enabled by default. File watcher uses polling (`vite.config.ts:20-22`) for Docker volume mount compatibility.

### Production Build

```bash
cd web && npm run build  # tsc -b && vite build
```

Output goes to `web/dist/` which is served by nginx in the Docker container.

### Docker

```bash
# Full production build
docker compose up --build -d

# Dev profile (Vite dev server instead of nginx)
docker compose --profile dev up --build -d
```

The `web` container mounts the `web/` source directory, so changes to frontend files are reflected instantly via Vite HMR in dev mode. Production builds require `docker compose up --build -d --force-recreate web`.

### Vite Configuration (`web/vite.config.ts`)

| Setting | Value | Purpose |
|---------|-------|---------|
| `server.port` | 5173 | Dev server port |
| `server.host` | `0.0.0.0` | Listen on all interfaces |
| `server.allowedHosts` | `["test.weasts.net"]` | Hostname allowlist |
| `server.proxy["/api"]` | `VITE_API_URL` | Proxy API requests to backend |
| `server.proxy["/ws"]` | `ws://...` | Proxy WebSocket to backend |
| `watch.usePolling` | `true` | Polling-based file watching (Docker) |
| `watch.interval` | 500ms | Poll interval |

### Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start Vite dev server |
| `npm run build` | TypeScript check + production build |
| `npm run preview` | Preview production build locally |
