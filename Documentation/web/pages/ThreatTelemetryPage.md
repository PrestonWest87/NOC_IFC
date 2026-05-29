# ThreatTelemetryPage.tsx

Unified Threat Telemetry page. Provides four tabs: RSS Triage, CISA KEV, Cloud Services, and Perimeter Crime. Integrates article scoring, pagination, pinning, CVE browsing, cloud outage monitoring, and crime incident geo-mapping.

---

## Constants

### `CATEGORIES`
- Purpose: Article category filter options.
- Values: `"All"`, `"Cyber: Exploits & Vulns"`, `"Cyber: Malware & Threats"`, `"ICS/OT & SCADA"`, `"Cloud & IT Infra"`, `"Physical Security"`, `"Severe Weather"`, `"Geopolitics & Policy"`, `"AI & Emerging Tech"`, `"General"`

### `CATEGORY_ICONS`
- Purpose: Maps category strings to icon components.
- Type: `Record<string, React.ReactNode>`

### `SUB_TABS`
- Purpose: Sub-tab labels for RSS Triage.
- Values: `["Pinned", "Live", "Low", "Search"]`

### `THREAT_TABS`
- Purpose: Main tab labels.
- Values: `["RSS Triage", "CISA KEV", "Cloud Services", "Perimeter Crime"]`

### Style Object `s`
- Purpose: Complete style dictionary with keys `page`, `tabBar`, `tab`, `tabActive`, `card`, `btn`, `btnDanger`, `btnPrimary`, `input`, `select`, `badge`, `articleTitle`, `caption`, `divider`.

---

## `getScoreColor(score)`

### Purpose
Returns a color hex string based on score threshold.

### Parameters
| Param | Type | Description |
|-------|------|-------------|
| `score` | `number` | Numeric score |

### Returns
- `#ef4444` (>= 80)
- `#f97316` (>= 60)
- `#eab308` (>= 40)
- `#6b7280` (< 40)

---

## `formatDate(d)`

### Purpose
Formats an optional date string to a human-readable US locale string.

### Parameters
| Param | Type | Description |
|-------|------|-------------|
| `d` | `string \| null \| undefined` | ISO date string |

### Returns
Formatted date like "May 29, 2026, 02:30 PM" or "Unknown" on failure.

---

## `truncate(s, len)`

### Purpose
Truncates a string with ellipsis if it exceeds the given length.

### Parameters
| Param | Type | Description |
|-------|------|-------------|
| `s` | `string \| null \| undefined` | Input string |
| `len` | `number` | Maximum characters |

---

## `TabButton({ active, label, onClick })`

### Purpose
Renders a tab button with active underline style.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `active` | `boolean` | Active state |
| `label` | `string` | Tab label |
| `onClick` | `() => void` | Click handler |

---

## `SubTabButton({ active, label, onClick })`

### Purpose
Renders a subtab button with filled/outlined styling.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `active` | `boolean` | Active state |
| `label` | `string` | Button label |
| `onClick` | `() => void` | Click handler |

---

## `ScoreBadge({ score })`

### Purpose
Renders a colored score badge.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `score` | `number` | Score value |

### Returns
A `<span>` with color from `getScoreColor` showing `Math.round(score)`.

---

## `Pagination({ page, totalPages, total, onPrev, onNext })`

### Purpose
Renders a pagination control with Previous/Next buttons and page counter.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `page` | `number` | Current page number |
| `totalPages` | `number` | Total pages |
| `total` | `number` | Total items |
| `onPrev` | `() => void` | Previous page handler |
| `onNext` | `() => void` | Next page handler |

### Returns
Null if `totalPages <= 1`, otherwise a centered control bar.

---

## `ThreatTelemetryPage` (named export)

### Purpose
Main threat telemetry page with four tabs, article management, and geo-mapped crime data.

### Props
None (uses `useAuth` for user context).

### Returns
- Title "Unified Threat Telemetry"
- Tab navigation (filtered by permissions)
- Conditional rendering of tab content

### Flow

#### State Management
| State | Type | Default | Description |
|-------|------|---------|-------------|
| `activeTab` | `number` | `0` | Active threat tab |
| `subTab` | `number` | `0` | Active RSS sub-tab |
| `categoryFilter` | `string` | `"All"` | Article category filter |
| `pagePinned` | `number` | `1` | Pinned articles page |
| `pageLive` | `number` | `1` | Live articles page |
| `pageLow` | `number` | `1` | Low-score articles page |
| `pageSearch` | `number` | `1` | Search results page |
| `searchTerm` | `string` | `""` | Search query |
| `searchMinScore` | `number` | `0` | Minimum score filter |
| `searchPageSize` | `number` | `20` | Items per page in search |
| `selectedProvider` | `string \| null` | `null` | Cloud provider filter |
| `cooldownRss` | `boolean` | `false` | RSS sync cooldown (60s) |
| `cooldownKev` | `boolean` | `false` | KEV sync cooldown (60s) |
| `cooldownCloud` | `boolean` | `false` | Cloud sync cooldown (60s) |
| `radiusFilter` | `number` | `1` | Crime geofence radius in miles |
| `selectedCrimeId` | `number \| null` | `null` | Selected crime incident |

#### Data Queries
| Query Key | Endpoint | Interval | Description |
|-----------|----------|----------|-------------|
| `articles` | `GET /threat/articles` | 60s | Paginated articles |
| `cves` | `GET /threat/cves?limit=50&days_back=30` | 5min | CISA KEV list |
| `outages` | `GET /threat/cloud-outages?active_only=true` | 2min | Active cloud outages |
| `resolved-outages` | `GET /threat/cloud-outages?active_only=false` | - | All outages for resolved view |
| `crimes` | `GET /threat/crime-incidents` | 3min | Crime incidents |

#### Mutations
| Mutation | Endpoint | Cooldown |
|----------|----------|----------|
| `togglePinMut` | `POST /dashboard/articles/toggle-pin` | None |
| `boostScoreMut` | `POST /dashboard/articles/boost-score?amount=15` | None |
| `feedbackMut` | `POST /dashboard/articles/feedback` | None |
| `blufMut` | `POST /dashboard/articles/generate-bluf` | None |
| `syncFeedsMut` | `POST /threat/fetch-feeds` | 60s |
| `syncKevMut` | `POST /threat/sync-cisa-kev` | 60s |
| `syncCloudMut` | `POST /threat/sync-cloud-status` | 60s |
| `fetchCrimeMut` | `POST /threat/fetch-crime-data` | None |

#### Tab Content

**Tab 0 — RSS Triage:**
- Category filter dropdown + Force Fetch Feeds button
- Four sub-tabs: Pinned, Live, Low, Search
- Search sub-tab has additional search term, min score, and page size controls
- Pagination above and below article list
- Each article card shows: ScoreBadge, title link, date/source/category, AI BLUF, summary, action buttons (Pin/Unpin, +15 Score, Keep, Dismiss, BLUF)

**Tab 1 — CISA KEV:**
- Sync CISA KEV button (60s cooldown)
- Collapsible `<details>` elements for each CVE showing CVE ID, vendor, product, vulnerability name, description, and date added

**Tab 2 — Cloud Services:**
- Sync Cloud Status button (60s cooldown)
- Active incidents warning banner with affected provider count
- Provider filter tabs
- Outage details as collapsible elements with service, title, description, link, and update timestamp
- Historical / Resolved incidents collapsible section

**Tab 3 — Perimeter Crime:**
- Geofence radius selector (1/3/5/10 miles) + Force Fetch LRPD button
- deck.gl crime map with:
  - Crime scatter points (color-coded by category)
  - Selected crime highlight
  - HQ marker with campus boundary polygon
  - Radius circle overlay
- Raw incident log table (Timestamp, Distance, Category, Severity, Title) with row selection for map highlight

#### Derived Data
- `articles`, `totalArticles`, `totalPages`, `currentPage`: Destructured from articles query.
- `activeOutages`: Filters out maintenance/scheduled events unless they include today's date or active keywords.
- `filteredOutages`: Provider-filtered subset of active outages.
- `affectedProviders`: Unique sorted provider names.
- `resolvedOutages`: Outages where `is_resolved` is true.
- `selectedCrime`: Full crime object for selected ID.

#### Handlers
- `handlePrev` / `handleNext`: Delegate to page-specific setters based on `feedType`.
- `crimeTooltip`: Returns HTML tooltip for crime scatter layer.
- `crimeLayers`: Memoized deck.gl layer array including crime scatter, highlight, HQ marker, campus polygon, and radius circle.
- `renderArticles(items)`: Renders a list of article cards with all action buttons.

#### Permission Enforcement
- `getAllowedTabs(user?.allowed_actions, "threatTelemetry")` filters main tabs.
- `useEffect` enforces tab permissions on changes.

### Dependencies
- `useState`, `useMemo`, `useCallback`, `useEffect` from `react`
- `useQuery`, `useMutation`, `useQueryClient` from `@tanstack/react-query`
- `MapContainer` from `../components/MapContainer`
- `DeckGL` from `@deck.gl/react`
- `Map` from `react-map-gl/maplibre`
- `ScatterplotLayer`, `PolygonLayer` from `@deck.gl/layers`
- `MapViewState` type from `@deck.gl/core`
- `maplibre-gl/dist/maplibre-gl.css`
- `lucide-react` icons (15+ icons)
- `api` from `../utils/api`
- `useAuth` from `../utils/AuthContext`
- `getAllowedTabs` from `../utils/permissions`
