# ThreatHuntingPage.tsx

Active Threat Hunting & Detection Engineering page. Provides three tabs: Live Global IOC Matrix, Deep Hunt & Detection Builder, and Elastic SIEM Report.

---

## Constants

### `ALL_HUNT_TABS`
- Purpose: Tab configuration with key, label, and icon.
- Values: `ioc` (Live Global IOC Matrix), `hunt` (Deep Hunt & Detection Builder), `siem` (Elastic SIEM Report)

### `IOC_TYPE_OPTIONS`
- Purpose: Available IOC type filter options.
- Values: `IPv4`, `SHA256`, `Domain`, `CVE`, `MITRE ATT&CK`, `URL`, `MD5`, `Email`, `SHA1`

### `IOC_TYPE_COLORS`
- Purpose: Maps IOC type to background color, text color, and icon component.
- Type: `Record<string, { bg: string; text: string; icon: any }>`

### Style Constants
- `CARD`, `CARD_HEADER`, `BTN_PRIMARY`, `BTN_SECONDARY`, `INPUT_STYLE`, `LABEL`, `TH`, `TD` — reusable CSS property objects.

---

## `osintPivotLink(iocType, value)`

### Purpose
Generates an external OSINT pivot URL for a given IOC type and value.

### Parameters
| Param | Type | Description |
|-------|------|-------------|
| `iocType` | `string` | IOC type (e.g. "SHA256", "IPv4") |
| `value` | `string` | IOC value |

### Returns
- VirusTotal file URL for SHA256/MD5/SHA1
- Shodan URL for IPv4
- VirusTotal domain URL for Domain
- NVD URL for CVE
- MITRE ATT&CK URL for MITRE ATT&CK
- `null` for unsupported types

---

## `formatDt(s)`

### Purpose
Formats a date string to a human-readable format.

### Parameters
| Param | Type | Description |
|-------|------|-------------|
| `s` | `string \| null \| undefined` | ISO date string |

### Returns
Formatted string like "May 29, 2026, 02:30 PM" or em-dash on failure.

---

## `csvEscape(v)`

### Purpose
Escapes a string for CSV output.

### Parameters
| Param | Type | Description |
|-------|------|-------------|
| `v` | `string` | Value to escape |

### Returns
Quoted string if it contains commas, quotes, newlines; raw string otherwise.

---

## `downloadCsv(filename, headers, rows, mapFn)`

### Purpose
Triggers a CSV file download in the browser with BOM for UTF-8 encoding.

### Parameters
| Param | Type | Description |
|-------|------|-------------|
| `filename` | `string` | Download filename |
| `headers` | `string[]` | CSV header row |
| `rows` | `any[]` | Data rows |
| `mapFn` | `(r: any) => string[]` | Maps each row to string array |

---

## `InfoBox({ type, children })`

### Purpose
Renders a colored information box with left border accent.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `type` | `"info" \| "success" \| "warning" \| "error"` | Box style variant |
| `children` | `React.ReactNode` | Content |

### Color Mapping
Same as RegionalGridPage's `InfoBox`.

---

## `Badge({ label })`

### Purpose
Renders an IOC type badge with type-specific coloring and icon.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `label` | `string` | IOC type string |

### Returns
A `<span>` with background, text color, and icon from `IOC_TYPE_COLORS`.

---

## `ThreatHuntingPage` (named export)

### Purpose
Main threat hunting page with tab navigation and permission filtering.

### Props
None (uses `useAuth` for user context).

### Returns
- Title header "Active Threat Hunting & Detection Engineering"
- Tab navigation bar (filtered by permissions)
- Conditional rendering of `IocMatrixTab`, `DeepHuntTab`, or `ElasticSiemTab`

### Flow
1. Reads `user` from `useAuth()`.
2. Calls `getAllowedTabs(user?.allowed_actions, "threatHunting")` for permission filtering.
3. Filters `ALL_HUNT_TABS` and sets active tab to first allowed tab.
4. `useEffect` enforces tab permissions on changes.

### Dependencies
- `useState`, `useMemo`, `useCallback`, `useEffect` from `react`
- `useQuery`, `useMutation` from `@tanstack/react-query`
- `api` from `../utils/api`
- `useAuth` from `../utils/AuthContext`
- `getAllowedTabs` from `../utils/permissions`
- `lucide-react` icons

---

## `IocMatrixTab()`

### Purpose
Live Global IOC Matrix — displays extracted IOCs from the last 72 hours with type filtering and CSV export.

### Returns
- Filter bar with expandable type filter chips
- IOC table with columns: Type, Indicator, Context, Detected, Source Intel, Investigate
- OSINT pivot links in the Investigate column
- CSV Export button via `downloadCsv`

### Flow
1. Fetches IOCs via `GET /hunting/iocs?days_back=3` (2min refetch).
2. Filters by selected type filter (default: IPv4, SHA256, Domain, CVE, MITRE ATT&CK).
3. Extract all unique types from data for available filter options.
4. Each IOC row renders a type badge, monospace indicator value, truncated context, formatted detection date, source article link, and OSINT pivot link.

### Dependencies
- `osintPivotLink`, `downloadCsv`, `formatDt`, `Badge`, `InfoBox` (local)
- `lucide-react` icons

---

## `DeepHuntTab()`

### Purpose
Targeted LLM Deep Hunt & Detection Engine — searches articles for a target entity and generates a structured detection package.

### Returns
- Target Entity input (with icon, Enter key to submit)
- Historical Depth slider (7-90 days)
- Compile Detection Package button
- Search results list (up to 15 articles)
- Auto-generated detection package in monospace textarea

### Flow
1. User enters a target entity (e.g. "Volt Typhoon", "LockBit 3.0").
2. `compileHunt` mutation posts to `GET /hunting/search-articles` with target and days_back.
3. On success, calls `buildDetectionPackage` to generate a structured report.
4. Detection package includes:
   - Threat Overview & MITRE TTPs (from top 8 articles)
   - Known Vulnerabilities & Infrastructure (extracted CVEs)
   - SIEM Hunt Queries (Splunk/Elastic patterns)
   - YARA Detection Stub (auto-generated rule)

### Dependencies
- `useState` from `react`
- `useMutation` from `@tanstack/react-query`
- `buildDetectionPackage` (local)
- `InfoBox` (local)
- `lucide-react` icons

---

## `buildDetectionPackage(target, articles)`

### Purpose
Generates a structured detection package string from search result articles.

### Parameters
| Param | Type | Description |
|-------|------|-------------|
| `target` | `string` | Entity being hunted |
| `articles` | `any[]` | Search result articles |

### Returns
A formatted string with five sections:
1. Threat Overview & MITRE TTPs
2. Known Vulnerabilities & Infrastructure (CVEs extracted via regex)
3. SIEM Hunt Queries (Splunk/Elastic templates)
4. YARA Detection Stub (auto-generated rule from keywords)
5. End marker

---

## `ElasticSiemTab()`

### Purpose
Advanced SIEM Fusion & Hunt — displays cached Elastic events with AI triage.

### Returns
- Summary metric cards (Local Events, Unique Threat IPs, Critical Density %)
- Sync Local Cache button (triggers `POST /threat/sync-elastic-cache`)
- Events table (Timestamp, Severity, Category, Source IP, Message) — up to 100 rows
- AI Triage & Summarize Results button (triggers `POST /threat/generate-siem-triage`)
- Triage summary display area

### Flow
1. Fetches events via `GET /threat/elastic-events?hours_back=24` (2min refetch).
2. `handleSync` syncs cache via `POST /threat/sync-elastic-cache` then refetches.
3. `handleTriage` posts up to 50 events to `POST /threat/generate-siem-triage`.
4. On error, generates a client-side triage summary from the raw event data.
5. Severity color function maps severity strings to colors (CRITICAL=red, HIGH=orange, etc.).
6. Memoized calculations for `uniqueIps` and `criticalCount`.

### Dependencies
- `useState` from `react`
- `useQuery` from `@tanstack/react-query`
- `formatDt` (local)
- `InfoBox` (local)
- `lucide-react` icons
