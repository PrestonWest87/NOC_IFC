# ReportingPage.tsx

Reporting & Briefings page. Provides three tabs: Daily Fusion Briefing, Custom Report Builder, and Shared Library.

---

## Constants

### Style Constants
- `btn(color)`: Returns a `React.CSSProperties` object for a button with the given background color.
- `inputStyle`, `textareaStyle`, `selectStyle`, `cardStyle`, `sectionTitle` — shared CSS property objects.

---

## `formatDate(d)`

### Purpose
Formats a date string to YYYY-MM-DD.

### Parameters
| Param | Type | Description |
|-------|------|-------------|
| `d` | `string \| null \| undefined` | ISO date string |

### Returns
First 10 characters of the date, or empty string if falsy.

---

## `Spinner()`

### Purpose
Renders a rotating `Loader2` icon as a loading indicator.

### Returns
A `<Loader2>` element with a CSS spin animation.

### Dependencies
- `Loader2` icon from `lucide-react`

---

## `ReportingPage` (named export)

### Purpose
Main reporting page with tab navigation and permission filtering.

### Props
None (uses `useAuth` for user context).

### Returns
- Title header "Reporting & Briefings"
- Tab navigation bar with three tabs: Daily Fusion Briefing, Custom Report Builder, Shared Library
- Conditional rendering of tab content

### Flow
1. Reads `user` from `useAuth()`.
2. Calls `getAllowedTabs(user?.allowed_actions, "reporting")` for permission filtering.
3. Renders filtered tab buttons.
4. Renders `DailyFusionBriefing` (`tab === 0`), `CustomReportBuilder` (`tab === 1`), or `SharedLibrary` (`tab === 2`).

### Dependencies
- `useState`, `useEffect` from `react`
- `useQuery`, `useMutation`, `useQueryClient` from `@tanstack/react-query`
- `api` from `../utils/api`
- `useAuth` from `../utils/AuthContext`
- `getAllowedTabs` from `../utils/permissions`
- `lucide-react` icons

---

## `DailyFusionBriefing()`

### Purpose
AI-synthesized daily situational report covering cyber, vulnerabilities, physical hazards, and cloud infrastructure.

### Returns
- Generate Yesterday's Report button (triggers `POST /reporting/generate-daily`)
- Success/error status indicators
- Historical briefing selector dropdown
- Selected briefing content display (monospace, scrollable)
- Broadcast report form (email recipients + transmit button via `POST /reporting/broadcast`)

### Flow
1. Fetches briefings via `GET /reporting/daily-briefings` (60s refetch).
2. Fetches config via `GET /settings/config` (60s refetch) for default SMTP recipient.
3. `genMutation`: Generates new briefing, invalidates cache on success.
4. `broadcastMutation`: Sends report via email with report date, content, and recipients.
5. User selects historical briefings via dropdown (`selectedIdx`).

### Dependencies
- `useQuery`, `useMutation`, `useQueryClient` from `@tanstack/react-query`
- `api` from `../utils/api`
- `Spinner` (local)

---

## `CustomReportBuilder()`

### Purpose
Search and compile intelligence articles into a formatted custom report.

### Returns
- Target Entity input field
- Historical Depth selector (1, 3, 7, 14, 30 days)
- Analyst name field (auto-populated from session storage)
- AI Objective textarea with default prompt
- Compile Custom Report button (triggers `POST /reporting/generate-custom`)
- Generated report display area
- Save to Library form (title input + save button via `POST /reporting/save-report`)

### Flow
1. User fills in target, depth, analyst name, and objective.
2. `genMutation` posts to `/reporting/generate-custom`.
3. On success, displays generated content and pre-fills a save title.
4. `saveMutation` posts to `/reporting/save-report` and invalidates `saved-reports` cache.

### Dependencies
- `useState` from `react`
- `useMutation`, `useQueryClient` from `@tanstack/react-query`
- `api` from `../utils/api`
- `lucide-react` icons

---

## `SharedLibrary()`

### Purpose
Organization Shared Library — browsable list of saved reports with expand/collapse and delete.

### Returns
- Report count badge
- Report list with expandable items (title, author, date)
- Expanded report content (monospace, scrollable)
- Delete button with confirmation dialog

### Flow
1. Fetches saved reports via `GET /reporting/saved-reports` (30s refetch).
2. Each report renders as a collapsible row with title, author, created_at metadata.
3. Expand/collapse managed via `expandedId` state.
4. `deleteMutation` sends `DELETE /reporting/saved-reports/{id}` and invalidates cache.
5. Delete requires user confirmation via `window.confirm`.

### Dependencies
- `useState` from `react`
- `useQuery`, `useMutation`, `useQueryClient` from `@tanstack/react-query`
- `api` from `../utils/api`
- `lucide-react` icons

---

## `MessageSquare({ size, ...props })`

### Purpose
Custom SVG icon component for a message/chat bubble (used in the report builder objective section).

### Props
| Prop | Type | Description |
|------|------|-------------|
| `size` | `number` (optional) | Width and height in pixels |
| `...props` | `any` | Additional SVG attributes |

### Returns
An inline SVG element.
