# ShiftLogbookPage.tsx

NOC Running Shift Log & Calendar page. Provides incident log entry creation, AI-powered auto-drafting, end-of-shift report generation, log browsing with search/filter, day/week calendar views, and CSV export.

---

## Constants

### Style Constants
- `card`, `inputBase`, `btnBase`, `label`, `modalOverlay`, `modalContent` — shared CSS property objects for consistent styling.

---

## `ShiftLogbookPage` (named export)

### Purpose
Full shift logbook page with entry form, log browser, calendar explorer, and admin export.

### Props
None (uses `useAuth` for user context).

### Returns
A two-column layout:
- **Left Column**: Log entry form + End-of-Shift Report card
- **Right Column**: Recent entries list + Shift Log Explorer (Day/Week views) + Admin Export Utility

### Flow

#### State Management
| State | Type | Default | Description |
|-------|------|---------|-------------|
| `analyst` | `string` | `user.full_name ?? user.username` | Analyst name for entries |
| `shiftPeriod` | `string` | `"Morning"` | Shift period selection |
| `customDate` | `string` | today ISO date | Custom date for "No Shift" period |
| `role` | `string` | `user.role` | Role selector |
| `content` | `string` | `""` | Entry content textarea |
| `selectedEntry` | `any` | `null` | Currently selected entry for detail modal |
| `searchQuery` | `string` | `""` | Search filter text |
| `dateFrom` | `string` | today ISO | Date range start |
| `dateTo` | `string` | `""` | Date range end |
| `roleFilter` | `string` | `"All"` or user role | Role filter for entries list |
| `logViewMode` | `"day" \| "week"` | `"day"` | Calendar view mode |
| `weekOffset` | `number` | `0` | Week offset for week view |
| `selectedLogDate` | `string` | today ISO | Selected date for day view |
| `summaryRole` | `string` | `"All"` or user role | Role filter for summary generation |
| `summaryShiftPeriod` | `string` | `"Morning"` | Shift period for summary |
| `summaryResult` | `string \| null` | `null` | Generated summary text |

#### Data Queries
| Query Key | Endpoint | Interval | Description |
|-----------|----------|----------|-------------|
| `logbook-roles` | `GET /admin/roles` | 5min stale | Available roles |
| `logbook` | `GET /logbook/entries` | 30s | Log entries with filters |

#### Mutations
| Mutation | Endpoint | On Success |
|----------|----------|------------|
| `autoDraftMutation` | `GET /rca/dashboard` + `POST /rca/analyze` | Prepends auto-draft to `content` |
| `saveMutation` | `POST /logbook/entries` | Invalidates logbook, clears content |
| `deleteMutation` | `PATCH /logbook/entries/{id}` (is_deleted=true) | Invalidates logbook |
| `restoreMutation` | `PATCH /logbook/entries/{id}` (is_deleted=false) | Invalidates logbook |
| `generateSummaryMut` | `POST /logbook/generate-summary` | Sets summaryResult, invalidates logbook |

#### Key Handlers

**`handleSubmit(e)`**: Prevents default, builds params with analyst, role, shift_period, content, and optional custom_date, then calls `saveMutation.mutate(params)`.

**`autoDraftMutation`**: Fetches `GET /rca/dashboard` and `POST /rca/analyze`, parses clustered incidents, calculates downtime durations, and appends formatted lines to the content textarea.

**`generateSummaryMut`**: Posts to `/logbook/generate-summary` with role filter, shift period, and auto_append flag.

#### Derived Data
- `filteredEntries`: Memoized filter of entries by search query, date range, and reverse chronological order.
- `weekStart`: Calculated start of the week (Monday) with `weekOffset`.
- `weekDays`: Array of 7 Date objects for the week.
- `dayLogs`: Entries filtered to the selected date.
- `logsForDay(date)`: Function that filters entries for a specific date.
- `selectedEntryLocal`: Enriches selectedEntry with localized `created_at_local` string.

#### Admin Export Utility
- Only rendered when `isAdmin` is true.
- Exports filtered entries as CSV with headers: `Local_Time,Analyst,Role,Shift_Period,Content`.
- CSV encoding handles quotes and commas properly.
- Filename format: `NOC_ShiftLogs_{ROLE}_{date}.csv`.

#### Detail Modal
- Displays full entry details: analyst, role, date/time, shift period, content.
- Soft-deleted entries show a warning banner.
- Delete button (soft delete) or Restore button for admin on deleted entries.
- Modal closes on overlay click or X button.

### Dependencies
- `useState`, `useMemo` from `react`
- `useQuery`, `useMutation`, `useQueryClient` from `@tanstack/react-query`
- `api` from `../utils/api`
- `useAuth` from `../utils/AuthContext`
- `lucide-react` icons (15+ icons)
