# SettingsPage.tsx

Settings & Admin page. Provides eleven tabs: Profile, Theme, Facilities, Internal Assets, RSS Sources, ML Training, AI & SMTP, Application Settings, Users & Roles, Backup & Restore, and Danger Zone.

## Current Source Behavior

The role editor loads the backend permission catalog and groups page, tab, action, and site-type grants. User management is a searchable directory with separate individual-invitation and display-account creation, account status and access history, session revocation, and reviewed recovery requests. Application Settings contains risk scoring, scheduler, and global defaults. A tab grant controls visibility; component permissions and backend route dependencies control edits. Backup, restore, and danger-zone operations remain administrator-only.

---

## Constants

### `TABS`
Array of 11 tab configuration objects. Tab visibility is filtered by the current user's `Tab: Settings -> ...` grants; administrators see every tab:
`profile`, `theme`, `facilities`, `assets`, `rss`, `ml`, `ai-smtp`, `application`, `users`, `backup`, `danger`.

### `btn(color)`
Returns a `React.CSSProperties` object with the given background color.

### `inputStyle`, `textareaStyle`
Shared CSS property objects for form inputs and textareas.

---

## `TabButton({ active, label, icon: Icon, onClick })`

### Purpose
Renders a settings tab button with active/inactive styling.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `active` | `boolean` | Whether tab is selected |
| `label` | `string` | Tab label |
| `icon` | `any` | Icon component |
| `onClick` | `() => void` | Click handler |

---

## `Card({ title, children, icon: Icon, wide })`

### Purpose
Renders a titled card container with optional icon.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `title` | `string` | Card title |
| `children` | `React.ReactNode` | Card content |
| `icon` | `any` (optional) | Icon component |
| `wide` | `boolean` (optional) | Sets gridColumn to `1 / -1` |

---

## `SectionTitle({ text })`

### Purpose
Renders a section heading.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `text` | `string` | Heading text |

---

## `SettingsPage` (named export)

### Purpose
Main settings page with tab navigation and permission filtering.

### Props
None (uses `useAuth` for user context).

### Returns
- Title header "Settings & Admin"
- Tab navigation bar (filtered by permissions)
- Conditional rendering of tab content

### Flow
1. Reads `currentUser` from `useAuth()`.
2. Calls `getAllowedTabs(currentUser?.allowed_actions, "settings")`; Profile and Theme are available to signed-in users, while administrators see all tabs.
3. Enables tab-specific queries only while their tab is active: AI/SMTP config, facilities, RSS/keywords, or ML counts.
4. Keeps AI/SMTP changes in `saveConfigMutation`; permission-sensitive sections continue to rely on backend route authorization.
5. Delegates account/role management to `UsersRolesTab` and risk/scheduler/global settings to `ApplicationSettingsTab`.

### Dependencies
- `useState`, `useEffect` from `react`
- `useQuery`, `useMutation`, `useQueryClient` from `@tanstack/react-query`
- `api` from `../utils/api`
- `useAuth` from `../utils/AuthContext`
- `getAllowedTabs`, `hasActionPermission`, `isAdministrator` from `../utils/permissions`
- `ThemeSelector` from `../components/ThemeSelector`
- `UsersRolesTab` and `ApplicationSettingsTab` from `../components/`
- `lucide-react` icons

---

## `ProfileTab({ user, onProfileUpdated })`

### Purpose
Profile settings — personal information, password change, and reviewed recovery-email requests.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `user` | `any` | Current user object |
| `onProfileUpdated` | `() => void` | Refreshes the current authenticated user after an update. |

### Returns
Two-column grid:
- Personal Information card (username, full name, job title, contact info, default shift)
- Change Password card (current password, new password with show/hide toggle, role display)
- Password Recovery Email card (request approval, resend verification, and pending-state messages for individual accounts)

### Flow
1. Initializes local state from `user` object.
2. `updateProfile` mutation posts to `POST /auth/update-profile`.
3. HandleSave sends all profile fields plus optional password change.

---

## `FacilitiesTab({ locations, locationsLoading, locationsError, refetchLocations, queryClient, canEdit })`

### Purpose
Facility locations management — JSON import and manual table editing.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `locations` | `any` | Array of location records |
| `locationsLoading` | `boolean` | Whether the location query is pending. |
| `locationsError` | `boolean` | Whether the location query failed. |
| `refetchLocations` | `() => unknown` | Retries the location query. |
| `queryClient` | `any` | React Query client for cache invalidation |
| `canEdit` | `boolean` | Whether the current user may edit location data. |

### Returns
- Facility map (DeckGL/MapLibre) and site details.
- JSON import with add/upsert/replace modes via `POST /admin/location/import`.
- Location table with Name, Type, District, Priority, Lat, and Lon; writes use `PUT /admin/location` and are administrator-managed.

---

## `AssetsTab({ canManage })`

### Purpose
Internal Assets upload — CSV upload for software and hardware assets.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `canManage` | `boolean` | Whether the current user may import assets. |

### Returns
- Software CSV upload with a required `name` column via `POST /admin/assets/software`.
- Hardware CSV upload with a required `IP Address` column via `POST /admin/assets/hardware`.
- Non-administrators with tab access receive a read-only notice.

---

## `RssTab({ lists, queryClient, canManage })`

### Purpose
RSS Sources management — bulk add keywords and feeds.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `lists` | `any` | Object with `keywords` and `feeds` arrays |
| `queryClient` | `any` | React Query client |
| `canManage` | `boolean` | Whether the current user may manage keywords and feeds. |

### Returns
Two-column grid:
- Keywords card (textarea for bulk add "word, weight", existing keyword list with delete buttons via `POST /admin/keywords/bulk`)
- RSS Feeds card (textarea for bulk add "URL, Name", existing feed list with delete buttons via `POST /admin/feeds/bulk`)

---

## `MlTab({ mlCounts, canTrain })`

### Purpose
ML Training tab — displays dataset counts and retrain trigger.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `mlCounts` | `any` | Object with `total`, `positive`, `negative` counts |
| `canTrain` | `boolean` | Whether manual retraining is permitted. |

### Returns
- Three metric cards (Total Samples, Positives, Negatives)
- Retrain Model Now button via `POST /application-settings/ml-retrain`, shown only with `Action: Train ML Model`.

---

## `AiSmtpTab({ config, configLoading, saveConfigMutation, readOnly })`

### Purpose
AI & SMTP configuration.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `config` | `any` | Current system configuration |
| `configLoading` | `boolean` | Config loading state |
| `saveConfigMutation` | `any` | Mutation for saving config |
| `readOnly` | `boolean` | Whether this tab is view-only. |

### Returns
- LLM Configuration card (endpoint, API key with show/hide, model name, tech stack, enable toggle, test connection button)
- SMTP Broadcast card (server, port, username, password, sender, recipient, enabled toggle)
- Configuration editor covers LLM endpoint/model/key and SMTP server/credentials/sender/recipient.
- LLM connection test uses `POST /api/v1/llm/test-connection`.
- Editing is administrator-only; risk overrides, scheduler schedules, application defaults, and failed-login alert settings are in `ApplicationSettingsTab`.

### Flow
1. Initializes `form` state from `config` data once loaded.
2. `testConnectionMutation` tests LLM endpoint via `POST /llm/test-connection`.
3. Save posts form data via `saveConfigMutation` to `POST /admin/config`.

---

## `UsersRolesTab({ user })`

### Purpose
User and role management is implemented in `web/src/components/UsersRolesTab.tsx` and imported by `SettingsPage`. It receives the current user and fetches the directory, roles, invitations, permission catalog, and recovery queues itself.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `user` | current user or `null` | Used to gate user, role, recovery, and self-approval controls. |

### Returns
Renders a searchable account directory, invite-individual and create-display-account flows, role editor, session controls, administrator-assisted reset, and recovery-request queues. Each action is gated by the corresponding canonical permission; the API remains authoritative.

---

## `ApplicationSettingsTab({ user })`

Risk-scoring overrides, validated scheduler settings, application defaults, and failed-login alert configuration are implemented in `web/src/components/ApplicationSettingsTab.tsx`. Each section has a separate action permission; reads and writes use `/api/v1/application-settings/*` routes.

---

## `BackupRestoreTab({ isAdmin })`

### Purpose
Backup & Restore — administrator-only legacy JSON backup/restore, supported 27-model JSON export/import, and SQLite file data import.

### Returns
Administrator-only controls provide a legacy four-collection JSON backup/restore, export/import for the 27 supported application models via `GET /admin/export-all` and `POST /admin/import-all`, and a `.db` upload that imports rows into the current database via `POST /admin/upload-db`. None of these JSON/upload paths replaces a complete SQLite database-file backup.

---

## `DangerZoneTab({ isAdmin })`

### Purpose
Danger Zone — destructive administrative actions.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `isAdmin` | `boolean` | Controls administrator-only rendering; backend dependencies remain authoritative. |

### Returns
- Delete Record card (model name + record ID inputs via `DELETE /admin/record`)
- Destructive Actions card (Nuke Tables, Nuke Crime Data, Nuke Weather Data, Run DB Maintenance, Clear Timeline Events, Nuke Active Alerts — each with confirmation dialog)

### Danger Buttons
| Button | Endpoint |
|--------|----------|
| Nuke Tables | `POST /admin/nuke` |
| Nuke Crime Data | `POST /admin/nuke/crime` |
| Nuke Weather Data | `POST /admin/nuke/weather` |
| Run DB Maintenance | `POST /admin/maintenance` |
| Clear Timeline Events | `POST /rca/clear-events` |
| Nuke Active Alerts | `POST /rca/nuke-alerts` |

All buttons use a `dangerBtn` helper that wraps each mutation with a `window.confirm` dialog.

---

## `ThemeTab()`

### Purpose
Theme selection tab.

### Returns
A card containing the `ThemeSelector` component.

### Dependencies
- `ThemeSelector` from `../components/ThemeSelector`

---

## `Cloud({ size, ...props })`

### Purpose
Custom SVG icon component for a cloud.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `size` | `number` (optional) | Width and height |
| `...props` | `any` | Additional SVG attributes |

### Returns
An inline SVG cloud icon.
