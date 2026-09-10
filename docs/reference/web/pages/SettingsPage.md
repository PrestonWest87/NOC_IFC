# SettingsPage.tsx

Settings & Admin page. Provides ten tabs: Profile, Theme, Facilities, Internal Assets, RSS Sources, ML Training, AI & SMTP, Users & Roles, Backup & Restore, and Danger Zone.

---

## Constants

### `ALL_PAGES`
Array of 8 page names used for role-based page permissions.

### `ALL_ACTIONS`
Array of 35+ action/permission strings including page-level tab granularity and functional actions.

### `ALL_SITE_TYPES`
Array of 7 site type strings: `NOC`, `SOC`, `Data Center`, `Field Office`, `HQ`, `Remote Site`, `Cloud`.

### `TABS`
Array of 10 tab configuration objects with id, label, and icon:
`profile`, `theme`, `facilities`, `assets`, `rss`, `ml`, `ai-smtp`, `users`, `backup`, `danger`

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
2. Calls `getAllowedTabs(currentUser?.allowed_actions, "settings")` for permission filtering.
3. Filters `TABS` against `SETTINGS_ACTION_IDS` derived from `TAB_PERMISSION_MAP.settings`.
4. Fetches config, roles, users, locations, lists, and ML counts via React Query.
5. Creates `saveConfigMutation` for posting config changes.

### Dependencies
- `useState`, `useEffect` from `react`
- `useQuery`, `useMutation`, `useQueryClient` from `@tanstack/react-query`
- `api` from `../utils/api`
- `useAuth` from `../utils/AuthContext`
- `getAllowedTabs`, `TAB_PERMISSION_MAP` from `../utils/permissions`
- `ThemeSelector` from `../components/ThemeSelector`
- `lucide-react` icons

---

## `ProfileTab({ user })`

### Purpose
Profile settings — personal information and password change.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `user` | `any` | Current user object |

### Returns
Two-column grid:
- Personal Information card (username, full name, job title, contact info, default shift)
- Change Password card (current password, new password with show/hide toggle, role display)

### Flow
1. Initializes local state from `user` object.
2. `updateProfile` mutation posts to `POST /auth/update-profile`.
3. HandleSave sends all profile fields plus optional password change.

---

## `FacilitiesTab({ locations, queryClient })`

### Purpose
Facility locations management — JSON import and manual table editing.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `locations` | `any` | Array of location records |
| `queryClient` | `any` | React Query client for cache invalidation |

### Returns
- Mass Import JSON card (file picker + import button via `POST /admin/location/import`)
- Manual Adjustments card (editable table of all locations with Name, Type, District, Priority, Lat, Lon columns + Save Changes button via `PUT /admin/location`)

---

## `AssetsTab()`

### Purpose
Internal Assets upload — CSV upload for software and hardware assets.

### Returns
- Software Assets card (CSV file upload with `name` column requirement, uploads via `POST /admin/config` as `software_assets_csv`)
- Hardware Assets card (CSV file upload with `IP Address` column requirement, uploads via `POST /admin/config` as `hardware_assets_csv`)

---

## `RssTab({ lists, queryClient })`

### Purpose
RSS Sources management — bulk add keywords and feeds.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `lists` | `any` | Object with `keywords` and `feeds` arrays |
| `queryClient` | `any` | React Query client |

### Returns
Two-column grid:
- Keywords card (textarea for bulk add "word, weight", existing keyword list with delete buttons via `POST /admin/keywords/bulk`)
- RSS Feeds card (textarea for bulk add "URL, Name", existing feed list with delete buttons via `POST /admin/feeds/bulk`)

---

## `MlTab({ mlCounts })`

### Purpose
ML Training tab — displays dataset counts and retrain trigger.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `mlCounts` | `any` | Object with `total`, `positive`, `negative` counts |

### Returns
- Three metric cards (Total Samples, Positives, Negatives)
- Retrain Model Now button via `POST /admin/ml-retrain`

---

## `AiSmtpTab({ config, configLoading, saveConfigMutation })`

### Purpose
AI & SMTP configuration.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `config` | `any` | Current system configuration |
| `configLoading` | `boolean` | Config loading state |
| `saveConfigMutation` | `any` | Mutation for saving config |

### Returns
- LLM Configuration card (endpoint, API key with show/hide, model name, tech stack, enable toggle, test connection button)
- SMTP Broadcast card (server, port, username, password, sender, recipient, enabled toggle)
- Threat Matrix Baseline Overrides card (cyber baseline, physical baseline)
- CIS Countermeasures card (system and network sliders 1-5)
- Save Configuration button

### Flow
1. Initializes `form` state from `config` data once loaded.
2. `testConnectionMutation` tests LLM endpoint via `POST /llm/test-connection`.
3. Save posts form data via `saveConfigMutation` to `POST /admin/config`.

---

## `CheckboxGroup({ label, options, selected, onChange })`

### Purpose
Renders a group of toggleable checkbox chips.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `label` | `string` | Group label |
| `options` | `string[]` | Available options |
| `selected` | `string[]` | Currently selected options |
| `onChange` | `(v: string[]) => void` | Selection change handler |

### Returns
A section with clickable chip-style labels that toggle options in/out of the selected array. Checkboxes are visually hidden; selection is indicated by blue background.

---

## `UsersRolesTab({ roles, users, queryClient })`

### Purpose
User & Role management — create/edit users, roles, and password resets.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `roles` | `any` | Array of role objects |
| `users` | `any` | Array of user objects |
| `queryClient` | `any` | React Query client |

### Returns
Two-column grid:
- Create User card (username, password, full name, role selector via `POST /admin/users`)
- Change User Role card (user dropdown, role dropdown via `PUT /admin/users/{username}/role`)
- Create Custom Role card (name, allowed pages/actions/site types checkboxes via `POST /admin/roles`)
- Edit Existing Role card (role selector, editable name + checkboxes via `PUT /admin/roles/{name}`)
- Reset Password card (user dropdown, new password input via `POST /admin/users/{username}/reset-password`)

---

## `BackupRestoreTab()`

### Purpose
Backup & Restore — download full JSON backup or upload a backup for restoration.

### Returns
Two-column grid:
- Export Backup card (downloads backup JSON via `GET /admin/backup`, displays truncated preview)
- Import Restore card (file upload + restore via `POST /admin/restore`)

---

## `DangerZoneTab()`

### Purpose
Danger Zone — destructive administrative actions.

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
