# Module: `src.api.routes.logbook`

Shift logbook entry management, soft-delete, and AI-powered summary generation routes. Prefix: `/api/v1/logbook`.

---

## Endpoint: `GET /entries`

### Purpose
Retrieves shift log entries with optional role and date-range filtering. Non-administrators are limited to their own role; users without History-tab access are limited to the current Central-time day.

### Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `role_filter` | `str` | `"All"` | Filter by role name (e.g., analyst, admin). |
| `start_date` | `str` | `None` | ISO 8601 start date for range filtering. |
| `end_date` | `str` | `None` | ISO 8601 end date for range filtering. |
| Authentication | Bearer session | Required | Legacy `token`/`session_token` query authentication remains supported by middleware. |

### Returns
```json
[
  {
    "id": 1,
    "analyst": "John Doe",
    "author_role": "analyst",
    "shift_date": "2024-01-15T06:00:00",
    "shift_period": "Morning",
    "content": "Handoff notes...",
    "created_at": "2024-01-15T06:30:00",
    "is_deleted": false
  },
  ...
]
```

### Flow
1. Parses `start_date` and `end_date` from ISO 8601 strings to `datetime` objects.
2. Uses the authenticated user context to restrict non-admin results by role and, without History-tab permission, to the current Central-time day.
3. Delegates to `svc.get_shift_logs(role_filter, start_date, end_date)`.

### Dependencies
- `src.services.get_shift_logs()`
- `src.api.auth_guard.get_current_user()`

---

## Endpoint: `POST /entries`

### Purpose
Creates a shift-log entry attributed to the authenticated user's display name/username. Non-administrators cannot choose another role; an optional custom date is supported.

### Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `role` | `str` | `"analyst"` | Admin-selected author role; non-admin values are replaced by the authenticated user's role. |
| `shift_period` | `str` | `"Morning"` | One of Morning, Afternoon, Evening, or No Shift. |
| `content` | `str` | `""` | Free-text log entry content. |
| `custom_date` | `str` | `None` | ISO 8601 date override for historical entries. |
| `Authentication` | Bearer session | Required | Analyst identity and role are derived from the session. |

### Returns
```json
{ "status": "ok" }
```

### Flow
1. Requires the Active Shift tab and `Action: Submit Shift Log`.
2. Attributes the entry to the authenticated user's full name or username; non-admins use their own role.
3. Rejects unsupported shift periods, empty content, or content longer than 20,000 characters.
4. Parses `custom_date` when supplied and delegates to `svc.save_shift_log()`.

### Dependencies
- `src.services.save_shift_log()`
- `src.api.auth_guard.get_current_user()`

---

## Endpoint: `PATCH /entries/{entry_id}`

### Purpose
Updates a shift log entry's soft-delete flag. The body supports `{ "is_deleted": true|false }`; content/date edits are not handled by this route.

### Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `entry_id` | `int` | — | Entry ID (path parameter). |
| `is_deleted` | `bool` | `None` | Soft-delete flag to set on the entry. Set to `true` to hide, `false` to restore. |

### Returns
```json
{
  "status": "ok",
  "id": 1,
  "is_deleted": true
}
```

### Error Response
```json
{
  "status": "error",
  "message": "Entry not found"
}
```

### Flow
1. Opens a database session and queries for the `ShiftLogEntry` by ID.
2. If not found, returns an error status.
3. Allows an admin, the entry's author, or a caller with `Action: Manage Shift Logs` to change `is_deleted`.
4. Commits and returns the updated delete state.

### Dependencies
- `src.models.schema.ShiftLogEntry`
- `src.core.db.SessionLocal`

---

## Endpoint: `GET /roles`

Returns available role names for shift-log filters. It is protected by the router-level `Shift Logbook` page permission.

## Endpoint: `POST /generate-summary`

### Purpose
Generates an AI-powered summary of shift log entries for a given role and shift period, with optional auto-append to the logbook. Used for end-of-morning and end-of-day handoff reports.

### Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `data` | `dict[str, Any]` | `{}` | JSON body with summary parameters. |

#### Body Fields
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `role_filter` | `str` | `"All"` | Role to filter entries by for the summary. |
| `shift_period` | `str` | `"Morning"` | Shift period to summarize. |
| `timeframe_label` | `str` | Same as `shift_period` | Display label for the timeframe (e.g., "Morning Shift", "End of Day"). |
| `auto_append` | `bool` | `False` | Whether to append the generated summary text as a new logbook entry. |

### Returns
Result of `svc.trigger_shift_summary()`, which returns an LLM-generated summary string. Structure depends on LLM provider configuration.

### Flow
1. Logs the trigger with key parameters.
2. Delegates to `svc.trigger_shift_summary()` with the extracted parameters.
3. Requires the Active Shift tab and `Action: Generate Reports`; non-admin users are restricted to their own role before the service generates the summary.

### Dependencies
- `src.services.trigger_shift_summary()`
## Current Source Surface

Router prefix: `/api/v1/logbook`.

- `GET /entries` supports role and date-range filtering.
- `GET /roles` returns role names for filters.
- `POST /entries` requires `Action: Submit Shift Log`.
- `PATCH /entries/{entry_id}` requires a Shift Log tab and `Action: Submit Shift Log`; authors can update their own soft-delete state, while cross-user edits require `Action: Manage Shift Logs`.
- `POST /generate-summary` requires `Action: Generate Reports`, uses the authenticated user context, and invokes the shift-summary pipeline.
