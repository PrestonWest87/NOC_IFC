# Module: `src.api.routes.logbook`

Shift logbook entry management, soft-delete, and AI-powered summary generation routes. Prefix: `/api/v1/logbook`.

---

## Endpoint: `GET /entries`

### Purpose
Retrieves shift log entries with optional role filtering, date range filtering, and session-based role enforcement. Non-admin users are restricted to seeing only entries matching their own role.

### Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `role_filter` | `str` | `"All"` | Filter by role name (e.g., analyst, admin). |
| `start_date` | `str` | `None` | ISO 8601 start date for range filtering. |
| `end_date` | `str` | `None` | ISO 8601 end date for range filtering. |
| `session_token` | `str` | `None` | Session token for role-based access control. |

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
2. If `session_token` is provided, looks up the user. Non-admin users are restricted to their own role.
3. Delegates to `svc.get_shift_logs(role_filter, start_date, end_date)`.

### Dependencies
- `src.services.get_shift_logs()`
- `src.services.get_user_by_token()`

---

## Endpoint: `POST /entries`

### Purpose
Creates a new shift log entry with analyst attribution, role enforcement, and optional date override.

### Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `analyst` | `str` | `""` | Name of the analyst submitting the entry. |
| `role` | `str` | `"analyst"` | Role of the analyst. |
| `shift_period` | `str` | `"Morning"` | Shift period: Morning, Afternoon, Night. |
| `content` | `str` | `""` | Free-text log entry content. |
| `custom_date` | `str` | `None` | ISO 8601 date override for historical entries. |
| `session_token` | `str` | `None` | Session token for role enforcement. |

### Returns
```json
{ "status": "ok" }
```

### Flow
1. If `session_token` is provided, looks up the user. Non-admin users have their role overridden to the user's actual role (prevents privilege escalation).
2. Parses `custom_date` to `datetime` if provided.
3. Delegates to `svc.save_shift_log(analyst, role, shift_period, content, custom_date)`.

### Dependencies
- `src.services.save_shift_log()`
- `src.services.get_user_by_token()`

---

## Endpoint: `PATCH /entries/{entry_id}`

### Purpose
Updates a shift log entry's soft-delete status. Supports restoring previously deleted entries.

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
2. If not found, returns error status.
3. If `is_deleted` is provided (not `None`), sets the flag on the entry.
4. Commits and returns updated state.

### Dependencies
- `src.models.schema.ShiftLogEntry`
- `src.core.db.SessionLocal`

---

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
3. The service layer queries matching entries, sends them to the configured LLM for synthesis, and optionally saves the result as a new entry.

### Dependencies
- `src.services.trigger_shift_summary()`
