# Module: `src.api.routes.logbook`

Shift logbook entry management and summary generation routes. Prefix: `/api/v1/logbook`.

---

## Endpoint: `GET /entries`

### Purpose
Retrieves shift log entries with optional role filtering, date range filtering, and session-based role enforcement.

### Parameters
| Parameter       | Type   | Default  | Description                                      |
|-----------------|--------|----------|--------------------------------------------------|
| `role_filter`   | `str`  | `"All"`  | Filter by role name.                             |
| `start_date`    | `str`  | `None`   | ISO 8601 start date for range filtering.         |
| `end_date`      | `str`  | `None`   | ISO 8601 end date for range filtering.           |
| `session_token` | `str`  | `None`   | Session token for role-based access control.     |

### Returns
List of shift log entry objects.

### Raises
None.

### Flow
1. Parses `start_date` and `end_date` from ISO 8601 strings to `datetime` objects (if provided).
2. If a `session_token` is provided, looks up the user. Non-admin users are restricted to seeing only entries matching their own role.
3. Delegates to `svc.get_shift_logs()` with the resolved filter parameters.

### Dependencies
- `src.services.get_shift_logs()`
- `src.services.get_user_by_token()`

---

## Endpoint: `POST /entries`

### Purpose
Creates a new shift log entry.

### Parameters
| Parameter       | Type   | Default     | Description                                   |
|-----------------|--------|-------------|-----------------------------------------------|
| `analyst`       | `str`  | `""`        | Name of the analyst submitting the entry.     |
| `role`          | `str`  | `"analyst"` | Role of the analyst.                          |
| `shift_period`  | `str`  | `"Morning"` | Shift period (e.g., Morning, Afternoon, Night).|
| `content`       | `str`  | `""`        | Free-text log entry content.                  |
| `custom_date`   | `str`  | `None`      | ISO 8601 date override for the entry.         |
| `session_token` | `str`  | `None`      | Session token for role enforcement.           |

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
1. If a `session_token` is provided, looks up the user. Non-admin users have their role overridden to the user's actual role (prevents privilege escalation).
2. Parses `custom_date` to `datetime` if provided.
3. Delegates to `svc.save_shift_log()`.

### Dependencies
- `src.services.save_shift_log()`
- `src.services.get_user_by_token()`

---

## Endpoint: `PATCH /entries/{entry_id}`

### Purpose
Updates a shift log entry's soft-delete status.

### Parameters
| Parameter   | Type    | Default | Description                          |
|-------------|---------|---------|--------------------------------------|
| `entry_id`  | `int`   | —       | Entry ID (path parameter).           |
| `is_deleted`| `bool`  | `None`  | Soft-delete flag to set on the entry.|

### Returns
```json
{
  "status": "ok" | "error",
  "id": <entry_id>,
  "is_deleted": true | false,
  "message": "<error description>"
}
```

### Raises
None.

### Flow
1. Opens a database session and queries for the `ShiftLogEntry` by ID.
2. If not found, returns an error status.
3. If `is_deleted` is provided (not `None`), sets the flag on the entry.
4. Commits the session and returns the updated state.

### Dependencies
- `src.models.schema.ShiftLogEntry`
- `src.core.db.SessionLocal`

---

## Endpoint: `POST /generate-summary`

### Purpose
Generates an AI-powered summary of shift log entries for a given role and shift period, with optional auto-append to the logbook.

### Parameters
| Parameter        | Type               | Default               | Description                                     |
|------------------|--------------------|-----------------------|-------------------------------------------------|
| `data`           | `dict[str, Any]`   | `{}`                  | JSON body with summary parameters.              |

#### Body Fields
| Field            | Type      | Default                | Description                              |
|------------------|-----------|------------------------|------------------------------------------|
| `role_filter`    | `str`     | `"All"`                | Role to filter entries by.               |
| `shift_period`   | `str`     | `"Morning"`            | Shift period to summarize.               |
| `timeframe_label`| `str`     | Same as `shift_period` | Display label for the timeframe.         |
| `auto_append`    | `bool`    | `False`                | Whether to append the summary to logbook.|

### Returns
Result of `svc.trigger_shift_summary()`.

### Raises
None.

### Flow
1. Logs the trigger with key parameters.
2. Delegates to `svc.trigger_shift_summary()` with the extracted parameters.

### Dependencies
- `src.services.trigger_shift_summary()`
