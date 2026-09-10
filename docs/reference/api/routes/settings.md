# Module: `src.api.routes.settings`

System configuration and user list retrieval routes. Prefix: `/api/v1/settings`.

---

## Endpoint: `GET /config`

### Purpose
Returns the current system configuration including LLM settings, SMTP settings, tech stack, monitored ASNs, and brief generation times.

### Parameters
None (uses `db: Session` via `Depends(get_db)`).

### Returns
```json
{
  "llm_endpoint": "...",
  "llm_model_name": "...",
  "is_active": true | false,
  "smtp_enabled": true | false,
  "smtp_server": "...",
  "smtp_port": ...,
  "smtp_sender": "...",
  "smtp_recipient": "...",
  "tech_stack": "...",
  "monitored_asns": "...",
  "sys_countermeasures": "...",
  "net_countermeasures": "...",
  "unified_brief": true | false,
  "unified_brief_time": "<ISO 8601>",
  "rolling_summary": true | false,
  "rolling_summary_time": "<ISO 8601>"
}
```

Returns an empty object `{}` if no `SystemConfig` row exists.

### Raises
None.

### Flow
1. Opens a database session via `Depends(get_db)`.
2. Queries for the first `SystemConfig` row.
3. If no config exists, returns `{}`.
4. Otherwise, constructs and returns a dict of all relevant configuration fields.
5. Datetime fields (`unified_brief_time`, `rolling_summary_time`) are serialized to ISO 8601 strings.

### Dependencies
- `src.core.db.get_db`
- `src.models.schema.SystemConfig`

---

## Endpoint: `GET /users`

### Purpose
Returns a list of all registered users with their profile information (excluding passwords and tokens).

### Parameters
None (uses `db: Session` via `Depends(get_db)`).

### Returns
```json
[
  {
    "id": <int>,
    "username": "...",
    "role": "...",
    "full_name": "...",
    "job_title": "...",
    "contact_info": "..."
  },
  ...
]
```

### Raises
None.

### Flow
1. Opens a database session via `Depends(get_db)`.
2. Queries all `User` records.
3. Maps each user to a sanitized dict (excluding sensitive fields).
4. Returns the list.

### Dependencies
- `src.core.db.get_db`
- `src.models.schema.User`
