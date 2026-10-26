# Route module: `src.api.routes.logbook`

Prefix: `/api/v1/logbook`. Every endpoint requires page permission `Shift Logbook`.

| Method/path | Additional grants | Inputs and behavior |
|---|---|---|
| `GET /roles` | None beyond page | Returns available role names for filters. |
| `GET /entries?role_filter=All&start_date=&end_date=` | Either `Tab: Shift Log -> Active Shift` or `Tab: Shift Log -> History` | Parses optional ISO dates. Non-administrators are forced to their own role. Without History-tab access, the range is forced to the current Central-time day. The service excludes soft-deleted entries by default and sorts newest first. |
| `POST /entries` | `Tab: Shift Log -> Active Shift` + `Action: Submit Shift Log` | Query parameters: `role`, `shift_period`, `content`, optional `custom_date`. The author comes from the authenticated user's full name/username; non-admins cannot choose another role. Accepted periods: Morning, Afternoon, Evening, No Shift. Content is required and at most 20,000 characters. |
| `PATCH /entries/{entry_id}` | Either Active Shift or History tab + `Action: Submit Shift Log` | JSON `{ "is_deleted": true|false }` soft-deletes/restores. Only the author, an administrator, or a user with `Action: Manage Shift Logs` may modify another user's entry. The API has no deletion-reason field. |
| `POST /generate-summary` | Active Shift tab + `Action: Generate Reports` | JSON fields: `role_filter`, `shift_period`, `timeframe_label`, `auto_append`, `timeframe`. Non-admin role filters are forced to the caller's role. `timeframe` is used for the current shift/day, full day (`fullday`), or trailing seven days (`week`). The UI requests auto-append. |

## Summary behavior

`generate-summary` delegates to `src.services.trigger_shift_summary()`, which excludes soft-deleted entries and caps its source set at 200. It requests an LLM summary in a background thread and waits up to 30 seconds; timeout/provider failure returns a deterministic source-based fallback. When `auto_append=true`, the resulting summary is saved as a new entry with the authenticated user's attribution. The response is `{status:"ok",summary:"..."}` unless the service returns an error object.
