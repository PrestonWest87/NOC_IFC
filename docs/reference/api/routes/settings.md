# Route module: `src.api.routes.settings`

Router prefix: `/api/v1/settings`. The routes are read-only compatibility/data endpoints; writes are handled by `/api/v1/admin`, `/api/v1/user-admin`, or `/api/v1/application-settings`.

| Method/path | Required grants | Response and behavior |
|---|---|---|
| `GET /config` | Page `Settings & Admin` and `Tab: Settings -> AI & SMTP` | Returns LLM endpoint/model/active flag, SMTP enabled/server/port/username/sender/recipient, and `llm_context_window`. It does not return `llm_api_key` or `smtp_password`. Returns `{}` if no `SystemConfig` row exists. |
| `GET /users` | `Tab: Settings -> Users & Roles` and `Action: Manage Users` | Legacy user-directory endpoint. Returns `svc.get_user_directory()`; new UI uses `/user-admin/users`, which also enforces router-level Settings page and Users & Roles tab grants. |
| `GET /facilities` | Page `Settings & Admin` and `Tab: Settings -> Facility Locations` | Returns cached monitored locations filtered by the caller's `allowed_site_types`; built-in administrators receive all locations. |
| `GET /rss` | Page `Settings & Admin` and `Tab: Settings -> RSS Sources` | Returns `{keywords, feeds}` from the admin list service and deliberately excludes the legacy user list. |

The routes use `get_db()` for the AI/SMTP configuration read and the shared service/cache layer for directory/location/feed reads. `GET /users` is the compatibility exception that does not declare a router-level page dependency; its exact tab and user-management action requirements remain enforced.
