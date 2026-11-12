# Route module: `src.api.routes.settings`

Router prefix: `/api/v1/settings`. The routes are read-only compatibility/data endpoints; writes are handled by `/api/v1/admin`, `/api/v1/user-admin`, or `/api/v1/application-settings`.

| Method/path | Required grants | Response and behavior |
|---|---|---|
| `GET /config` | Page `Settings & Admin` and `Tab: Settings -> AI & SMTP` | Returns LLM provider/endpoint/model/active flag, `llm_api_key_configured`, selected email provider, both profiles' non-secret fields, OAuth-configured flags, and `llm_context_window`. It does not return API keys, SMTP passwords, Gmail OAuth client secrets, or refresh tokens. Returns `{}` if no `SystemConfig` row exists. |
| `GET /users` | `Tab: Settings -> Users & Roles` and `Action: Manage Users` | Legacy user-directory endpoint. Returns `svc.get_user_directory()`; new UI uses `/user-admin/users`, which also enforces router-level Settings page and Users & Roles tab grants. |
| `GET /facilities` | Page `Settings & Admin` and `Tab: Settings -> Facility Locations` | Returns cached monitored locations filtered by the caller's `allowed_site_types`; built-in administrators receive all locations. |
| `GET /email-contacts` | Page `Settings & Admin` and `Tab: Settings -> Email Contacts` | Returns Fiber company contacts and ONPAGE department email contacts. |
| `GET /network-orders` | Page `Settings & Admin` and `Tab: Settings -> Network Orders & Circuits` | Returns ordered A/Z circuit and network-order records. |
| `GET /rss` | Page `Settings & Admin` and `Tab: Settings -> RSS Sources` | Returns `{keywords, feeds}` from the admin list service and deliberately excludes the legacy user list. |

The routes use `get_db()` for the AI/SMTP configuration read and the shared service/cache layer for directory/location/feed/reference reads. `GET /users` is the compatibility exception that does not declare a router-level page dependency; its exact tab and user-management action requirements remain enforced. Contact and network-directory writes use administrator-only `/api/v1/admin` endpoints.
