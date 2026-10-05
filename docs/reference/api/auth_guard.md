# Module: `src.api.auth_guard`

The authentication guard centralizes request token extraction and permission dependencies.

## `token_from_request(request)`

Checks credentials in this order:

1. `Authorization` header with a case-insensitive `Bearer ` prefix.
2. For `/api/v1/admin/backups/{id}/download`, the `noc_backup_download` cookie.
3. The `token` query parameter, then the legacy `session_token` query parameter.

The backup-download cookie supports authenticated streaming downloads when a browser download cannot attach the normal bearer header.

## `get_current_user(request, token="")`

Uses `request.state.user` populated by middleware when available. If middleware has not populated the request, FastAPI supplies the `token` query parameter to this dependency and it resolves that value with `services.get_user_by_token`; this fallback does not independently parse the bearer header. Missing users raise HTTP `401` with the structured `unauthenticated` error detail.

## `is_admin(user)`

Returns true for role values `admin` or `administrator`, case-insensitively.

## `require_admin(user)`

Dependency that returns the user for administrators and raises HTTP `403` otherwise.

## `has_page_permission(user, page)` and `require_page(page)`

Administrators pass automatically. Other users must contain the exact page string in `allowed_pages`; failures raise HTTP `403`.

## `require_action(action)`

Returns a dependency checker. Non-administrators must contain the exact action string in `allowed_actions`.

## Permission helpers

- `permission_denied(permission, scope="action")` builds a structured `403` exception with `code="permission_denied"`, the relevant scope/key, and a scope-specific message.
- `has_action_permission(user, action)` returns true for administrators or users with the exact action in `allowed_actions`.
- `has_site_type_permission(user, site_type)` returns true for administrators or users with the exact site type in `allowed_site_types`.
- `require_any_page(pages)` validates the requested keys against `PAGE_KEYS`, then allows administrators or a user who has at least one listed page.
- `require_any_action(actions)` validates the keys against `ACTION_KEYS` and `TAB_KEYS`, then allows administrators or a user who has at least one listed grant.

## `authentication_middleware(request, call_next)`

Before authentication, checks whether a coordinated restore is in progress and tracks API requests for restore draining. It passes OPTIONS, non-API paths, `/health`, `/ready`, and these public API paths through without session authentication: login, registration, registration validation, password-reset request, password reset, and recovery-email verification. The short-lived capability endpoint `/api/v1/restore-status` also bypasses session authentication and validates its restore ID in the route. Every other `/api/v1` request must resolve a user through `token_from_request`; otherwise it receives a JSON `401`. Successful resolution is stored in `request.state.user` and `request.state.auth_token`.
