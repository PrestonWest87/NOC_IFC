# Module: `src.api.auth_guard`

The authentication guard centralizes request token extraction and permission dependencies.

## `token_from_request(request)`

Checks `Authorization` first. A case-insensitive `Bearer ` prefix yields the bearer token. Otherwise it falls back to `token` and then `session_token` query parameters. This compatibility order lets the current Axios client and older clients coexist.

## `get_current_user(request, token="")`

Uses `request.state.user` populated by middleware when available. Otherwise it resolves the dependency token with `services.get_user_by_token`. Missing users raise HTTP `401`.

## `is_admin(user)`

Returns true for role values `admin` or `administrator`, case-insensitively.

## `require_admin(user)`

Dependency that returns the user for administrators and raises HTTP `403` otherwise.

## `has_page_permission(user, page)` and `require_page(page)`

Administrators pass automatically. Other users must contain the exact page string in `allowed_pages`; failures raise HTTP `403`.

## `require_action(action)`

Returns a dependency checker. Non-administrators must contain the exact action string in `allowed_actions`.

## `authentication_middleware(request, call_next)`

Passes OPTIONS, `/health`, `/ready`, login, registration, and non-API paths through. Every other `/api/v1` request must resolve a user, otherwise it receives a JSON `401`. Successful resolution is stored in `request.state.user` and `request.state.auth_token`.
