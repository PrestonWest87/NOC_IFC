# Route module: `src.api.routes.permissions`

## `GET /api/v1/permissions/catalog`

Requires an authenticated session. Returns the public page, action, tab, and description catalogs from `src.core.permissions.public_permission_catalog()`. The frontend uses the result to build the role editor; role writes are separately authorized by the `/user-admin/roles` routes.
