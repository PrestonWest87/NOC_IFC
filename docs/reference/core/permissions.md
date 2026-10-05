# Module: `src.core.permissions`

The canonical catalog of page, action, and tab permission keys used by backend authorization and the Users & Roles editor.

## Catalogs

- `PAGE_CATALOG` declares each frontend page key, route, and description.
- `ACTION_CATALOG` declares action keys, groups, descriptions, and the recognized legacy `Action: Trigger AI Functions` key.
- `TAB_CATALOG` maps frontend page identifiers to tab keys, labels, and tab values.
- `PAGE_KEYS`, `ACTION_KEYS`, and `TAB_KEYS` are derived from those catalogs; `ADMIN_ACTIONS` is the combined recognized action/tab key list used by authorization helpers.
- `public_permission_catalog()` returns the catalog structure consumed by the role editor.

The catalogs describe stable key names, not the full enforcement policy. Route dependencies and `src.api.auth_guard` enforce grants; the frontend permission utilities mirror them for visibility and UX. Tests verify frontend permission strings exist in this catalog.
