# Shared Permission Contract

`contracts/permission_catalog.json` is the canonical page, action, and tab catalog used by C# authorization and the Users & Roles editor. The retained `src.core.permissions` adapter loads it for host-side bootstrap role seeding. The frontend maps catalog keys to its routes and local tab identifiers.

## Catalogs

- `pages` declares each frontend page key, route, and description.
- `actions` declares action keys, groups, descriptions, and the recognized legacy `Action: Trigger AI Functions` key.
- `tabs` maps frontend page identifiers to tab keys, labels, and tab values.
- The Python adapter derives `PAGE_KEYS`, `ACTION_KEYS`, `TAB_KEYS`, and `ADMIN_ACTIONS` from the JSON file.
- `public_permission_catalog()` returns the catalog structure consumed by the role editor.

The catalog defines stable key names, not enforcement policy. Backend authorization enforces grants; frontend permission utilities mirror the keys for visibility and usability. Keep frontend mappings aligned with this file when changing either side.
