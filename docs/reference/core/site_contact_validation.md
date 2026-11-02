# Module: `src.core.site_contact_validation`

Shared normalization and validation rules for optional contacts associated with monitored sites. The admin API applies these rules through Pydantic field validation; service imports use the same functions for contact rows.

## Bounds

| Setting | Value |
|---|---:|
| Contacts per site | 50 |
| Name | 128 characters |
| Phone | 64 characters |
| Email | 254 characters |

Name, phone, and email are individually optional. Values are trimmed; empty strings become `None`; control characters are rejected. Rows with all fields empty are omitted by `normalize_site_contacts()`.

## Functions

### `normalize_site_contact_value(field, value)`

Validates one optional field. Email accepts one IFC-style email address. Phone accepts a leading `+`, common number separators, optional balanced numeric parentheses, and an optional `ext`, `x`, or `#` extension; it requires 7–15 number digits excluding the extension. It validates syntax and length, not assignment or reachability.

### `normalize_site_contact(contact)`

Requires a mapping and returns normalized `name`, `phone`, and `email` values. Extra mapping keys are ignored here; the API request schema rejects extra keys.

### `normalize_site_contacts(contacts)`

Requires a list of at most 50 mappings, normalizes each row, and omits rows with no populated fields. Invalid input raises `ValueError` for service/import callers; request validation returns FastAPI's field-level `422` response.
