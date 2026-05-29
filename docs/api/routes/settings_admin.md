# Module: `src.api.routes.settings_admin`

Admin-level system administration routes for user management, keyword/feed management, role management, location management, backup/restore, database maintenance, ML retraining, and data nuking. Prefix: `/api/v1/admin`.

---

## Endpoint: `GET /lists`

### Purpose
Returns all admin list data: keywords, RSS feeds, and users.

### Parameters
None.

### Returns
```json
{
  "keywords": [...],
  "feeds": [...],
  "users": [...]
}
```

### Raises
None.

### Flow
Calls `svc.get_admin_lists()` which returns a 3-tuple destructured into keywords, feeds, and users.

### Dependencies
- `src.services.get_admin_lists()`

---

## Endpoint: `POST /keywords/bulk`

### Purpose
Bulk-adds keywords from raw text (one per line or comma-separated).

### Parameters
| Parameter  | Type   | Default | Description                    |
|------------|--------|---------|--------------------------------|
| `raw_text` | `str`  | `""`    | Raw text containing keywords.  |

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Direct delegation to `svc.add_bulk_keywords()`.

### Dependencies
- `src.services.add_bulk_keywords()`

---

## Endpoint: `POST /feeds/bulk`

### Purpose
Bulk-adds RSS feed URLs from raw text (one per line).

### Parameters
| Parameter  | Type   | Default | Description                    |
|------------|--------|---------|--------------------------------|
| `raw_text` | `str`  | `""`    | Raw text containing feed URLs. |

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Direct delegation to `svc.add_bulk_feeds()`.

### Dependencies
- `src.services.add_bulk_feeds()`

---

## Endpoint: `GET /ml-counts`

### Purpose
Returns the count of positive, negative, and total ML training samples.

### Parameters
None.

### Returns
```json
{
  "positive": <int>,
  "negative": <int>,
  "total": <int>
}
```

### Raises
None.

### Flow
Calls `svc.get_ml_counts()` which returns a 3-tuple destructured into pos, neg, total.

### Dependencies
- `src.services.get_ml_counts()`

---

## Endpoint: `POST /config`

### Purpose
Saves the global system configuration from a JSON body.

### Parameters
| Parameter | Type               | Description                           |
|-----------|--------------------|---------------------------------------|
| `data`    | `dict[str, Any]`   | JSON body with configuration fields.  |

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Direct delegation to `svc.save_global_config()`.

### Dependencies
- `src.services.save_global_config()`

---

## Endpoint: `GET /roles`

### Purpose
Returns all defined roles and their permissions (allowed pages, actions, site types).

### Parameters
None.

### Returns
List of role objects.

### Raises
None.

### Flow
Direct delegation to `svc.get_all_roles()`.

### Dependencies
- `src.services.get_all_roles()`

---

## Endpoint: `POST /roles`

### Purpose
Creates a new role with specified permissions.

### Parameters
| Parameter | Type               | Description                                   |
|-----------|--------------------|-----------------------------------------------|
| `data`    | `dict[str, Any]`   | JSON body with `name`, `allowed_pages`, `allowed_actions`, `allowed_site_types`.|

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Extracts fields from the body and delegates to `svc.create_role()`.

### Dependencies
- `src.services.create_role()`

---

## Endpoint: `PUT /roles/{name}`

### Purpose
Updates an existing role's permissions.

### Parameters
| Parameter | Type               | Description                                   |
|-----------|--------------------|-----------------------------------------------|
| `name`    | `str`              | Role name (path parameter).                   |
| `data`    | `dict[str, Any]`   | JSON body with `allowed_pages`, `allowed_actions`, `allowed_site_types`.|

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Extracts fields from the body and delegates to `svc.update_role()`.

### Dependencies
- `src.services.update_role()`

---

## Endpoint: `POST /users`

### Purpose
Creates a new user account.

### Parameters
| Parameter | Type               | Description                                             |
|-----------|--------------------|---------------------------------------------------------|
| `data`    | `dict[str, Any]`   | JSON body with `username`, `password`, `role`, `full_name`.|

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Extracts fields from the body and delegates to `svc.create_user()`.

### Dependencies
- `src.services.create_user()`

---

## Endpoint: `PUT /users/{username}/role`

### Purpose
Updates a user's role assignment.

### Parameters
| Parameter  | Type               | Description                              |
|------------|--------------------|------------------------------------------|
| `username` | `str`              | Username (path parameter).               |
| `data`     | `dict[str, Any]`   | JSON body with `role` field.             |

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Delegates to `svc.update_user_role()`.

### Dependencies
- `src.services.update_user_role()`

---

## Endpoint: `POST /users/{username}/reset-password`

### Purpose
Force-resets a user's password (admin override).

### Parameters
| Parameter  | Type               | Description                                |
|------------|--------------------|--------------------------------------------|
| `username` | `str`              | Username (path parameter).                 |
| `data`     | `dict[str, Any]`   | JSON body with `new_password` field.       |

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Delegates to `svc.force_reset_pwd()`.

### Dependencies
- `src.services.force_reset_pwd()`

---

## Endpoint: `GET /location`

### Purpose
Returns all cached monitored locations.

### Parameters
None.

### Returns
List of location objects.

### Raises
None.

### Flow
Direct delegation to `svc.get_cached_locations()`.

### Dependencies
- `src.services.get_cached_locations()`

---

## Endpoint: `POST /location/import`

### Purpose
Bulk-imports location data from a list of dictionaries.

### Parameters
| Parameter | Type           | Description                      |
|-----------|----------------|----------------------------------|
| `data`    | `list[dict]`   | JSON body array of location dicts.|

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
1. Delegates to `svc.import_locations(data)`.
2. Clears the cached locations via `svc.get_cached_locations.clear()`.

### Dependencies
- `src.services.import_locations()`
- `src.services.get_cached_locations.clear()` (LRU cache clear)

---

## Endpoint: `PUT /location`

### Purpose
Updates existing location records from a list of dictionaries.

### Parameters
| Parameter | Type           | Description                          |
|-----------|----------------|--------------------------------------|
| `data`    | `list[dict]`   | JSON body array of updated location dicts.|

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
1. Converts the JSON body list to a `pandas.DataFrame`.
2. Delegates to `svc.update_locations()`.
3. Clears the cached locations.

### Dependencies
- `pandas`
- `src.services.update_locations()`
- `src.services.get_cached_locations.clear()`

---

## Endpoint: `GET /backup`

### Purpose
Exports all system data as a JSON-serializable backup object.

### Parameters
None.

### Returns
Backup data object from `svc.get_backup_data()`.

### Raises
None.

### Flow
Direct delegation to service layer.

### Dependencies
- `src.services.get_backup_data()`

---

## Endpoint: `POST /restore`

### Purpose
Restores system data from a previously exported backup.

### Parameters
| Parameter | Type               | Description                      |
|-----------|--------------------|----------------------------------|
| `data`    | `dict[str, Any]`   | JSON body with backup data.      |

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Delegates to `svc.restore_backup_data()`.

### Dependencies
- `src.services.restore_backup_data()`

---

## Endpoint: `DELETE /record`

### Purpose
Deletes a record from any table by model name and record ID.

### Parameters
| Parameter    | Type   | Default | Description                         |
|--------------|--------|---------|-------------------------------------|
| `model_name` | `str`  | `""`    | SQLAlchemy model class name.        |
| `record_id`  | `int`  | `0`     | ID of the record to delete.         |

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Delegates to `svc.delete_record()`.

### Dependencies
- `src.services.delete_record()`

---

## Endpoint: `POST /nuke`

### Purpose
Truncates specified database tables (destructive operation).

### Parameters
| Parameter | Type        | Description                            |
|-----------|-------------|----------------------------------------|
| `tables`  | `list[str]` | JSON body array of table names to nuke.|

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Delegates to `svc.nuke_tables()`.

### Dependencies
- `src.services.nuke_tables()`

---

## Endpoint: `POST /nuke/crime`

### Purpose
Truncates all crime incident data from the database.

### Parameters
None.

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Delegates to `svc.nuke_crime_data()`.

### Dependencies
- `src.services.nuke_crime_data()`

---

## Endpoint: `POST /nuke/weather`

### Purpose
Truncates all weather/hazard data from the database.

### Parameters
None.

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Delegates to `svc.nuke_weather_data()`.

### Dependencies
- `src.services.nuke_weather_data()`

---

## Endpoint: `POST /maintenance`

### Purpose
Manually triggers database maintenance operations (deduplication, purging stale data).

### Parameters
None.

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Imports and calls `run_database_maintenance()` from `src.scheduler`.

### Dependencies
- `src.scheduler.run_database_maintenance()`

---

## Endpoint: `POST /ml-retrain`

### Purpose
Manually triggers ML model retraining and scorer reload.

### Parameters
None.

### Returns
```json
{
  "status": "ok" | "error",
  "message": "<description>"
}
```

### Raises
None.

### Flow
1. Imports `train()` from `src.train_model`.
2. Imports `force_reload_scorer()` from `src.services.logic`.
3. Calls `train()` to retrain the model.
4. Calls `force_reload_scorer()` to reload the scoring logic.
5. Returns success, or catches any exception and returns error message.

### Dependencies
- `src.train_model.train()`
- `src.services.logic.force_reload_scorer()`
