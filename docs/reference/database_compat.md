# Module: `src.database`

`src/database.py` is an active compatibility re-export module, not a second database implementation. It preserves older imports while the runtime database implementation lives in `src.core.db` and `src.models.schema`.

## Re-exports

It re-exports:

- `engine`, `SessionLocal`, `init_db`, and `get_db` from `src.core.db`.
- `Base` and all current ORM model classes from `src.models.schema`, including `UserSession` and `RegistrationInvite`.

## Runtime Usage

The worker imports model/session symbols from this module. `src/services.py`, `src/train_model.py`, and email/scheduler paths also use it. Removing or renaming it requires migrating every active import in the same change; it must not be treated as an unused legacy file.

## Operational Boundary

Use `src.core.db` for new database lifecycle code and `src.models.schema` for new model imports. Keep `src.database` stable for existing consumers until a deliberate compatibility migration is completed.
