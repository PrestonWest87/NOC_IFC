# Module: `src.core.paths`

This module derives persistent application data paths from the configured SQLite URL.

| Function | Behavior |
|---|---|
| `sqlite_database_path(database_url=None)` | Validates the backend is SQLite, resolves relative paths against the project root, and returns `None` for `sqlite://` or `:memory:`. |
| `application_data_dir(database_url=None)` | Returns the database file's parent directory, or the repository `data/` directory for an in-memory database. |
