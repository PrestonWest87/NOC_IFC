# Module: `src.core.paths`

This module derives persistent application artifact paths from the configured SQLite URL.

| Function | Behavior |
|---|---|
| `sqlite_database_path(database_url=None)` | Validates the backend is SQLite, resolves relative paths against the project root, and returns `None` for `sqlite://` or `:memory:`. |
| `application_data_dir(database_url=None)` | Returns the database file's parent directory, or the repository `data/` directory for an in-memory database. |
| `ml_model_path(database_url=None)` | Uses `<database directory>/models/ml_model.pkl` for file-backed databases; falls back to `src/ml_model.pkl` for in-memory development/tests. |

With the container default `sqlite:////app/data/noc_fusion.db`, the trained model is `/app/data/models/ml_model.pkl` on the shared persistent data volume. The model path is used by both `src.train_model` and `src.services.logic` and is included in encrypted full backups when present.
