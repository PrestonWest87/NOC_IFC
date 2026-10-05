# Module: `src.train_model`

Offline/worker ML training pipeline used by the Settings admin action and weekly scheduler job.

## Constants

### `MODEL_PATH`

`MODEL_PATH` is initialized from `src.core.paths.ml_model_path()` when the module is imported. With the production database URL (`sqlite:////app/data/noc_fusion.db`), the shared artifact path is `/app/data/models/ml_model.pkl`; for an in-memory SQLite database it falls back to the repository's `src/ml_model.pkl` path for development/tests. It is a generated runtime artifact, not checked-in source.

## `train() -> None`

1. Opens a database session and selects article title, summary, and `human_feedback` values 1 or 2.
2. Loads the selected records as tuples and stops with a warning when fewer than 10 labeled rows exist.
3. Combines title and summary into lowercase Python strings and maps feedback `1` (dismiss/noise) to class `0` and feedback `2` (keep/important) to class `1`.
4. Builds a scikit-learn pipeline with English stop-word removal, unigram/bigram TF-IDF, `max_df=0.9`, `min_df=3`, `max_features=50000`, and balanced logistic regression (`max_iter=1000`). No fixed `random_state` is set.
5. Fits the model, writes it to a temporary file in the target directory, and atomically replaces `MODEL_PATH` with the completed artifact.

The scheduler clears and reloads the in-memory `HybridScorer` after successful training. Training does not run automatically when fewer than 10 labels are available.
