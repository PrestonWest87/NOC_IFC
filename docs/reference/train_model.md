# Module: `src.train_model`

Offline/worker ML training pipeline used by the Settings admin action and weekly scheduler job.

## Constants

### `MODEL_PATH`

`src/ml_model.pkl`, interpreted relative to the Python process working directory. The file is a generated runtime artifact, not a checked-in source module.

## `train() -> None`

1. Opens a database session and selects article title, summary, and `human_feedback` values 1 or 2.
2. Builds a pandas frame and stops with a warning when fewer than 10 labeled rows exist.
3. Combines title and summary, lowercases text, and maps feedback `1` to noise (`0`) and `2` to important (`1`).
4. Builds a scikit-learn pipeline with English stop-word removal, unigram/bigram TF-IDF, `max_df=0.9`, `min_df=3`, `max_features=50000`, balanced logistic regression, and a fixed random state.
5. Fits the model and serializes it with `joblib.dump` to `MODEL_PATH`.

The scheduler clears and reloads the in-memory `HybridScorer` after successful training. Training does not run automatically when fewer than 10 labels are available.
