# Module: `src/train_model.py`

## Overview

ML model training module for the NOC Intelligence Fusion Center. Uses scikit-learn to train a TfidfVectorizer + LogisticRegression pipeline on human-feedback-labeled articles. The model learns to distinguish between "Keep" (important) and "Dismiss" (noise) articles and is saved to disk for runtime scoring.

---

## Function: `train()`

**Purpose:** Trains a scikit-learn NLP pipeline on labeled article data and saves the model to disk.

**Parameters:** None

**Returns:** None (implicitly `None`; returns early if insufficient data)

**Raises:** None (exceptions propagate)

**Flow:**
1. Opens a database session and queries articles where `human_feedback` is 1 (Dismiss) or 2 (Keep).
2. Loads the query result into a pandas DataFrame.
3. If fewer than 10 labeled articles exist, logs a warning and returns early.
4. Preprocessing:
   - Combines `title` and `summary` into a `text` column (lowercased).
   - Maps labels: 1 (Dismiss) -> 0 (Noise), 2 (Keep) -> 1 (Important).
5. Builds a scikit-learn pipeline:
   - `TfidfVectorizer`: stop_words='english', ngram_range=(1,2), max_df=0.9, min_df=3, max_features=50000.
   - `LogisticRegression`: class_weight='balanced', max_iter=1000.
6. Fits the pipeline to the training data `X` (text) and `y` (labels).
7. Serializes the trained model to `src/ml_model.pkl` via `joblib.dump()`.
8. Logs success.

**Dependencies:**
| Module | Usage |
|--------|-------|
| `pandas` | DataFrame for training data |
| `sklearn.feature_extraction.text.TfidfVectorizer` | Text vectorization with n-grams |
| `sklearn.linear_model.LogisticRegression` | Classification model |
| `sklearn.pipeline.make_pipeline` | Pipeline composition |
| `joblib` | Model serialization |
| `src.database.SessionLocal` | Database session |
| `src.database.Article` | Article ORM model |

**Raises:** Exceptions propagate if database query fails or training errors occur.
