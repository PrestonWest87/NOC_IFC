# Hybrid Scorer Documentation

**File:** `/home/weast/docker/NOC_IFC/src/services/logic.py`

---

## Class: `HybridScorer`

**Purpose:** Hybrid scoring engine that combines keyword-based scoring with an optional ML model (random forest classifier) to score articles on a 0-100 scale. The ML model can boost hidden threats, penalize noise, or provide synergy bonuses.

### `__init__(self, model_path="src/ml_model.pkl")`

**Purpose:** Initializes the scorer by loading the ML model (if available) and keyword weights from the database.

**Parameters:**
- `model_path` (str) -- Path to the pickled ML model file (default: "src/ml_model.pkl")

**Attributes:**
- `model_path` (str) -- Path to ML model file
- `model` (object | None) -- Loaded scikit-learn model, or None if file not found
- `keywords` (dict[str, int]) -- Mapping of lowercase keyword to weight, loaded from Keyword table

**Dependencies:** `os`, `joblib`, `SessionLocal`, `Keyword`

**Flow:**
1. Checks if model_path exists on disk; if so, loads via `joblib.load()`
2. Queries all Keyword records from database, stores as `{word.lower(): weight}` dict

---

### `score(self, text: str) -> tuple`

**Purpose:** Computes a 0-100 threat score for a given text using keyword matching and ML augmentation.

**Parameters:**
- `text` (str) -- Input text to score (typically title + summary of an article)

**Returns:** `tuple[float, list[str]]` -- `(final_score, reason_list)` where:
- `final_score` (float) -- Score from 0.0 to 100.0
- `reason_list` (list[str]) -- List of matching keywords and AI decision reasons

**Flow:**
1. **Keyword Scoring:** Lowercases text. For each keyword, checks if it exists in text. Accumulates `kw_score += weight` and appends keyword to reasons list.
2. **ML Augmentation (if model is loaded):**
   - Calls `model.predict_proba([text_lower])` to get class probabilities
   - Extracts probability of class 1 (keep/relevant) as `keep_prob`
   - **AI Boost:** If `keep_prob >= 0.75` and `final_score < 50.0`, sets `final_score = max(final_score, 65.0)` -- catches hidden threats missed by keywords
   - **AI Penalty:** If `keep_prob <= 0.25` and `final_score >= 50.0`, applies a 60% penalty -- reduces noise articles
   - **AI Synergy:** If `keep_prob > 0.50` and `final_score > 0`, adds `keep_prob * 10.0` bonus
3. Returns `min(final_score, 100.0)` and the reasons list

---

## Module-Level Functions

### `get_scorer() -> HybridScorer`

**Purpose:** Returns the global singleton HybridScorer instance, creating it if necessary.

**Returns:** `HybridScorer` -- Singleton instance stored in `_SCORER_INSTANCE`.

---

### `force_reload_scorer()`

**Purpose:** Forces a reload of the scorer (e.g., after keyword or model changes).

**Flow:** Creates a new `HybridScorer()` instance, overwriting the global singleton.

---

## Global Variable

### `_SCORER_INSTANCE` (HybridScorer | None)

Module-level singleton holder for the HybridScorer instance. Initialized as `None`; populated on first call to `get_scorer()`.
