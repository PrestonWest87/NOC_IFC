# Keyword Scorer Documentation

**File:** `src/services/logic.py`

---

## Class: `KeywordScorer`

**Purpose:** Scores article text from the configured keyword weights on a 0-100 scale.

### `__init__(self)`

**Purpose:** Loads a snapshot of configured keyword weights from the database.

**Attributes:**
- `keywords` (dict[str, int]) -- Mapping of lowercase keyword to weight, loaded from Keyword table

**Dependencies:** `SessionLocal`, `Keyword`

**Flow:**
1. Queries all Keyword records from the database.
2. Stores `{word.lower(): weight}` for process-local scoring.

---

### `score(self, text: str) -> tuple`

**Purpose:** Computes a 0-100 threat score for a given text using keyword matching.

**Parameters:**
- `text` (str) -- Input text to score (typically title + summary of an article)

**Returns:** `tuple[float, list[str]]` -- `(score, reason_list)` where:
- `score` (float) -- Sum of matched keyword weights, capped at 100.0
- `reason_list` (list[str]) -- Matching keywords

**Flow:**
1. Lowercases the text.
2. For each configured keyword contained in the text, adds its weight and appends the keyword to the reasons list.
3. Returns the score capped at 100 and the reasons list.

---

## Module-Level Functions

### `get_scorer() -> KeywordScorer`

**Purpose:** Returns the global singleton KeywordScorer instance, creating it if necessary.

**Returns:** `KeywordScorer` -- Singleton instance stored in `_SCORER_INSTANCE`.

---

### `force_reload_scorer()`

**Purpose:** Forces a reload of the scorer after keyword changes or database restore.

**Flow:** Creates a new `KeywordScorer()` instance, overwriting the global singleton.

---

## Global Variable

### `_SCORER_INSTANCE` (KeywordScorer | None)

Module-level singleton holder for the KeywordScorer instance. Initialized as `None`; populated on first call to `get_scorer()`.
