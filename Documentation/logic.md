# Enterprise Architecture & Algorithmic Specification: `src/logic.py`

## 1. Executive Overview

The `src/logic.py` module houses the **Hybrid Threat Scoring Engine** for the Intelligence Fusion Center (IFC). This module is responsible for analyzing raw, unstructured text (such as intelligence articles or threat summaries) and assigning a quantitative threat score. 

To overcome the fragility of purely rule-based systems and the unpredictability of purely statistical models, this engine implements a **Hybrid Fusion Architecture**. It simultaneously evaluates text using a deterministic Keyword Heuristic engine and a probabilistic Machine Learning (ML) model, taking the maximum score between the two. This ensures high-fidelity threat detection where the AI acts as a safety net for novel threats, while strict keywords guarantee that known priorities are never missed.

---

## 2. Engine Initialization: `HybridScorer`

The `HybridScorer` class manages the lifecycle and execution of the scoring algorithms. It is designed to be instantiated via the `get_scorer()` factory function.

### `__init__(self, model_path="ml_model.pkl")`
Upon initialization, the engine boots two distinct analytical brains:
1.  **The Statistical Brain (ML Model):** It checks the file system for a compiled binary model (`ml_model.pkl`), typically a Scikit-Learn Random Forest or Logistic Regression pipeline built by `train_model.py`. If found, it loads it into memory via `joblib`.
2.  **The Deterministic Brain (Keyword Rules):** It opens a transient database transaction (`SessionLocal()`) and fetches the entire active taxonomy from the `Keyword` table. It loads this into a highly optimized, localized memory dictionary (`self.keywords = {word: weight}`), allowing for rapid, in-memory string matching without hammering the database during high-volume ingestion.

---

## 3. The Tri-Phasic Scoring Algorithm

The `score(text: str)` method executes the core evaluation pipeline. It returns a tuple containing the `final_score` (float) and a list of `reasons` (strings) explaining the score's derivation for transparency.

### Phase 1: Rule-Based Scoring (Deterministic Heuristics)
* **Execution:** The engine converts the incoming text to lowercase and iterates through the pre-loaded `self.keywords` dictionary.
* **Calculation:** If a keyword exists anywhere within the text, its associated `weight` (integer) is added to the `kw_score` accumulator. 
* **Audit Trail:** The matched keyword is appended to the `reasons` list, providing human analysts with exact traceability of why an article was flagged.

### Phase 2: Machine Learning Scoring (Probabilistic Inference)
* **Execution:** If the ML model is successfully loaded, it passes the raw text into the `predict_proba()` function.
* **Calculation:** * The engine extracts the probability array. It is specifically looking for the confidence percentage that the text belongs to Class `2` (the application's internal designation for "Keep / High Threat").
    * It converts this floating-point probability into a percentage (e.g., 0.85 becomes `85.0`).
    * *Failsafe:* If the model has only been trained on a single class (e.g., a brand new system with only positive feedback), it forcefully sets the score to `100.0` if the class is `2`, or `0.0` otherwise, preventing array index out-of-bounds exceptions.
* **AI Safety Net Flagging:** If the ML model returns a confidence score $\ge 45\%$, it injects a specific string into the `reasons` array (e.g., `"AI Safety Net (65%)"`). This alerts the operator that the AI detected a threat pattern even if no specific keywords were triggered.

### Phase 3: Hybrid Fusion (Maximal Output)
* **Calculation:** `final_score = max(float(kw_score), ml_score)`
* **Design Philosophy:** By using a `max()` function instead of an average or sum, the engine enforces a **"No Drop" policy**. 
    * If an analyst defines a strict keyword ("Log4J" = 100 points), the system will score it 100 even if the AI doesn't recognize it. 
    * Conversely, if an entirely novel zero-day attack occurs containing no known keywords (`kw_score` = 0), but the AI recognizes the semantic structure of a cyberattack (`ml_score` = 82), the system will output 82. 

---

## 4. System Integration Context

Within the broader Intelligence Fusion Center ecosystem, this module is primarily leveraged by:
* **`telemetry_worker.py` (RSS Ingestion):** As new intelligence articles are pulled from RSS feeds, the text is passed through `HybridScorer.score()`. The resulting `final_score` populates the `Article.score` database column, and the `reasons` populate the `Article.keywords_found` JSON column. This ultimately determines if an article breaches the threshold (default $\ge$ 50) to appear on the Live Threat Triage dashboard.
