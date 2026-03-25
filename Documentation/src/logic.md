# Enterprise Architecture & Algorithmic Specification: `src/logic.py`

## 1. Executive Overview

The `src/logic.py` module houses the Hybrid Threat Scoring Engine for the Intelligence Fusion Center (IFC). This module is responsible for analyzing raw, unstructured text and assigning a quantitative threat score. 

In its latest architectural iteration, the engine has moved away from a simple "maximum score" approach and now implements a sophisticated Dynamic Override Matrix. It simultaneously evaluates text using a deterministic keyword heuristic engine and a probabilistic machine learning model, allowing the AI to actively penalize noise or boost hidden threats based on confidence thresholds.

---

## 2. Engine Initialization: `HybridScorer`

The `HybridScorer` class manages the lifecycle and execution of the scoring algorithms. It is designed to be instantiated via the `get_scorer()` factory function.

### `__init__(self, model_path="src/ml_model.pkl")`
Upon initialization, the engine boots two distinct analytical systems:
1.  **The Statistical Brain (ML Model):** It explicitly checks the file system for a compiled binary model (`src/ml_model.pkl`). If the file exists, it loads the model into memory via `joblib`.
2.  **The Deterministic Brain (Keyword Rules):** It opens a transient database transaction (`SessionLocal()`) and fetches the entire active taxonomy from the `Keyword` table. It loads this into a highly optimized, localized memory dictionary (`self.keywords`), allowing for rapid, in-memory string matching without hammering the database during high-volume ingestion.

---

## 3. The Tri-Phasic Scoring Algorithm

The `score(text: str)` method executes the core evaluation pipeline. It returns a tuple containing the `final_score` (capped at a maximum of 100.0) and a list of `reasons` explaining the score's derivation for transparency.

### Phase 1: Base Rule-Based Scoring (Keywords)
* **Execution:** The engine converts the incoming text to lowercase to ensure case-insensitive matching.
* **Calculation:** It iterates through the pre-loaded `self.keywords` dictionary. If a keyword exists anywhere within the text, its associated weight is added to the `kw_score` accumulator. 
* **Audit Trail:** The matched keyword is appended to the `reasons` list, providing human analysts with exact traceability of why an article was flagged. The `final_score` is initially set to this keyword score.

### Phase 2: Machine Learning Overlay
* **Execution:** If the ML model is successfully loaded, it passes the raw lowercase text into the `predict_proba()` function.
* **Calculation:** The engine extracts the probability array and specifically targets the confidence percentage that the text belongs to Class 1 ("Keep / Important").
* **Failsafe:** If the model has only been trained on a single class, it safely extracts the probability to avoid array index out-of-bounds exceptions, forcefully setting the probability to 1.0 or 0.0 based on the available class.

### Phase 3: Dynamic Override Matrix
Rather than relying on a simplistic maximum value function, the engine applies contextual logic based on the interaction between the keyword score and the AI confidence.

* **Scenario A: AI Spidey-Sense (Safety Net):**
    * **Trigger:** The keywords missed the threat (`final_score` is less than 50.0), but the AI is highly confident (`keep_prob` is greater than or equal to 0.75) that it is a threat.
    * **Action:** Instantly bubbles the score up to a minimum of 65.0 to ensure dashboard visibility.
    * **Reason Injection:** Appends an "AI Boost: Hidden Threat Detected" message containing the specific confidence percentage.
* **Scenario B: AI Spam Filter (Noise Reduction):**
    * **Trigger:** The keyword heuristics were triggered (`final_score` is greater than or equal to 50.0), but the AI recognizes the context is harmless (`keep_prob` is less than or equal to 0.25).
    * **Action:** Strips 60% of the score away as a penalty.
    * **Reason Injection:** Appends an "AI Penalty: Context identified as Noise" message.
* **Scenario C: Minor Synergy Adjustments:**
    * **Trigger:** The AI is mildly confident (`keep_prob` is greater than 0.50) and the text already possesses a baseline keyword score (`final_score` is greater than 0).
    * **Action:** Provides a slight algorithmic bump by adding the `keep_prob` multiplied by 10.0 to the `final_score`.
    * **Reason Injection:** Appends an "AI Synergy Bonus" message indicating the added point value.

---

## 4. System Integration Context

Within the broader Intelligence Fusion Center ecosystem, this module is directly leveraged by background ingestion pipelines. As new intelligence is pulled, the text is passed through `HybridScorer.score()`. The resulting `final_score` and `reasons` populate database records, dictating whether incoming data breaches the threshold to alert operators.
