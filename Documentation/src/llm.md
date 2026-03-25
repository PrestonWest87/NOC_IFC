# Enterprise Architecture & Algorithmic Specification: `src/llm.py`

## 1. Executive Overview

The `src/llm.py` module acts as the Cognitive Processing Hub of the Intelligence Fusion Center (IFC). In its latest architectural iteration, this module has been heavily refactored to optimize for Local Edge Compute and GPU Memory constraints, such as running open-weights models via LM Studio, Ollama, or vLLM.

To prevent massive context-window overflows, CUDA Out-Of-Memory crashes, and severe UI latency, the engine implements aggressive text truncation, dynamic chunk resizing, universal Map-Reduce pipelines, and extended timeout tolerances for local inference speeds.

---

## 2. Core Architecture: Compute & Context Optimization

Standard LLM API calls are highly sequential and prone to context bloat. The updated engine introduces several utilities to strictly manage the data payload sent to the LLM and handle the latency inherent to local hosting.

### 2.1 Universal API Gateway: `call_llm(messages, config, temperature)`
* **Extended Latency Tolerance:** The `requests.post` timeout has been explicitly increased to 120 seconds to accommodate the slower generation speeds of locally hosted LLMs without crashing the application thread.
* **Built-In Error Surfacing:** Catches `Timeout` and `ConnectionError` exceptions, returning formatted network error strings directly to the UI rather than throwing backend Python exceptions.

### 2.2 Context Management Utilities
* **`chunk_list(data, size)`:** A helper generator that chunks lists to prevent LLM context-window overflows.
* **`truncate_text(text, max_chars)`:** Aggressively trims long article summaries down to a predefined character limit, which defaults to 300 characters. This prevents the LLM context window from overflowing when batching multiple intelligence articles together.

### 2.3 The Universal Pipeline: `_map_reduce_summarize(...)`
A newly abstracted, universal Map-Reduce pipeline designed to safely process large arrays of database objects without triggering context limits or timeouts.
* **Tier 1 (Map Phase):** Takes a large array of database items, chunks them into small micro-batches (defaulting to 6 items), and runs a "Map Prompt" with a strict temperature of 0.1 against each chunk to extract core facts.
* **Tier 2 (Reduce Phase):** If multiple batches were processed, it concatenates the resulting summaries and runs a final "Reduce Prompt" with a slightly higher variance (temperature 0.2) to synthesize a single, cohesive narrative.
* **Fault Tolerance:** Automatically ignores chunks that return network error strings during the Map phase, allowing the Reduce phase to continue with the successful batches rather than failing the entire pipeline.

---

## 3. High-Velocity Tactical Intelligence

### 3.1 Unified BLUF Generation: `generate_bluf(article, session)`
The generation of the "Bottom Line Up Front" (BLUF) prioritizes self-attention and contextual accuracy using a single unified prompt.

* **Architecture:** Uses a single context-aware call to preserve self-attention, rather than splitting prompts concurrently.
* **Context Preservation:** Passes a generously truncated 1500-character article summary to the LLM.
* **Strict Output Structuring:** Forces the LLM to output exactly four concise bullet points: Core Event, Impact Radius, Technical Details, and Actionable Posture. It executes with a strict temperature of 0.1 to avoid conversational filler.

---

## 4. Strategic & Analytical Pipelines (Tuned Chunking)

All strategic reporting functions have had their chunk sizes and ingestion limits aggressively tuned to accommodate the throughput of local models and prevent hallucination due to context dilution.

* **`cross_reference_cves`:** Chunks Known Exploited Vulnerabilities (KEVs) into batches of 8. It executes a strict scan (temperature 0.0) against the internal tech stack during the Map phase, and then reduces any matches into a Master Alert.
* **`build_custom_intel_report`:** Utilizes a chunk limit of 3 and sets text truncation to 600 characters. This ensures exhaustive extraction of technical details, IOCs, and targeted systems during the Map phase without losing intelligence.
* **`analyze_cascading_impacts` & `generate_briefing`:** Utilizes the universal `_map_reduce_summarize` pipeline with chunk sizes of 8 and 10, respectively, securely fitting within standard context windows. `analyze_cascading_impacts` aggressively truncates input summaries to 200 characters.

---

## 5. Automated Scheduled Reporting

### 5.1 Shift Context: `generate_rolling_summary(session)`
* **Temporal Scoping:** Generates a cohesive executive narrative scoped strictly to the last 6 hours.
* **Native String Compression:** Because the 6-hour volume is relatively small, this function bypasses the Map-Reduce pipeline. It natively gathers up to 10 top-scoring cyber articles, 10 hazards, and 10 cloud outages, appending them into a single context string. This is passed to a Master Editor prompt (temperature 0.2) to weave a fast-paced 2-paragraph executive summary.

### 5.2 Master SitRep: `generate_daily_fusion_report(session)`
* **Architecture:** Refactored to route entirely through the `_map_reduce_summarize` pipeline across four distinct infrastructure domains.
* **Execution:** Iterates over the previous day's telemetry. Each domain executes its own Map-Reduce pipeline with tuned chunk sizes: Cyber (chunk 6), Vulnerabilities (chunk 8), Infrastructure Hazards (chunk 6), and Cloud Services (chunk 5).
* **Master Editor & Fallback:** The four resulting domain summaries are concatenated and sent to a final Senior Director prompt for narrative smoothing and Markdown formatting. If the Master Editor fails or times out, the function falls back to a hardcoded string concatenation, guaranteeing the daily report is consistently generated regardless of LLM stability.
