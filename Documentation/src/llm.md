# Enterprise Architecture & Algorithmic Specification: `src/llm.py` *(Updated)*

## 1. Executive Overview

The `src/llm.py` module acts as the **Cognitive Processing Hub** of the Intelligence Fusion Center (IFC). In its latest architectural iteration, this module has been heavily refactored to optimize for **Local Edge Compute and GPU Memory constraints** (e.g., running open-weights models via LM Studio, Ollama, or vLLM).

To prevent massive context-window overflows, CUDA Out-Of-Memory (OOM) crashes, and severe UI latency, the engine now implements aggressive text truncation, dynamic chunk resizing, universal Map-Reduce pipelines, and highly parallelized concurrent LLM queries.

---

## 2. Core Architecture: Compute & Context Optimization

Standard LLM API calls are highly sequential and prone to context bloat. The updated engine introduces several utilities to strictly manage the data payload sent to the LLM.

### 2.1 VRAM Conservation: `truncate_text(text, max_chars)`
* **Purpose:** Aggressively trims long article summaries down to a predefined character limit (default 250, or 600 for deep reports).
* **Impact:** Prevents the LLM context window from overflowing when batching 10+ intelligence articles together, ensuring stable performance on consumer-grade or edge-deployed GPUs.

### 2.2 The Universal Pipeline: `_map_reduce_summarize(...)`
A newly abstracted, universal pipeline function designed to process massive daily datasets (like the 24-hour Daily Briefing) without triggering timeouts.
* **Map Phase:** Takes a large array of database items (e.g., 15 CVEs), chunks them into very small micro-batches (e.g., 6 items), and runs a "Map Prompt" against each chunk to extract core facts.
* **Reduce Phase:** If multiple batches were processed, it concatenates the resulting summaries and runs a final "Reduce Prompt" to synthesize a single, cohesive narrative.
* **Fault Tolerance:** Automatically checks for the `⚠️` error string returned by `call_llm` on timeouts. If a single chunk fails due to network latency, it skips it rather than crashing the entire daily report generation.

---

## 3. High-Velocity Tactical Intelligence

### 3.1 Concurrent BLUF Generation: `generate_bluf(article, session)`
The generation of the "Bottom Line Up Front" (BLUF) has been fundamentally redesigned to reduce UI latency using Python's `concurrent.futures`.

* **The Problem:** Asking an LLM to generate a complex, multi-part response in a single prompt often results in slow generation speeds and muddled formatting.
* **The Concurrent Solution:** The function breaks the BLUF into three distinct, hyper-focused prompts:
    1.  *Core Event* (What happened?)
    2.  *Cascading Impact* (What is the blast radius?)
    3.  *Strategic Posture* (What should the NOC do?)
* **Execution:** It spins up a `ThreadPoolExecutor(max_workers=3)` and fires all three prompts to the LLM endpoint **simultaneously**. 
* **Impact:** By executing in parallel, a process that previously took 6 seconds sequentially now completes in ~2 seconds, reassembling the final output mathematically and drastically improving the operator experience.

---

## 4. Strategic & Analytical Pipelines (Tuned Chunking)

All strategic reporting functions have had their chunk sizes and ingestion limits aggressively tuned downwards to accommodate the throughput of local models.

* **`cross_reference_cves`:** Reduced chunk limits from 15 to 8. Ensures the AI Security Auditor does not hallucinate false positive infrastructure matches due to context dilution.
* **`build_custom_intel_report`:** Reduced chunk limits from 3 to 2. Forces the AI to extract highly technical IOCs and TTPs from only two articles at a time, ensuring zero intelligence is lost during the Map phase.
* **`analyze_cascading_impacts` & `generate_briefing`:** Capped array limits to 10 articles and utilized the new `truncate_text` helper to safely fit within standard 4k-8k context windows.

---

## 5. Automated Scheduled Reporting

### 5.1 Shift Context: `generate_rolling_summary(session)`
* Maintains its strict 6-hour temporal scoping for the live Operational Dashboard HUD.
* **Geographic Alignment:** The prompt for the "Cloud Services" chunk was explicitly updated (`"Include the geographic regions mentioned."`). This allows the LLM to process the newly appended US/Foreign region tags injected by the upgraded `cloud_worker.py` and output highly localized cloud status summaries (e.g., *"Monitored cloud platforms are tracking Azure degradation localized to US-East"*).

### 5.2 Master SitRep: `generate_daily_fusion_report(session)`
* **Architecture:** Completely stripped of its procedural LLM calls and refactored to route entirely through the new `_map_reduce_summarize` pipeline.
* **Execution:** It formats database objects (Articles, Hazards, CVEs) into single-line bullet strings using inline `lambda` functions, passing them alongside specialized Map and Reduce prompts. This ensures the daily Master Report is consistently generated every morning at 06:00 AM, regardless of the underlying LLM's speed or memory constraints.
