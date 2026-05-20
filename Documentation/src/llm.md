# Enterprise Architecture & Functional Specification: `src/llm.py`

## 1. Executive Overview

The `src/llm.py` module acts as the **Cognitive Processing Hub** of the Intelligence Fusion Center (IFC). It provides LLM integration for unified brief generation, daily reports, executive summaries, SIEM triage, and shift log synthesis.

The engine implements aggressive text truncation, dynamic chunk resizing, universal Map-Reduce pipelines, and extended timeout tolerances for local inference speeds. Supports OpenAI-compatible APIs and local LLM deployments (Ollama, LM Studio).

---

## 2. Core Architecture: Map-Reduce Engine

### `call_llm(messages, config, temperature)`
Universal API caller with:
- **120-second timeout** for local LLM inference speeds
- **Error surfacing** returning formatted network error strings (Timeout, ConnectionError)

### `chunk_list(data, size)`
Generator that chunks lists to prevent LLM context-window overflow.

### `truncate_text(text, max_chars=300)`
Aggressively trims text to save local GPU VRAM/context window during Map phases.

### `_map_reduce_summarize(items, formatter_func, map_prompt, reduce_prompt, config, chunk_size)`
Universal Map-Reduce pipeline:
- **Tier 1 (Map):** Chunks items, runs strict fact extraction (temperature 0.1)
- **Tier 2 (Reduce):** Concatenates batch summaries, runs narrative synthesis (temperature 0.2)
- **Fault Tolerance:** Ignores chunks returning network errors

---

## 3. Tactical Intelligence Functions

### `generate_bluf(article, session)`
Generates a 4-point Bottom Line Up Front using a single unified prompt to preserve self-attention: Core Event, Impact Radius, Technical Details, Actionable Posture.

### `generate_rolling_summary(session)`
Scoped to the last 6 hours. Natively gathers top-scoring cyber articles, hazards, and cloud outages from separate database queries. Single-pass Master Editor prompt generates a 2-paragraph executive summary with a bolded "Grid Status" assessment.

### `analyze_cascading_impacts(articles, session)`
Multi-Tier synthesis identifying converging threats between disparate intelligence feeds (e.g., severe weather overlapping with cyber vulnerabilities).

---

## 4. Executive Briefing Functions

### `generate_unified_risk_brief(session, global_intel, internal_snapshot)`
Generates an exhaustive, boardroom-ready Unified Risk Brief in a single fast pass using pre-calculated matrices:
1. Extracts pre-calculated `hw_data_json` and `sw_data_json` from `InternalRiskSnapshot`
2. Formats top 10 hardware/software exposures with OSINT match counts
3. Compiles macro threat posture with global and internal risk levels
4. Single-pass LLM execution generating 5-section Markdown brief (Executive Summary, Internal Attack Surface, Global Threat Landscape, Physical & Perimeter Security, Strategic Recommendations)

### `generate_dynamic_scoring_report(session, intel)`
Generates an expansive Executive Intelligence Brief without calculating or justifying scores. Uses Map-Reduce for cyber intelligence, then a Master Editor to weave a cohesive narrative.

### `generate_executive_weather_brief(analytics, p1_count, sys_config)`
2-paragraph Executive Weather Briefing focusing on district-level impacts and critical infrastructure exposures.

---

## 5. CVE & SIEM Integration

### `cross_reference_cves(cves, session)`
Chunks KEVs in batches of 8, cross-references against internal `tech_stack`, and reduces matches into a unified Security Alert. Returns "CLEAR" if no matches found.

### `generate_siem_triage_summary(session, flat_results)`
Reviews extracted SIEM telemetry (capped at 30 results) and produces a boardroom-ready Executive Summary with correlated IOCs.

### `generate_elastic_dsl(session, nl_query)`
Translates natural language to valid Elasticsearch JSON query DSL. Strips markdown formatting from LLM responses.

---

## 6. Reporting & Shift Log Functions

### `generate_daily_fusion_report(session)`
Four-domain Map-Reduce pipeline spanning Cyber, Vulnerabilities, Infrastructure, and Cloud. Each domain runs its own Map-Reduce with tuned chunk sizes. A Master Editor prompt weaves the four summaries into a single cohesive Daily Fusion Report with Markdown formatting. Falls back to hardcoded concatenation if the Master Editor fails.

### `generate_aggregated_shift_summary(session, logs, timeframe_label, target_role)`
Two-tier Map-Reduce pipeline for shift log volumes. First pass digests logs into an incident digest (chunk size 20), then a Master Editor produces a structured 3-section executive summary scoped to the requested role and timeframe.

### `generate_briefing(articles, session)`
Multi-Tier synthesis compressing a large article feed into a tight 2-paragraph situational briefing.

### `generate_feed_overview(articles, focus_prompt, session)`
Macro-level overview using Map-Reduce with a configurable focus prompt.

### `build_custom_intel_report(articles, objective, session)`
Exhaustive, multi-article technical intelligence report using chunk size 3 and 600-character truncation for deep extraction.

---

## 7. Complete Function Reference

### Configuration Functions

| Function | Signature | Purpose |
|----------|-----------|---------|
| `get_llm_config` | `(session) -> SystemConfig` | Get LLM configuration from database |

### Core LLM Functions

| Function | Signature | Purpose |
|----------|-----------|---------|
| `call_llm` | `(messages, config, temperature) -> str` | Universal API caller with timeout handling |
| `chunk_list` | `(data, size) -> generator` | Chunk list for context management |
| `truncate_text` | `(text, max_chars) -> str` | Truncate text to limit |
| `_map_reduce_summarize` | `(items, formatter_func, map_prompt, reduce_prompt, config, chunk_size) -> str` | Universal Map-Reduce pipeline |

### BLUF & Analysis Functions

| Function | Signature | Purpose |
|----------|-----------|---------|
| `generate_bluf` | `(article, session) -> str` | Bottom Line Up Front for article |
| `analyze_cascading_impacts` | `(articles, session) -> str` | Multi-tier impact analysis |
| `generate_unified_risk_brief` | `(session, global_intel, internal_snapshot) -> str` | Unified risk brief |
| `generate_aggregated_shift_summary` | `(session, logs, timeframe_label, target_role) -> str` | Shift log summary |

### Reporting Functions

| Function | Signature | Purpose |
|----------|-----------|---------|
| `generate_briefing` | `(articles, session) -> str` | Multi-article briefing |
| `cross_reference_cves` | `(cves, session) -> str` | CVE cross-reference |
| `generate_feed_overview` | `(articles, focus_prompt, session) -> str` | Feed overview |
| `generate_executive_weather_brief` | `(analytics, p1_count, sys_config) -> str` | Weather brief |
| `build_custom_intel_report` | `(articles, objective, session) -> str` | Custom report |
| `generate_rolling_summary` | `(session) -> str` | 6-hour rolling summary |
| `generate_dynamic_scoring_report` | `(session, intel) -> str` | Boardroom-ready report |

### SIEM Functions

| Function | Signature | Purpose |
|----------|-----------|---------|
| `generate_siem_triage_summary` | `(session, flat_results) -> str` | SIEM alert summary |
| `generate_elastic_dsl` | `(session, nl_query) -> str` | Natural language to DSL |

### Daily Functions

| Function | Signature | Purpose |
|----------|-----------|---------|
| `generate_daily_fusion_report` | `(session) -> tuple` | Daily fusion report with Map-Reduce |

---

## 8. API Citations

| API / Service | Purpose | Documentation |
|---------------|---------|---------------|
| Requests | HTTP client | https://docs.python-requests.org/ |
| Ollama | Local LLM | https://github.com/ollama/ollama |
| LM Studio | Local LLM | https://lmstudio.ai/ |
| OpenAI | Cloud LLM | https://platform.openai.com/ |
