# Enterprise Architecture & Functional Specification: `src/llm.py`

## 1. Executive Overview

The `src/llm.py` module acts as the **Cognitive Processing Hub** of the Intelligence Fusion Center (IFC). It provides a universal, model-agnostic abstraction layer to interface with OpenAI-compatible LLM endpoints (which can include local instances like LM Studio, Ollama, or vLLM). 

This module does not merely pass text to an AI; it relies on complex prompt engineering, context-window management, and multi-stage Map-Reduce pipelines to synthesize massive amounts of raw, disparate telemetry into highly structured, boardroom-ready Markdown intelligence reports.

---

## 2. Core LLM Connectivity & Fault Tolerance

### `call_llm(messages, config, temperature=0.1)`
This is the foundational communication function used by all other methods in the file. It is designed for high reliability, particularly when querying slower, locally-hosted LLMs.

**Key Architecture Constraints:**
* **Agnostic Endpointing:** By dynamically constructing the URL (`config.llm_endpoint.rstrip('/') + "/chat/completions"`), the system seamlessly switches between OpenAI, Groq, or local server environments without code changes.
* **Aggressive Timeouts:** Sets a `timeout=120` seconds. This is significantly longer than standard web requests, intentionally designed to accommodate the slower token generation speeds of local, on-premise hardware.
* **Native Error Surfacing:** Instead of crashing the Python thread on a timeout or `ConnectionError`, it catches the exception and returns a pre-formatted Markdown error string (e.g., `⚠️ **AI NETWORK ERROR:**...`). This allows the Streamlit UI to render the error gracefully directly inside the application dashboards without throwing stack traces to the user.

---

## 3. Context Window Management

### `chunk_list(data, size)`
A critical utility generator function. LLMs possess strict context windows (the maximum amount of text they can process at once). If the NOC passes 100 intelligence articles to the LLM simultaneously, it will either crash the API or cause severe hallucination (the "lost in the middle" phenomenon). This function divides large datasets into smaller, digestible arrays (e.g., chunks of 15) to enable Map-Reduce pipelines.

---

## 4. Tactical Intelligence Generation (Single/Small Batch)

These functions are executed on individual articles or small datasets for immediate triage.

### `generate_bluf(article, session)`
* **Purpose:** Generates a Bottom Line Up Front (BLUF) for a single intelligence article.
* **Prompt Engineering:** Forces a rigid, clinical Markdown structure extracting four specific entities: `Incident`, `Threat Actor / TTPs`, `Target Vector`, and `Intelligence Posture`. It explicitly instructs the AI: *"Do not add conversational filler."*

### `generate_briefing(articles, session)`
* **Purpose:** Reads the top 20 raw articles and synthesizes them into a fluid, authoritative 2-paragraph narrative suitable for an executive shift brief.

### `cross_reference_cves(cves, session)`
* **Purpose:** The core function of the "Security Auditor" UI. Compares incoming CISA Known Exploited Vulnerabilities against the organization's internal `tech_stack`.
* **Execution:** Iterates over the CVEs using `chunk_list(cves, 15)`. For each chunk, it instructs the AI to evaluate if the CVE vendor/product intersects with the tech stack. If it does, it outputs a critical alert starting with `"MATCH:"`. It aggregates all matches across all chunks and returns them to the user.

---

## 5. Strategic & Master Reporting (Map-Reduce Pipelines)

For large-scale intelligence synthesis, the module employs a **Map-Reduce** architectural pattern. It first asks the AI to extract facts from small batches of data (Map), and then feeds those aggregated facts back into the AI to write the final narrative (Reduce).

### `build_custom_intel_report(articles, objective, session)`
* **The Map Phase:** Chunks the selected articles into groups of 3 (preserving deep context). Instructs the AI to act as an "Intelligence Collector" and extract raw bullet points of TTPs, IOCs (IPs, hashes), and targeted systems aligned with the user's specific `objective`.
* **The Reduce Phase:** Concatenates all the raw intelligence nuggets from Phase 1 and passes them back to the AI. The prompt forces the output into an exhaustive, 4-section Markdown report: Executive Summary, Threat Actors & TTPs, IOCs, and Defensive Posture.

### `generate_feed_overview(articles, focus_prompt, session)`
* **The Map Phase:** Chunks articles by 20. Extracts 2-3 core threat themes as bullet points.
* **The Reduce Phase:** Compiles the themes and synthesizes a 2-paragraph macro-level situational overview.

---

## 6. Automated Scheduled Reporting

These functions are designed to run autonomously without human prompt input, typically triggered by the daily scheduler or background UI loops.

### `generate_rolling_summary(session)`
* **Purpose:** Populates the "AI Shift Briefing" on the Operational Dashboard.
* **Temporal Scoping:** Strictly limits its database queries to data updated in the **last 6 hours**.
* **Segmented Prompting:** Instead of one massive prompt, it makes three independent, highly constrained LLM calls for Cyber, Physical Hazards, and Cloud Outages. It explicitly forces the AI to output exactly one sentence per section starting with a predefined phrase (e.g., *"Active cyber threats include..."*), ensuring absolute uniformity in the UI.

### `generate_daily_fusion_report(session)`
* **Purpose:** The Master SitRep. Generates a comprehensive summary of the previous operational day.
* **Timezone Logic:** Utilizes `ZoneInfo("America/Chicago")` to calculate `start_of_yesterday`. It then converts this back to UTC to accurately query the database timestamps.
* **Sectional Generation:** Queries the database for high-scoring Cyber Articles ($>80$), CVEs, Physical Hazards, and Cloud Outages from the last 24 hours. It passes each dataset to the LLM individually with tailored prompts (e.g., instructing the AI to act as a "Vulnerability Analyst" for the KEV section) and appends the markdown responses into a single master document.
