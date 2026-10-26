# Module: `src/utils/llm.py`

Implements the application's OpenAI-compatible chat-completions client, optional Ollama context lookup, sequential map/reduce helpers, in-process brief progress state, and report-generation functions. The module does not use provider SDKs. SMTP is implemented separately in `src/utils/mailer.py`.

## Context and provider selection

### `MODEL_CONTEXT_WINDOWS`

Lookup table for known cloud/local model context sizes. When an API key is configured, `get_effective_context_window()` trusts `SystemConfig.llm_context_window`. Without a key it checks the model name (including a name with a tag/version suffix), queries Ollama `/api/show` for unknown models, and falls back to the configured context size. `/api/show` results are cached per endpoint/model in `_ollama_ctx_cache`.

### `get_llm_config(session)`

Returns the first `SystemConfig` row with `is_active=True`, or `None`. The caller owns the session.

### `call_llm(messages, config, temperature=0.1, max_tokens=None)`

Accepts a `SystemConfig`-like object or dictionary, posts `{model, messages, temperature, max_tokens}` to `{llm_endpoint}/chat/completions`, and uses a 300-second request timeout. It adds a Bearer header when an API key is present. If `max_tokens` is omitted, it uses `min(effective_context // 2, 8192)`. Network, HTTP, response-shape, and other errors are returned as strings prefixed with `[WARN]`; they are not raised to callers.

### `chunk_list(data, size)` and `truncate_text(text, max_chars=300)`

`chunk_list` yields slices of the input list. `truncate_text` returns a short placeholder for falsy input and otherwise clips by character count with `...` appended when over the limit.

## Progress store

`_brief_progress_store` is a process-local dictionary protected by `_brief_progress_lock`; it is not shared between API replicas or persisted to SQLite. Each entry contains `stage`, `message`, `total_items`, `processed_items`, `percent`, and `error`.

| Function | Behavior |
|---|---|
| `init_brief_progress(generation_id)` | Creates a `starting` entry with zero progress. |
| `update_brief_progress(generation_id, *, stage=None, message=None, total_items=None, processed_items=None, percent=None)` | Updates supplied fields; if no explicit percent is supplied and counts are nonzero, computes a percentage capped at 99. |
| `get_brief_progress(generation_id)` | Returns the current stored dictionary or `None`. |
| `clear_brief_progress(generation_id)` | Removes one entry. |

HTTP polling works only while the generating API process still holds the entry. Client code also stores the generation ID in `sessionStorage` so it can resume polling after in-app navigation.

## Sequential map/reduce

### `_map_reduce_summarize(items, formatter_func, map_prompt, reduce_prompt, config, chunk_size=6, progress_callback=None, map_temperature=0.1, reduce_temperature=0.2, skip_reduce=False, skip_noise_filter=False, force_reduce=False)`

1. Returns `None` for an empty item list.
2. Computes an effective chunk size of `max(1, int(chunk_size * max(1, context_window / 128000)))`.
3. Formats and sends each chunk **sequentially** to `call_llm`; it does not create parallel LLM requests.
4. Calls `progress_callback(done, total_chunks, total_items, processed_items)` before each map request and before a reduce request when applicable.
5. Discards `[WARN]` map responses. Unless `skip_noise_filter=True`, it also discards several common “no threat”/conversational responses.
6. Returns `"AI failed to process batch."` if no map output survives.
7. Returns the list of map outputs when `skip_reduce=True`; otherwise performs one reduce call when there are multiple summaries or `force_reduce=True`. A single summary with no forced reduce is returned directly.

No recursive reduction is performed. Callers choose the chunk size, temperatures, filtering behavior, and whether to reduce.

## Article and general intelligence functions

| Function | Current behavior |
|---|---|
| `generate_bluf(article, session)` | Uses full content (first 3,000 chars) when it exceeds 200 chars; otherwise title plus summary (first 1,500 chars). Requests exactly four BLUF bullets. Returns `None` when no active LLM config exists. |
| `analyze_cascading_impacts(articles, session)` | Maps article title/short summary and reduces them into converging threat/cascade observations; chunk size 8. |
| `generate_briefing(articles, session)` | Generic two-paragraph article briefing; chunk size 10. |
| `generate_feed_overview(articles, focus_prompt, session)` | Two-paragraph focused summary from article titles/source names; chunk size 10. |
| `generate_dynamic_scoring_report(session, intel)` | Uses supplied cyber/physical articles and crimes plus up to 15 CVEs from the last 48 hours to draft an executive intelligence report. It does not calculate scores. |
| `cross_reference_cves(cves, session)` | Compares CVEs in chunks of 8 with `SystemConfig.tech_stack`, then summarizes any model-reported matches. It is an LLM assessment, not deterministic version matching. |
| `generate_executive_weather_brief(analytics, p1_count, sys_config)` | Generates a two-paragraph weather brief only if the supplied config has `is_active`; accepts analytics records/lists. |
| `generate_elastic_dsl(session, nl_query)` | Legacy callable that asks the LLM for raw Elasticsearch DSL JSON. No current REST route exposes this helper. |

### `generate_siem_triage_summary(session, flat_results)`

Uses at most 50 dictionary events, retains only `id`, `timestamp`, `index_name`, `severity`, `message`, `source_ip`, and `event_category`, truncates each string field to 2,000 characters, and caps serialized prompt data at 100,000 characters. The route additionally validates 1–50 event objects and the same 100 KB boundary. Event content is explicitly treated as untrusted prompt data.

## Brief generation pipelines

### `generate_unified_risk_brief(session, global_intel, internal_snapshot, progress_callback=None)`

- Uses the current external CIS payload, the latest internal snapshot, up to 150 cyber articles and 100 physical articles from `global_intel`, 20 crimes, 200 recent KEVs, 30 recent hazards, and 20 recent cloud records.
- Uses sequential map/reduce with base chunk size 15 for cyber and physical groups, followed by a final executive synthesis call at temperature 0.5.
- Emits `gathering`, `cyber_map`, `phys_map`, `synthesizing`, `complete`, or `error` progress stages through the callback.
- Adds an OSINT-correlation disclaimer and an AI-generated-content disclaimer when the response is available.
- Returns the disabled message when no active LLM config is present; persistence is performed by `src.services.trigger_unified_brief`, not by this function.

### `generate_global_threat_brief(session, progress_callback=None)`

- Reads up to 250 score-50-or-higher articles from the previous 24 hours, up to 300 recent CISA KEVs, up to 30 cloud outages and hazards updated in the same window, and grid-relevant crimes within one mile of headquarters for the last 24 hours.
- Applies source-defined CI and APT keyword filters, classifies US/global by configured text patterns, maps cyber items in chunks of 8, and maps physical inputs in chunks of 6. It uses `skip_reduce=True`; the report body is assembled programmatically rather than by a single LLM reduce call. A separate short LLM call may replace the template BLUF.
- Consolidates Arkansas-located hazard areas for the physical report and returns a controlled text error/empty-input message when appropriate.
- `phys_map_outputs` is accepted by `_assemble_global_brief_from_maps`; the current assembler uses structured `physical_data` for the physical section.

### `generate_internal_risk_brief(session, internal_snapshot, progress_callback=None)`

Requires a snapshot. It includes its stored hardware/software correlation arrays and up to 200 KEVs from the previous 24 hours, maps the combined payload with chunk size 15, then performs final synthesis at temperature 0.35. It returns controlled text for a disabled LLM, missing snapshot, no payload, or failed generation. `src.services.trigger_internal_brief` saves successful text.

### `generate_rolling_summary(session)`

Queries the previous 24 hours of score-50-or-higher articles (up to 15), hazards (up to 20), and cloud records (up to 15), and requests two paragraphs ending with a Grid Status sentence at temperature 0.2. `src.services.trigger_rolling_summary` owns persistence.

### `generate_aggregated_shift_summary(session, logs, timeframe_label, target_role="All", generated_by="Unknown", generated_by_role="analyst")`

Uses map/reduce with chunk size 20 and a final LLM call at temperature 0.6. Prompts treat log text as untrusted evidence and prohibit inventing causes, owners, ticket status, or unresolved work. It returns `None` if LLM is disabled and a no-logs message for an empty list. The service wrapper limits source logs to 200 and waits up to 30 seconds before producing its deterministic fallback summary.

### `build_custom_intel_report(articles, objective, session, progress_callback=None, target="")`

Uses source-supported article evidence, full content up to 2,000 chars or summary up to 800 chars per article, map chunk size 8, and `force_reduce=True`. It returns the report text; route code handles progress, assembly, result caching, and error responses.

### `generate_daily_fusion_report(session)`

Calculates the previous local calendar day in `America/Chicago`, queries articles with score at least 80 (up to 15), KEVs (up to 20), hazards (up to 15), and cloud outages (up to 15), and generates per-domain summaries plus a final report at temperature 0.2. On final LLM failure it returns a static report assembled from the domain outputs. The return value is `(start_of_yesterday, report_markdown)`; `src/workers/report_worker.py` and the manual reporting route persist it.

## Helper functions

| Helper | Behavior |
|---|---|
| `_query_ollama_context_window(endpoint, model)` | POSTs `{name:model}` to the derived `/api/show`, caches a recognized architecture context length, and returns `None` on failure. |
| `_consolidate_hazards(hazards, arkansas_only=False)` | Skips replaced alerts, groups by hazard name/severity, merges area labels, and optionally filters locations to the Arkansas county list. |
| `_dedup_phys_outputs(phys_outputs)` | Merges repeated physical map lines by a parsed `TYPE`/`HAZARD` prefix. |
| `_format_physical_posture(hazards, crimes)` | Renders structured hazard and perimeter-crime summaries with bounded text/area details. |
| `_assemble_global_brief_from_maps(map_outputs, phys_map_outputs, config, kev_items=None, physical_data=None)` | Classifies map bullets into sector/actor/CVE/US/global groups, assembles Markdown, and optionally calls the LLM for a BLUF. |

## Notes for callers

- Brief progress dictionaries are in-memory and process-local; they are not durable job records.
- LLM-generated correlations and recommendations are machine-generated assessments, not proof that an internal asset is compromised.
- `SystemConfig.is_active` and endpoint/key/model settings come from database configuration. The general LLM call timeout is five minutes; the settings connection-test endpoint uses a separate 30-second request.
- Update `docs/DATA_FLOWS.md` and `docs/API.md` when input windows, output sections, progress stages, or caller permissions change.
