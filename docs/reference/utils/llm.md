# Module: `src/utils/llm.py`

LLM interaction utilities for the NOC Intelligence Fusion Center. Provides a comprehensive set of AI-powered intelligence, briefing, and analysis functions powered by a configurable LLM backend (OpenAI-compatible API).

---

## Functions

---

### `get_llm_config`

**Purpose:** Retrieve the active LLM system configuration from the database.

**Signature:**
```python
def get_llm_config(session) -> SystemConfig | None
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `session` | `sqlalchemy.orm.Session` | Active database session |

**Returns:**

| Type | Description |
|------|-------------|
| `SystemConfig \| None` | The first active `SystemConfig` row, or `None` if none exists |

**Raises:** None

**Flow:**
1. Queries `SystemConfig` table filtered by `is_active=True`
2. Logs the found config details (endpoint, model name)
3. Returns the config object or `None`

**Dependencies:** `src.models.schema.SystemConfig`

---

### `call_llm`

**Purpose:** Send a message chain to the configured LLM backend and return the generated text.

**Signature:**
```python
def call_llm(messages: list, config: SystemConfig, temperature: float = 0.1) -> str
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `messages` | `list[dict]` | List of message dicts with `role` and `content` keys |
| `config` | `SystemConfig` | Active system configuration containing endpoint, model, and API key |
| `temperature` | `float` | LLM temperature parameter; defaults to `0.1` |

**Returns:**

| Type | Description |
|------|-------------|
| `str` | LLM response text on success; user-facing error message prefixed with `[WARN]` on failure |

**Raises:** None (all exceptions are caught and returned as error strings)

**Flow:**
1. Builds headers with optional `Authorization: Bearer` from `config.llm_api_key`
2. Constructs payload with model, messages, and temperature
3. POSTs to `{config.llm_endpoint}/chat/completions` with a 120-second timeout
4. On success: extracts `choices[0].message.content` from JSON response
5. On `requests.exceptions.Timeout`: returns timeout error message
6. On `requests.exceptions.ConnectionError`: returns connection refused error message
7. On any other `Exception`: returns unexpected error message with details

**Dependencies:** `requests`, `json`, `src.models.schema.SystemConfig`

---

### `chunk_list`

**Purpose:** Split a list into fixed-size chunks for batch processing.

**Signature:**
```python
def chunk_list(data: list, size: int) -> Generator[list, None, None]
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | `list` | The list to split into chunks |
| `size` | `int` | Maximum number of elements per chunk |

**Returns:**

| Type | Description |
|------|-------------|
| `Generator[list]` | Yields successive sub-lists of at most `size` elements |

**Raises:** None

**Flow:**
1. Iterates over `range(0, len(data), size)`
2. Yields `data[i:i + size]` for each step

**Dependencies:** None

---

### `truncate_text`

**Purpose:** Truncate text to a maximum character count with an ellipsis.

**Signature:**
```python
def truncate_text(text: str | None, max_chars: int = 300) -> str
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `text` | `str \| None` | Input text to truncate |
| `max_chars` | `int` | Maximum allowed characters; defaults to `300` |

**Returns:**

| Type | Description |
|------|-------------|
| `str` | The original text if within limit; truncated text with `...` suffix; or `"No details provided."` if input is `None`/falsy |

**Raises:** None

**Flow:**
1. If `text` is falsy, returns `"No details provided."`
2. If `len(text) <= max_chars`, returns text unchanged
3. Otherwise returns `text[:max_chars] + "..."`

**Dependencies:** None

---

### `_map_reduce_summarize`

**Purpose:** Internal map-reduce summarization engine. Chunks items, summarizes each chunk via LLM (map phase), then merges batch summaries into a final output (reduce phase).

**Signature:**
```python
def _map_reduce_summarize(
    items: list,
    formatter_func: callable,
    map_prompt: str,
    reduce_prompt: str,
    config: SystemConfig,
    chunk_size: int = 6
) -> str | None
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `items` | `list` | List of items to summarize |
| `formatter_func` | `callable` | Function that converts a single item to a string for the LLM context |
| `map_prompt` | `str` | System prompt for the map (per-chunk) LLM call |
| `reduce_prompt` | `str` | System prompt for the reduce (merge) LLM call |
| `config` | `SystemConfig` | Active system configuration for LLM calls |
| `chunk_size` | `int` | Number of items per chunk; defaults to `6` |

**Returns:**

| Type | Description |
|------|-------------|
| `str \| None` | Final merged summary, or `None` if `items` is empty |

**Raises:** None

**Flow:**
1. Returns `None` immediately if `items` is empty
2. Splits items into chunks via `chunk_list`
3. For each chunk: formats items using `formatter_func`, calls LLM with `map_prompt` as system message
4. Collects successful responses (those not containing `[WARN]`)
5. If no batch summaries collected, returns `"AI failed to process batch."`
6. If only one batch summary, returns it directly
7. If multiple batch summaries, joins them and calls LLM with `reduce_prompt` at temperature `0.2`
8. Returns the final merged result

**Dependencies:** `chunk_list`, `call_llm`

---

### `generate_bluf`

**Purpose:** Generate a Bottom Line Up Front (BLUF) intelligence summary for a single article.

**Signature:**
```python
def generate_bluf(article: Article, session) -> str | None
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `article` | `Article` | The article to analyze |
| `session` | `sqlalchemy.orm.Session` | Active database session |

**Returns:**

| Type | Description |
|------|-------------|
| `str \| None` | Four-bullet BLUF markdown string, or `None` if LLM is disabled |

**Raises:** None

**Flow:**
1. Retrieves LLM config via `get_llm_config`; returns `None` if not found
2. Builds article context from `title` and first 1500 characters of `summary`
3. Sends a system prompt instructing the LLM to act as a Senior Threat Intelligence Analyst
4. The prompt enforces exactly four bullet points: Core Event, Impact Radius, Technical Details, Actionable Posture
5. Returns stripped response or `None`

**Dependencies:** `get_llm_config`, `call_llm`, `src.models.schema.Article`

---

### `analyze_cascading_impacts`

**Purpose:** Analyze a list of articles for converging threats and cascading operational impacts.

**Signature:**
```python
def analyze_cascading_impacts(articles: list[Article], session) -> str | None
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `articles` | `list[Article]` | List of articles to analyze |
| `session` | `sqlalchemy.orm.Session` | Active database session |

**Returns:**

| Type | Description |
|------|-------------|
| `str \| None` | Analysis with "Converging Threat Vectors" and "Cascading Fallout Assessment" sections, or `None` |

**Raises:** None

**Flow:**
1. Retrieves LLM config; returns `None` if missing or `articles` is empty
2. Defines a map prompt to identify core threats/vulnerable systems
3. Defines a reduce prompt asking for converging threat vectors and cascading fallout assessment
4. Delegates to `_map_reduce_summarize` with chunk size 8
5. Each article is formatted as `"- {title}: {truncated summary}"`

**Dependencies:** `_map_reduce_summarize`, `truncate_text`, `get_llm_config`

---

### `generate_unified_risk_brief`

**Purpose:** Generate a comprehensive, boardroom-ready Unified Risk Brief combining global intelligence and internal attack surface data.

**Signature:**
```python
def generate_unified_risk_brief(
    session,
    global_intel: dict,
    internal_snapshot
) -> str
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `session` | `sqlalchemy.orm.Session` | Active database session |
| `global_intel` | `dict` | Dictionary containing `unified_risk`, `raw_cyber_articles`, `raw_phys_articles`, `recent_crimes`, `cyber_brief`, `physical_brief` |
| `internal_snapshot` | `object` | Internal snapshot object with `risk_level`, `total_assets`, `total_osint_hits`, `hw_data_json`, `sw_data_json`, `timestamp` |

**Returns:**

| Type | Description |
|------|-------------|
| `str` | Markdown-formatted Unified Risk Brief with 5 sections, or `"AI is currently disabled in settings."` if disabled, or `"Brief generation failed."` on error |

**Raises:** None

**Flow:**
1. Retrieves LLM config; returns warning if not found
2. Extracts global and internal risk levels
3. Logs article counts and internal snapshot age
4. Parses `hw_data_json` and `sw_data_json` into Python objects; takes top 10 of each
5. Limits cyber articles to 6, physical articles to 5, crimes to 5
6. Builds formatted context strings for hardware, software, cyber, physical, and crime data
7. Constructs `compiled_intel` string with sections: Macro Threat Posture, Internal Attack Surface, Global Threat Landscape
8. Sends a CISO-style master system prompt enforcing 5 specific markdown headers
9. Calls LLM at temperature 0.3
10. Returns stripped response, or fallback message on failure

**Dependencies:** `get_llm_config`, `call_llm`, `json`, `datetime`, `src.utils.llm.call_llm` (redundant import internally)

---

### `generate_aggregated_shift_summary`

**Purpose:** Generate an executive shift summary from logbook entries using map-reduce, filtered by department role.

**Signature:**
```python
def generate_aggregated_shift_summary(
    session,
    logs: list,
    timeframe_label: str,
    target_role: str = "All"
) -> str | None
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `session` | `sqlalchemy.orm.Session` | Active database session |
| `logs` | `list` | List of log entry objects with `created_at`, `analyst`, `content` attributes |
| `timeframe_label` | `str` | Human-readable label for the time period (e.g., "24-Hour", "Weekly") |
| `target_role` | `str` | Department/role filter string; defaults to `"All"` |

**Returns:**

| Type | Description |
|------|-------------|
| `str \| None` | Markdown-formatted shift summary, or `None` if LLM disabled, or fallback message if no logs |

**Raises:** None

**Flow:**
1. Retrieves LLM config; returns `None` if not found
2. Returns a "no logs" message if `logs` is empty
3. Defines map prompt tailored to `target_role` to extract critical incidents
4. Defines reduce prompt to combine batch extractions
5. Runs `_map_reduce_summarize` with chunk size 20, formatting each log as `"[timestamp] analyst: content"`
6. Defines a master system prompt for a NOC Operations Manager with specific markdown headers (Overview, Critical Incidents, Ongoing Issues)
7. Calls LLM with the log digest at temperature 0.25
8. Returns stripped response or fallback

**Dependencies:** `get_llm_config`, `_map_reduce_summarize`, `call_llm`, `datetime`, `zoneinfo.ZoneInfo`, `src.models.schema.Article` (via logger logger refs)

---

### `generate_briefing`

**Purpose:** Generate a high-level situational briefing from a list of articles.

**Signature:**
```python
def generate_briefing(articles: list[Article], session) -> str | None
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `articles` | `list[Article]` | List of articles to synthesize |
| `session` | `sqlalchemy.orm.Session` | Active database session |

**Returns:**

| Type | Description |
|------|-------------|
| `str \| None` | 2-paragraph situational briefing, or `None` if LLM disabled or articles empty |

**Raises:** None

**Flow:**
1. Retrieves LLM config; returns `None` if missing or no articles
2. Map prompt: summarize threat actor campaigns/vulnerabilities in 2 bullet points
3. Reduce prompt: synthesize into a single 2-paragraph narrative as an All-Source Intelligence Director
4. Delegates to `_map_reduce_summarize` with chunk size 10
5. Each article formatted as `"Title: {title} | Source: {source}"`

**Dependencies:** `_map_reduce_summarize`, `get_llm_config`

---

### `cross_reference_cves`

**Purpose:** Cross-reference a list of Known Exploited Vulnerabilities (KEVs) against the organization's internal technology stack.

**Signature:**
```python
def cross_reference_cves(cves: list[CveItem], session) -> str
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `cves` | `list[CveItem]` | List of CVE items to check |
| `session` | `sqlalchemy.orm.Session` | Active database session |

**Returns:**

| Type | Description |
|------|-------------|
| `str` | Either `"CLEAR: ..."` message if no matches, or `"MATCH DETECTED:"` with detailed alert, or `"ERROR: AI Engine is disabled."` |

**Raises:** None

**Flow:**
1. Retrieves LLM config; returns error if not found
2. Returns clear message if `cves` is empty
3. Gets `tech_stack` from config or uses a hardcoded default
4. Builds system prompt to cross-reference KEVs against the internal tech stack
5. Processes CVEs in chunks of 8; for each chunk, formats CVE context and calls LLM at temperature 0.0
6. Collects non-clear, non-error responses as `raw_matches`
7. If no matches found, returns clear message
8. If matches found, calls LLM again with a SOC Director reduce prompt to generate a unified security alert
9. Returns `"MATCH DETECTED:\n\n{final_alert}"`

**Dependencies:** `get_llm_config`, `call_llm`, `chunk_list`, `src.models.schema.CveItem`

---

### `generate_feed_overview`

**Purpose:** Generate a high-level situational overview of intelligence feeds based on a focus prompt.

**Signature:**
```python
def generate_feed_overview(articles: list[Article], focus_prompt: str, session) -> str | None
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `articles` | `list[Article]` | List of articles to summarize |
| `focus_prompt` | `str` | Directing focus for the intelligence director |
| `session` | `sqlalchemy.orm.Session` | Active database session |

**Returns:**

| Type | Description |
|------|-------------|
| `str \| None` | 2-paragraph briefing string, or `None` if LLM disabled or articles empty |

**Raises:** None

**Flow:**
1. Retrieves LLM config; returns `None` if missing or no articles
2. Map prompt: extract 2 core threat themes from headlines
3. Reduce prompt: write 2-paragraph overview as Intelligence Director, incorporating focus
4. Delegates to `_map_reduce_summarize` with chunk size 10
5. Each article formatted as `"- {source}: {title}"`

**Dependencies:** `_map_reduce_summarize`, `get_llm_config`

---

### `generate_executive_weather_brief`

**Purpose:** Generate a 2-paragraph Executive Weather Briefing for electrical grid infrastructure.

**Signature:**
```python
def generate_executive_weather_brief(
    analytics: dict,
    p1_count: int,
    sys_config: SystemConfig | dict
) -> str
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `analytics` | `dict` | Dictionary with keys `district_distribution` (DataFrame), `total_sites`, `at_risk_sites`, `highest_risk` |
| `p1_count` | `int` | Number of critical (Priority 1) sites exposed |
| `sys_config` | `SystemConfig \| dict` | System configuration object or dict with `is_active` key |

**Returns:**

| Type | Description |
|------|-------------|
| `str` | 2-paragraph weather briefing, or `"AI is currently disabled in settings."` if disabled |

**Raises:** None

**Flow:**
1. Returns disabled message if `sys_config` is falsy or not active
2. Extracts district distribution counts from the analytics DataFrame
3. Builds a prompt with weather threat data (total sites, at-risk sites, highest risk, P1 count, district distribution)
4. Calls LLM with a meteorological intelligence analyst system prompt at temperature 0.2
5. Returns the LLM response

**Dependencies:** `call_llm`

---

### `build_custom_intel_report`

**Purpose:** Build an exhaustive, technical custom intelligence report from articles tailored to a user-defined objective.

**Signature:**
```python
def build_custom_intel_report(
    articles: list[Article],
    objective: str,
    session
) -> str | None
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `articles` | `list[Article]` | List of articles to analyze |
| `objective` | `str` | User-defined objective for the intelligence report |
| `session` | `sqlalchemy.orm.Session` | Active database session |

**Returns:**

| Type | Description |
|------|-------------|
| `str \| None` | Technical report with 4 required sections, or `None` if LLM disabled or articles empty |

**Raises:** None

**Flow:**
1. Retrieves LLM config; returns `None` if missing or no articles
2. Map prompt: extract every technical detail, IOC, targeted system, and threat actor aligned with the objective
3. Reduce prompt: compile into a report with 4 sections (Executive Summary, TTPs, IOCs, Remediation)
4. Delegates to `_map_reduce_summarize` with chunk size 3 for deep extraction
5. Each article formatted with source, title, and up to 600 characters of summary content

**Dependencies:** `_map_reduce_summarize`, `truncate_text`, `get_llm_config`

---

### `generate_rolling_summary`

**Purpose:** Generate a live Shift Handover Briefing synthesizing recent cyber threats, physical hazards, and cloud outages from the last 6 hours.

**Signature:**
```python
def generate_rolling_summary(session) -> str | None
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `session` | `sqlalchemy.orm.Session` | Active database session |

**Returns:**

| Type | Description |
|------|-------------|
| `str \| None` | 2-paragraph executive summary with a bolded "Grid Status" line, or `None` if LLM disabled |

**Raises:** None

**Flow:**
1. Retrieves LLM config; logs and returns `None` if not found
2. Calculates cutoff time: 6 hours ago from `datetime.utcnow()`
3. Queries:
   - `Article` with `published_date >= cutoff` and `score >= 50`, ordered by score desc, limit 10
   - `RegionalHazard` with `updated_at >= cutoff`, limit 10
   - `CloudOutage` with `updated_at >= cutoff`, limit 10
4. Builds context string with sections: Cyber Threats, Physical Hazards, Cloud Outages
5. Sends system prompt instructing the LLM to act as a Senior NOC Director and weave telemetry into a narrative ending with **Grid Status: ...**
6. Calls LLM at temperature 0.2; returns result or `"Generation failed."`

**Dependencies:** `get_llm_config`, `call_llm`, `datetime`, `timedelta`, `src.models.schema.Article`, `src.models.schema.RegionalHazard`, `src.models.schema.CloudOutage`

---

### `generate_dynamic_scoring_report`

**Purpose:** Generate an expansive Executive Intelligence Brief combining cyber articles, physical articles, crimes, and recent CVEs from the last 48 hours.

**Signature:**
```python
def generate_dynamic_scoring_report(session, intel: dict) -> str | None
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `session` | `sqlalchemy.orm.Session` | Active database session |
| `intel` | `dict` | Dictionary with keys `raw_cyber_articles`, `raw_phys_articles`, `recent_crimes`, `unified_risk` |

**Returns:**

| Type | Description |
|------|-------------|
| `str \| None` | Markdown-formatted Executive Intelligence Brief with Cyber and Physical sections, or `None` if LLM disabled |

**Raises:** None

**Flow:**
1. Retrieves LLM config; returns `None` if not found
2. Computes 48-hour cutoff from `datetime.utcnow()`
3. Combines cyber and physical articles; extracts crimes and unified_risk from intel dict
4. Queries `CveItem` with `date_added >= t48`, limit 15
5. Returns "No active intelligence" if all sources are empty
6. Runs map-reduce on articles (up to 25, chunk size 8) to produce a cyber digest
7. Formats crime context (up to 15, with FBI category and distance)
8. Formats CVE context (up to 15)
9. Builds `compiled_intel` with sections: Cyber Intelligence Digest, CISA Vulnerabilities, Active Perimeter Incidents
10. Sends master system prompt enforcing 2 specific markdown headers, instructing the LLM to expand without calculating scores
11. Calls LLM at temperature 0.3
12. Returns result or fallback message

**Dependencies:** `get_llm_config`, `_map_reduce_summarize`, `call_llm`, `datetime`, `timedelta`, `src.models.schema.CveItem`

---

### `generate_siem_triage_summary`

**Purpose:** Generate a boardroom-ready Executive Summary from extracted SIEM telemetry data.

**Signature:**
```python
def generate_siem_triage_summary(session, flat_results: list) -> str
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `session` | `sqlalchemy.orm.Session` | Active database session |
| `flat_results` | `list` | List of SIEM result objects/dicts |

**Returns:**

| Type | Description |
|------|-------------|
| `str` | Executive summary string, or `"[WARN] AI is currently disabled in settings."` if disabled |

**Raises:** None

**Flow:**
1. Retrieves LLM config; returns disabled warning if not found
2. Serializes first 30 items of `flat_results` to JSON
3. Sends system prompt for a Tier 3 SOC Analyst to produce an executive summary with bulleted IOC or anomaly list
4. Calls LLM at temperature 0.2
5. Returns stripped response or `"Triage generation failed."`

**Dependencies:** `get_llm_config`, `call_llm`, `json`

---

### `generate_elastic_dsl`

**Purpose:** Convert a natural language query into a valid Elasticsearch JSON query body.

**Signature:**
```python
def generate_elastic_dsl(session, nl_query: str) -> str
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `session` | `sqlalchemy.orm.Session` | Active database session |
| `nl_query` | `str` | Natural language query string (e.g., "show me all failed login attempts from external IPs") |

**Returns:**

| Type | Description |
|------|-------------|
| `str` | Valid Elasticsearch JSON query body string, or `"{}"` if LLM disabled, or fallback `{"query": {"match_all": {}}}` |

**Raises:** None

**Flow:**
1. Retrieves LLM config; returns `"{}"` if not found
2. Sends system prompt instructing the LLM to act as an Elastic SIEM engineer and output ONLY raw JSON
3. Calls LLM at temperature 0.1 with the natural language query
4. Strips any markdown code fences (` ```json ` / ` ``` ` ) from the response
5. Returns cleaned JSON string, or default match_all query on failure

**Dependencies:** `get_llm_config`, `call_llm`

---

### `generate_daily_fusion_report`

**Purpose:** Generate a comprehensive NOC Daily Fusion Report covering cyber intelligence, CISA KEVs, physical infrastructure/weather, and cloud services for the previous day.

**Signature:**
```python
def generate_daily_fusion_report(session) -> tuple | None
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `session` | `sqlalchemy.orm.Session` | Active database session |

**Returns:**

| Type | Description |
|------|-------------|
| `tuple \| None` | `(start_of_yesterday_datetime, report_string)` on success; `None` if LLM disabled |

**Raises:** None

**Flow:**
1. Retrieves LLM config; returns `None` if not found
2. Computes start and end of previous day in `America/Chicago` timezone, converted to UTC
3. Queries data for the previous day:
   - `Article` with `score >= 80.0`, limit 15
   - `CveItem` with `date_added` in range, limit 20
   - `RegionalHazard` with `updated_at` in range, limit 15
   - `CloudOutage` with `updated_at` in range, limit 15
4. For each non-empty dataset, runs map-reduce with appropriate prompts and chunk sizes
5. Builds `compiled_domains` string with 4 sections
6. Sends master system prompt for a Senior NOC Director to weave domain summaries into a seamless report
7. If LLM fails or returns `[WARN]`, returns a fallback report constructed from the individual domain summaries
8. Otherwise returns `(start_of_yesterday, master_report)`

**Dependencies:** `get_llm_config`, `_map_reduce_summarize`, `call_llm`, `datetime`, `timedelta`, `zoneinfo.ZoneInfo`, `src.models.schema.Article`, `src.models.schema.CveItem`, `src.models.schema.RegionalHazard`, `src.models.schema.CloudOutage`

---

## Module-level Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `LOCAL_TZ` | `ZoneInfo("America/Chicago")` | Central Time timezone used for local time conversions |
| `logger` | `logging.getLogger(__name__)` | Module-level logger instance |

---

## Error Handling Convention

All LLM-facing functions follow a consistent error handling pattern:
- **Network errors** (timeout, connection refused) return human-readable `[WARN]` prefixed strings
- **Unexpected exceptions** return `[WARN] **AI SYSTEM ERROR:** {details}`
- **Disabled AI** returns either `None` or `"[WARN] AI is currently disabled in settings."` depending on the function
- Functions propagating through `_map_reduce_summarize` silently skip failed batches
