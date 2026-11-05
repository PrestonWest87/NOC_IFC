# Module: `src.api.routes.llm`

LLM (Large Language Model) connection testing and executive weather brief generation routes. Prefix: `/api/v1/llm`.

---

## Endpoint: `POST /test-connection`

### Purpose
Tests connectivity to the selected LLM provider by sending a simple prompt and validating a non-empty assistant response.

### Parameters
| Parameter | Type               | Default   | Description                             |
|-----------|--------------------|-----------|-----------------------------------------|
| `data`    | `LLMConnectionTest` | — | JSON body with provider, endpoint, model, and optional API key. Administrator-only. |

#### Body Fields
| Field | Type | Default | Description |
|---|---|---|---|
| `llm_provider` | Literal | `openai_compatible` | `openai_compatible`, `ollama_openai`, `ollama_native`, or `vllm`. |
| `llm_endpoint` | `str` | `""` | Base URL reachable from the API container; no credentials, query, or fragment. |
| `llm_api_key` | `str` | `""` | Optional key; an empty value reuses the saved key only when the provider matches the saved provider. |
| `llm_model_name` | `str` | `"gpt-4o-mini"` | Provider model identifier. |

### Returns
```json
{
  "success": true | false,
  "message": "<description or model response>"
}
```

### Raises
None. All connection errors are caught and returned as structured failure responses.

### Flow
1. Validates provider, endpoint scheme, URL credentials/query/fragment, model name, and target network policy.
2. Builds the provider-specific request with system/user prompts and a 30-second timeout.
3. Uses `/api/chat` and Ollama `options` for `ollama_native`; OpenAI-compatible chat completions for the other providers.
4. Parses the selected provider's response shape and rejects missing or empty content.
5. Returns actionable timeout, connection, HTTP status, and response-format messages without including API credentials.

### Dependencies
- `src.utils.llm.request_llm_completion()` and the shared provider URL/payload adapter.
- `ALLOW_PRIVATE_LLM_ENDPOINTS`; explicitly selected local providers may target private/loopback hosts after URL validation.

---

## Endpoint: `POST /executive-weather-brief`

### Purpose
Generates an executive-level weather briefing using the configured LLM, based on analytics data and P1 site risk counts.

### Parameters
| Parameter | Type               | Default | Description                             |
|-----------|--------------------|---------|-----------------------------------------|
| `data`    | `dict[str, Any]`   | `{}`    | JSON body with analytics and risk data. |

#### Body Fields
| Field          | Type               | Default | Description                           |
|----------------|--------------------|---------|---------------------------------------|
| `analytics`    | `dict`             | `{}`    | Infrastructure analytics object.      |
| `p1_at_risk`   | `int`              | `0`     | Number of P1 sites currently at risk. |

### Returns
```json
{
  "brief": "<generated markdown brief or fallback message>"
}
```

### Raises
None.

### Flow
1. Imports `generate_executive_weather_brief` from `src.utils.llm`.
2. Retrieves the cached system configuration via `svc.get_cached_config()`.
3. Calls the LLM brief generator with analytics, P1 at-risk count, and config.
4. Returns the brief or a fallback message if generation failed.

### Dependencies
- `src.utils.llm.generate_executive_weather_brief()`
- `src.services.get_cached_config()`
## Current Source Surface

`_safe_llm_endpoint` validates endpoint policy. `POST /test-connection` uses the same provider-aware request adapter as normal LLM generation. `POST /executive-weather-brief` builds a weather summary from the supplied analytics payload and active LLM configuration.
