# Module: `src.api.routes.llm`

LLM (Large Language Model) connection testing and executive weather brief generation routes. Prefix: `/api/v1/llm`.

---

## Endpoint: `POST /test-connection`

### Purpose
Tests connectivity to a configurable LLM API endpoint by sending a simple prompt and verifying the response.

### Parameters
| Parameter | Type               | Default   | Description                             |
|-----------|--------------------|-----------|-----------------------------------------|
| `data`    | `dict[str, Any]`   | `{}`      | JSON body with optional LLM connection parameters.|

#### Body Fields
| Field             | Type     | Default        | Description                     |
|-------------------|----------|----------------|---------------------------------|
| `llm_endpoint`    | `str`    | `""`           | Base URL of the LLM API.        |
| `llm_api_key`     | `str`    | `""`           | API key for authentication.     |
| `llm_model_name`  | `str`    | `"gpt-4o-mini"`| Model identifier string.        |

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
1. Extracts endpoint, API key, and model name from the request body.
2. Validates that endpoint is not empty.
3. Constructs a minimal `_TestConfig` object.
4. Builds a request with system prompt and user prompt `"Reply with exactly: CONNECTION_OK"`.
5. Sends an HTTP POST to `{endpoint}/chat/completions` with a 30-second timeout.
6. Checks for HTTP errors via `resp.raise_for_status()`.
7. Parses the response and returns the model's reply.
8. Catches `Timeout`, `ConnectionError`, and generic exceptions, returning appropriate error messages.

### Dependencies
- `requests` (stdlib via `import requests`)
- `src.utils.llm.call_llm` (imported but not used; inline HTTP call is used instead)

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
