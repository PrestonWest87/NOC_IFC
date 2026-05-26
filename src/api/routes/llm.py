import logging
from fastapi import APIRouter, Body
from typing import Any

from src import services as svc

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/llm", tags=["llm"])


@router.post("/test-connection")
def test_llm_connection(data: dict[str, Any] = Body({})):
    from src.utils.llm import call_llm

    endpoint = data.get("llm_endpoint", "").rstrip("/")
    api_key = data.get("llm_api_key", "")
    model_name = data.get("llm_model_name", "gpt-4o-mini")

    if not endpoint:
        return {"success": False, "message": "Endpoint URL is required."}

    class _TestConfig:
        llm_endpoint = endpoint
        llm_api_key = api_key
        llm_model_name = model_name

    config = _TestConfig()
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Reply with exactly: CONNECTION_OK"}
    ]

    try:
        import requests
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        payload = {"model": model_name, "messages": messages, "temperature": 0.0, "max_tokens": 20}
        url = f"{endpoint}/chat/completions"
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        resp.raise_for_status()
        result = resp.json()['choices'][0]['message']['content'].strip()
        return {"success": True, "message": f"Connection successful. Model response: {result}"}
    except requests.exceptions.Timeout:
        return {"success": False, "message": "Request timed out after 30 seconds. Check your endpoint URL and network connectivity."}
    except requests.exceptions.ConnectionError:
        return {"success": False, "message": "Connection refused. Verify the endpoint URL is correct and the server is reachable."}
    except Exception as e:
        return {"success": False, "message": f"Connection failed: {str(e)}"}


@router.post("/executive-weather-brief")
def executive_weather_brief(data: dict[str, Any] = Body({})):
    from src.utils.llm import generate_executive_weather_brief
    config = svc.get_cached_config()
    brief = generate_executive_weather_brief(
        data.get("analytics", {}),
        data.get("p1_at_risk", 0),
        config,
    )
    return {"brief": brief or "Unable to generate weather brief."}
