"""LLM connection testing and weather-brief endpoints.

Endpoint validation is provider-aware: explicit local providers may target
validated loopback/private URLs; generic providers follow the deployment policy.
"""

import logging
import ipaddress
import socket
from urllib.parse import urlparse
from fastapi import APIRouter, Body, Depends
from pydantic import BaseModel, ConfigDict, Field
from typing import Any, Literal

from src.core.config import settings
from src.api.auth_guard import require_action, require_admin, require_page
from src.core.llm_providers import LOCAL_LLM_PROVIDERS, normalize_llm_provider

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/llm", tags=["llm"])


def _safe_llm_endpoint(endpoint: str, provider: str = "openai_compatible") -> bool:
    """Validate an HTTP(S) endpoint and allow local targets only for explicit local providers."""
    try:
        parsed = urlparse(endpoint)
    except ValueError:
        return False
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.username
        or parsed.password
        or not parsed.hostname
        or parsed.query
        or parsed.fragment
    ):
        return False
    try:
        port = parsed.port or (80 if parsed.scheme == "http" else 443)
    except ValueError:
        return False
    try:
        provider = normalize_llm_provider(provider)
        if settings.allow_private_llm_endpoints:
            return True
        addresses = {
            ipaddress.ip_address(item[4][0])
            for item in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
        }
        if not addresses:
            return False
        for address in addresses:
            if address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
                return False
            if provider not in LOCAL_LLM_PROVIDERS and (address.is_private or address.is_loopback):
                return False
        return True
    except (OSError, ValueError):
        return False


class LLMConnectionTest(BaseModel):
    """Submitted model/provider values for one bounded connection check."""
    model_config = ConfigDict(extra="forbid")

    llm_provider: Literal["openai_compatible", "ollama_openai", "ollama_native", "vllm"] = "openai_compatible"
    llm_endpoint: str = Field(default="", max_length=2048)
    llm_api_key: str = Field(default="", max_length=4096)
    llm_model_name: str = Field(default="gpt-4o-mini", max_length=256)


@router.post("/test-connection", dependencies=[
    Depends(require_page("Settings & Admin")),
    Depends(require_action("Tab: Settings -> AI & SMTP")),
    Depends(require_admin),
])
def test_llm_connection(data: LLMConnectionTest):
    """Test the selected provider with a bounded request using the runtime chat adapter."""
    from src.core.db import SessionLocal
    from src.models.schema import SystemConfig
    from src.utils.llm import LLMRequestError, request_llm_completion

    endpoint = data.llm_endpoint.strip().rstrip("/")
    provider = data.llm_provider
    model_name = data.llm_model_name.strip()
    if not endpoint:
        return {"success": False, "message": "Endpoint URL is required."}
    if not model_name:
        return {"success": False, "message": "Model name is required."}
    if not _safe_llm_endpoint(endpoint, provider):
        return {
            "success": False,
            "message": "Endpoint is not allowed. Use a valid HTTP(S) URL; local/private endpoints require an explicit local provider or ALLOW_PRIVATE_LLM_ENDPOINTS.",
        }

    api_key = data.llm_api_key.strip()
    if not api_key:
        with SessionLocal() as db:
            saved = db.query(SystemConfig).first()
            saved_provider = normalize_llm_provider(saved.llm_provider) if saved else None
            if saved and saved_provider == provider:
                api_key = saved.llm_api_key or ""
    config = {
        "llm_provider": provider,
        "llm_endpoint": endpoint,
        "llm_api_key": api_key,
        "llm_model_name": model_name,
        "llm_context_window": 128000,
    }
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Reply with exactly: CONNECTION_OK"},
    ]

    try:
        result = request_llm_completion(
            messages, config, temperature=0.0, max_tokens=20, timeout=30,
        )
        return {"success": True, "message": f"Connection successful. Model response: {result[:240]}"}
    except LLMRequestError as exc:
        logger.warning("LLM connection test failed provider=%s model=%s: %s", provider, model_name, exc)
        return {"success": False, "message": str(exc)}
    except Exception:
        logger.exception("LLM connection test failed provider=%s model=%s", provider, model_name)
        return {"success": False, "message": "Connection failed unexpectedly. Check the API server logs."}


@router.post("/executive-weather-brief", dependencies=[
    Depends(require_page("Regional Grid")),
    Depends(require_action("Tab: Regional Grid -> Executive Dash")),
    Depends(require_action("Action: Generate Reports")),
])
def executive_weather_brief(data: dict[str, Any] = Body({})):
    """Generate a Regional Grid weather brief from submitted analytics and cached settings."""
    from src.utils.llm import generate_executive_weather_brief
    config = svc.get_cached_config()
    brief = generate_executive_weather_brief(
        data.get("analytics", {}),
        data.get("p1_at_risk", 0),
        config,
    )
    return {"brief": brief or "Unable to generate weather brief."}
