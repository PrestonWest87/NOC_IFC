"""Supported LLM wire protocols and endpoint normalization."""

DEFAULT_LLM_PROVIDER = "openai_compatible"
LLM_PROVIDER_LABELS = {
    "openai_compatible": "OpenAI-compatible",
    "ollama_openai": "Ollama (OpenAI-compatible API)",
    "ollama_native": "Ollama (native API)",
    "vllm": "vLLM (OpenAI-compatible API)",
}
LLM_PROVIDER_KEYS = tuple(LLM_PROVIDER_LABELS)
LOCAL_LLM_PROVIDERS = frozenset({"ollama_openai", "ollama_native", "vllm"})
OLLAMA_PROVIDERS = frozenset({"ollama_openai", "ollama_native"})


def normalize_llm_provider(provider):
    """Return a supported provider key, defaulting legacy/missing settings safely."""
    if provider is None or provider == "":
        return DEFAULT_LLM_PROVIDER
    if not isinstance(provider, str):
        raise ValueError("llm_provider must be text.")
    value = provider.strip().lower()
    if value not in LLM_PROVIDER_LABELS:
        raise ValueError(f"Unsupported LLM provider: {value}")
    return value


def build_chat_url(endpoint, provider):
    """Construct one provider's chat URL from a base endpoint or a full API path."""
    provider = normalize_llm_provider(provider)
    base = str(endpoint or "").strip().rstrip("/")
    if not base:
        raise ValueError("Endpoint URL is required.")

    if provider == "ollama_native":
        if base.endswith("/api/chat"):
            return base
        if base.endswith("/api"):
            return f"{base}/chat"
        if base.endswith("/v1"):
            base = base[:-len("/v1")].rstrip("/")
        return f"{base}/api/chat"

    if base.endswith("/chat/completions"):
        return base

    if provider in {"ollama_openai", "vllm"} and not base.endswith("/v1"):
        base = f"{base}/v1"
    return f"{base}/chat/completions"


def ollama_base_url(endpoint):
    """Remove an Ollama OpenAI-compatible/native API suffix to locate `/api/show`."""
    base = str(endpoint or "").strip().rstrip("/")
    changed = True
    while changed:
        changed = False
        for suffix in ("/chat/completions", "/api/chat", "/api", "/v1"):
            if base.endswith(suffix):
                base = base[:-len(suffix)].rstrip("/")
                changed = True
                break
    return base
