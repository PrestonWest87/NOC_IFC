# LLM Provider Protocols

**File:** `src/core/llm_providers.py`

The provider catalog is persisted as `SystemConfig.llm_provider`:

| Key | API protocol | Endpoint handling |
|---|---|---|
| `openai_compatible` | `/chat/completions` with OpenAI-style `choices` response | Preserves configured base URL semantics for existing configurations. |
| `ollama_openai` | OpenAI-compatible chat completions | Adds `/v1` when not already present. |
| `ollama_native` | Ollama `/api/chat`; reads `message.content` | Removes an optional `/v1` suffix and adds `/api/chat`. |
| `vllm` | OpenAI-compatible chat completions | Adds `/v1` when not already present. |

`normalize_llm_provider()` validates keys and defaults missing legacy values to `openai_compatible`. `build_chat_url()` constructs the provider path, while `ollama_base_url()` derives the root URL for Ollama context metadata queries.
