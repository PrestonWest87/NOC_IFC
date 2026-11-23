# Module: `src/utils/`

Utilities package for the NOC Intelligence Fusion Center. Contains helpers for LLM interactions, email delivery, risk-alert orchestration, and safe Markdown rendering.

## Submodules

| Module | Description |
|--------|-------------|
| `llm` | LLM interaction utilities -- AI-powered intelligence briefings, summaries, and analysis via configurable OpenAI-compatible API |
| `mailer` | Email sending utility -- active SMTP/Gmail profile delivery using database-stored configuration |
| `risk_alert` | Risk alert engine -- monitors global/internal risk level escalations and sends email notifications |
| `markdown` | Safe renderer for the supported Markdown subset used by reports and email bodies |
