# Module: `src.utils.markdown`

Renders the Markdown subset used by application-generated reports into email-safe HTML. The parser escapes source text and does not pass raw HTML through.

## `markdown_to_html(content: str) -> str`

Converts paragraphs, ATX headings, ordered/unordered and nested lists, blockquotes, horizontal rules, tables, fenced code blocks, bold/italic emphasis, inline code, and safe links. Link schemes are limited to ordinary relative links, HTTP/HTTPS, and `mailto`; unsupported schemes remain escaped text. Email report builders use this helper before handing HTML to `send_alert_email()`.

The frontend mirror is `web/src/utils/markdown.ts`; `MarkdownContent` renders the same parsed blocks as React elements without using raw HTML.
