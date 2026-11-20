# Component: `web/src/components/MarkdownContent.tsx`

Renders Markdown used by generated briefs, reports, and detection packages. The shared parser also supplies HTML for the Regional Grid SitRep email, keeping its displayed brief and email output aligned.

## Supported subset

The parser supports paragraphs, ATX headings, ordered and unordered/nested lists, blockquotes, horizontal rules, fenced code, tables, bold and italic emphasis, inline code, and safe links. Raw HTML is rendered as text. Unsupported link schemes remain plain text.

## `MarkdownContent({ content })`

Parses content into blocks and inline nodes, then renders semantic React elements with theme-aware styles. It does not use `dangerouslySetInnerHTML` or render raw HTML.
