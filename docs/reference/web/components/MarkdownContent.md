# Component: `web/src/components/MarkdownContent.tsx`

Renders the restricted Markdown subset used by generated briefs and reports.

## `inlineMarkdown(value)`

Parses inline emphasis/link-like formatting into React nodes without using `dangerouslySetInnerHTML`. It returns React node fragments for safe rendering.

## `MarkdownContent({ content })`

Splits report text into lines, renders headings, bullets, paragraphs, and inline formatting, and applies the application’s theme variables. It is a presentation component; it does not call the LLM or sanitize arbitrary HTML because the component does not render raw HTML.
