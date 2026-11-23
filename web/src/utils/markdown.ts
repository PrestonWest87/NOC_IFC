/** Safe, parsed inline Markdown nodes shared by the React and email renderers. */
export type MarkdownInline =
  | { type: "text"; value: string }
  | { type: "strong"; children: MarkdownInline[] }
  | { type: "emphasis"; children: MarkdownInline[] }
  | { type: "code"; value: string }
  | { type: "link"; href: string; children: MarkdownInline[] }
  | { type: "break" };

/** One list item, including any nested block children. */
export type MarkdownListItem = { content: MarkdownInline[]; children: MarkdownBlock[] };
/** Discriminated union of the supported block-level Markdown constructs. */
export type MarkdownBlock =
  | { type: "paragraph"; children: MarkdownInline[] }
  | { type: "heading"; level: number; children: MarkdownInline[] }
  | { type: "code-block"; language: string; value: string }
  | { type: "quote"; children: MarkdownBlock[] }
  | { type: "list"; ordered: boolean; start: number; items: MarkdownListItem[] }
  | { type: "table"; header: MarkdownInline[][]; rows: MarkdownInline[][][] }
  | { type: "rule" };

type ListMarker = { indent: number; ordered: boolean; start: number; content: string };

function escapedAt(value: string, index: number): boolean {
  let slashes = 0;
  for (let cursor = index - 1; cursor >= 0 && value[cursor] === "\\"; cursor -= 1) slashes += 1;
  return slashes % 2 === 1;
}

function closingDelimiter(value: string, delimiter: string, start: number): number {
  let index = value.indexOf(delimiter, start);
  while (index >= 0) {
    if (!escapedAt(value, index)) return index;
    index = value.indexOf(delimiter, index + delimiter.length);
  }
  return -1;
}

/** Permit relative, HTTP(S), and mailto URLs; reject empty, protocol-relative, control-character, and other-scheme values. */
export function safeMarkdownHref(value: string): string | null {
  const href = value.trim();
  if (!href || href.startsWith("//") || /[\u0000-\u0020]/.test(href)) return null;
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(href)?.[1]?.toLowerCase();
  return scheme && !["http", "https", "mailto"].includes(scheme) ? null : href;
}

function linkParts(value: string, start: number): { end: number; label: string; href: string } | null {
  const labelEnd = value.indexOf("](", start + 1);
  if (labelEnd < 0) return null;
  const end = closingDelimiter(value, ")", labelEnd + 2);
  if (end < 0) return null;
  const destination = value.slice(labelEnd + 2, end).trim();
  const href = destination.startsWith("<")
    ? destination.slice(1, destination.indexOf(">"))
    : destination.split(/\s+/, 1)[0];
  return href ? { end, label: value.slice(start + 1, labelEnd), href } : null;
}

/** Parse the supported inline syntax into nodes, bounding recursive emphasis/link nesting. */
export function parseInlineMarkdown(value: string, depth = 0): MarkdownInline[] {
  if (depth > 8) return [{ type: "text", value }];
  const nodes: MarkdownInline[] = [];
  let plain = "";
  const flush = () => {
    if (plain) nodes.push({ type: "text", value: plain });
    plain = "";
  };

  for (let index = 0; index < value.length;) {
    if (value[index] === "\\" && index + 1 < value.length) {
      plain += value[index + 1];
      index += 2;
      continue;
    }

    if (value[index] === "`") {
      const ticks = /^`+/.exec(value.slice(index))?.[0] || "`";
      const end = closingDelimiter(value, ticks, index + ticks.length);
      if (end >= 0) {
        flush();
        nodes.push({ type: "code", value: value.slice(index + ticks.length, end).replace(/\n/g, " ").trim() });
        index = end + ticks.length;
        continue;
      }
    }

    if (value[index] === "[") {
      const link = linkParts(value, index);
      if (link) {
        flush();
        const href = safeMarkdownHref(link.href);
        if (href) nodes.push({ type: "link", href, children: parseInlineMarkdown(link.label, depth + 1) });
        else nodes.push({ type: "text", value: value.slice(index, link.end + 1) });
        index = link.end + 1;
        continue;
      }
    }

    const strong = value.slice(index, index + 2);
    if (strong === "**" || strong === "__") {
      const end = closingDelimiter(value, strong, index + 2);
      if (end > index + 2 && value[index + 2] !== " " && value[end - 1] !== " ") {
        flush();
        nodes.push({ type: "strong", children: parseInlineMarkdown(value.slice(index + 2, end), depth + 1) });
        index = end + 2;
        continue;
      }
    }

    const emphasis = value[index];
    if ((emphasis === "*" || emphasis === "_") && value[index + 1] !== emphasis) {
      const end = closingDelimiter(value, emphasis, index + 1);
      if (end > index + 1 && value[index + 1] !== " " && value[end - 1] !== " ") {
        flush();
        nodes.push({ type: "emphasis", children: parseInlineMarkdown(value.slice(index + 1, end), depth + 1) });
        index = end + 1;
        continue;
      }
    }

    plain += value[index];
    index += 1;
  }
  flush();
  return nodes;
}

function listMarker(line: string): ListMarker | null {
  const match = /^([ \t]*)([-+*]|\d+[.)])\s+(.*)$/.exec(line);
  if (!match) return null;
  const marker = match[2];
  return {
    indent: match[1].replace(/\t/g, "    ").length,
    ordered: /^\d/.test(marker),
    start: /^\d/.test(marker) ? Number.parseInt(marker, 10) : 1,
    content: match[3],
  };
}

function splitTableRow(line: string): string[] {
  const value = line.trim().replace(/^\|/, "").replace(/\|$/, "");
  const cells: string[] = [];
  let cell = "";
  let escaped = false;
  for (const character of value) {
    if (character === "|" && !escaped) {
      cells.push(cell.trim().replace(/\\\|/g, "|"));
      cell = "";
    } else {
      cell += character;
    }
    escaped = character === "\\" && !escaped;
    if (character !== "\\") escaped = false;
  }
  cells.push(cell.trim().replace(/\\\|/g, "|"));
  return cells;
}

function isTableAt(lines: string[], index: number): boolean {
  if (index + 1 >= lines.length || !lines[index].includes("|")) return false;
  const cells = splitTableRow(lines[index + 1]);
  return cells.length > 1 && cells.every(cell => /^:?-{3,}:?$/.test(cell));
}

function fenceAt(line: string): { marker: string; language: string } | null {
  const match = /^ {0,3}(`{3,}|~{3,})\s*([\w+-]*)[^\n]*$/.exec(line);
  return match ? { marker: match[1], language: match[2] } : null;
}

function isRule(line: string): boolean {
  return /^ {0,3}(?:(?:\*\s*){3,}|(?:-\s*){3,}|(?:_\s*){3,})$/.test(line);
}

function isBlockStart(lines: string[], index: number): boolean {
  return Boolean(
    fenceAt(lines[index])
    || /^ {0,3}#{1,6}\s+/.test(lines[index])
    || /^ {0,3}>/.test(lines[index])
    || listMarker(lines[index])
    || isRule(lines[index])
    || isTableAt(lines, index),
  );
}

function parseList(lines: string[], startIndex: number, depth = 0): { block: MarkdownBlock; nextIndex: number } {
  const first = listMarker(lines[startIndex])!;
  const block: Extract<MarkdownBlock, { type: "list" }> = {
    type: "list", ordered: first.ordered, start: first.start, items: [],
  };
  let index = startIndex;
  while (index < lines.length) {
    if (!lines[index].trim()) {
      let next = index + 1;
      while (next < lines.length && !lines[next].trim()) next += 1;
      const nextMarker = next < lines.length ? listMarker(lines[next]) : null;
      if (nextMarker && nextMarker.indent >= first.indent) {
        index = next;
        continue;
      }
      break;
    }

    const marker = listMarker(lines[index]);
    if (!marker) {
      const indent = lines[index].match(/^[ \t]*/)?.[0].replace(/\t/g, "    ").length || 0;
      if (indent > first.indent && block.items.length) {
        const item = block.items[block.items.length - 1];
        item.content.push({ type: "text", value: ` ${lines[index].trim()}` });
        index += 1;
        continue;
      }
      break;
    }
    if (marker.indent < first.indent) break;
    if (marker.indent > first.indent) {
      if (!block.items.length) break;
      if (depth >= 8) {
        block.items[block.items.length - 1].content.push({ type: "text", value: ` ${marker.content}` });
        index += 1;
        continue;
      }
      const nested = parseList(lines, index, depth + 1);
      block.items[block.items.length - 1].children.push(nested.block);
      index = nested.nextIndex;
      continue;
    }
    if (marker.ordered !== first.ordered) break;

    const item: MarkdownListItem = { content: parseInlineMarkdown(marker.content), children: [] };
    block.items.push(item);
    index += 1;
  }
  return { block, nextIndex: index };
}

/** Parse the supported block syntax into safe typed nodes; raw HTML remains ordinary text. */
export function parseMarkdown(content: string, depth = 0): MarkdownBlock[] {
  const lines = String(content || "").replace(/\r\n?/g, "\n").split("\n");
  if (depth > 8) {
    return lines.some(line => line.trim())
      ? [{ type: "paragraph", children: parseInlineMarkdown(lines.map(line => line.trim()).filter(Boolean).join(" ")) }]
      : [];
  }
  const blocks: MarkdownBlock[] = [];
  let index = 0;
  while (index < lines.length) {
    const line = lines[index];
    if (!line.trim()) { index += 1; continue; }

    const fence = fenceAt(line);
    if (fence) {
      const code: string[] = [];
      index += 1;
      const fenceChar = fence.marker[0];
      const close = new RegExp(`^ {0,3}${fenceChar}{${fence.marker.length},}\\s*$`);
      while (index < lines.length && !close.test(lines[index])) code.push(lines[index++]);
      if (index < lines.length) index += 1;
      blocks.push({ type: "code-block", language: fence.language, value: code.join("\n") });
      continue;
    }

    const heading = /^ {0,3}(#{1,6})\s+(.+?)\s*#*\s*$/.exec(line);
    if (heading) {
      blocks.push({ type: "heading", level: heading[1].length, children: parseInlineMarkdown(heading[2]) });
      index += 1;
      continue;
    }

    if (isRule(line)) { blocks.push({ type: "rule" }); index += 1; continue; }

    if (/^ {0,3}>/.test(line)) {
      const quoted: string[] = [];
      while (index < lines.length) {
        const match = /^ {0,3}> ?(.*)$/.exec(lines[index]);
        if (!match) break;
        quoted.push(match[1]);
        index += 1;
      }
      blocks.push({ type: "quote", children: parseMarkdown(quoted.join("\n"), depth + 1) });
      continue;
    }

    if (isTableAt(lines, index)) {
      const header = splitTableRow(lines[index]).map(parseInlineMarkdown);
      index += 2;
      const rows: MarkdownInline[][][] = [];
      while (index < lines.length && lines[index].trim() && lines[index].includes("|")) {
        rows.push(splitTableRow(lines[index]).map(parseInlineMarkdown));
        index += 1;
      }
      blocks.push({ type: "table", header, rows });
      continue;
    }

    if (listMarker(line)) {
      const list = parseList(lines, index, depth);
      blocks.push(list.block);
      index = list.nextIndex;
      continue;
    }

    const paragraph: string[] = [];
    while (index < lines.length && lines[index].trim() && !(paragraph.length && isBlockStart(lines, index))) {
      paragraph.push(lines[index++]);
    }
    const children: MarkdownInline[] = [];
    paragraph.forEach((part, partIndex) => {
      const hardBreak = /(?: {2,}|\\)$/.test(part);
      children.push(...parseInlineMarkdown(part.replace(/(?: {2,}|\\)$/, "").trim()));
      if (partIndex < paragraph.length - 1) {
        children.push(hardBreak ? { type: "break" } : { type: "text", value: " " });
      }
    });
    blocks.push({ type: "paragraph", children });
  }
  return blocks;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character] || character);
}

function renderInlineHtml(nodes: MarkdownInline[]): string {
  return nodes.map(node => {
    if (node.type === "text") return escapeHtml(node.value);
    if (node.type === "break") return "<br>";
    if (node.type === "code") return `<code style="font-family:monospace;background:#f3f4f6;padding:1px 3px;border-radius:3px;">${escapeHtml(node.value)}</code>`;
    if (node.type === "strong") return `<strong>${renderInlineHtml(node.children)}</strong>`;
    if (node.type === "emphasis") return `<em>${renderInlineHtml(node.children)}</em>`;
    return `<a href="${escapeHtml(node.href)}" style="color:#2563eb;text-decoration:underline;">${renderInlineHtml(node.children)}</a>`;
  }).join("");
}

function renderBlockHtml(block: MarkdownBlock): string {
  if (block.type === "paragraph") return `<p style="margin:0 0 12px;line-height:1.6;">${renderInlineHtml(block.children)}</p>`;
  if (block.type === "heading") return `<h${block.level} style="color:#111827;margin:20px 0 10px;">${renderInlineHtml(block.children)}</h${block.level}>`;
  if (block.type === "code-block") {
    const language = block.language && /^[\w+-]+$/.test(block.language) ? ` class="language-${block.language}"` : "";
    return `<pre style="overflow:auto;white-space:pre-wrap;background:#f3f4f6;padding:12px;border-radius:4px;"><code${language}>${escapeHtml(block.value)}</code></pre>`;
  }
  if (block.type === "quote") return `<blockquote style="margin:12px 0;padding:4px 14px;border-left:3px solid #94a3b8;color:#475569;">${block.children.map(renderBlockHtml).join("")}</blockquote>`;
  if (block.type === "rule") return "<hr style=\"border:0;border-top:1px solid #cbd5e1;margin:18px 0;\">";
  if (block.type === "list") {
    const tag = block.ordered ? "ol" : "ul";
    const start = block.ordered && block.start !== 1 ? ` start="${block.start}"` : "";
    const items = block.items.map(item => `<li>${renderInlineHtml(item.content)}${item.children.map(renderBlockHtml).join("")}</li>`).join("");
    return `<${tag}${start} style="margin:0 0 12px;padding-left:24px;">${items}</${tag}>`;
  }
  const header = block.header.map(cell => `<th style="text-align:left;border:1px solid #cbd5e1;padding:6px;background:#f8fafc;">${renderInlineHtml(cell)}</th>`).join("");
  const rows = block.rows.map(row => `<tr>${block.header.map((_cell, index) => `<td style="vertical-align:top;border:1px solid #cbd5e1;padding:6px;">${renderInlineHtml(row[index] || [])}</td>`).join("")}</tr>`).join("");
  return `<div style="overflow-x:auto;"><table style="border-collapse:collapse;margin:12px 0;width:100%;"><thead><tr>${header}</tr></thead><tbody>${rows}</tbody></table></div>`;
}

/** Render parsed Markdown to email-friendly HTML with all source text escaped. */
export function markdownToHtml(content: string): string {
  return parseMarkdown(content).map(renderBlockHtml).join("");
}
