import { Fragment, type ReactNode } from "react";
import { parseMarkdown, type MarkdownBlock, type MarkdownInline } from "../utils/markdown";

function renderInline(nodes: MarkdownInline[], prefix: string): ReactNode[] {
  return nodes.map((node, index) => {
    const key = `${prefix}-${index}`;
    if (node.type === "text") return <Fragment key={key}>{node.value}</Fragment>;
    if (node.type === "break") return <br key={key} />;
    if (node.type === "code") return <code key={key} style={{ fontFamily: "var(--font-mono, monospace)", background: "var(--bg-tertiary, #f1f5f9)", padding: "0.05rem 0.25rem", borderRadius: 3 }}>{node.value}</code>;
    if (node.type === "strong") return <strong key={key}>{renderInline(node.children, key)}</strong>;
    if (node.type === "emphasis") return <em key={key}>{renderInline(node.children, key)}</em>;
    const external = /^https?:/i.test(node.href);
    return <a key={key} href={node.href} target={external ? "_blank" : undefined} rel={external ? "noopener noreferrer" : undefined} style={{ color: "var(--accent-blue, #2563eb)" }}>{renderInline(node.children, key)}</a>;
  });
}

function renderBlocks(blocks: MarkdownBlock[], prefix: string): ReactNode[] {
  return blocks.map((block, index) => {
    const key = `${prefix}-${index}`;
    if (block.type === "paragraph") return <p key={key} style={{ margin: 0, lineHeight: 1.65 }}>{renderInline(block.children, key)}</p>;
    if (block.type === "heading") {
      const style = { margin: block.level < 3 ? "0.8rem 0 0.1rem" : "0.4rem 0 0", fontSize: block.level < 3 ? "1.05rem" : "0.95rem", color: "var(--text-primary, #1f2937)", borderBottom: block.level < 3 ? "1px solid var(--border-primary, #e2e8f0)" : undefined, paddingBottom: block.level < 3 ? "0.45rem" : undefined };
      const children = renderInline(block.children, key);
      if (block.level === 1) return <h2 key={key} style={style}>{children}</h2>;
      if (block.level === 2) return <h3 key={key} style={style}>{children}</h3>;
      if (block.level === 3) return <h4 key={key} style={style}>{children}</h4>;
      if (block.level === 4) return <h5 key={key} style={style}>{children}</h5>;
      if (block.level === 5) return <h6 key={key} style={style}>{children}</h6>;
      return <h6 key={key} style={style}>{children}</h6>;
    }
    if (block.type === "code-block") return <pre key={key} style={{ margin: 0, padding: "0.75rem", overflowX: "auto", whiteSpace: "pre-wrap", background: "var(--bg-tertiary, #f1f5f9)", borderRadius: "var(--radius-sm, 4px)", fontFamily: "var(--font-mono, monospace)", fontSize: "0.9em" }}><code className={block.language ? `language-${block.language}` : undefined}>{block.value}</code></pre>;
    if (block.type === "quote") return <blockquote key={key} style={{ margin: 0, padding: "0.2rem 0.9rem", borderLeft: "3px solid var(--border-primary, #cbd5e1)", color: "var(--text-secondary, #475569)" }}>{renderBlocks(block.children, key)}</blockquote>;
    if (block.type === "rule") return <hr key={key} style={{ width: "100%", border: 0, borderTop: "1px solid var(--border-primary, #cbd5e1)" }} />;
    if (block.type === "list") {
      const items = block.items.map((item, itemIndex) => <li key={`${key}-${itemIndex}`} style={{ lineHeight: 1.6 }}>{renderInline(item.content, `${key}-${itemIndex}`)}{renderBlocks(item.children, `${key}-${itemIndex}-nested`)}</li>);
      const style = { margin: 0, paddingLeft: "1.25rem", display: "grid", gap: "0.35rem" } as const;
      return block.ordered
        ? <ol key={key} start={block.start} style={style}>{items}</ol>
        : <ul key={key} style={style}>{items}</ul>;
    }
    return <div key={key} style={{ overflowX: "auto" }}><table style={{ borderCollapse: "collapse", width: "100%", fontSize: "0.95em" }}>
      <thead><tr>{block.header.map((cell, cellIndex) => <th key={cellIndex} style={{ textAlign: "left", borderBottom: "1px solid var(--border-primary, #cbd5e1)", padding: "0.35rem 0.5rem" }}>{renderInline(cell, `${key}-header-${cellIndex}`)}</th>)}</tr></thead>
      <tbody>{block.rows.map((row, rowIndex) => <tr key={rowIndex}>{block.header.map((_cell, cellIndex) => <td key={cellIndex} style={{ verticalAlign: "top", borderBottom: "1px solid var(--border-primary, #e2e8f0)", padding: "0.35rem 0.5rem" }}>{renderInline(row[cellIndex] || [], `${key}-${rowIndex}-${cellIndex}`)}</td>)}</tr>)}</tbody>
    </table></div>;
  });
}

/** Render the report Markdown subset without interpreting raw HTML. */
export function MarkdownContent({ content }: { content: string }) {
  return <div style={{ display: "grid", gap: "0.8rem" }}>{renderBlocks(parseMarkdown(content), "markdown")}</div>;
}
