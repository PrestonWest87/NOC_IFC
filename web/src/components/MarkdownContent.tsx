import type { ReactNode } from "react";

function inlineMarkdown(value: string): ReactNode[] {
  return value.split(/(\*\*.*?\*\*)/g).map((part, index) =>
    part.startsWith("**") && part.endsWith("**")
      ? <strong key={index}>{part.slice(2, -2)}</strong>
      : part
  );
}

export function MarkdownContent({ content }: { content: string }) {
  const blocks = content.replace(/\r/g, "").split(/\n\s*\n/).filter(Boolean);
  return (
    <div style={{ display: "grid", gap: "0.8rem" }}>
      {blocks.map((block, blockIndex) => {
        const lines = block.split("\n").filter(line => line.trim());
        const headingMatch = lines[0]?.match(/^(#{2,3}) (.+)$/);
        if (headingMatch) {
          const level = headingMatch[1].length;
          const title = headingMatch[2];
          const heading = level === 3
            ? <h4 style={{ margin: "0.4rem 0 0", color: "var(--text-secondary, #475569)", fontSize: "0.95rem" }}>{title}</h4>
            : <h3 style={{ margin: "0.8rem 0 0.1rem", paddingBottom: "0.45rem", borderBottom: "1px solid var(--border-primary, #e2e8f0)", fontSize: "1.05rem" }}>{title}</h3>;
          if (lines.length === 1) return <div key={blockIndex}>{heading}</div>;
          return <div key={blockIndex} style={{ display: "grid", gap: "0.45rem" }}>{heading}<p style={{ margin: 0, lineHeight: 1.65 }}>{inlineMarkdown(lines.slice(1).join(" "))}</p></div>;
        }
        if (lines.every(line => /^\s*[-*] /.test(line))) {
          return (
            <ul key={blockIndex} style={{ margin: 0, paddingLeft: "1.25rem", display: "grid", gap: "0.35rem" }}>
              {lines.map((line, index) => <li key={index}>{inlineMarkdown(line.replace(/^\s*[-*] /, ""))}</li>)}
            </ul>
          );
        }
        return <p key={blockIndex} style={{ margin: 0, lineHeight: 1.65 }}>{inlineMarkdown(lines.join(" "))}</p>;
      })}
    </div>
  );
}
