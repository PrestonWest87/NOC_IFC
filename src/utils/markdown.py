"""Render the Markdown subset produced and edited by IFC reports safely."""

from html import escape
import re
from urllib.parse import urlsplit


_LIST_ITEM = re.compile(r"^([ \t]*)([-+*]|\d+[.)])\s+(.*)$")
_HEADING = re.compile(r"^ {0,3}(#{1,6})\s+(.+?)\s*#*\s*$")
_QUOTE = re.compile(r"^ {0,3}> ?(.*)$")
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})\s*([\w+-]*)[^\n]*$")
_RULE = re.compile(r"^ {0,3}(?:(?:\*\s*){3,}|(?:-\s*){3,}|(?:_\s*){3,})$")


def _safe_href(value: str) -> str | None:
    """Allow ordinary links but reject script/data schemes and protocol-relative URLs."""
    value = value.strip()
    if not value or value.startswith("//") or re.search(r"[\x00-\x20]", value):
        return None
    try:
        scheme = urlsplit(value).scheme.lower()
    except ValueError:
        return None
    return value if not scheme or scheme in {"http", "https", "mailto"} else None


def _closing_delimiter(text: str, delimiter: str, start: int) -> int:
    index = text.find(delimiter, start)
    while index >= 0:
        slashes = 0
        cursor = index - 1
        while cursor >= 0 and text[cursor] == "\\":
            slashes += 1
            cursor -= 1
        if slashes % 2 == 0:
            return index
        index = text.find(delimiter, index + len(delimiter))
    return -1


def _link_parts(text: str, start: int):
    label_end = text.find("](", start + 1)
    if label_end < 0:
        return None
    end = _closing_delimiter(text, ")", label_end + 2)
    if end < 0:
        return None
    destination = text[label_end + 2:end].strip()
    if destination.startswith("<") and ">" in destination:
        href = destination[1:destination.index(">")]
    else:
        href = destination.split(None, 1)[0] if destination else ""
    return (end, text[start + 1:label_end], href) if href else None


def _render_inline(text: str, depth: int = 0) -> str:
    if depth > 8:
        return escape(text)
    output = []
    plain = []

    def flush():
        if plain:
            output.append(escape("".join(plain)))
            plain.clear()

    index = 0
    while index < len(text):
        if text[index] == "\\" and index + 1 < len(text):
            plain.append(text[index + 1])
            index += 2
            continue

        if text[index] == "`":
            ticks = re.match(r"`+", text[index:]).group(0)
            end = _closing_delimiter(text, ticks, index + len(ticks))
            if end >= 0:
                flush()
                code = text[index + len(ticks):end].replace("\n", " ").strip()
                output.append(f'<code style="font-family:monospace;background:#f3f4f6;padding:1px 3px;border-radius:3px;">{escape(code)}</code>')
                index = end + len(ticks)
                continue

        if text[index] == "[":
            link = _link_parts(text, index)
            if link:
                end, label, raw_href = link
                flush()
                href = _safe_href(raw_href)
                if href:
                    output.append(
                        f'<a href="{escape(href, quote=True)}" rel="noopener noreferrer" '
                        f'style="color:#2563eb;text-decoration:underline;">{_render_inline(label, depth + 1)}</a>'
                    )
                else:
                    output.append(escape(text[index:end + 1]))
                index = end + 1
                continue

        strong = text[index:index + 2]
        if strong in {"**", "__"}:
            end = _closing_delimiter(text, strong, index + 2)
            if end > index + 2 and text[index + 2] != " " and text[end - 1] != " ":
                flush()
                output.append(f"<strong>{_render_inline(text[index + 2:end], depth + 1)}</strong>")
                index = end + 2
                continue

        emphasis = text[index]
        if emphasis in {"*", "_"} and text[index + 1:index + 2] != emphasis:
            end = _closing_delimiter(text, emphasis, index + 1)
            if end > index + 1 and text[index + 1] != " " and text[end - 1] != " ":
                flush()
                output.append(f"<em>{_render_inline(text[index + 1:end], depth + 1)}</em>")
                index = end + 1
                continue

        plain.append(text[index])
        index += 1

    flush()
    return "".join(output)


def _list_marker(line: str):
    match = _LIST_ITEM.match(line)
    if not match:
        return None
    marker = match.group(2)
    return {
        "indent": len(match.group(1).expandtabs(4)),
        "ordered": marker[0].isdigit(),
        "start": int(re.match(r"\d+", marker).group(0)) if marker[0].isdigit() else 1,
        "content": match.group(3),
    }


def _split_table_row(line: str) -> list[str]:
    value = line.strip()
    if value.startswith("|"):
        value = value[1:]
    if value.endswith("|"):
        value = value[:-1]
    cells, cell = [], []
    escaped = False
    for character in value:
        if character == "|" and not escaped:
            cells.append("".join(cell).replace(r"\|", "|").strip())
            cell = []
        else:
            cell.append(character)
        escaped = character == "\\" and not escaped
        if character != "\\":
            escaped = False
    cells.append("".join(cell).replace(r"\|", "|").strip())
    return cells


def _is_table_at(lines: list[str], index: int) -> bool:
    if index + 1 >= len(lines) or "|" not in lines[index]:
        return False
    cells = _split_table_row(lines[index + 1])
    return len(cells) > 1 and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells)


def _is_block_start(lines: list[str], index: int) -> bool:
    line = lines[index]
    return bool(
        _FENCE.match(line) or _HEADING.match(line) or _QUOTE.match(line)
        or _list_marker(line) or _RULE.match(line) or _is_table_at(lines, index)
    )


def _render_list(lines: list[str], start_index: int, depth: int = 0) -> tuple[str, int]:
    first = _list_marker(lines[start_index])
    base_indent = first["indent"]
    ordered = first["ordered"]
    items = []
    index = start_index
    while index < len(lines):
        if not lines[index].strip():
            next_index = index + 1
            while next_index < len(lines) and not lines[next_index].strip():
                next_index += 1
            next_marker = _list_marker(lines[next_index]) if next_index < len(lines) else None
            if next_marker and next_marker["indent"] >= base_indent:
                index = next_index
                continue
            break

        marker = _list_marker(lines[index])
        if marker and marker["indent"] > base_indent:
            if not items:
                break
            if depth >= 8:
                items[-1]["text"] += " " + marker["content"]
                index += 1
                continue
            nested, index = _render_list(lines, index, depth + 1)
            items[-1]["nested"].append(nested)
            continue
        if not marker:
            indent = len(lines[index]) - len(lines[index].lstrip(" \t"))
            if indent > base_indent and items:
                items[-1]["text"] += " " + lines[index].strip()
                index += 1
                continue
            break
        if marker["indent"] < base_indent or marker["ordered"] != ordered:
            break

        items.append({"text": marker["content"], "nested": []})
        index += 1

    tag = "ol" if ordered else "ul"
    start = f' start="{first["start"]}"' if ordered and first["start"] != 1 else ""
    rendered_items = "".join(
        f'<li>{_render_inline(item["text"])}{"".join(item["nested"])}</li>' for item in items
    )
    return f'<{tag}{start} style="margin:0 0 12px;padding-left:24px;">{rendered_items}</{tag}>', index


def _render_blocks(lines: list[str], depth: int = 0) -> str:
    if depth > 8:
        return f'<p style="margin:0 0 12px;line-height:1.6;">{_render_inline(" ".join(line.strip() for line in lines))}</p>'
    output = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            continue

        fence = _FENCE.match(line)
        if fence:
            marker, language = fence.group(1), fence.group(2)
            code = []
            index += 1
            close = re.compile(rf"^ {{0,3}}{re.escape(marker[0])}{{{len(marker)},}}\s*$")
            while index < len(lines) and not close.match(lines[index]):
                code.append(lines[index])
                index += 1
            if index < len(lines):
                index += 1
            language_attr = f' class="language-{language}"' if re.fullmatch(r"[\w+-]+", language or "") else ""
            code_content = escape("\n".join(code))
            output.append(
                '<pre style="overflow:auto;white-space:pre-wrap;background:#f3f4f6;padding:12px;border-radius:4px;">'
                f'<code{language_attr}>{code_content}</code></pre>'
            )
            continue

        heading = _HEADING.match(line)
        if heading:
            level, title = len(heading.group(1)), heading.group(2)
            output.append(f'<h{level} style="color:#111827;margin:20px 0 10px;">{_render_inline(title)}</h{level}>')
            index += 1
            continue

        if _RULE.match(line):
            output.append('<hr style="border:0;border-top:1px solid #cbd5e1;margin:18px 0;">')
            index += 1
            continue

        if _QUOTE.match(line):
            quote_lines = []
            while index < len(lines):
                match = _QUOTE.match(lines[index])
                if not match:
                    break
                quote_lines.append(match.group(1))
                index += 1
            output.append(
                '<blockquote style="margin:12px 0;padding:4px 14px;border-left:3px solid #94a3b8;color:#475569;">'
                f'{_render_blocks(quote_lines, depth + 1)}</blockquote>'
            )
            continue

        if _is_table_at(lines, index):
            header = _split_table_row(lines[index])
            index += 2
            rows = []
            while index < len(lines) and lines[index].strip() and "|" in lines[index]:
                rows.append(_split_table_row(lines[index]))
                index += 1
            header_html = "".join(
                f'<th style="text-align:left;border:1px solid #cbd5e1;padding:6px;background:#f8fafc;">{_render_inline(cell)}</th>'
                for cell in header
            )
            rows_html = []
            for row in rows:
                cells = [
                    f'<td style="vertical-align:top;border:1px solid #cbd5e1;padding:6px;">{_render_inline(row[i] if i < len(row) else "")}</td>'
                    for i in range(len(header))
                ]
                rows_html.append("<tr>" + "".join(cells) + "</tr>")
            output.append(
                '<div style="overflow-x:auto;"><table style="border-collapse:collapse;margin:12px 0;width:100%;">'
                f'<thead><tr>{header_html}</tr></thead><tbody>{"".join(rows_html)}</tbody></table></div>'
            )
            continue

        if _list_marker(line):
            rendered, index = _render_list(lines, index, depth)
            output.append(rendered)
            continue

        paragraph = []
        while index < len(lines) and lines[index].strip() and not (paragraph and _is_block_start(lines, index)):
            paragraph.append(lines[index])
            index += 1
        parts = []
        for part_index, part in enumerate(paragraph):
            hard_break = bool(re.search(r"(?: {2,}|\\)$", part))
            parts.append(_render_inline(re.sub(r"(?: {2,}|\\)$", "", part).strip()))
            if part_index < len(paragraph) - 1:
                parts.append("<br>" if hard_break else " ")
        output.append(f'<p style="margin:0 0 12px;line-height:1.6;">{"".join(parts)}</p>')
    return "".join(output)


def markdown_to_html(content: str) -> str:
    """Render application Markdown as safe, email-friendly HTML without raw HTML passthrough."""
    text = str(content or "").replace("\r\n", "\n").replace("\r", "\n")
    return _render_blocks(text.split("\n"))
