/** Build an Excel-friendly CSV while preserving commas, quotes, and line breaks in cells. */
export function buildCsv(headers: readonly string[], rows: readonly (readonly unknown[])[]): string {
  const cell = (value: unknown) => `"${String(value ?? "").replace(/"/g, '""')}"`;
  return `\uFEFF${[headers, ...rows].map(row => row.map(cell).join(",")).join("\r\n")}\r\n`;
}

/** Trigger a browser download for a CSV table. */
export function downloadCsv(
  filename: string,
  headers: readonly string[],
  rows: readonly (readonly unknown[])[],
): void {
  const url = URL.createObjectURL(new Blob([buildCsv(headers, rows)], { type: "text/csv;charset=utf-8;" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
