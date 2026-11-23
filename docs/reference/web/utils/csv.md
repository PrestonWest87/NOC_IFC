# Module: `web/src/utils/csv.ts`

Creates browser CSV downloads for Settings reference directories.

## Exports

| Symbol | Input | Behavior |
|---|---|---|
| `buildCsv(headers, rows)` | Column names and ordered rows of values | Returns UTF-8-friendly CSV text with a BOM, CRLF row separators, and every cell quoted with embedded quotes escaped. |
| `downloadCsv(filename, headers, rows)` | Download name, headers, and ordered rows | Builds a CSV Blob, creates a temporary object URL, and starts a browser download. |

Email-contact exports use the same headers accepted by their importers. Network-order exports write `associated_circuit_network_order_ids` as semicolon-separated circuit IDs so reciprocal associations can be restored through the existing CSV import.
