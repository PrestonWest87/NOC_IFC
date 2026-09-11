# Page: `KeywordAnalysisPage`

Route: `/keyword-analysis`. This protected React Query page provides overview, keyword, category, timeline, and cross-reference tabs. It reads the `/keyword-analysis/*` endpoints, uses 30-second polling for the overview, and invalidates keyword queries after recategorization.

## Query Surface

| Query | Endpoint | Main inputs |
|---|---|---|
| Overview | `/overview` | None; refreshes every 30 seconds |
| Keyword stats | `/keyword-stats` | `sort_by`, `order`, `search`, `limit` |
| Category distribution | `/category-distribution` | `days` |
| Timeline | `/timeline` | `days`, selected `keyword`, `interval` |
| Category matrix | `/category-keyword-matrix` | `top_n` |
| Category details | `/category-details` | selected `category`, `days` |
| Keyword articles | `/keyword-articles` | selected `keyword`, `limit` |
| Score distribution | `/score-distribution` | `days`, `bucket_size` |

The recategorization mutation calls `/recategorize`, invalidates the keyword-analysis query family, and requires the backend action permission `Action: Trigger AI Functions`.

The page does not calculate scores itself. It renders persisted weights, match counts, category distributions, timelines, score buckets, and category-keyword matrices returned by the API. Search, sort order, day range, selected keyword, and selected category are query inputs.
