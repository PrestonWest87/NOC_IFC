# Page: `KeywordAnalysisPage`

Route: `/keyword-analysis`. This protected React Query page provides overview, keyword, category, timeline, and cross-reference tabs. It reads the `/keyword-analysis/*` endpoints, uses 30-second polling for the overview, and invalidates keyword queries after recategorization.

The page does not calculate scores itself. It renders persisted weights, match counts, category distributions, timelines, score buckets, and category-keyword matrices returned by the API. Search, sort order, day range, selected keyword, and selected category are query inputs.
