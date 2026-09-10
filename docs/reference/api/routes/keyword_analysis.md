# Route Module: `src.api.routes.keyword_analysis`

Router prefix: `/api/v1/keyword-analysis`. Every endpoint requires page permission `Keyword Analysis`; `POST /recategorize` additionally requires `Action: Trigger AI Functions`.

## Read Endpoints

| Endpoint | Function | Behavior |
|---|---|---|
| `GET /overview` | `keyword_overview` | Counts keywords/articles, weights, used/unused keywords, and articles with matches |
| `GET /keyword-stats` | `keyword_stats` | Filters and sorts configured keywords by weight, trigger count, or contribution |
| `GET /category-distribution` | `category_distribution` | Counts categories and average scores, optionally after a day cutoff |
| `GET /timeline` | `keyword_timeline` | Aggregates total/matched articles and average score by day or week |
| `GET /keyword-articles` | `keyword_articles` | Returns recent articles whose persisted `keywords_found` contains the requested word |
| `GET /score-distribution` | `score_distribution` | Buckets scores by configurable bucket size and reports top category |
| `GET /category-keyword-matrix` | `category_keyword_matrix` | Builds a category by top-keyword occurrence matrix |
| `GET /category-details` | `category_details` | Returns category totals, score average, top keywords/sources, and up to 50 recent articles |

All handlers open a `SessionLocal` session and close it in `finally`. Filters are calculated from persisted article fields rather than re-running the scorer.

## `POST /recategorize`

`recategorize_all` loads every article, calls `categorize_text` on title plus summary, counts changed categories, commits once, and returns `{status, total, changed}`. A failure before commit is not silently converted to success; the session is always closed.
