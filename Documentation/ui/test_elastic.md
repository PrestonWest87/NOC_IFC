# Module: `src/test_elastic.py`

## Overview

Diagnostic utility script that tests Elasticsearch API key read access. Connects to a configured Elasticsearch cluster using an API key, executes a broad index sweep aggregation query against all indices, and reports which indices the key has read access to along with document counts.

---

## Module-Level Execution Flow

**Purpose:** Tests and reports Elasticsearch API key permissions.

**Flow:**
1. Suppresses SSL/TLS insecure request warnings (for self-signed certs).
2. Reads `ELASTIC_URL` (default `https://localhost:9200`) and `ELASTIC_API_KEY` from environment variables.
3. Prints a header banner.
4. Creates an `Elasticsearch` client using the API key with `verify_certs=False`.
5. Executes a `match_all` aggregation query across all indices (`index="*"`) with `ignore_unavailable=True` and `allow_no_indices=True`:
   - `"size": 0` (no hits, only aggregation)
   - Aggregation `"accessible_indices"`: `terms` on `_index` field with `size: 500`
6. Processes the aggregation buckets:
   - If empty: reports that the key has no read permissions or indices are empty.
   - If populated: prints a table of index names and document counts.
7. Catches and prints any `Exception` as an error message.

**Dependencies:**
| Module | Usage |
|--------|-------|
| `os` | Environment variable access |
| `urllib3` | SSL warning suppression |
| `elasticsearch.Elasticsearch` | Elasticsearch client |

**Raises:** Exceptions are caught and printed to stdout (no re-raise).
