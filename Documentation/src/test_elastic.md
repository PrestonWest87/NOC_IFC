# Enterprise Architecture & Functional Specification: `src/test_elastic.py`

## 1. Executive Overview

The `src/test_elastic.py` module is a **diagnostic utility** that validates API key access to Elasticsearch. It performs a broad sweep of all accessible indices and reports document counts—useful for verifying read permissions before enabling the `elastic_worker.py` sync engine.

---

## 2. Configuration

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `ELASTIC_URL` | `https://localhost:9200` | Elastic endpoint |
| `ELASTIC_API_KEY` | `your_read_only_api_key` | Read-only API key |

---

## 3. Execution Logic

### Connection Test

1. Initializes `Elasticsearch` client with API key
2. Suppresses SSL warnings via `urllib3.disable_warnings()`

### Access Sweep Query

```python
{
    "size": 0,  # No actual documents, just metadata
    "query": {"match_all": {}},
    "aggs": {
        "accessible_indices": {
            "terms": {
                "field": "_index",
                "size": 500
            }
        }
    }
}
```

Uses `size: 0` for efficiency—we only want index metadata, not document content.

---

## 4. Output Interpretation

### Success Case

```
========================================
     ELASTIC API KEY ACCESS TESTER      
========================================

Executing broad access sweep...

[OK] SUCCESS! Your API Key has read access to 12 index/data streams:

INDEX / DATA STREAM NAME                     | DOCUMENTS SEEN
----------------------------------------------------------------------
network_traffic_log-2024.12                 | 1,452,891
firewall_syslog-2024.12                     |   987,541
ids_alerts-2024.12                          |    23,401
...
========================================
```

### Warning Cases

| Output | Meaning |
|--------|---------|
| `[WARN] Query succeeded, but 0 indices returned` | API key has no read permission, or allowed indices are empty |
| `[ERROR] ERROR: message` | Connection failed (wrong URL, wrong key, network issue) |

---

## 5. Usage

```bash
# Set environment variables
export ELASTIC_URL="https://elastic.example.com:9200"
export ELASTIC_API_KEY="your_api_key_here"

# Run test
python src/test_elastic.py
```

---

## 6. API Citations

- **Elasticsearch Python Client:** https://elasticsearch-py.readthedocs.io/
- **Elasticsearch Aggregations:** https://www.elastic.co/guide/en/elasticsearch/reference/current/aggregations.html
- **Elasticsearch Security:** https://www.elastic.co/guide/en/elasticsearch/current/security.html