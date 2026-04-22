import os
import urllib3
from elasticsearch import Elasticsearch

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ELASTIC_URL = os.environ.get("ELASTIC_URL", "https://localhost:9200")
ELASTIC_API_KEY = os.environ.get("ELASTIC_API_KEY", "your_read_only_api_key")

print("========================================")
print("     ELASTIC API KEY ACCESS TESTER      ")
print("========================================")

try:
    es = Elasticsearch(ELASTIC_URL, api_key=ELASTIC_API_KEY, verify_certs=False)
    
    print("Executing broad access sweep...")
    
    # We use size: 0 because we don't want the actual logs, just the metadata/counts
    query = {
        "size": 0,
        "query": {
            "match_all": {}
        },
        "aggs": {
            "accessible_indices": {
                "terms": {
                    "field": "_index",
                    "size": 500  # Max number of indices to list
                }
            }
        }
    }
    
    # Search everything (*), but ignore anything we don't have permission for
    res = es.search(
        index="*", 
        body=query, 
        ignore_unavailable=True,
        allow_no_indices=True
    )
    
    buckets = res.get('aggregations', {}).get('accessible_indices', {}).get('buckets', [])
    
    if not buckets:
        print("\n[WARN] Query succeeded, but 0 indices were returned.")
        print("Your API key either has no read permissions, or the allowed indices are currently empty.")
    else:
        print(f"\n[OK] SUCCESS! Your API Key has read access to {len(buckets)} index/data streams:\n")
        print(f"{'INDEX / DATA STREAM NAME':<50} | {'DOCUMENTS SEEN'}")
        print("-" * 70)
        
        for bucket in buckets:
            index_name = bucket['key']
            doc_count = bucket['doc_count']
            print(f"{index_name:<50} | {doc_count:,}")
            
    print("\n========================================")

except Exception as e:
    print(f"\n[ERROR] ERROR: {e}")
