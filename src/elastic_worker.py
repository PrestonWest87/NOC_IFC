import os
import json
import urllib3
from elasticsearch import Elasticsearch

# Suppress the SSL warnings for a cleaner output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ELASTIC_URL = os.environ.get("ELASTIC_URL", "https://localhost:9200")
ELASTIC_API_KEY = os.environ.get("ELASTIC_API_KEY", "your_read_only_api_key")

print("========================================")
print("   ELASTIC DIAGNOSTIC TOOL (LITE)       ")
print("========================================")
print(f"Attempting data pull from: {ELASTIC_URL}")

try:
    es = Elasticsearch(ELASTIC_URL, api_key=ELASTIC_API_KEY, verify_certs=False)
    
    print("\n--- PULLING LATEST RAW DOCUMENT ---")
    
    # Match absolutely anything, sorted by the newest first
    query = {
        "query": {"match_all": {}},
        "size": 1,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "boolean"}}]
    }
    
    # Search across all indices, but safely ignore ones we don't have permission for
    res = es.search(
        index="*", 
        body=query, 
        ignore_unavailable=True,
        allow_no_indices=True
    )
    
    hits = res['hits']['hits']
    
    if hits:
        latest_doc = hits[0]
        print(f"✅ SUCCESS! Document pulled from index: {latest_doc['_index']}")
        print(f"Document ID: {latest_doc['_id']}")
        print("\n--- JSON PAYLOAD ---")
        # Pretty-print the raw JSON payload
        print(json.dumps(latest_doc['_source'], indent=4))
    else:
        print("❌ Search executed successfully, but 0 documents were returned.")
        print("   Make sure your API key has read access to your specific log indices.")

except Exception as e:
    print(f"\n❌ ERROR: {e}")
