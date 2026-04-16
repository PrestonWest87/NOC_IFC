import os
import json
import urllib3
from elasticsearch import Elasticsearch

# Suppress the SSL warnings for a cleaner output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ELASTIC_URL = os.environ.get("ELASTIC_URL", "https://localhost:9200")
ELASTIC_API_KEY = os.environ.get("ELASTIC_API_KEY", "your_read_only_api_key")

print("========================================")
print("      ELASTIC DIAGNOSTIC TOOL           ")
print("========================================")
print(f"Attempting connection to: {ELASTIC_URL}")

try:
    es = Elasticsearch(ELASTIC_URL, api_key=ELASTIC_API_KEY, verify_certs=False)
    
    # 1. Verify Connection & Cluster Info
    info = es.info()
    print(f"\n✅ CONNECTION SUCCESSFUL!")
    print(f"Cluster Name: {info['cluster_name']}")
    print(f"Elastic Version: {info['version']['number']}")
    
    # 2. List All Available Indices
    print("\n--- AVAILABLE INDICES (Databases) ---")
    indices = es.cat.indices(format="json")
    non_system_indices = []
    
    for idx in indices:
        # Ignore Elastic's hidden system indices (which start with a dot)
        if not idx['index'].startswith('.'):
            non_system_indices.append(idx['index'])
            print(f"Name: {idx['index']:<30} | Document Count: {idx['docs.count']}")
            
    if not non_system_indices:
        print("⚠️ No non-system indices found. Your API key might not have permission to view them.")

    # 3. Pull 1 Raw Document to see the exact JSON structure
    print("\n--- RAW DOCUMENT STRUCTURE (LATEST EVENT) ---")
    
    # Match absolutely anything, sorted by the newest first
    query = {
        "query": {"match_all": {}},
        "size": 1,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "boolean"}}]
    }
    
    # Search across all non-system indices
    res = es.search(index="*,-.*", body=query, ignore_unavailable=True)
    hits = res['hits']['hits']
    
    if hits:
        latest_doc = hits[0]
        print(f"Document pulled from index: {latest_doc['_index']}")
        print(f"Document ID: {latest_doc['_id']}")
        print("\n--- JSON PAYLOAD ---")
        # Pretty-print the raw JSON payload
        print(json.dumps(latest_doc['_source'], indent=4))
    else:
        print("❌ Search completed, but 0 documents were returned.")

except Exception as e:
    print(f"\n❌ FATAL ERROR: {e}")
