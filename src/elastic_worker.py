import os
import logging
import urllib3
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from src.database import SessionLocal, ElasticEvent

# Suppress the SSL warnings for a cleaner output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ELASTIC_URL = os.environ.get("ELASTIC_URL", "https://localhost:9200")
ELASTIC_API_KEY = os.environ.get("ELASTIC_API_KEY", "your_read_only_api_key")

try:
    es = Elasticsearch(ELASTIC_URL, api_key=ELASTIC_API_KEY, verify_certs=False)
except Exception as e:
    logging.error(f"Failed to connect to Elastic: {e}")
    es = None

def sync_elastic_telemetry(hours_back=24):
    """Pulls high-severity SIEM alerts to enrich OSINT and AIOps correlation."""
    if not es: return
    
    cutoff_time = (datetime.utcnow() - timedelta(hours=hours_back)).isoformat()
    
    # NEW QUERY: Tailored to Cisco FTD and ECS standards
    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": cutoff_time}}}
                ],
                "minimum_should_match": 1,
                "should": [
                    # Catch string-based severity (ECS standard)
                    {"terms": {"log.level": ["emergency", "alert", "critical", "error", "severe"]}},
                    # Catch numeric-based Cisco syslog severity (0-3 are Crit/Error)
                    {"range": {"event.severity": {"lte": 3}}} 
                ]
            }
        },
        "size": 500, # Sufficient for daily reporting
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "boolean"}}]
    }

    try:
        # Search all non-system indices (catches .ds-logs data streams safely)
        res = es.search(index="*,-.*", body=query, ignore_unavailable=True)
        hits = res['hits']['hits']
        
        with SessionLocal() as db:
            for hit in hits:
                doc_id = hit['_id']
                if db.query(ElasticEvent).filter_by(id=doc_id).first():
                    continue
                    
                source = hit['_source']
                
                # --- INTELLIGENT FIELD EXTRACTION ---
                
                # 1. Determine Severity String (Map numbers to English if necessary)
                log_level = source.get('log', {}).get('level')
                event_sev_num = source.get('event', {}).get('severity')
                
                if log_level:
                    final_sev = str(log_level).upper()
                elif isinstance(event_sev_num, int):
                    if event_sev_num <= 2: final_sev = "CRITICAL"
                    elif event_sev_num == 3: final_sev = "HIGH"
                    else: final_sev = "WARNING"
                else:
                    final_sev = "UNKNOWN"
                    
                # 2. Extract Message
                msg = source.get('message')
                if not msg:
                    msg = source.get('event', {}).get('original', 'No payload provided')
                    
                # 3. Extract Source IP
                src_ip = source.get('source', {}).get('ip')
                if not src_ip:
                    src_ip = source.get('log', {}).get('source', {}).get('address', 'Unknown')
                    
                # 4. Extract Category (Safely handle lists)
                evt_cat = source.get('event', {}).get('category', ['Unknown'])
                cat_str = evt_cat[0] if isinstance(evt_cat, list) and evt_cat else str(evt_cat)

                # --- DATABASE INSERTION ---
                new_event = ElasticEvent(
                    id=doc_id,
                    index_name=hit['_index'],
                    timestamp=datetime.fromisoformat(source.get('@timestamp', datetime.utcnow().isoformat()).replace('Z', '+00:00')),
                    severity=final_sev,
                    message=str(msg)[:250],
                    source_ip=str(src_ip),
                    event_category=str(cat_str).upper()
                )
                db.add(new_event)
            db.commit()
    except Exception as e:
        logging.error(f"Elastic fetch error: {e}")

def execute_live_query(index_pattern="*", query_body=None, size=100):
    """Executes a direct, live query against Elastic without touching SQLite."""
    if not es:
        return {"error": "Elasticsearch client is not connected."}
    
    if not query_body:
        query_body = {
            "query": {"match_all": {}},
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "boolean"}}]
        }
        
    # Inject a hard size limit to protect your 4GB RAM system
    query_body["size"] = min(size, 500) 
    
    try:
        res = es.search(index=index_pattern, body=query_body, ignore_unavailable=True)
        return res['hits']['hits']
    except Exception as e:
        return {"error": str(e)}

def purge_stale_elastic_data(hours_to_keep=72):
    """Ensures the local SQLite cache remains tiny by dropping old SIEM records."""
    with SessionLocal() as db:
        cutoff = datetime.utcnow() - timedelta(hours=hours_to_keep)
        db.query(ElasticEvent).filter(ElasticEvent.timestamp < cutoff).delete()
        db.commit()
