import os
import logging
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from src.database import SessionLocal, ElasticEvent

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
    
    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": cutoff_time}}},
                    {"terms": {"event.severity": ["high", "critical", "severe"]}}
                ]
            }
        },
        "size": 500, # Sufficient for daily reporting
        "sort": [{"@timestamp": {"order": "desc"}}]
    }

    try:
        res = es.search(index="logs-*,alerts-*", body=query)
        hits = res['hits']['hits']
        
        with SessionLocal() as db:
            for hit in hits:
                doc_id = hit['_id']
                if db.query(ElasticEvent).filter_by(id=doc_id).first():
                    continue
                    
                source = hit['_source']
                new_event = ElasticEvent(
                    id=doc_id,
                    index_name=hit['_index'],
                    timestamp=datetime.fromisoformat(source.get('@timestamp', datetime.utcnow().isoformat()).replace('Z', '+00:00')),
                    severity=str(source.get('event', {}).get('severity', 'unknown')).upper(),
                    message=str(source.get('message', 'No message provided'))[:250],
                    source_ip=str(source.get('source', {}).get('ip', 'Unknown')),
                    event_category=str(source.get('event', {}).get('category', 'Unknown'))
                )
                db.add(new_event)
            db.commit()
    except Exception as e:
        logging.error(f"Elastic fetch error: {e}")

def purge_stale_elastic_data(hours_to_keep=72):
    """Ensures the local SQLite cache remains tiny by dropping old SIEM records."""
    with SessionLocal() as db:
        cutoff = datetime.utcnow() - timedelta(hours=hours_to_keep)
        db.query(ElasticEvent).filter(ElasticEvent.timestamp < cutoff).delete()
        db.commit()