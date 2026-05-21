import logging
import urllib3
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from src.core.db import SessionLocal
from src.core.config import ELASTIC_URL, ELASTIC_API_KEY
from src.models.schema import ElasticEvent

logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    es = Elasticsearch(ELASTIC_URL, api_key=ELASTIC_API_KEY, verify_certs=False)
except Exception as e:
    logger.error("Failed to connect to Elastic: %s", e)
    es = None


def sync_elastic_telemetry(hours_back=24):
    if not es:
        return

    cutoff_time = (datetime.utcnow() - timedelta(hours=hours_back)).isoformat()

    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": cutoff_time}}}
                ],
                "minimum_should_match": 1,
                "should": [
                    {"terms": {"log.level": ["emergency", "alert", "critical", "error", "severe"]}},
                    {"range": {"event.severity": {"lte": 3}}}
                ]
            }
        },
        "size": 500,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "boolean"}}]
    }

    try:
        res = es.search(index="*,-.*", body=query, ignore_unavailable=True)
        hits = res['hits']['hits']

        with SessionLocal() as db:
            for hit in hits:
                doc_id = hit['_id']
                if db.query(ElasticEvent).filter_by(id=doc_id).first():
                    continue

                source = hit['_source']

                log_level = source.get('log', {}).get('level')
                event_sev_num = source.get('event', {}).get('severity')

                if log_level:
                    final_sev = str(log_level).upper()
                elif isinstance(event_sev_num, int):
                    if event_sev_num <= 2:
                        final_sev = "CRITICAL"
                    elif event_sev_num == 3:
                        final_sev = "HIGH"
                    else:
                        final_sev = "WARNING"
                else:
                    final_sev = "UNKNOWN"

                msg = source.get('message')
                if not msg:
                    msg = source.get('event', {}).get('original', 'No payload provided')

                src_ip = source.get('source', {}).get('ip')
                if not src_ip:
                    src_ip = source.get('log', {}).get('source', {}).get('address', 'Unknown')

                evt_cat = source.get('event', {}).get('category', ['Unknown'])
                cat_str = evt_cat[0] if isinstance(evt_cat, list) and evt_cat else str(evt_cat)

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
        logger.error("Elastic fetch error: %s", e)


def execute_live_query(index_pattern="*", query_body=None, size=100):
    if not es:
        return {"error": "Elasticsearch client is not connected."}

    if not query_body:
        query_body = {
            "query": {"match_all": {}},
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "boolean"}}]
        }

    query_body["size"] = min(size, 500)

    try:
        res = es.search(index=index_pattern, body=query_body, ignore_unavailable=True)
        return res['hits']['hits']
    except Exception as e:
        return {"error": str(e)}


def purge_stale_elastic_data(hours_to_keep=72):
    with SessionLocal() as db:
        cutoff = datetime.utcnow() - timedelta(hours=hours_to_keep)
        db.query(ElasticEvent).filter(ElasticEvent.timestamp < cutoff).delete()
        db.commit()
