import logging
import re
from copy import deepcopy
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from src.core.db import SessionLocal
from src.core.config import (
    ELASTIC_URL,
    ELASTIC_API_KEY,
    ELASTIC_VERIFY_CERTS,
    ELASTIC_CA_CERTS,
    ELASTIC_REQUEST_TIMEOUT,
    ELASTIC_MAX_RESULTS,
)
from src.models.schema import ElasticEvent

logger = logging.getLogger(__name__)

es = None


def _get_client():
    """Create the client on first use so API imports do not require Elastic."""
    global es
    if es is not None:
        return es

    options = {
        "verify_certs": ELASTIC_VERIFY_CERTS,
        "request_timeout": ELASTIC_REQUEST_TIMEOUT,
        "max_retries": 2,
        "retry_on_timeout": True,
    }
    if ELASTIC_CA_CERTS:
        options["ca_certs"] = ELASTIC_CA_CERTS
    if ELASTIC_API_KEY:
        options["api_key"] = ELASTIC_API_KEY
    try:
        es = Elasticsearch(ELASTIC_URL, **options)
        return es
    except Exception:
        logger.exception("Failed to create Elasticsearch client")
        return None


def sync_elastic_telemetry(hours_back=24):
    if not isinstance(hours_back, int) or isinstance(hours_back, bool) or hours_back < 1:
        raise ValueError("hours_back must be a positive integer")

    client = _get_client()
    if client is None:
        return {"status": "error", "imported": 0, "message": "Elasticsearch client is not connected."}

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
        "size": ELASTIC_MAX_RESULTS,
        "sort": [
            {"@timestamp": {"order": "desc", "unmapped_type": "boolean"}},
            {"_id": {"order": "asc"}},
        ],
    }

    try:
        hits = []
        # Search-after avoids silently dropping events during high-volume windows.
        for _ in range(20):
            res = client.search(index="*,-.*", body=query, ignore_unavailable=True)
            batch = res.get("hits", {}).get("hits", [])
            if not batch:
                break
            hits.extend(batch)
            if len(batch) < ELASTIC_MAX_RESULTS or not batch[-1].get("sort"):
                break
            query["search_after"] = batch[-1]["sort"]
        imported = 0

        with SessionLocal() as db:
            for hit in hits:
                doc_id = str(hit.get('_id', ''))
                index_name = str(hit.get('_index', 'unknown'))
                if not doc_id:
                    continue
                # IDs are only unique within an Elasticsearch index.
                event_id = f"{index_name}:{doc_id}"
                if db.query(ElasticEvent).filter(ElasticEvent.id.in_([event_id, doc_id])).first():
                    continue

                source = hit.get('_source', {})
                if not isinstance(source, dict):
                    source = {}

                log_data = source.get('log') if isinstance(source.get('log'), dict) else {}
                event_data = source.get('event') if isinstance(source.get('event'), dict) else {}
                log_level = log_data.get('level')
                event_sev_num = event_data.get('severity')

                if log_level:
                    final_sev = str(log_level).upper()
                else:
                    try:
                        numeric_severity = float(event_sev_num)
                    except (TypeError, ValueError):
                        numeric_severity = None
                    if numeric_severity is not None:
                        if numeric_severity <= 2:
                            final_sev = "CRITICAL"
                        elif numeric_severity <= 3:
                            final_sev = "HIGH"
                        else:
                            final_sev = "WARNING"
                    else:
                        final_sev = "UNKNOWN"

                msg = source.get('message')
                if not msg:
                    msg = event_data.get('original', 'No payload provided')

                source_data = source.get('source') if isinstance(source.get('source'), dict) else {}
                src_ip = source_data.get('ip')
                if not src_ip:
                    log_source = log_data.get('source') if isinstance(log_data.get('source'), dict) else {}
                    src_ip = log_source.get('address', 'Unknown')

                evt_cat = event_data.get('category', ['Unknown'])
                cat_str = evt_cat[0] if isinstance(evt_cat, list) and evt_cat else str(evt_cat)

                timestamp = source.get('@timestamp')
                try:
                    timestamp = datetime.fromisoformat(
                        str(timestamp or datetime.utcnow().isoformat()).replace('Z', '+00:00')
                    )
                except ValueError:
                    timestamp = datetime.utcnow()

                new_event = ElasticEvent(
                    id=event_id,
                    index_name=index_name,
                    timestamp=timestamp,
                    severity=final_sev,
                    message=str(msg)[:250],
                    source_ip=str(src_ip),
                    event_category=str(cat_str).upper()
                )
                db.add(new_event)
                imported += 1
            db.commit()
        return {"status": "ok", "imported": imported}
    except Exception as e:
        logger.error("Elastic fetch error: %s", e)
        return {"status": "error", "imported": 0, "message": "Elasticsearch request failed."}


def execute_live_query(index_pattern="*", query_body=None, size=100):
    if not isinstance(index_pattern, str) or not index_pattern or not re.fullmatch(r"[A-Za-z0-9_.*?,:-]+", index_pattern):
        return {"error": "Invalid Elasticsearch index pattern."}
    if not isinstance(size, int) or isinstance(size, bool) or size < 1 or size > ELASTIC_MAX_RESULTS:
        return {"error": "Invalid Elasticsearch result size."}
    if query_body is not None and not isinstance(query_body, dict):
        return {"error": "Invalid Elasticsearch query."}

    client = _get_client()
    if client is None:
        return {"error": "Elasticsearch client is not connected."}

    if not query_body:
        query_body = {
            "query": {"match_all": {}},
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "boolean"}}]
        }

    query_body = deepcopy(query_body)
    query_body["size"] = size

    try:
        res = client.search(index=index_pattern, body=query_body, ignore_unavailable=True)
        return res.get('hits', {}).get('hits', [])
    except Exception:
        logger.exception("Elastic live query failed")
        return {"error": "Elasticsearch request failed."}


def purge_stale_elastic_data(hours_to_keep=72):
    with SessionLocal() as db:
        cutoff = datetime.utcnow() - timedelta(hours=hours_to_keep)
        db.query(ElasticEvent).filter(ElasticEvent.timestamp < cutoff).delete()
        db.commit()


# Public name used by the manual-sync API endpoint.
run_elastic_sync = sync_elastic_telemetry
