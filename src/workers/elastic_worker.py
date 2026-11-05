"""Query Elasticsearch safely and maintain the bounded local high-severity event cache."""

import logging
import re
import threading
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from elasticsearch import Elasticsearch
from src.core.db import SessionLocal
from src.core.runtime_settings import resolve_operational_settings
from src.models.schema import ElasticEvent

logger = logging.getLogger(__name__)

es = None
_es_settings_signature = None
_es_lock = threading.RLock()


def _get_client(operational_settings=None):
    """Create or refresh the process-local client from live database/environment settings."""
    global es, _es_settings_signature
    if operational_settings is None:
        operational_settings, _sources = resolve_operational_settings()

    endpoint = (operational_settings.get("elastic_url") or "").strip()
    api_key = (operational_settings.get("elastic_api_key") or "").strip()
    verify_certs = bool(operational_settings.get("elastic_verify_certs", True))
    ca_certs = operational_settings.get("elastic_ca_certs") or None
    request_timeout = float(operational_settings.get("elastic_request_timeout") or 15)
    signature = (endpoint, api_key, verify_certs, ca_certs, request_timeout)

    with _es_lock:
        if signature == _es_settings_signature and (es is not None or not endpoint):
            return es
        if es is not None:
            try:
                es.close()
            except Exception:
                logger.debug("Failed to close stale Elasticsearch client", exc_info=True)
            es = None
        _es_settings_signature = signature

        if not endpoint:
            logger.info("Elasticsearch client not created because ELASTIC_URL is not configured.")
            return None

        try:
            endpoint_host = urlsplit(endpoint).hostname or "invalid"
        except ValueError:
            endpoint_host = "invalid"

        options = {
            "verify_certs": verify_certs,
            "request_timeout": request_timeout,
            "max_retries": 2,
            "retry_on_timeout": True,
        }
        if ca_certs:
            options["ca_certs"] = ca_certs
        if api_key.casefold() in {"your_read_only_api_key", "changeme", "placeholder"}:
            logger.warning("Ignoring a placeholder Elasticsearch API key.")
            api_key = ""
        if api_key:
            options["api_key"] = api_key
        logger.info(
            "Creating Elasticsearch client host=%s verify_certs=%s api_key_configured=%s timeout=%ss",
            endpoint_host, verify_certs, bool(api_key), request_timeout,
        )
        try:
            es = Elasticsearch(endpoint, **options)
            return es
        except Exception:
            logger.exception("Failed to create Elasticsearch client")
            return None


def sync_elastic_telemetry(hours_back=24):
    """Query recent high-severity events with bounded scroll pages and upsert the local cache."""
    if not isinstance(hours_back, int) or isinstance(hours_back, bool) or hours_back < 1:
        raise ValueError("hours_back must be a positive integer")

    operational_settings, _sources = resolve_operational_settings()
    endpoint = (operational_settings.get("elastic_url") or "").strip()
    max_results = int(operational_settings.get("elastic_max_results") or 500)
    if not endpoint:
        logger.info("Elasticsearch sync skipped because ELASTIC_URL is not configured.")
        return {"status": "skipped", "imported": 0, "message": "ELASTIC_URL is not configured."}

    client = _get_client(operational_settings)
    if client is None:
        logger.error("Elasticsearch sync stopped because a client could not be created.")
        return {"status": "error", "imported": 0, "message": "Elasticsearch client is not configured."}

    cutoff_time = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()

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
        "size": max_results,
        "sort": [
            {"@timestamp": {"order": "desc", "unmapped_type": "date"}},
        ],
    }

    try:
        hits = []
        logger.info(
            "Starting Elasticsearch cache sync hours_back=%d page_size=%d",
            hours_back, max_results,
        )
        res = client.search(
            index="*,-.*",
            body=query,
            scroll="1m",
            ignore_unavailable=True,
            allow_no_indices=True,
        )
        scroll_id = res.get("_scroll_id")
        try:
            # Scroll keeps a stable result snapshot and avoids sorting on the
            # reserved _id field, which Elasticsearch does not support.
            for page_number in range(20):
                batch = res.get("hits", {}).get("hits", [])
                if not batch:
                    break
                hits.extend(batch)
                logger.debug(
                    "Elasticsearch sync page=%d hits=%d total_hits=%d",
                    page_number + 1, len(batch), len(hits),
                )
                if len(batch) < max_results or not scroll_id:
                    break
                res = client.scroll(scroll_id=scroll_id, scroll="1m")
                scroll_id = res.get("_scroll_id") or scroll_id
        finally:
            if scroll_id:
                try:
                    client.clear_scroll(scroll_id=scroll_id)
                except Exception:
                    logger.warning("Unable to clear Elasticsearch scroll context.", exc_info=True)

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
        logger.info("Elasticsearch cache sync complete fetched=%d imported=%d", len(hits), imported)
        return {"status": "ok", "imported": imported}
    except Exception:
        logger.exception("Elasticsearch cache sync failed hours_back=%d", hours_back)
        return {"status": "error", "imported": 0, "message": "Elasticsearch sync failed."}


def execute_live_query(index_pattern="*", query_body=None, size=100):
    """Execute a bounded live Elastic query for analyst inspection."""
    if not isinstance(index_pattern, str) or not index_pattern or not re.fullmatch(r"[A-Za-z0-9_.*?,:-]+", index_pattern):
        return {"error": "Invalid Elasticsearch index pattern."}
    operational_settings, _sources = resolve_operational_settings()
    max_results = int(operational_settings.get("elastic_max_results") or 500)
    if not isinstance(size, int) or isinstance(size, bool) or size < 1 or size > max_results:
        return {"error": "Invalid Elasticsearch result size."}
    if query_body is not None and not isinstance(query_body, dict):
        return {"error": "Invalid Elasticsearch query."}

    client = _get_client(operational_settings)
    if client is None:
        return {"error": "Elasticsearch client is not connected."}

    if not query_body:
        query_body = {
            "query": {"match_all": {}},
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]
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
    """Delete cached Elastic events older than the configured local-retention window."""
    with SessionLocal() as db:
        cutoff = datetime.utcnow() - timedelta(hours=hours_to_keep)
        db.query(ElasticEvent).filter(ElasticEvent.timestamp < cutoff).delete()
        db.commit()


# Public name used by the manual-sync API endpoint.
run_elastic_sync = sync_elastic_telemetry
