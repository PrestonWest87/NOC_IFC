"""Fetch regional weather, earthquake, and wildfire feeds and evaluate proximity."""

import requests
import math
import json
import hashlib
import logging
import time
import concurrent.futures
from email.utils import parsedate_to_datetime
from shapely.geometry import shape
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from src.core.db import SessionLocal
from src.models.schema import RegionalHazard, GeoJsonCache, MonitoredLocation, SystemConfig
from src.core.arkansas_coverage import (
    REQUEST_STATE_CODES,
    alert_state_codes,
    is_unexpired_alert,
    parse_nws_datetime,
    split_alerts_for_region,
)

CENTRAL_TZ = ZoneInfo("America/Chicago")
logger = logging.getLogger(__name__)


def _is_small_wildfire(details):
    """Classify a finite acreage value at or below one acre as a small fire."""
    try:
        acres = float(details.get("acres"))
    except (TypeError, ValueError):
        return False
    return math.isfinite(acres) and acres <= 1.0


def save_geojson_to_db(session, feed_name, data, duration_ms=None):
    """Upsert one provider GeoJSON layer and its refresh timestamp."""
    now = datetime.utcnow()
    feature_count = len((data or {}).get("features", [])) if isinstance(data, dict) else 0
    cache_entry = session.query(GeoJsonCache).filter_by(feed_name=feed_name).first()
    if cache_entry:
        cache_entry.data = data
        cache_entry.updated_at = now
        cache_entry.last_attempt_at = now
        cache_entry.last_success_at = now
        cache_entry.last_error = None
        cache_entry.last_http_status = 200
        cache_entry.last_duration_ms = duration_ms
        cache_entry.feature_count = feature_count
    else:
        session.add(GeoJsonCache(
            feed_name=feed_name,
            data=data,
            updated_at=now,
            last_attempt_at=now,
            last_success_at=now,
            last_http_status=200,
            last_duration_ms=duration_ms,
            feature_count=feature_count,
        ))


def _record_geojson_failure(session, feed_name, error, http_status=None, duration_ms=None):
    """Record provider failure details without replacing its last good payload."""
    now = datetime.utcnow()
    cache_entry = session.query(GeoJsonCache).filter_by(feed_name=feed_name).first()
    if cache_entry is None:
        cache_entry = GeoJsonCache(feed_name=feed_name, data=None)
        session.add(cache_entry)
    cache_entry.last_attempt_at = now
    cache_entry.last_error = str(error)[:2000]
    cache_entry.last_http_status = http_status
    cache_entry.last_duration_ms = duration_ms


def fetch_spc_outlooks():
    """Fetch SPC outlook layers and update their cached GeoJSON records."""
    SPC_URLS = {
        "spc_day1": "https://www.spc.noaa.gov/products/outlook/day1otlk_cat.nolyr.geojson",
        "spc_day2": "https://www.spc.noaa.gov/products/outlook/day2otlk_cat.nolyr.geojson",
        "spc_day3": "https://www.spc.noaa.gov/products/outlook/day3otlk_cat.nolyr.geojson"
    }

    logger.debug("fetch_spc_outlooks: fetching %d SPC outlooks", len(SPC_URLS))
    headers = {'User-Agent': 'Mozilla/5.0 (NOC_Fusion_Center)'}

    def _fetch_spc(item):
        """Fetch one SPC outlook and return its feed name, data, and optional error."""
        feed_name, url = item
        started = time.monotonic()
        status_code = None
        try:
            response = requests.get(url, headers=headers, timeout=15)
            status_code = response.status_code
            if response.status_code == 200:
                payload = response.json()
                if not isinstance(payload, dict) or not isinstance(payload.get("features"), list):
                    raise ValueError("SPC response did not contain a FeatureCollection")
                return feed_name, payload, None, status_code, int((time.monotonic() - started) * 1000)
            return feed_name, None, f"HTTP {response.status_code}", status_code, int((time.monotonic() - started) * 1000)
        except Exception as e:
            return feed_name, None, str(e), status_code, int((time.monotonic() - started) * 1000)

    with SessionLocal() as session:
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                results = list(executor.map(_fetch_spc, SPC_URLS.items()))
            feed_statuses = {}
            for feed_name, data, error, status_code, duration_ms in results:
                if error:
                    logger.error(f"Failed to fetch {feed_name}. {error}")
                    _record_geojson_failure(session, feed_name, error, status_code, duration_ms)
                    feed_statuses[feed_name] = {"status": "error", "message": error, "http_status": status_code}
                else:
                    save_geojson_to_db(session, feed_name, data, duration_ms)
                    logger.debug(f"Downloaded and cached {feed_name} GeoJSON to DB.")
                    feed_statuses[feed_name] = {"status": "ok", "feature_count": len(data.get("features", []))}
            session.commit()
            failures = [name for name, status in feed_statuses.items() if status["status"] != "ok"]
            return {"status": "partial_failure" if failures else "ok", "feeds": feed_statuses}
        except Exception as e:
            session.rollback()
            logger.error(f"SPC Fetch Error: {e}", exc_info=True)
            return {"status": "error", "message": str(e)}


NWS_ACTIVE_FEED = "nws_region"
NWS_ACTIVE_URL = (
    "https://api.weather.gov/alerts/active?area=" + ",".join(REQUEST_STATE_CODES)
)


def _nws_request_headers(cache_entry=None):
    """Identify this poller and send validators when the NWS supplied them."""
    import os

    from src.core.config import settings

    user_agent = os.environ.get("NWS_API_USER_AGENT", "").strip() or settings.nws_api_user_agent
    contact = str(settings.default_admin_email or "").strip()
    if contact and contact.casefold() not in user_agent.casefold():
        user_agent = f"{user_agent} ({contact})"
    headers = {
        "User-Agent": user_agent,
        "Accept": "application/geo+json",
    }
    if cache_entry is not None:
        if cache_entry.etag:
            headers["If-None-Match"] = cache_entry.etag
        if cache_entry.last_modified:
            headers["If-Modified-Since"] = cache_entry.last_modified
    return headers


def _utc_naive(value):
    """Convert a CAP timestamp to the naive-UTC convention used by SQLite rows."""
    parsed = parse_nws_datetime(value)
    return parsed.astimezone(timezone.utc).replace(tzinfo=None) if parsed else None


def _retry_after_utc(value, now=None):
    """Parse an HTTP Retry-After delay or date into naive UTC for persistence."""
    if not value:
        return None
    current = now or datetime.utcnow()
    try:
        seconds = float(value)
        return current + timedelta(seconds=max(0, seconds))
    except (TypeError, ValueError):
        try:
            parsed = parsedate_to_datetime(str(value))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).replace(tzinfo=None)
        except (TypeError, ValueError, OverflowError):
            return None


def _references_from_properties(properties):
    """Normalize CAP/API references to identifier strings for reconciliation."""
    references = properties.get("references") or []
    if isinstance(references, str):
        references = references.split()
    if not isinstance(references, (list, tuple)):
        return []
    identifiers = []
    for reference in references:
        if isinstance(reference, dict):
            identifier = reference.get("identifier") or reference.get("id") or reference.get("url")
        else:
            parts = [part.strip() for part in str(reference).split(",")]
            identifier = parts[1] if len(parts) >= 2 else (parts[0] if parts else None)
        if identifier:
            identifiers.append(str(identifier))
    return list(dict.fromkeys(identifiers))


def _reference_matches(hazard_id, reference_id):
    """Match a CAP identifier to an API alert URL or its trailing identifier."""
    stored = str(hazard_id or "").rstrip("/")
    reference = str(reference_id or "").rstrip("/")
    if not stored or not reference:
        return False
    return stored == reference or stored.endswith("/" + reference) or reference.endswith("/" + stored)


def _stable_alert_id(feature):
    properties = feature.get("properties") or {}
    identifier = properties.get("id") or feature.get("id")
    if identifier:
        return str(identifier)
    stable_fields = (
        properties.get("sender"), properties.get("event"), properties.get("sent"),
        properties.get("areaDesc"), properties.get("headline"),
    )
    return "nws-" + hashlib.sha256("|".join(str(value or "") for value in stable_fields).encode()).hexdigest()


def _state_fallback_split(data):
    """Retain target-state alerts when county geometry cannot be loaded."""
    arkansas, border = [], []
    features = data.get("features", []) if isinstance(data, dict) else []
    for feature in features:
        if not isinstance(feature, dict) or not is_unexpired_alert(feature):
            continue
        properties = dict(feature.get("properties") or {})
        state_codes = alert_state_codes(properties)
        if "AR" in state_codes:
            scope, destination = "arkansas", arkansas
        else:
            scope, destination = "border", border
        properties["noc_coverage_scope"] = scope
        properties["noc_coverage_precision"] = "state_fallback"
        normalized = dict(feature)
        normalized["properties"] = properties
        destination.append(normalized)
    return (
        {"type": "FeatureCollection", "features": arkansas},
        {"type": "FeatureCollection", "features": border},
        {
            "source_feature_count": len(features),
            "arkansas_alert_count": len(arkansas),
            "border_alert_count": len(border),
            "coverage_precision_counts": {"state_fallback": len(arkansas) + len(border)},
            "border_states": list(REQUEST_STATE_CODES[1:]),
            "buffer_miles": 50,
            "fallback": True,
        },
    )


def _mark_nws_expired(session, now=None):
    """Deactivate records at the CAP expiration time, independent of poll success."""
    current = now or datetime.utcnow()
    changed = session.query(RegionalHazard).filter(
        RegionalHazard.status == "active",
        RegionalHazard.expires_at.isnot(None),
        RegionalHazard.expires_at <= current,
    ).update({
        RegionalHazard.status: "expired",
        RegionalHazard.updated_at: current,
    }, synchronize_session="fetch")
    if changed:
        logger.info("NWS lifecycle: expired %d alert records at CAP expires time", changed)
    return changed


def _reconcile_nws_alerts(session, features, now, lifecycle_features=None):
    """Upsert current alert details, apply CAP references, and reconcile snapshots."""
    incoming = []
    for feature in features:
        if not isinstance(feature, dict):
            continue
        properties = feature.get("properties") or {}
        incoming.append((_stable_alert_id(feature), properties))

    references = []
    for feature in (lifecycle_features if lifecycle_features is not None else features):
        properties = feature.get("properties") or {}
        message_type = str(properties.get("messageType") or "Alert").casefold()
        references.extend(
            (reference, "cancelled" if message_type == "cancel" else "superseded")
            for reference in _references_from_properties(properties)
        )

    _mark_nws_expired(session, now)
    active_records = session.query(RegionalHazard).filter_by(status="active").all()
    for hazard in active_records:
        for reference, status in references:
            if _reference_matches(hazard.hazard_id, reference):
                hazard.status = status
                hazard.updated_at = now
                break

    incoming_ids = [hazard_id for hazard_id, _ in incoming]
    existing_by_id = {}
    for offset in range(0, len(incoming_ids), 500):
        chunk = incoming_ids[offset:offset + 500]
        if not chunk:
            continue
        for hazard in session.query(RegionalHazard).filter(
            RegionalHazard.hazard_id.in_(chunk)
        ).all():
            existing_by_id[hazard.hazard_id] = hazard

    seen_ids = set()
    upserted = 0
    for hazard_id, properties in incoming:
        message_type = str(properties.get("messageType") or "Alert").casefold()
        if message_type == "cancel":
            continue
        hazard = existing_by_id.get(hazard_id)
        if hazard is None:
            hazard = RegionalHazard(hazard_id=hazard_id)
            session.add(hazard)
            existing_by_id[hazard_id] = hazard
        hazard.hazard_type = properties.get("event", "Unknown")
        hazard.severity = properties.get("severity", "Unknown")
        hazard.title = properties.get("headline") or properties.get("event") or "Weather Alert"
        hazard.description = properties.get("description", "")
        hazard.location = properties.get("areaDesc", "Regional")
        hazard.updated_at = now
        hazard.last_seen_at = now
        hazard.sent_at = _utc_naive(properties.get("sent"))
        hazard.effective_at = _utc_naive(properties.get("effective"))
        hazard.onset_at = _utc_naive(properties.get("onset"))
        hazard.expires_at = _utc_naive(properties.get("expires"))
        hazard.event_ending_at = _utc_naive(
            properties.get("ends") or properties.get("eventEndingTime")
        )
        hazard.message_type = properties.get("messageType") or "Alert"
        hazard.references_json = _references_from_properties(properties)
        hazard.coverage_scope = properties.get("noc_coverage_scope")
        hazard.coverage_precision = properties.get("noc_coverage_precision")
        hazard.status = (
            "expired"
            if hazard.expires_at is not None and hazard.expires_at <= now
            else "active"
        )
        if hazard.status == "active":
            seen_ids.add(hazard_id)
        upserted += 1

    # Only a successful complete active snapshot reaches this function. An
    # absent ID is therefore inactive, while an upstream fetch failure leaves
    # the prior active records untouched (apart from their scheduled expiry).
    for hazard in active_records:
        if hazard.hazard_id not in seen_ids and hazard.status == "active":
            hazard.status = "inactive"
            hazard.updated_at = now
    _mark_nws_expired(session, now)
    return upserted


def fetch_nws_alerts():
    """Poll one combined Arkansas/seven-state NWS active-alert endpoint."""
    started = datetime.utcnow()
    started_clock = time.monotonic()
    http_status = None
    result = {"status": "error", "feed": NWS_ACTIVE_FEED, "url": NWS_ACTIVE_URL}
    with SessionLocal() as session:
        cache_entry = session.query(GeoJsonCache).filter_by(feed_name=NWS_ACTIVE_FEED).first()
        if cache_entry and cache_entry.retry_after_at and cache_entry.retry_after_at > started:
            _mark_nws_expired(session, started)
            session.commit()
            return {
                "status": "backoff",
                "feed": NWS_ACTIVE_FEED,
                "retry_after_at": cache_entry.retry_after_at.isoformat(),
                "message": "NWS Retry-After window has not elapsed; polling is deferred.",
            }
        if cache_entry and cache_entry.last_attempt_at and (
            started - cache_entry.last_attempt_at < timedelta(seconds=60)
        ):
            return {
                "status": "throttled",
                "feed": NWS_ACTIVE_FEED,
                "last_attempt_at": cache_entry.last_attempt_at.isoformat(),
                "last_success_at": cache_entry.last_success_at.isoformat() if cache_entry.last_success_at else None,
                "message": "A centralized NWS request was made within the last 60 seconds.",
            }
        if cache_entry is None:
            cache_entry = GeoJsonCache(feed_name=NWS_ACTIVE_FEED, data=None)
            cache_entry.last_attempt_at = started
            session.add(cache_entry)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                current_entry = session.query(GeoJsonCache).filter_by(feed_name=NWS_ACTIVE_FEED).first()
                return {
                    "status": "throttled",
                    "feed": NWS_ACTIVE_FEED,
                    "last_attempt_at": current_entry.last_attempt_at.isoformat() if current_entry and current_entry.last_attempt_at else None,
                    "message": "Another process acquired the NWS poll lease.",
                }
        else:
            reserved = session.query(GeoJsonCache).filter(
                GeoJsonCache.feed_name == NWS_ACTIVE_FEED,
                or_(
                    GeoJsonCache.last_attempt_at.is_(None),
                    GeoJsonCache.last_attempt_at <= started - timedelta(seconds=60),
                ),
                or_(GeoJsonCache.retry_after_at.is_(None), GeoJsonCache.retry_after_at <= started),
            ).update(
                {GeoJsonCache.last_attempt_at: started}, synchronize_session=False
            )
            session.commit()
            if reserved != 1:
                current_entry = session.query(GeoJsonCache).filter_by(feed_name=NWS_ACTIVE_FEED).first()
                if current_entry and current_entry.retry_after_at and current_entry.retry_after_at > started:
                    return {
                        "status": "backoff", "feed": NWS_ACTIVE_FEED,
                        "retry_after_at": current_entry.retry_after_at.isoformat(),
                        "message": "NWS Retry-After window has not elapsed; polling is deferred.",
                    }
                return {
                    "status": "throttled", "feed": NWS_ACTIVE_FEED,
                    "last_attempt_at": current_entry.last_attempt_at.isoformat() if current_entry and current_entry.last_attempt_at else None,
                    "message": "Another process acquired the NWS poll lease.",
                }
        # Persist a lease before issuing the upstream request so a manual sync
        # cannot race the minute scheduler and duplicate the NWS poll.
        headers = _nws_request_headers(cache_entry)
        try:
            response = requests.get(NWS_ACTIVE_URL, headers=headers, timeout=15)
            http_status = response.status_code
            finished = datetime.utcnow()
            duration_ms = max(0, int((time.monotonic() - started_clock) * 1000))
            cache_entry = session.query(GeoJsonCache).filter_by(feed_name=NWS_ACTIVE_FEED).first()
            if cache_entry is None:
                cache_entry = GeoJsonCache(feed_name=NWS_ACTIVE_FEED, data=None)
                session.add(cache_entry)

            cache_entry.last_attempt_at = started
            cache_entry.last_http_status = response.status_code
            cache_entry.last_duration_ms = duration_ms
            if response.status_code == 304:
                if not cache_entry.data:
                    cache_entry.etag = None
                    cache_entry.last_modified = None
                    cache_entry.last_error = "NWS returned 304 but no cached response body is available."
                    session.commit()
                    result.update({"message": cache_entry.last_error, "http_status": 304})
                else:
                    cache_entry.last_success_at = finished
                    cache_entry.last_error = None
                    cache_entry.retry_after_at = None
                    session.query(RegionalHazard).filter_by(status="active").update(
                        {RegionalHazard.last_seen_at: finished}, synchronize_session=False
                    )
                    session.commit()
                    _mark_nws_expired(session, finished)
                    session.commit()
                    result.update({
                        "status": "not_modified",
                        "http_status": 304,
                        "feature_count": cache_entry.feature_count or 0,
                    })
                return result

            if response.status_code != 200:
                retry_after = response.headers.get("Retry-After")
                cache_entry.last_error = f"HTTP {response.status_code}" + (
                    f"; Retry-After={retry_after}" if retry_after else ""
                )
                cache_entry.retry_after_at = _retry_after_utc(retry_after, finished)
                session.commit()
                logger.error("NWS alerts returned %s; prior snapshot retained", response.status_code)
                result.update({"message": cache_entry.last_error, "http_status": response.status_code})
                _mark_nws_expired(session, finished)
                session.commit()
                return result

            data = response.json()
            features = data.get("features") if isinstance(data, dict) else None
            if not isinstance(features, list):
                raise ValueError("NWS active alerts response did not contain a FeatureCollection")

            try:
                ar_data, border_data, coverage_summary = split_alerts_for_region(data)
            except Exception:
                logger.exception("Unable to build exact NWS border coverage; using state-level fallback")
                ar_data, border_data, coverage_summary = _state_fallback_split(data)

            # Persist the provider snapshot, the two prefiltered display feeds,
            # alert lifecycle state, and validators in one database transaction.
            cache_entry.data = data
            cache_entry.updated_at = finished
            cache_entry.last_success_at = finished
            cache_entry.last_error = None
            cache_entry.retry_after_at = None
            cache_entry.last_http_status = 200
            cache_entry.last_duration_ms = duration_ms
            cache_entry.etag = response.headers.get("ETag") or cache_entry.etag
            cache_entry.last_modified = response.headers.get("Last-Modified") or cache_entry.last_modified
            cache_entry.feature_count = len(features)
            cache_entry.coverage_summary = coverage_summary
            save_geojson_to_db(session, "nws_ar", ar_data)
            save_geojson_to_db(session, "nws_oos", border_data)
            active_region_features = ar_data["features"] + border_data["features"]
            upserted = _reconcile_nws_alerts(
                session, active_region_features, finished, lifecycle_features=features
            )
            session.commit()
            _mark_nws_expired(session, finished)
            session.commit()
            result.update({
                "status": "ok",
                "http_status": 200,
                "feature_count": len(features),
                "arkansas_alerts": len(ar_data["features"]),
                "border_alerts": len(border_data["features"]),
                "records_reconciled": upserted,
                "coverage": coverage_summary,
            })
            logger.info(
                "NWS active-alert sync: source=%d Arkansas=%d border=%d duration_ms=%d",
                len(features), len(ar_data["features"]), len(border_data["features"]), duration_ms,
            )
            return result
        except Exception as exc:
            session.rollback()
            # Record the failed attempt separately without touching the last
            # successful payload or its timestamp.
            cache_entry = session.query(GeoJsonCache).filter_by(feed_name=NWS_ACTIVE_FEED).first()
            finished = datetime.utcnow()
            if cache_entry is None:
                cache_entry = GeoJsonCache(feed_name=NWS_ACTIVE_FEED, data=None)
                session.add(cache_entry)
            cache_entry.last_attempt_at = started
            cache_entry.last_http_status = http_status
            cache_entry.last_duration_ms = max(0, int((time.monotonic() - started_clock) * 1000))
            cache_entry.last_error = str(exc)[:2000]
            cache_entry.retry_after_at = None
            try:
                session.commit()
            except Exception:
                session.rollback()
            _mark_nws_expired(session, finished)
            try:
                session.commit()
            except Exception:
                session.rollback()
            logger.error("NWS active-alert fetch failed; prior snapshot retained: %s", exc, exc_info=True)
            result.update({"message": str(exc), "http_status": None})
            return result


USGS_BOUNDS = {
    "ar": {"minlat": 32.9, "maxlat": 36.6, "minlon": -94.7, "maxlon": -89.5},
    # Conservative envelope for Arkansas plus the six-state 50-mile border band.
    "oos": {"minlat": 31.8, "maxlat": 38.0, "minlon": -96.0, "maxlon": -88.0},
}


def fetch_usgs_earthquakes(area_key, feed_name):
    """Fetch USGS earthquake GeoJSON for one operating-area query."""
    from src.core.arkansas_coverage import get_arkansas_coverage

    coverage = None
    try:
        coverage = get_arkansas_coverage()
        west, south, east, north = (
            coverage.arkansas_bounds if area_key == "ar" else coverage.bounds
        )
        bounds = {"minlon": west, "minlat": south, "maxlon": east, "maxlat": north}
    except Exception:
        logger.warning("USGS %s using conservative static bounds; Arkansas geometry unavailable", area_key, exc_info=True)
        bounds = USGS_BOUNDS.get(area_key, USGS_BOUNDS["ar"])
    start_time = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")

    url = (
        f"https://earthquake.usgs.gov/fdsnws/event/1/query?"
        f"format=geojson&starttime={start_time}&minmagnitude=2.0"
        f"&minlatitude={bounds['minlat']}&maxlatitude={bounds['maxlat']}"
        f"&minlongitude={bounds['minlon']}&maxlongitude={bounds['maxlon']}"
    )

    started = time.monotonic()
    http_status = None
    with SessionLocal() as session:
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (NOC_Fusion_Center)'}
            response = requests.get(url, headers=headers, timeout=20)
            http_status = response.status_code
            duration_ms = max(0, int((time.monotonic() - started) * 1000))

            if response.status_code == 200:
                data = response.json()
                if not isinstance(data, dict) or not isinstance(data.get("features"), list):
                    raise ValueError("USGS response did not contain a FeatureCollection")
                if coverage and isinstance(data, dict):
                    scope = "arkansas" if area_key == "ar" else "border"
                    filtered = []
                    for feature in data.get("features", []):
                        coordinates = (feature.get("geometry") or {}).get("coordinates") or []
                        if len(coordinates) < 2:
                            continue
                        try:
                            if coverage.includes_point(coordinates[0], coordinates[1], scope):
                                filtered.append(feature)
                        except (TypeError, ValueError):
                            continue
                    data = {**data, "features": filtered}
                save_geojson_to_db(session, feed_name, data, duration_ms)
                cache_entry = session.query(GeoJsonCache).filter_by(feed_name=feed_name).first()
                if cache_entry:
                    cache_entry.coverage_summary = {
                        "scope": area_key,
                        "border_states": list(REQUEST_STATE_CODES[1:]),
                        "buffer_miles": 50,
                        "precision": "projected_geometry" if coverage else "conservative_bbox_fallback",
                    }
                session.commit()
                count = len(data.get('features', []))
                logger.debug(f"USGS ({area_key}) Fetched {count} earthquakes.")
                return {"status": "ok", "feed": feed_name, "feature_count": count, "http_status": http_status}
            else:
                logger.error(f"USGS API returned HTTP {response.status_code} for {area_key}")
                _record_geojson_failure(session, feed_name, f"HTTP {response.status_code}", http_status, duration_ms)
                session.commit()
                return {"status": "error", "feed": feed_name, "message": f"HTTP {response.status_code}", "http_status": http_status}

        except Exception as e:
            session.rollback()
            duration_ms = max(0, int((time.monotonic() - started) * 1000))
            _record_geojson_failure(session, feed_name, e, http_status, duration_ms)
            session.commit()
            logger.error(f"USGS Fetch Error for {area_key}: {e}")
            return {"status": "error", "feed": feed_name, "message": str(e), "http_status": http_status}


def haversine_distance(lat1, lon1, lat2, lon2):
    """Return great-circle distance in miles between two coordinate pairs."""
    R = 3959
    lat1_r, lat2_r = math.radians(lat1), math.radians(lat2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + math.cos(lat1_r) * math.cos(lat2_r) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    return R * c


def check_earthquake_proximity(equake_data, distance_miles=50):
    """Email newly qualifying nearby earthquakes and retain alerted event IDs."""
    from src.utils.risk_alert import send_alert, get_alert_recipients, build_eq_alert_email_body
    from src.services import get_cached_config, save_global_config

    if not equake_data or 'features' not in equake_data:
        return

    # Read previously alerted earthquake IDs
    sys_config = get_cached_config()
    try:
        alerted_ids = set(json.loads(sys_config.get('alerted_eq_ids', '[]')))
    except Exception:
        alerted_ids = set()

    with SessionLocal() as session:
        sites = session.query(MonitoredLocation).filter(
            MonitoredLocation.lat.isnot(None),
            MonitoredLocation.lon.isnot(None)
        ).all()

        new_alerts = []
        triggered_ids = []

        for f in equake_data['features']:
            props = f.get('properties', {})
            eq_id = f.get('id', '') or f"{props.get('time', '0')}_{props.get('place', 'unknown')}_{props.get('mag', 0)}"
            if eq_id in alerted_ids:
                continue

            mag = props.get('mag', 0)
            if mag < 2.5:
                continue

            coords = f.get('geometry', {}).get('coordinates', [0, 0, 0])
            eq_lon, eq_lat = coords[0], coords[1]
            place = props.get('place', 'Unknown')
            time_ms = props.get('time', 0)
            time_str = datetime.fromtimestamp(time_ms/1000, CENTRAL_TZ).strftime('%Y-%m-%d %H:%M') if time_ms else 'Unknown'
            depth = coords[2]

            hit = False
            for site in sites:
                if not site.lat or not site.lon:
                    continue
                dist = haversine_distance(eq_lat, eq_lon, site.lat, site.lon)
                if dist <= distance_miles:
                    new_alerts.append({
                        'site': site.name,
                        'site_type': site.loc_type,
                        'distance': round(dist, 1),
                        'mag': mag,
                        'place': place,
                        'depth': depth,
                        'time': time_str,
                        'lat': eq_lat,
                        'lon': eq_lon
                    })
                    hit = True

            if hit:
                triggered_ids.append(eq_id)

        if new_alerts:
            recipients = get_alert_recipients()
            if recipients:
                body = build_eq_alert_email_body(new_alerts)
                send_alert(recipients, f"NOC Alert: Earthquake Proximity Warning", body)
                logger.info(f"Earthquake alert sent for {len(new_alerts)} site proximities")

                # Persist alerted IDs so we never re-alert the same quake
                updated = alerted_ids | set(triggered_ids)
                save_global_config({'alerted_eq_ids': json.dumps(list(updated))})


def check_wildfire_proximity(distance_miles=5):
    """Email NOC_NOTIFY_EMAIL when active WFCA fire activity meets site-distance/re-alert rules."""
    import os
    from src.services import get_active_wildfires, _haversine_miles, _shape_site_distances_miles
    from src.utils.mailer import send_alert_email

    recipient = os.environ.get("NOC_NOTIFY_EMAIL", "").strip()
    if not recipient:
        logger.warning("Wildfire proximity alert skipped: NOC_NOTIFY_EMAIL is not set")
        return

    payload = get_active_wildfires()
    if not isinstance(payload, dict):
        return
    if (payload.get("meta") or {}).get("status") != "ok":
        logger.warning("Skipping wildfire proximity notifications because the WFCA snapshot is not freshly verified")
        return
    incidents = payload.get("incidents", [])
    perimeters = payload.get("perimeters", [])
    if not incidents and not perimeters:
        return

    with SessionLocal() as db:
        sites = db.query(MonitoredLocation).filter(
            MonitoredLocation.lat.isnot(None), MonitoredLocation.lon.isnot(None)
        ).all()
        config = db.query(SystemConfig).first()
        try:
            alerted = set(json.loads(config.alerted_wildfire_ids or "[]")) if config else set()
        except (TypeError, ValueError):
            alerted = set()
        try:
            proximity_state = json.loads(config.wildfire_proximity_state or "{}") if config else {}
            if not isinstance(proximity_state, dict):
                proximity_state = {}
        except (TypeError, ValueError):
            proximity_state = {}

        matches = []
        perimeter_names = set()
        perimeter_ids = set()
        closest_sites = {}
        for perimeter in perimeters:
            name = str(perimeter.get("name") or "Unknown Fire")
            small_fire = _is_small_wildfire(perimeter)
            geometry = perimeter.get("geometry")
            if not geometry:
                continue
            try:
                fire_shape = shape(geometry)
            except Exception:
                logger.warning("Skipping invalid WFCA perimeter for %s", name, exc_info=True)
                continue
            fire_id = str(perimeter.get("irwin_id") or name).strip()
            perimeter_names.add(name.strip().upper())
            perimeter_ids.add(fire_id.strip("{}").casefold())
            site_coordinates = [(float(site.lon), float(site.lat)) for site in sites]
            distances = _shape_site_distances_miles(fire_shape, site_coordinates)
            for site, distance in zip(sites, distances):
                # One degree of latitude is approximately 69 miles. This is
                # a local projection for the perimeter itself, not just the
                # incident centroid.
                if small_fire and distance > 1.0:
                    continue
                nearest = closest_sites.setdefault(name, [])
                if not nearest or distance < nearest[0][0] - 0.1:
                    closest_sites[name] = [(distance, site.name)]
                elif abs(distance - nearest[0][0]) <= 0.1:
                    nearest.append((distance, site.name))
                alert_key = f"{fire_id}:{site.id}"
                previous = proximity_state.get(alert_key, {})
                last_alert_distance = previous.get("last_alert_distance")
                if distance <= distance_miles and (
                    alert_key not in alerted or
                    last_alert_distance is None or
                    float(last_alert_distance) - distance >= 0.5
                ):
                    matches.append((alert_key, name, distance, perimeter, site.name, bool(alert_key in alerted)))
                proximity_state[alert_key] = {
                    "last_seen_distance": round(distance, 3),
                    "last_alert_distance": last_alert_distance,
                }

        # Use incident points as a fallback for each fire that does not yet
        # have a perimeter, even when other fires already have polygons.
        for incident in incidents:
            name = str(incident.get("name") or "Unknown Fire")
            small_fire = _is_small_wildfire(incident)
            fire_id = str(incident.get("irwin_id") or "").strip().strip("{}").casefold()
            if name.strip().upper() in perimeter_names or (fire_id and fire_id in perimeter_ids):
                continue
            if incident.get("lat") is None or incident.get("lon") is None:
                continue
            fire_id = str(incident.get("irwin_id") or incident.get("unique_id") or name).strip()
            lon, lat = float(incident["lon"]), float(incident["lat"])
            for site in sites:
                distance = _haversine_miles(lon, lat, float(site.lon), float(site.lat))
                if small_fire and distance > 1.0:
                    continue
                nearest = closest_sites.setdefault(name, [])
                if not nearest or distance < nearest[0][0] - 0.1:
                    closest_sites[name] = [(distance, site.name)]
                elif abs(distance - nearest[0][0]) <= 0.1:
                    nearest.append((distance, site.name))
                alert_key = f"{fire_id}:{site.id}"
                previous = proximity_state.get(alert_key, {})
                last_alert_distance = previous.get("last_alert_distance")
                if distance <= distance_miles and (
                    alert_key not in alerted or
                    last_alert_distance is None or
                    float(last_alert_distance) - distance >= 0.5
                ):
                    matches.append((alert_key, name, distance, incident, site.name, bool(alert_key in alerted)))
                proximity_state[alert_key] = {
                    "last_seen_distance": round(distance, 3),
                    "last_alert_distance": last_alert_distance,
                }

        if not matches:
            if config:
                config.wildfire_proximity_state = json.dumps(proximity_state)
                db.commit()
            return

        def fmt_date(value):
            """Normalize ISO or epoch-millisecond provider timestamps to Central time."""
            if not value:
                return "Unknown"
            try:
                if isinstance(value, str):
                    try:
                        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
                    except ValueError:
                        parsed = None
                    if parsed is not None:
                        if parsed.tzinfo is None:
                            parsed = parsed.replace(tzinfo=CENTRAL_TZ)
                        return parsed.astimezone(CENTRAL_TZ).strftime("%Y-%m-%d %H:%M %Z")
                return datetime.fromtimestamp(float(value) / 1000, CENTRAL_TZ).strftime("%Y-%m-%d %H:%M %Z")
            except (TypeError, ValueError, OSError):
                return str(value)

        lines = ["NOC WILDFIRE PROXIMITY ALERT", "", f"Active WFCA wildfire activity detected within {distance_miles} miles of a monitored site.", ""]
        for _, name, distance, details, site_name, previously_alerted in matches:
            encroaching = previously_alerted
            nearest = closest_sites.get(name, [])
            closest_text = ", ".join(f"{site} ({miles:.1f} mi)" for miles, site in nearest) or "Unknown"
            containment = details.get("contained")
            containment_text = f"{containment}%" if containment is not None else "Unknown"
            lines.extend([
                f"FIRE: {name}",
                f"ALERT TYPE: {'WARNING - FIRE ENCROACHING' if encroaching else 'INITIAL PROXIMITY ALERT'}",
                f"CLOSEST MONITORED SITE(S): {closest_text}",
                f"MONITORED SITE: {site_name}", f"DISTANCE: {distance:.1f} miles",
                f"STATE: {details.get('state', 'Unknown')}", f"COUNTY: {details.get('county', 'Unknown')}",
                f"STARTED: {fmt_date(details.get('started'))}",
                f"ACRES: {details.get('acres', details.get('perimeter_acres', 'Unknown'))}",
                f"MAPPED ACRES: {details.get('perimeter_acres', 'Unknown')}",
                f"CONTAINMENT: {containment_text}",
                f"CAUSE: {details.get('cause', 'Unknown')}",
                f"PERIMETER UPDATED: {fmt_date(details.get('perimeter_updated'))}",
                f"MAP METHOD: {details.get('map_method', 'Unknown')}", "",
            ])
        success, message = send_alert_email(
            "Wildfire Proximity Alert", "\n".join(lines), recipient_override=recipient, is_html=False
        )
        if success and config:
            for alert_key, _, distance, _, _, _ in matches:
                proximity_state[alert_key]["last_alert_distance"] = round(distance, 3)
            config.alerted_wildfire_ids = json.dumps(sorted(alerted | {match[0] for match in matches}))
            config.wildfire_proximity_state = json.dumps(proximity_state)
            db.commit()
            logger.info("Wildfire proximity alert sent for %d site matches", len(matches))
        elif not success:
            logger.warning("Wildfire proximity alert email failed: %s", message)


def fetch_regional_hazards():
    """Refresh slower SPC/USGS feeds, then run earthquake and wildfire checks."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(fetch_spc_outlooks): "spc",
            executor.submit(fetch_usgs_earthquakes, "ar", "usgs_ar"): "usgs_ar",
            executor.submit(fetch_usgs_earthquakes, "oos", "usgs_oos"): "usgs_oos",
        }
        results = {}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as e:
                results[name] = {"status": "error", "message": str(e)}
                logger.error("infra_worker: parallel fetch error: %s", e)

    with SessionLocal() as db:
        usgs_ar = db.query(GeoJsonCache).filter_by(feed_name="usgs_ar").first()
        usgs_oos = db.query(GeoJsonCache).filter_by(feed_name="usgs_oos").first()
        if results.get("usgs_ar", {}).get("status") == "ok" and usgs_ar and usgs_ar.data:
            check_earthquake_proximity(usgs_ar.data, 50)
        if results.get("usgs_oos", {}).get("status") == "ok" and usgs_oos and usgs_oos.data:
            check_earthquake_proximity(usgs_oos.data, 50)
    check_wildfire_proximity(5)
    failed = [name for name, result in results.items() if not isinstance(result, dict) or result.get("status") != "ok"]
    return {
        "status": "ok" if not failed else "partial_failure",
        "feeds": results,
        "failed_feeds": failed,
    }


if __name__ == "__main__":
    fetch_nws_alerts()
    fetch_regional_hazards()
