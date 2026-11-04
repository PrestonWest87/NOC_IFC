"""Regional map, weather, and hazard endpoints over cached provider data.

The map compiler returns a positional six-element response consumed by the
frontend; endpoint grants correspond to Regional Grid tabs.
"""

import logging
import math
import uuid
from fastapi import APIRouter, Query, Body, Depends, HTTPException
from typing import Any

from src import services as svc
from src.api.auth_guard import get_current_user, require_any_action, require_page, require_action

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/regional", tags=["regional"], dependencies=[Depends(require_page("Regional Grid"))])


def _parse_bbox(value):
    """Validate a WGS84 viewport box supplied as comma text or four values."""
    if value is None or value == "":
        return None
    try:
        values = [float(part) for part in value.split(",")] if isinstance(value, str) else [float(part) for part in value]
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="bbox must contain west,south,east,north coordinates.")
    if len(values) != 4 or not all(math.isfinite(part) for part in values):
        raise HTTPException(status_code=400, detail="bbox must contain four finite coordinates.")
    west, south, east, north = values
    if not (-180 <= west < east <= 180 and -90 <= south < north <= 90):
        raise HTTPException(status_code=400, detail="bbox coordinates are outside valid WGS84 bounds.")
    return west, south, east, north


def _site_in_viewport(row, bbox):
    """Check a map site coordinate against a validated WGS84 viewport."""
    try:
        lon = float(row.get("Lon", row.get("lon")))
        lat = float(row.get("Lat", row.get("lat")))
        west, south, east, north = bbox
        return west <= lon <= east and south <= lat <= north
    except (TypeError, ValueError):
        return False


@router.get("/locations", dependencies=[Depends(require_any_action([
    "Tab: Regional Grid -> Geospatial Map", "Tab: Regional Grid -> Executive Dash",
    "Tab: Regional Grid -> Hazard Analytics", "Tab: Regional Grid -> Location Matrix",
    "Tab: Regional Grid -> Weather Alerts Log", "Tab: Regional Grid -> Atmos Weather",
]))])
def locations(user=Depends(get_current_user)):
    """Return cached monitored locations filtered to the caller's site types."""
    logger.debug("GET /locations")
    locations_data = svc.get_cached_locations()
    if str(user.role or "").casefold() in {"admin", "administrator"}:
        return locations_data
    allowed_types = set(user.allowed_site_types or [])
    return [location for location in locations_data if location.get("loc_type") in allowed_types]


@router.get("/geojson", dependencies=[Depends(require_any_action([
    "Tab: Regional Grid -> Geospatial Map", "Tab: Regional Grid -> Executive Dash",
    "Tab: Regional Grid -> Hazard Analytics", "Tab: Regional Grid -> Weather Alerts Log",
    "Tab: Regional Grid -> Atmos Weather",
]))])
def geojson(
    layers: str | None = Query(None, description="Comma-separated feed names; omitted returns every layer."),
    bbox: str | None = Query(None, description="Optional WGS84 viewport: west,south,east,north."),
):
    """Return requested cached layers, active NWS event names, and compact freshness metadata."""
    allowed = set(svc.REGIONAL_GEOJSON_FEEDS)
    requested = allowed if layers is None else set() if layers.strip().casefold() == "summary" else {
        name.strip() for name in layers.split(",") if name.strip()
    }
    unknown = requested - allowed
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown regional GeoJSON layer(s): {', '.join(sorted(unknown))}")
    viewport = _parse_bbox(bbox)
    logger.debug("GET /geojson layers=%s bbox=%s", sorted(requested), viewport)
    feeds = svc.get_cached_geojson_layers(requested, viewport)
    return {
        **{name: feeds.get(name) for name in requested},
        "nws_events": svc.get_active_nws_event_types(),
        "meta": svc.get_cached_geojson_status(),
    }


@router.get("/wildfires", dependencies=[Depends(require_action("Tab: Regional Grid -> Geospatial Map"))])
def wildfires(bbox: str | None = Query(None, description="Optional WGS84 viewport: west,south,east,north.")):
    """Return cached WFCA features scoped to the optional current map viewport."""
    viewport = _parse_bbox(bbox)
    logger.debug("GET /wildfires bbox=%s", viewport)
    payload = svc.get_active_wildfires()
    return svc.filter_wildfires_to_bbox(payload, viewport) if viewport else payload


@router.post("/compile-map", dependencies=[Depends(require_any_action([
    "Tab: Regional Grid -> Geospatial Map", "Tab: Regional Grid -> Executive Dash",
    "Tab: Regional Grid -> Hazard Analytics", "Tab: Regional Grid -> Location Matrix",
    "Tab: Regional Grid -> Weather Alerts Log", "Tab: Regional Grid -> Atmos Weather",
]))])
def compile_map(data: dict[str, Any] = Body({}), user=Depends(get_current_user)):
    """Intersect selected cached hazard layers with scoped sites and return the positional map payload."""
    logger.info("POST /compile-map toggles=%s", data.get("toggles", {}))
    toggles = data.get("toggles", {})
    spc = data.get("spc_data")
    ar = data.get("ar_data")
    oos = data.get("oos_data")
    usgs_ar = data.get("usgs_ar_data")
    usgs_oos = data.get("usgs_oos_data")
    selected = tuple(data.get("selected_events", []))
    include_analytics = bool(data.get("include_analytics", False))
    raw_map_rows = data.get("map_df", [])
    viewport = _parse_bbox(data.get("viewport_bounds"))

    # The browser no longer needs to echo the full GeoJSON snapshot back to the
    # API. Keep accepting the old fields for compatibility, but use the server's
    # coherent cached snapshot when they are omitted.
    legacy_fields = ("spc_data", "ar_data", "oos_data", "usgs_ar_data", "usgs_oos_data")
    has_legacy_snapshot = any(data.get(name) is not None for name in legacy_fields)

    map_rows = [dict(row) for row in raw_map_rows if isinstance(row, dict)] if isinstance(raw_map_rows, list) else []
    if str(user.role or "").casefold() not in {"admin", "administrator"} and map_rows:
        allowed_names = svc.get_allowed_site_names_for_user(user)
        available_columns = {key for row in map_rows for key in row}
        site_column = next((name for name in ("Monitored Site", "name", "Name") if name in available_columns), None)
        if site_column:
            map_rows = [row for row in map_rows if str(row.get(site_column, "")) in allowed_names]
        else:
            map_rows = []

    if viewport and not include_analytics:
        map_rows = [row for row in map_rows if _site_in_viewport(row, viewport)]

    active_wildfires = include_analytics or bool(toggles.get("active_wildfires"))
    if not has_legacy_snapshot:
        requested_feeds = set()
        if include_analytics or toggles.get("spc"):
            requested_feeds.add("spc_day1")
        if include_analytics or toggles.get("warn") or toggles.get("watch") or toggles.get("fire_risk"):
            requested_feeds.add("nws_ar")
        if include_analytics or toggles.get("oos"):
            requested_feeds.add("nws_oos")
        if include_analytics or toggles.get("earthquakes"):
            requested_feeds.update(("usgs_ar", "usgs_oos"))
        feeds = svc.get_cached_geojson_layers(
            requested_feeds,
            viewport if viewport and not include_analytics else None,
        )
        spc = feeds.get("spc_day1")
        ar = feeds.get("nws_ar")
        oos = feeds.get("nws_oos")
        usgs_ar = feeds.get("usgs_ar")
        usgs_oos = feeds.get("usgs_oos")

    wildfire_data = svc.get_active_wildfires() if active_wildfires else None
    if wildfire_data is not None and viewport and not include_analytics:
        wildfire_data = svc.filter_wildfires_to_bbox(wildfire_data, viewport)
    feed_meta = svc.get_cached_geojson_status()
    feed_names = ("spc_day1", "nws_ar", "nws_oos", "usgs_ar", "usgs_oos")
    if has_legacy_snapshot:
        feed_versions = ("legacy", uuid.uuid4().hex)
    else:
        feed_versions = tuple(
            (name, (feed_meta.get(name) or {}).get("updated_at"))
            for name in feed_names if name in requested_feeds
        )
    nws_signature = tuple(sorted(
        (
            str((feature.get("properties") or {}).get("id") or feature.get("id") or ""),
            str((feature.get("properties") or {}).get("sent") or ""),
            str((feature.get("properties") or {}).get("expires") or ""),
        )
        for collection in (ar, oos) if isinstance(collection, dict)
        for feature in collection.get("features", [])
    ))
    wildfire_version = ((wildfire_data or {}).get("meta") or {}).get("last_success_at")
    cache_token = (feed_versions, nws_signature, wildfire_version, viewport, include_analytics)
    cache = svc._precompute_geo_matrix(
        spc, ar, oos, usgs_ar, usgs_oos, selected, map_rows,
        cache_token, active_wildfires, wildfire_data,
    )

    toggled_affected_sites_dict = {}
    for site in cache["master_affected_sites"]:
        hazard = site["Hazard"]
        is_visible = False
        if "SPC:" in hazard and toggles.get("spc", True): is_visible = True
        elif "Wildfire Risk:" in hazard and toggles.get("fire_risk", False): is_visible = True
        elif "Active Wildfire:" in hazard and toggles.get("active_wildfires", False): is_visible = True
        elif "EQ (" in hazard and toggles.get("earthquakes", True): is_visible = True
        elif "[OOS]" in hazard and toggles.get("oos", True): is_visible = True
        elif "[AR]" in hazard:
            if site["Severity"] == "Warning" and toggles.get("warn", True): is_visible = True
            elif site["Severity"] == "Watch/Advisory" and toggles.get("watch", True): is_visible = True
        if is_visible:
            name = site["Monitored Site"]
            if name not in toggled_affected_sites_dict:
                toggled_affected_sites_dict[name] = {
                    "Monitored Site": name, "District": site["District"],
                    "Facility Type": site["Type"], "Priority": site["Priority"], "Hazards": set()
                }
            toggled_affected_sites_dict[name]["Hazards"].add(hazard)

    toggled_affected_sites = []
    for v in toggled_affected_sites_dict.values():
        v["Intersecting Hazards"] = ", ".join(list(v["Hazards"]))
        v.pop("Hazards")
        toggled_affected_sites.append(v)

    master_affected_sites = cache["master_affected_sites"]

    analytics = svc.get_infrastructure_analytics(map_rows, master_affected_sites)
    analytics_serialized = {
        "total_sites": int(analytics["total_sites"]),
        "at_risk_sites": int(analytics["at_risk_sites"]),
        "highest_risk": str(analytics["highest_risk"]),
        "spc_distribution": analytics["spc_distribution"],
        "nws_distribution": analytics["nws_distribution"],
        "type_distribution": analytics["type_distribution"],
        "district_distribution": analytics["district_distribution"],
        "priority_risk_matrix": analytics["priority_risk_matrix"],
        "type_risk_matrix": analytics["type_risk_matrix"],
        "district_risk_matrix": analytics["district_risk_matrix"],
    }

    def _strip_feature(f):
        """Remove non-serializable Shapely objects from one GeoJSON feature."""
        if not isinstance(f, dict):
            return f
        return {
            k: (
                {pk: pv for pk, pv in v.items() if pk != "shapely_obj"}
                if k == "properties" and isinstance(v, dict)
                else v
            )
            for k, v in f.items() if k != "shapely_obj"
        }

    def _strip_collection(fc):
        """Normalize an absent collection and strip Shapely objects from its features."""
        if not fc:
            return {"type": "FeatureCollection", "features": []}
        return {
            "type": "FeatureCollection",
            "features": [_strip_feature(f) for f in fc.get("features", [])]
        }

    processed_geo = {
        "ar_warn": _strip_collection(cache.get("ar_warn")),
        "ar_watch": _strip_collection(cache.get("ar_watch")),
        "oos_warn": _strip_collection(cache.get("oos_warn")),
        "oos_watch": _strip_collection(cache.get("oos_watch")),
    }
    if viewport and not include_analytics:
        processed_geo = {
            name: svc.filter_geojson_to_bbox(collection, viewport)
            for name, collection in processed_geo.items()
        }

    logger.info("POST /compile-map complete: affected_sites=%d analytics=%s",
                 len(master_affected_sites), analytics_serialized.get('highest_risk'))
    return [processed_geo, {}, cache["map_diagnostics"], toggled_affected_sites, master_affected_sites, analytics_serialized]


@router.get("/weather-prefs", dependencies=[Depends(require_action("Tab: Regional Grid -> Atmos Weather"))])
def weather_prefs(user=Depends(get_current_user)):
    """Return alert preferences belonging to the authenticated user."""
    logger.debug("GET /weather-prefs username=%s", user.username)
    return svc.get_user_weather_prefs(user.username)


@router.post("/weather-prefs", dependencies=[Depends(require_action("Tab: Regional Grid -> Atmos Weather"))])
def set_weather_prefs(alerts: list[str] = Body([]), user=Depends(get_current_user)):
    """Replace the authenticated user's weather-alert preference list."""
    logger.info("POST /weather-prefs username=%s alerts=%s", user.username, alerts)
    svc.set_user_weather_prefs(user.username, alerts)
    return {"status": "ok"}


@router.get("/forecast", dependencies=[Depends(require_action("Tab: Regional Grid -> Atmos Weather"))])
def forecast(lat: float = Query(34.8), lon: float = Query(-92.2)):
    """Return the cached/upstream NWS forecast for the requested coordinates."""
    logger.debug("GET /forecast lat=%.4f lon=%.4f", lat, lon)
    return svc.get_nws_forecast(lat, lon)


@router.get("/weather-alerts-log", dependencies=[Depends(require_action("Tab: Regional Grid -> Weather Alerts Log"))])
def weather_alerts_log():
    """Build the weather-alert log from cached regional NWS and USGS layers."""
    logger.debug("GET /weather-alerts-log")
    data = svc.get_cached_geojson_layers(("nws_ar", "nws_oos", "usgs_ar", "usgs_oos"))
    ar, oos = data.get("nws_ar"), data.get("nws_oos")
    usgs_ar, usgs_oos = data.get("usgs_ar"), data.get("usgs_oos")
    return svc.get_weather_alerts_log(ar, oos, [], usgs_ar, usgs_oos)


@router.get("/site-types")
def site_types():
    """Return the merged default and database-backed site-type catalog."""
    logger.debug("GET /site-types")
    return svc.get_all_site_types()


@router.post("/sync-hazards", dependencies=[
    Depends(require_any_action([
        "Tab: Regional Grid -> Geospatial Map", "Tab: Regional Grid -> Executive Dash",
        "Tab: Regional Grid -> Hazard Analytics",
    ])),
    Depends(require_action("Action: Manually Sync Data")),
])
def sync_hazards():
    """Refresh NWS alerts and slower hazards, then clear derived API caches."""
    logger.info("POST /sync-hazards: triggering manual hazard sync")
    from src.workers.infra_worker import fetch_nws_alerts, fetch_regional_hazards
    try:
        nws_result = fetch_nws_alerts()
        regional_result = fetch_regional_hazards()
        svc.get_cached_geojson.clear()
        svc.get_cached_geojson_layers.clear()
        svc.get_cached_geojson_status.clear()
        svc._precompute_geo_matrix.clear()
        svc.get_active_wildfires.clear()
        failures = [name for name, result in (
            ("nws_alerts", nws_result), ("regional_hazards", regional_result)
        ) if result.get("status") not in {"ok", "not_modified", "throttled", "backoff"}]
        if failures:
            logger.error("POST /sync-hazards: partial failure %s", failures)
            raise HTTPException(
                status_code=502,
                detail={"message": "One or more hazard sources failed to refresh.", "feeds": {
                    "nws_alerts": nws_result, "regional_hazards": regional_result,
                }},
            )
        logger.info("POST /sync-hazards: sync complete")
        return {
            "status": "ok", "message": "Regional hazards synced.",
            "feeds": {"nws_alerts": nws_result, "regional_hazards": regional_result},
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("POST /sync-hazards failed: %s", e)
        raise HTTPException(status_code=502, detail="Regional hazard sync failed.") from e
