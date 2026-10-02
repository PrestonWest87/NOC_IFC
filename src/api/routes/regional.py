import logging
from fastapi import APIRouter, Query, Body, Depends, HTTPException
from typing import Any

from src import services as svc
from src.api.auth_guard import get_current_user, require_any_action, require_page, require_action

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/regional", tags=["regional"], dependencies=[Depends(require_page("Regional Grid"))])


@router.get("/locations", dependencies=[Depends(require_any_action([
    "Tab: Regional Grid -> Geospatial Map", "Tab: Regional Grid -> Executive Dash",
    "Tab: Regional Grid -> Hazard Analytics", "Tab: Regional Grid -> Location Matrix",
    "Tab: Regional Grid -> Weather Alerts Log", "Tab: Regional Grid -> Atmos Weather",
]))])
def locations(user=Depends(get_current_user)):
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
def geojson():
    logger.debug("GET /geojson")
    spc_d1, spc_d2, spc_d3, ar, oos, usgs_ar, usgs_oos = svc.get_cached_geojson()
    return {
        "spc_day1": spc_d1, "spc_day2": spc_d2, "spc_day3": spc_d3,
        "nws_ar": ar, "nws_oos": oos,
        "usgs_ar": usgs_ar, "usgs_oos": usgs_oos,
        "meta": svc.get_cached_geojson_status(),
    }


@router.get("/wildfires", dependencies=[Depends(require_action("Tab: Regional Grid -> Geospatial Map"))])
def wildfires():
    """Return active NIFC incidents independently of the heavier weather feeds."""
    logger.debug("GET /wildfires")
    return svc.get_active_wildfires()


@router.post("/compile-map", dependencies=[Depends(require_any_action([
    "Tab: Regional Grid -> Geospatial Map", "Tab: Regional Grid -> Executive Dash",
    "Tab: Regional Grid -> Hazard Analytics", "Tab: Regional Grid -> Location Matrix",
    "Tab: Regional Grid -> Weather Alerts Log", "Tab: Regional Grid -> Atmos Weather",
]))])
def compile_map(data: dict[str, Any] = Body({}), user=Depends(get_current_user)):
    logger.info("POST /compile-map toggles=%s", data.get("toggles", {}))
    toggles = data.get("toggles", {})
    spc = data.get("spc_data")
    ar = data.get("ar_data")
    oos = data.get("oos_data")
    usgs_ar = data.get("usgs_ar_data")
    usgs_oos = data.get("usgs_oos_data")
    selected = tuple(data.get("selected_events", []))
    raw_map_rows = data.get("map_df", [])

    # The browser no longer needs to echo the full GeoJSON snapshot back to the
    # API. Keep accepting the old fields for compatibility, but use the server's
    # coherent cached snapshot when they are omitted.
    if not any((spc, ar, oos, usgs_ar, usgs_oos)):
        spc, _, _, ar, oos, usgs_ar, usgs_oos = svc.get_cached_geojson()

    map_rows = [dict(row) for row in raw_map_rows if isinstance(row, dict)] if isinstance(raw_map_rows, list) else []
    if str(user.role or "").casefold() not in {"admin", "administrator"} and map_rows:
        allowed_names = svc.get_allowed_site_names_for_user(user)
        available_columns = {key for row in map_rows for key in row}
        site_column = next((name for name in ("Monitored Site", "name", "Name") if name in available_columns), None)
        if site_column:
            map_rows = [row for row in map_rows if str(row.get(site_column, "")) in allowed_names]
        else:
            map_rows = []

    cache = svc._precompute_geo_matrix(spc, ar, oos, usgs_ar, usgs_oos, selected, map_rows)

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

    logger.info("POST /compile-map complete: affected_sites=%d analytics=%s",
                 len(master_affected_sites), analytics_serialized.get('highest_risk'))
    return [processed_geo, {}, cache["map_diagnostics"], toggled_affected_sites, master_affected_sites, analytics_serialized]


@router.get("/weather-prefs", dependencies=[Depends(require_action("Tab: Regional Grid -> Atmos Weather"))])
def weather_prefs(user=Depends(get_current_user)):
    logger.debug("GET /weather-prefs username=%s", user.username)
    return svc.get_user_weather_prefs(user.username)


@router.post("/weather-prefs", dependencies=[Depends(require_action("Tab: Regional Grid -> Atmos Weather"))])
def set_weather_prefs(alerts: list[str] = Body([]), user=Depends(get_current_user)):
    logger.info("POST /weather-prefs username=%s alerts=%s", user.username, alerts)
    svc.set_user_weather_prefs(user.username, alerts)
    return {"status": "ok"}


@router.get("/forecast", dependencies=[Depends(require_action("Tab: Regional Grid -> Atmos Weather"))])
def forecast(lat: float = Query(34.8), lon: float = Query(-92.2)):
    logger.debug("GET /forecast lat=%.4f lon=%.4f", lat, lon)
    return svc.get_nws_forecast(lat, lon)


@router.get("/weather-alerts-log", dependencies=[Depends(require_action("Tab: Regional Grid -> Weather Alerts Log"))])
def weather_alerts_log():
    logger.debug("GET /weather-alerts-log")
    _, _, _, ar, oos, usgs_ar, usgs_oos = svc.get_cached_geojson()
    return svc.get_weather_alerts_log(ar, oos, [], usgs_ar, usgs_oos)


@router.get("/site-types")
def site_types():
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
    logger.info("POST /sync-hazards: triggering manual hazard sync")
    from src.workers.infra_worker import fetch_regional_hazards
    try:
        fetch_regional_hazards()
        svc.get_cached_geojson.clear()
        svc.get_cached_geojson_status.clear()
        svc._precompute_geo_matrix.clear()
        svc.get_active_wildfires.clear()
        logger.info("POST /sync-hazards: sync complete")
        return {"status": "ok", "message": "Regional hazards synced."}
    except Exception as e:
        logger.error("POST /sync-hazards failed: %s", e)
        raise HTTPException(status_code=502, detail="Regional hazard sync failed.") from e
