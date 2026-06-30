import logging
import pandas as pd
from fastapi import APIRouter, Query, Body
from typing import Any

from src import services as svc

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/regional", tags=["regional"])


@router.get("/locations")
def locations():
    logger.debug("GET /locations")
    return svc.get_cached_locations()


@router.get("/geojson")
def geojson():
    logger.debug("GET /geojson")
    spc_d1, spc_d2, spc_d3, ar, oos, usgs_ar, usgs_oos = svc.get_cached_geojson()
    return {
        "spc_day1": spc_d1, "spc_day2": spc_d2, "spc_day3": spc_d3,
        "nws_ar": ar, "nws_oos": oos,
        "usgs_ar": usgs_ar, "usgs_oos": usgs_oos,
    }


@router.post("/compile-map")
def compile_map(data: dict[str, Any] = Body({})):
    logger.info("POST /compile-map toggles=%s", data.get("toggles", {}))
    toggles = data.get("toggles", {})
    spc = data.get("spc_data")
    ar = data.get("ar_data")
    oos = data.get("oos_data")
    usgs_ar = data.get("usgs_ar_data")
    usgs_oos = data.get("usgs_oos_data")
    selected = tuple(data.get("selected_events", []))
    raw_map_df = data.get("map_df", [])

    if raw_map_df:
        map_df = pd.DataFrame(raw_map_df)
    else:
        map_df = pd.DataFrame()

    cache = svc._precompute_geo_matrix(spc, ar, oos, usgs_ar, usgs_oos, selected, map_df)

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

    analytics = svc.get_infrastructure_analytics(map_df, master_affected_sites)
    analytics_serialized = {
        "total_sites": int(analytics["total_sites"]),
        "at_risk_sites": int(analytics["at_risk_sites"]),
        "highest_risk": str(analytics["highest_risk"]),
        "spc_distribution": analytics["spc_distribution"].to_dict(orient="records") if not analytics["spc_distribution"].empty else [],
        "nws_distribution": analytics["nws_distribution"].to_dict(orient="records") if not analytics["nws_distribution"].empty else [],
        "type_distribution": analytics["type_distribution"].reset_index().to_dict(orient="records") if not analytics["type_distribution"].empty else [],
        "district_distribution": analytics["district_distribution"].reset_index().to_dict(orient="records") if not analytics["district_distribution"].empty else [],
        "priority_risk_matrix": analytics["priority_risk_matrix"].reset_index().to_dict(orient="records") if not analytics["priority_risk_matrix"].empty else [],
        "type_risk_matrix": analytics["type_risk_matrix"].reset_index().to_dict(orient="records") if not analytics["type_risk_matrix"].empty else [],
        "district_risk_matrix": analytics["district_risk_matrix"].reset_index().to_dict(orient="records") if not analytics["district_risk_matrix"].empty else [],
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


@router.get("/weather-prefs")
def weather_prefs(username: str = ""):
    logger.debug("GET /weather-prefs username=%s", username)
    return svc.get_user_weather_prefs(username)


@router.post("/weather-prefs")
def set_weather_prefs(username: str = "", alerts: list[str] = Body([])):
    logger.info("POST /weather-prefs username=%s alerts=%s", username, alerts)
    svc.set_user_weather_prefs(username, alerts)
    return {"status": "ok"}


@router.get("/forecast")
def forecast(lat: float = Query(34.8), lon: float = Query(-92.2)):
    logger.debug("GET /forecast lat=%.4f lon=%.4f", lat, lon)
    return svc.get_nws_forecast(lat, lon)


@router.get("/weather-alerts-log")
def weather_alerts_log():
    logger.debug("GET /weather-alerts-log")
    _, _, _, ar, oos, usgs_ar, usgs_oos = svc.get_cached_geojson()
    return svc.get_weather_alerts_log(ar, oos, [], usgs_ar, usgs_oos)


@router.get("/site-types")
def site_types():
    logger.debug("GET /site-types")
    return svc.get_all_site_types()


@router.post("/sync-hazards")
def sync_hazards():
    logger.info("POST /sync-hazards: triggering manual hazard sync")
    from src.workers.infra_worker import fetch_regional_hazards
    try:
        fetch_regional_hazards()
        svc.get_cached_geojson.clear()
        logger.info("POST /sync-hazards: sync complete")
        return {"status": "ok", "message": "Regional hazards synced."}
    except Exception as e:
        logger.error("POST /sync-hazards failed: %s", e)
        return {"status": "error", "message": str(e)}
